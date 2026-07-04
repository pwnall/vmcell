# vmcell — Gate & automation configuration

Deployable contents for every automatable gate in `docs/48-claude-code-review-rubric.md` (Part D and
the Part E preflight). Most of these files exist in some form; treat each block as the v3 target and
diff against the repo — names the repo already established (recipes, env selectors, fixture names)
win over the ones here. Interfaces invented here rather than read from the design are marked
*(align with repo)*.

---

## `src/lib.rs` / `src/main.rs` — crate-root lint preamble

Top of every workspace crate root (`vmcell`, `vmcell-protocol`, `vmcell-guest-agent`,
`vmcell-test-runner`, `vmcell-guest-tools`). Enforces the Part D lint families at compile time.
I/O-free modules additionally carry `#![forbid(unsafe_code)]` at module level, shrinking the
audit surface to the modules that genuinely need unsafe (VMM glue, `setns`, virtqueue rings, the
agent's syscalls, `net_sys`).

```rust
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc,
        clippy::missing_errors_doc, clippy::missing_panics_doc)]
#![cfg_attr(not(test), deny(
    clippy::unwrap_used, clippy::panic, clippy::unreachable,
    clippy::todo, clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro,
))]
// Under evaluation after M-HOST-6: cfg_attr(not(test), deny(clippy::expect_used)) with per-site
// allows carrying "invariant:" comments — at minimum the ban script greps `.expect(` in
// guest-driven modules.
```

---

## `clippy.toml`

Workspace root. Thresholds and targeted API bans; the lint *set* lives in the crate-root preamble
above so it is visible where it applies.

```toml
# Declared MSRV. Effective build floor is 1.88 via the committed lockfile (time 0.3.47 for
# RUSTSEC-2026-0009); CI builds --locked on 1.88 — see the toolchain note in docs/47 §10.5.
msrv = "1.85"

# The crate-root denies are cfg'd out for test builds; these keep behavior identical if any lint
# ever moves to [workspace.lints].
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-dbg-in-tests = true
allow-print-in-tests = true

disallowed-methods = [
  { path = "std::env::temp_dir", reason = "bare /tmp is squattable on shared hosts; use XDG_RUNTIME_DIR / the artifacts dir (rubric B1)" },
  { path = "std::process::exit", reason = "skips Drop-based ordered teardown; return from main. PID-1 agent must never exit at all (§12.6) — per-site allow with rationale if truly required" },
]
```

---

## `deny.toml`

Workspace root, consumed by `cargo deny check` (licenses / advisories / bans / sources). The license
allow-list is the design §10.4 set — permissive only; extending it gets the same review as a new
dependency. Every advisory ignore carries a per-crate rationale — sixteen identical boilerplate
ignores is the bulk-suppression pattern review 37 flagged.

```toml
[graph]
all-features = true

[licenses]
allow = [
  "MIT",
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Zlib",
  "0BSD",
  "Unicode-3.0",
  "CDLA-Permissive-2.0",
]

[advisories]
yanked = "deny"
# One entry per advisory, each with a per-crate reason naming the entry path and why it is inert.
# The known set: dormant `unmaintained` advisories from the tokio-0.1 tree, entering only via
# tun-tap 0.1.4 → tokio-core → tokio 0.1.22 (the optional privileged tap path). Keep the ids as
# committed in the repo; the shape is:
ignore = [
  # { id = "RUSTSEC-XXXX-NNNN", reason = "tokio-core: dormant dep of tun-tap 0.1.4 (privileged tap path only); no runtime exposure — re-evaluate if tun-tap is replaced" },
]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

---

## `Cargo.toml` (workspace root) — vendored-patch entries

Add to the existing workspace manifest. The carried QEMU-unprivileged vhost patch (§10.4) resolves
from in-tree sources; the dependent manifests use exact `=` pins because a caret requirement lets a
version bump silently drop the patch with only a cargo warning (M-VEND-3). `just vendor-check`
asserts the resolution.

```toml
[patch.crates-io]
# Carried patch: SET_VRING_ENABLE PROTOCOL_FEATURES relaxation gated on features_acked (M-VEND-2),
# needed only to attach the smoltcp NAT to QEMU. Apache-2.0 (rust-vmm). Drop vendor/ + these
# entries if the QEMU-unprivileged tier is dropped.
vhost = { path = "vendor/vhost" }                            # 0.16.0
vhost-user-backend = { path = "vendor/vhost-user-backend" }  # 0.22.0
```

In the consuming crate's `[dependencies]`:

```toml
vhost = "=0.16.0"
vhost-user-backend = "=0.22.0"
```

---

## `.config/nextest.toml`

Repo root (nextest reads `.config/nextest.toml`). Pins the nextest version that made
`--no-tests=fail` the default (a filter selecting zero tests is a failure, not a pass), defines the
`serial-host` group that positively selects every vmcell integration binary so a new VM test
auto-joins, and scopes retries to the VM profile only.

```toml
# --no-tests=fail became the default in 0.9.85; the pin is the "zero selected tests is a CI
# failure" gate.
nextest-version = "0.9.85"

[test-groups.serial-host]
max-threads = 1

# Positive selection: every vmcell integration binary joins automatically; proptests stay
# parallel. Inherited by all profiles.
[[profile.default.overrides]]
filter = 'package(vmcell) & kind(test) & !binary(proptests)'
test-group = 'serial-host'

[profile.default]
slow-timeout = { period = "60s", terminate-after = 2 }

# Used by the KVM suites (just test-priv / test-unpriv).
[profile.vm]
# Retries are the residual-environment backstop, not a diagnosis: the dominant historical cause of
# the "Agent … timed out" flake was the AGENT-2 reaper-epoch race, root-caused and fixed (§12.6).
# A fresh-VM retry absorbs a transient CH hybrid-vsock reset; a genuine break fails all attempts.
retries = { backoff = "exponential", count = 3, delay = "5s", max-delay = "20s" }
slow-timeout = { period = "120s", terminate-after = 2 }
```

---

## `justfile`

Repo root. **The single source of truth for gate commands** — CI invokes these recipes step by
step, which is how "`just ci` and CI are the same thing" holds by construction (Part D meta-rule 3).
`RUSTFLAGS=-D warnings` is exported process-wide; the blessed runner lives outside `target/`
precisely so this re-fingerprinting never strips the blessing. `VMCELL_MODE` is the requested-mode
selector from §6.4 *(align with repo)*.

```just
set shell := ["bash", "-euo", "pipefail", "-c"]

export RUSTFLAGS := "-D warnings"

default: ci

# ---- KVM-free gates (Part D). Known-red steps go last or non-gating (meta-rule 1); the powerset
# ---- is currently green and blocking, ordered last only because it is the slowest.
ci: fmt-check clippy lean reduced test-unit doc deny semver ban ban-selftest vendor-check powerset

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Each lean member is built AND clippied (a cargo-tree-only check compiles nothing), its dependency
# tree asserted free of the host async stack, and the agent grepped for the behavioral netlink
# escape (shelling out to `ip`/`nft` adds no crate and passes the tree gate).
lean:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in vmcell-guest-agent vmcell-test-runner vmcell-guest-tools; do
        cargo build --locked -p "$pkg"
        cargo clippy --locked -p "$pkg" -- -D warnings
    done
    for pkg in vmcell-guest-agent vmcell-test-runner; do   # guest-tools exempt (§10.5, recorded)
        if cargo tree --locked -p "$pkg" -e no-dev | grep -qE '\b(tokio|hyper|rtnetlink) v'; then
            echo "lean: $pkg pulls a banned host-stack crate" >&2; exit 1
        fi
    done
    if grep -RnE 'Command::new\("(ip|nft)"' vmcell-guest-agent/src; then
        echo "lean: agent shells out to ip/nft (zero-netlink invariant, §12.3)" >&2; exit 1
    fi

# The shipped reduced-host configs build and clippy as BLOCKING gates (review 40 CFG-1: a
# feature-gated arm silently changing semantics in a config only the powerset compiles). Extend
# per shipped configs.
reduced:
    cargo clippy --locked -p vmcell --no-default-features --features cloud-hypervisor -- -D warnings
    cargo clippy --locked -p vmcell --no-default-features --features cloud-hypervisor,metrics -- -D warnings

# All feature combos compile (blocking since the host-common collapse; ~205 configs).
powerset:
    cargo hack check --workspace --feature-powerset --locked

# Unit + KVM-free integration (ignored tests excluded by default); doctests.
test-unit:
    cargo nextest run --workspace --locked --no-tests=fail
    cargo test --doc --workspace --locked

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked

deny:
    cargo deny check

# Baseline: origin/main until the crates are published (then the registry baseline).
semver:
    cargo semver-checks check-release --workspace --baseline-rev origin/main

ban:
    scripts/ban-global-state.sh

# Red-on-inverse self-test: one MUST-flag fixture per keyword (Part D meta-rule 2).
ban-selftest:
    scripts/ban-global-state.sh --self-test

# The carried vhost patch resolves from vendor/ and stays exactly pinned (M-VEND-3).
vendor-check:
    #!/usr/bin/env bash
    set -euo pipefail
    tree=$(cargo tree --workspace --locked)
    for c in "vhost v0.16.0" "vhost-user-backend v0.22.0"; do
        if ! grep -F "$c" <<<"$tree" | grep -q 'vendor/'; then
            echo "vendor-check: $c does not resolve from vendor/ — the carried patch is dropped" >&2
            exit 1
        fi
    done
    if grep -RnE '^\s*vhost(-user-backend)?\s*=\s*"[^=]' --include=Cargo.toml . | grep -v vendor/; then
        echo "vendor-check: non-exact pin on a patched crate (caret drops the patch on bump)" >&2
        exit 1
    fi

# ---- KVM host only.
ci-kvm: preflight test-priv test-unpriv skips

preflight:
    scripts/review-preflight-priv.sh

# Build, install outside target/ (RUSTFLAGS churn never strips the blessing), setcap, stamp.
# Idempotent via a content-hash stamp keyed on the runner — never on test binaries.
bless:
    #!/usr/bin/env bash
    set -euo pipefail
    profile=release
    cargo build --locked --release -p vmcell-test-runner
    src="target/${profile}/vmcell-test-runner"
    dstdir=".vmcell-bin/${profile}"; dst="${dstdir}/vmcell-test-runner"; stamp="${dstdir}/.blessed"
    mkdir -p "$dstdir"
    h=$(sha256sum "$src" | cut -d' ' -f1)
    if [[ -f "$stamp" && "$(cat "$stamp")" == "$h" ]] && getcap "$dst" | grep -q cap_net_admin; then
        echo "bless: up to date"; exit 0
    fi
    install -m 0700 "$src" "$dst"                 # owner-only: the privilege boundary is who may execute
    sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep "$dst"   # +ep, not +p
    echo "$h" > "$stamp"
    getcap "$dst"

# Privileged suite: blessed runner registered as the nextest target runner; caps go to the test
# process only, cargo/rustc stay unprivileged. Secondary backends compiled in (--features): a
# default-features run compiles FC/QEMU out entirely (review 37).
test-priv:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="$PWD/.vmcell-bin/release/vmcell-test-runner" \
    VMCELL_MODE=privileged \
    cargo nextest run --locked -p vmcell --features firecracker,qemu \
        -E 'kind(test)' --run-ignored all --profile vm --no-tests=fail

test-unpriv:
    VMCELL_MODE=unprivileged \
    cargo nextest run --locked -p vmcell --features firecracker,qemu \
        -E 'kind(test)' --run-ignored all --profile vm --no-tests=fail

# Surface the durable skip manifest (a passing test's stdout is discarded; only the manifest
# survives). In CI this lands in the step summary.
skips:
    #!/usr/bin/env bash
    set -euo pipefail
    m="${VMCELL_SKIP_MANIFEST:-}"
    out="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
    if [[ -z "$m" || ! -f "$m" ]]; then echo "skips: no manifest (zero capability skips recorded)" >> "$out"; exit 0; fi
    echo "vmcell capability skips: $(wc -l < "$m")" >> "$out"
    sed 's/^/    /' "$m" >> "$out"
```

---

## `.github/workflows/ci.yml`

The gates job runs the same `just` recipes a developer runs — one named step per Part D table row,
one command source (meta-rule 3 by construction). The KVM job runs the two operating-mode suites on
a self-hosted KVM runner and surfaces the skip manifest; it does not depend on the gates job, so a
formatting red never hides a suite result (Part E: fail-fast=false across suites).

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # semver baseline is origin/main
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.88"         # effective floor: lockfile pins time 0.3.47 (RUSTSEC-2026-0009)
          components: clippy, rustfmt
      - uses: taiki-e/install-action@v2
        with:
          tool: just,cargo-nextest@0.9.85,cargo-deny,cargo-semver-checks,cargo-hack
      - uses: Swatinem/rust-cache@v2

      # Ordering mirrors `just ci`. If a step is ever accepted-red, it moves last or gains
      # continue-on-error — it must never short-circuit the gates behind it (meta-rule 1).
      - name: fmt
        run: just fmt-check
      - name: clippy (-D warnings)
        run: just clippy
      - name: lean members build+clippy+tree+netlink-grep
        run: just lean
      - name: reduced-host configs (blocking)
        run: just reduced
      - name: unit + KVM-free integration + doctests
        run: just test-unit
      - name: rustdoc (deny warnings)
        run: just doc
      - name: cargo deny
        run: just deny
      - name: semver-checks
        run: just semver
      - name: global-state ban
        run: just ban
      - name: ban self-test (red-on-inverse, per keyword)
        run: just ban-selftest
      - name: vendored-patch resolution
        run: just vendor-check
      - name: feature powerset
        run: just powerset

  kvm-suites:
    runs-on: [self-hosted, linux, kvm]
    env:
      VMCELL_SKIP_MANIFEST: ${{ runner.temp }}/vmcell-skips.txt
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.88"
      - uses: taiki-e/install-action@v2
        with:
          tool: just,cargo-nextest@0.9.85
      - name: preflight (fix-or-static-only)
        run: just preflight
      - name: privileged suite (all backends)
        run: just test-priv
      - name: unprivileged suite (all backends)
        if: ${{ !cancelled() }}      # a red privileged suite must not hide the unprivileged result
        run: just test-unpriv
      - name: surface skip manifest
        if: ${{ always() }}
        run: just skips
```

---

## `.github/workflows/fuzz.yml`

Nightly, non-blocking by virtue of being scheduled — it gates no PR, but a red run is visible and a
crash uploads its reproducer. Covers the rubric B10 decode surfaces.

```yaml
name: fuzz-nightly

on:
  schedule:
    - cron: "17 9 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-fuzz
      - name: run all targets (5 min each)
        run: |
          for t in $(cargo fuzz list); do
            cargo fuzz run "$t" -- -max_total_time=300
          done
      - name: upload crash reproducers
        if: ${{ failure() }}
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts/
```

---

## `fuzz/` — cargo-fuzz crate

`cargo fuzz init` layout at the repo root, one target per parser that guest or network bytes reach
(rubric B10): the protocol frame codec, the CH REST/chunked-response parser, the OCI/tar layer
ingest. The skeleton below is the codec target; entry-point names follow the repo *(align with
repo)*.

`fuzz/Cargo.toml`:

```toml
[package]
name = "vmcell-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
vmcell-protocol = { path = "../vmcell-protocol" }

[[bin]]
name = "protocol_decode"
path = "fuzz_targets/protocol_decode.rs"
test = false
doc = false
```

`fuzz/fuzz_targets/protocol_decode.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

// Decode must reject arbitrary bytes without panicking, without allocating past MAX_FRAME_BYTES,
// and without truncating integers (rubric B10). Errors are fine; panics and OOMs are findings.
fuzz_target!(|data: &[u8]| {
    let _ = vmcell_protocol::decode_frame(data); // (align with repo: the real decode entry point)
});
```

---

## `scripts/ban-global-state.sh` + `scripts/ban-fixtures/`

The un-fakeable-global-state ban (§10.6: module-global `static AtomicU32` counters are precisely
why a class of bugs was review-only). Grep-grade, not a parser: multi-line-aware (files are
flattened before matching) and alias-aware (renaming a banned type is itself a violation — write it
unaliased or allowlist it). One keyword list drives both the scanner and the self-test, closing
review 40's PRIV-4: a keyword deleted from the scanner leaves an orphan fixture that no longer
flags, and the self-test goes red in both directions.

Escape hatch: `scripts/ban-allowlist.txt`, one `path/to/file.rs  # reason` per approved seam.

```bash
#!/usr/bin/env bash
# Global-state ban. Flags `static` items holding OnceLock/OnceCell/LazyLock/Lazy/Mutex/RwLock/
# Atomic*, `static mut`, `lazy_static!`, and alias evasion. Known limitation: comments are not
# stripped (grep-grade); allowlist a doc-heavy false positive rather than weakening the regex.
set -euo pipefail
cd "$(dirname "$0")/.."

# Single source of truth — scanner regex AND self-test fixtures derive from these lists.
KEYWORDS=(OnceLock OnceCell LazyLock Lazy Mutex RwLock Atomic)
EXTRA_CHECKS=(static_mut lazy_static alias)   # each has its own detection arm + fixture

kw_alt="$(IFS='|'; echo "${KEYWORDS[*]}")"
ALLOWLIST="scripts/ban-allowlist.txt"

scan_file() {                       # returns 0 if the file violates the ban
    local flat
    flat=$(tr '\n' ' ' < "$1")
    grep -qE "static [^;={]{0,240}\b(${kw_alt})[A-Za-z0-9]*\b" <<<"$flat" && return 0
    grep -qE 'static mut ' <<<"$flat" && return 0
    grep -qE 'lazy_static!' <<<"$flat" && return 0
    grep -qE "use [^;]*\b(${kw_alt})[A-Za-z0-9]*\b[^;]* as " <<<"$flat" && return 0
    return 1
}

self_test() {
    local fixdir="scripts/ban-fixtures" fail=0 name f
    for name in "${KEYWORDS[@]}" "${EXTRA_CHECKS[@]}"; do
        f="${fixdir}/flag_${name}.rs"
        if [[ ! -f "$f" ]]; then echo "self-test: missing MUST-flag fixture for ${name}" >&2; fail=1
        elif ! scan_file "$f"; then echo "self-test: gate CANNOT fail for ${name} (${f} not flagged)" >&2; fail=1
        fi
    done
    for f in "$fixdir"/flag_*.rs; do          # orphan fixture = keyword removed from the scanner
        name=$(basename "$f" .rs); name=${name#flag_}
        printf '%s\n' "${KEYWORDS[@]}" "${EXTRA_CHECKS[@]}" | grep -qx "$name" \
            || { echo "self-test: orphan fixture ${f} — keyword removed from scanner?" >&2; fail=1; }
    done
    for f in "$fixdir"/clean_*.rs; do
        scan_file "$f" && { echo "self-test: false positive on ${f}" >&2; fail=1; }
    done
    (( fail )) && exit 1
    echo "ban self-test: ok ($((${#KEYWORDS[@]} + ${#EXTRA_CHECKS[@]})) flag fixtures, clean fixtures pass)"
}

[[ "${1:-}" == "--self-test" ]] && { self_test; exit 0; }

fail=0
while IFS= read -r f; do
    grep -qE "^${f}([[:space:]]|$)" "$ALLOWLIST" 2>/dev/null && continue
    if scan_file "$f"; then
        echo "ban: ${f}: global mutable state (un-fakeable; inject a seam or allowlist with reason)" >&2
        fail=1
    fi
done < <(find . \( -path ./vendor -o -path ./target -o -path ./fuzz -o -path ./scripts \) -prune \
              -o -name '*.rs' -path '*/src/*' -print | sed 's|^\./||')
exit "$fail"
```

`scripts/ban-fixtures/` — one MUST-flag fixture per keyword/check plus clean controls. Not compiled
(no cargo target; the directory is pruned from the scan itself):

```rust
// flag_OnceLock.rs
static CACHE: OnceLock<u32> = OnceLock::new();

// flag_OnceCell.rs
static CELL: OnceCell<String> = OnceCell::new();

// flag_LazyLock.rs
static TABLE: LazyLock<Vec<u8>> = LazyLock::new(Vec::new);

// flag_Lazy.rs
static L: Lazy<String> = Lazy::new(String::new);

// flag_Mutex.rs — deliberately line-wrapped: the multi-line case review 40 showed slipping through
static REGISTRY: Mutex<Vec<u32>>
    = Mutex::new(Vec::new());

// flag_RwLock.rs
static STATE: RwLock<u8> = RwLock::new(0);

// flag_Atomic.rs — the §10.6 anti-pattern verbatim
static COUNT: AtomicU32 = AtomicU32::new(0);

// flag_static_mut.rs
static mut GLOBAL: u32 = 0;

// flag_lazy_static.rs
lazy_static! {
    static ref X: u32 = 1;
}

// flag_alias.rs — alias evasion is itself a violation
use std::sync::OnceLock as Slot;
static S: Slot<u32> = Slot::new();

// clean_field.rs — locals and fields are fine; the ban targets statics
struct S {
    m: Mutex<()>,
}
fn f() {
    let c = AtomicU32::new(0);
    let _ = (S { m: Mutex::new(()) }, c);
}

// clean_static_str.rs — plain statics and 'static lifetimes are fine
static NAME: &str = "vmcell";
fn g<T: 'static + Send>(_: T) {}
```

---

## `scripts/review-preflight-priv.sh`

The Part E Phase-0 gate, matching the review-37 contract: verify the privileged suites *can* run
before any review or host-facing fix claims anything; otherwise fix, or label the run
**static-only** and mark every runtime claim unverified. Collects all failures rather than stopping
at the first.

```bash
#!/usr/bin/env bash
# vmcell privileged preflight: runner blessed, KVM + backends present, delegation available.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
ok()  { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; fail=1; }

echo "vmcell preflight"

[[ -r /dev/kvm && -w /dev/kvm ]] \
    && ok "/dev/kvm read/write" \
    || bad "/dev/kvm not accessible (usermod -aG kvm \$USER, then re-login)"
[[ -e /dev/vhost-vsock ]] && ok "/dev/vhost-vsock" || bad "/dev/vhost-vsock missing (modprobe vhost_vsock)"

for b in cloud-hypervisor firecracker qemu-system-x86_64 virtiofsd nft; do
    command -v "$b" >/dev/null && ok "$b on PATH" || bad "$b missing"
done

runner=".vmcell-bin/release/vmcell-test-runner"
stamp=".vmcell-bin/release/.blessed"
if [[ -x "$runner" ]]; then
    caps=$(getcap "$runner" 2>/dev/null || true)
    if grep -q cap_net_admin <<<"$caps" && grep -q cap_sys_admin <<<"$caps" \
       && grep -q cap_dac_override <<<"$caps" && grep -qE '\+ep' <<<"$caps"; then
        ok "runner blessed +ep"
    else
        bad "runner present but not blessed +ep (a +p-only blessing leaves effective caps un-raised) — just bless"
    fi
    perms=$(stat -c '%a' "$runner")
    [[ "$perms" == "700" ]] && ok "runner 0700 (owner-only execute boundary)" \
        || bad "runner perms ${perms}, expect 0700 — the privilege boundary is who may execute"
    [[ -f "$stamp" && "$(cat "$stamp")" == "$(sha256sum "$runner" | cut -d' ' -f1)" ]] \
        && ok "content-hash stamp matches" \
        || bad "blessing stamp stale or missing (rebuilt runner loses its caps by design) — just bless"
else
    bad "blessed runner missing at ${runner} — just bless"
fi

ctrl="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers"
if [[ -r "$ctrl" ]] && grep -qw memory "$ctrl"; then
    ok "cgroup v2 memory controller delegated"
else
    bad "memory controller not delegated to user@$(id -u).service — metrics/limits hard precondition"
fi

if [[ -n "${VMCELL_ARTIFACTS_DIR:-}" ]]; then
    [[ -d "$VMCELL_ARTIFACTS_DIR" ]] && ok "artifacts dir ${VMCELL_ARTIFACTS_DIR}" \
        || bad "VMCELL_ARTIFACTS_DIR=${VMCELL_ARTIFACTS_DIR} does not exist"
else
    echo "  note  VMCELL_ARTIFACTS_DIR unset — the default location must hold kernel/rootfs (no /tmp fallbacks; a missing artifact is an error, not a silent fetch)"
fi

if (( fail )); then
    echo
    echo "preflight: FAILED — fix the items above, or label this run STATIC-ONLY and mark every runtime claim unverified."
    exit 1
fi
echo "preflight: ok — both operating-mode suites can run."
```

---

## Coverage map

Rubric Part D/E row → where it is enforced. Rows tagged `review`/`test` in the rubric (fake
fidelity, drop-order, assertion quality, …) have no config file and stay with the reviewer and the
test suite.

| Rubric gate | Enforced by |
|---|---|
| Lint families, fmt | `lib.rs` preamble, `clippy.toml`, `just fmt-check` / `just clippy` |
| Lean members built **and** clippied; tree ∌ tokio/hyper/rtnetlink; agent `ip`/`nft` grep | `just lean` |
| Reduced-host configs blocking | `just reduced` |
| Feature powerset | `just powerset` |
| cargo-deny with per-crate rationales | `deny.toml`, `just deny` |
| semver-checks | `just semver` |
| `cargo doc` deny-warnings | `just doc` + `broken_intra_doc_links` in the preamble |
| nextest timeouts; retries scoped to the VM profile with the honest stanza | `.config/nextest.toml` |
| Zero-selected-tests fails; serial-host positive selection | `nextest-version = 0.9.85` pin, `--no-tests=fail` in recipes, the `serial-host` override |
| KVM `--ignored` matrix compiled with `--features firecracker,qemu` | `just test-priv` / `just test-unpriv`, `kvm-suites` job |
| Skip manifest surfaced in CI | `just skips`, `VMCELL_SKIP_MANIFEST` env in `ci.yml` |
| Global-state ban, alias/multi-line aware, per-keyword red-on-inverse self-test | `scripts/ban-global-state.sh` + `scripts/ban-fixtures/` |
| Vendored-patch resolution + exact pins | `just vendor-check`, `[patch.crates-io]` |
| `--locked` everywhere | every cargo invocation in the `justfile` |
| Nightly fuzz on decode surfaces | `fuzz.yml`, `fuzz/` |
| Gate meta-rule 3: `just ci` ≡ CI | `ci.yml` steps are `just` recipes — one command source |
| Part E Phase-0 preflight | `scripts/review-preflight-priv.sh`, first step of `kvm-suites` |
