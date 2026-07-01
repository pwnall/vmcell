set shell := ["bash", "-uc"]

# v15 §12.8: the blessed runner is installed to a STABLE path OUTSIDE target/, so cargo's
# RUSTFLAGS/feature re-fingerprint churn never rewrites it (and so never strips its caps).
runner := ".vmcell-bin/debug/vmcell-test-runner"
runner-release := ".vmcell-bin/release/vmcell-test-runner"

# Grant the three caps the privileged suite needs, durably (v15 §12.8). Builds the runner, copies
# it to the stable, gitignored ./.vmcell-bin/ path, and setcaps THAT copy. Idempotent via a
# content-hash `.blessed` stamp keyed on the RUNNER binary only (never test binaries): a re-run is
# a transparent no-op (no sudo prompt) until the runner genuinely changes. Because cargo only ever
# rewrites target/, the stable copy keeps its caps across all the unrelated rebuild churn.
bless:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p vmcell-test-runner
    cargo build --release -p vmcell-test-runner
    bless_one() {
      local built="$1" stable="$2"
      local dir; dir="$(dirname "$stable")"
      local stamp="$dir/.blessed"
      mkdir -p "$dir"
      # Key the stamp on the freshly-BUILT runner's content. If it matches the last bless and the
      # stable copy still exists, the stable copy is already blessed (cargo never touches it) — skip
      # both the copy (which would strip caps) and the sudo setcap.
      local h; h="$(sha256sum "$built" | cut -d' ' -f1)"
      if [[ -f "$stamp" && -f "$stable" && "$(cat "$stamp")" == "$h" ]]; then
        echo "bless: $stable already blessed (runner sha256 unchanged); skipping setcap"
        return 0
      fi
      cp -f "$built" "$stable"
      sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep "$stable"
      echo "$h" > "$stamp"
      echo "bless: $stable (re)blessed"
    }
    bless_one target/debug/vmcell-test-runner {{runner}}
    bless_one target/release/vmcell-test-runner {{runner-release}}

# Fast inner loop: unit + codec + property tests. No KVM, no privileges.
test-unit:
    cargo nextest run --all-features

# Privileged integration suite via the capability runner (dev box only; group-restrict the runner
# on shared hosts). Wraps every test binary with vmcell-test-runner via the cargo target-runner hook.
# The in-guest test-helper (ip/curl/kvm-ok) is baked into the rootfs by `vmcell build`, not
# built here. `--features` is scoped to the `vmcell` member that owns the integration tests.
test-privileged:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --profile integration -p vmcell --features firecracker,qemu --run-ignored all \
        -E 'not (test(unprivileged) | test(smoltcp))'

# Unprivileged integration suite under no elevation (keeps the unprivileged path honest).
test-unprivileged:
    cargo nextest run --profile integration -p vmcell --run-ignored all -E 'test(unprivileged) | test(smoltcp)'

# Everything the `lint` CI job runs, locally — a faithful mirror of .github/workflows/ci.yml.
# Shebang recipe so the whole job shares one shell: RUSTFLAGS=-D warnings is exported process-wide
# (matching CI's workflow-level env, which — unlike a clippy `-- -D warnings` arg — also denies
# warnings surfaced through path/patched deps), and the known-RED feature-powerset step runs LAST
# and non-blocking so it can no longer short-circuit the reachable gates (C-GATE-1 / S28).
ci:
    #!/usr/bin/env bash
    set -uo pipefail
    export RUSTFLAGS="-D warnings"
    set -e
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features
    cargo deny check
    # lean-agent invariant: the guest PID-1 member must omit the host stack AND compile standalone.
    # v15: the lean boundary is now a per-MEMBER structural property (§12.8 #4), so the check
    # targets the crate directly (`-p`) rather than a feature slice of the old single package.
    if cargo tree -e no-dev -p vmcell-guest-agent | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-agent invariant violated — host stack leaked into the agent build"; exit 1; fi
    cargo clippy -p vmcell-guest-agent --all-targets
    # lean-test-runner invariant: same host-stack ban + standalone compile for the privileged-window member.
    if cargo tree -e no-dev -p vmcell-test-runner | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-test-runner invariant violated — host stack leaked into the test-runner build"; exit 1; fi
    cargo clippy -p vmcell-test-runner --all-targets
    # guest-tools: build+clippy only (reqwest legitimately pulls hyper/tokio — see impl-notes, no lean-tree assertion).
    cargo clippy -p vmcell-guest-tools --all-targets
    ./scripts/ban-global-state.sh
    ./scripts/test-ban-global-state.sh
    ./scripts/ban-legacy-terms.sh
    ./scripts/test-ban-legacy-terms.sh
    cargo nextest run --all-features
    # public-API semver intent (CI runs this PRs-only against the PR base; locally diff vs the main merge-base).
    baseline="$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse main 2>/dev/null || true)"
    if [ -n "$baseline" ]; then cargo semver-checks --baseline-rev "$baseline" -p vmcell; else echo "semver-checks: no main baseline available locally, skipping (CI enforces it on PRs)"; fi
    # Accepted-RED debt LAST and non-blocking (C-GATE-1): host-common module-gating powerset.
    set +e
    echo "== feature-powerset (accepted-RED debt; non-blocking — see C-GATE-1) =="
    cargo hack --feature-powerset --depth 2 clippy -p vmcell --all-targets
    echo "note: feature-powerset is known-RED accepted debt; its status does NOT gate 'just ci'."
