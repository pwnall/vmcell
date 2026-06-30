set shell := ["bash", "-uc"]

runner := "target/debug/vmcell-test-runner"
runner-release := "target/release/vmcell-test-runner"

# (Re)grant the two caps the privileged suite needs. Re-run after every rebuild of the runner.
# Builds + blesses BOTH debug and release (matches README §5); `--features test-runner` is
# required or the required-features bin is skipped and setcap targets a stale binary.
bless:
    cargo build --bin vmcell-test-runner --features test-runner
    cargo build --release --bin vmcell-test-runner --features test-runner
    sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {{runner}}
    sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {{runner-release}}

# Fast inner loop: unit + codec + property tests. No KVM, no privileges.
test-unit:
    cargo nextest run --all-features

# Privileged integration suite via the capability runner (dev box only; group-restrict the runner
# on shared hosts). Wraps every test binary with vmcell-test-runner via the cargo target-runner hook.
# The in-guest test-helper (ip/curl/kvm-ok) is baked into the rootfs by `vmcell build`, not
# built here.
test-privileged:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --profile integration --features firecracker,qemu --run-ignored all \
        -E 'not (test(unprivileged) | test(smoltcp))'

# Unprivileged integration suite under no elevation (keeps the unprivileged path honest).
test-unprivileged:
    cargo nextest run --profile integration --run-ignored all -E 'test(unprivileged) | test(smoltcp)'

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
    cargo clippy --all-targets --all-features
    cargo deny check
    # lean-agent invariant: omit the host stack AND compile the agent-only target standalone.
    if cargo tree -e no-dev --no-default-features --features agent | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-agent invariant violated — host stack leaked into the agent build"; exit 1; fi
    cargo clippy --no-default-features --features agent --bin vmcell-guest-agent
    # lean-test-runner invariant: same host-stack ban + standalone compile for the privileged-window binary.
    if cargo tree -e no-dev --no-default-features --features test-runner | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-test-runner invariant violated — host stack leaked into the test-runner build"; exit 1; fi
    cargo clippy --no-default-features --features test-runner --bin vmcell-test-runner
    # guest-tools: build+clippy only (reqwest legitimately pulls hyper/tokio — see impl-notes, no lean-tree assertion).
    cargo clippy --no-default-features --features guest-tools --bin vmcell-guest-tools
    ./scripts/ban-global-state.sh
    ./scripts/test-ban-global-state.sh
    cargo nextest run --all-features
    # public-API semver intent (CI runs this PRs-only against the PR base; locally diff vs the main merge-base).
    baseline="$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse main 2>/dev/null || true)"
    if [ -n "$baseline" ]; then cargo semver-checks --baseline-rev "$baseline"; else echo "semver-checks: no main baseline available locally, skipping (CI enforces it on PRs)"; fi
    # Accepted-RED debt LAST and non-blocking (C-GATE-1): host-common module-gating powerset.
    set +e
    echo "== feature-powerset (accepted-RED debt; non-blocking — see C-GATE-1) =="
    cargo hack --feature-powerset --depth 2 clippy --all-targets
    echo "note: feature-powerset is known-RED accepted debt; its status does NOT gate 'just ci'."
