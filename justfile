set shell := ["bash", "-uc"]

runner := "target/debug/imp-test-runner"
runner-release := "target/release/imp-test-runner"

# (Re)grant the two caps the privileged suite needs. Re-run after every rebuild of the runner.
# Builds + blesses BOTH debug and release (matches README §5); `--features test-runner` is
# required or the required-features bin is skipped and setcap targets a stale binary.
bless:
    cargo build --bin imp-test-runner --features test-runner
    cargo build --release --bin imp-test-runner --features test-runner
    sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {{runner}}
    sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {{runner-release}}

# Fast inner loop: unit + codec + property tests. No KVM, no privileges.
test-unit:
    cargo nextest run --all-features

# Privileged integration suite via the capability runner (dev box only; group-restrict the runner
# on shared hosts). Wraps every test binary with imp-test-runner via the cargo target-runner hook.
# The in-guest test-helper (ip/curl/kvm-ok) is baked into the rootfs by `imp-testing build`, not
# built here.
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
    cargo clippy --all-targets --all-features -- -D warnings
    cargo hack --feature-powerset --depth 2 clippy --all-targets -- -D warnings
    cargo deny check
    # lean-agent invariant: the guest PID-1 build must omit the host stack (mirrors ci.yml).
    if cargo tree -e no-dev --no-default-features --features agent | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-agent invariant violated — host stack leaked into the agent build"; exit 1; fi
    ./scripts/ban-global-state.sh
    cargo nextest run --all-features
