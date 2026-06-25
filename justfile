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
