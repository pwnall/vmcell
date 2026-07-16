set shell := ["bash", "-uc"]

# v15 §12.8: the blessed runner is installed to a STABLE path OUTSIDE target/, so cargo's
# RUSTFLAGS/feature re-fingerprint churn never rewrites it (and so never strips its caps).
runner := ".vmcell-bin/debug/vmcell-test-runner"
runner-release := ".vmcell-bin/release/vmcell-test-runner"

# §18.2: `vmcelld` is NOT blessed on the dev hot path. It gets its caps by being LAUNCHED THROUGH the
# blessed runner (`just daemon`, and integration tests), which raises the three caps into the ambient
# set and execs `vmcelld` — so the ever-changing daemon rebuilds with no `setcap` churn. Only the runner
# (which rarely changes) carries file-caps. A standalone/production `vmcelld` is capped by the service
# manager (systemd `AmbientCapabilities=`) or a one-off `setcap`, off this hot path.

# Grant the three caps the privileged suite needs, durably (v15 §12.8). Builds the runner, copies
# it to the stable, gitignored ./.vmcell-bin/ path, and setcaps THAT copy. Idempotent via a
# content-hash `.blessed` stamp keyed on the RUNNER binary only (never test binaries): a re-run is
# a transparent no-op (no sudo prompt) until the runner genuinely changes. Because cargo only ever
# rewrites target/, the stable copy keeps its caps across all the unrelated rebuild churn.
bless:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --locked -p vmcell-test-runner
    cargo build --locked --release -p vmcell-test-runner
    bless_one() {
      local built="$1" stable="$2"
      local dir; dir="$(dirname "$stable")"
      local stamp="$dir/.blessed"
      mkdir -p "$dir"
      # Key the stamp on the freshly-BUILT runner's content. If it matches the last bless and the
      # stable copy still exists, the stable copy is already blessed (cargo never touches it) — skip
      # both the copy (which would strip caps) and the sudo setcap.
      local h; h="$(sha256sum "$built" | cut -d' ' -f1)"
      # M-BIN-2: the stamp+existence check alone is a FALSE skip if the stable copy silently lost
      # its caps or mode out-of-band (rsync / backup-restore / fs-move strips file xattrs). Also
      # verify the stable copy STILL carries all three caps with the effective bit (+ep / =ep) AND
      # its 0700 owner-only mode; if any check fails, fall through and RE-bless rather than reporting
      # a no-op "already blessed" that leaves the runner effectively un-capped (review-preflight-priv
      # then reads that as skip==pass).
      local caps_now; caps_now="$(getcap "$stable" 2>/dev/null || true)"
      if [[ -f "$stamp" && -f "$stable" && "$(cat "$stamp")" == "$h" ]] \
         && [[ "$caps_now" == *cap_net_admin* && "$caps_now" == *cap_sys_admin* \
               && "$caps_now" == *cap_dac_override* && "$caps_now" == *ep* ]] \
         && [[ "$(stat -c %a "$stable" 2>/dev/null)" == "700" ]]; then
        echo "bless: $stable already blessed (runner sha256 unchanged, caps +ep, mode 0700); skipping setcap"
        return 0
      fi
      cp -f "$built" "$stable"
      # PRIV-1: restrict the capability-carrying runner to its OWNER (0700) BEFORE setcap.
      # The blessed runner holds cap_sys_admin (≈ root); its file mode is the REAL security
      # boundary, not just a note — an other-executable +ep runner is a local priv-esc on a
      # shared host, and the path-confinement is only defense-in-depth. On a shared dev box
      # where a team shares one runner, use `chmod 0750` + a dedicated group instead of 0700.
      chmod 0700 "$stable"
      sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep "$stable"
      echo "$h" > "$stamp"
      echo "bless: $stable (re)blessed (mode 0700, owner-only; caps +ep)"
    }
    bless_one target/debug/vmcell-test-runner {{runner}}
    bless_one target/release/vmcell-test-runner {{runner-release}}

# Run `vmcelld` for manual poking (§D), LAUNCHED THROUGH the blessed runner so it gets its caps
# without being blessed itself (§18.2) — so it rebuilds with no `setcap` churn. Requires `just bless`
# first (blesses the runner). Uses --allow-unauthenticated for a loopback dev bind ONLY; pass
# --api-key-file for anything real.
daemon artifacts_dir="/tmp/vmcell-artifacts" bind="127.0.0.1:8787":
    cargo build --locked -p vmcelld
    mkdir -p {{artifacts_dir}}
    {{justfile_directory()}}/{{runner}} {{justfile_directory()}}/target/debug/vmcelld \
        --artifacts-dir {{artifacts_dir}} --bind {{bind}} --allow-unauthenticated

# Fast inner loop: unit + codec + property tests. No KVM, no privileges.
test-unit:
    cargo nextest run --locked --all-features

# Privileged integration suite via the capability runner. `just bless` installs it 0700 (owner-only)
# — that mode is the security boundary (PRIV-1); on a shared host use a dedicated group + 0750.
# Wraps every test binary with vmcell-test-runner via the cargo target-runner hook.
# The in-guest test-helper (ip/curl/kvm-ok) is baked into the rootfs by `vmcell build`, not
# built here. `--features` is scoped to the `vmcell` member that owns the integration tests.
# The `kind(test)` predicate scopes to the integration-test BINARIES only (all in the
# `serial-host` nextest group), excluding the ~172 `kind(lib)` unit tests that `-p vmcell`
# would otherwise pull in. Those lib tests are NOT in serial-host, so under the old filter they
# ran at test-threads=num_cpus CONCURRENTLY with the single serial VM test, oversubscribing the
# host CPU and stretching a guest's boot+agent-handshake past the connect/exec deadline — the
# root cause of the intermittent "Agent … timed out" flake. They still run in `just test-unit` /
# `just ci`, so no coverage is lost by excluding them here.
test-privileged:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell --features firecracker,qemu --run-ignored all \
        -E 'kind(test) & !(test(unprivileged) | test(smoltcp))'

# §14: daemon integration tests. The TEST BINARY is wrapped by the blessed runner (nextest
# target-runner), so it holds the caps and can plant privileged pre-existing state (an orphan netns for
# the start-up-sweep test) and inspect per-VM teardown residue; it then spawns `vmcelld` DIRECTLY,
# which inherits the caps via the ambient set (the inverse of `just daemon`, which launches `vmcelld`
# *through* the runner for manual poking). Each test boots a real Cloud Hypervisor micro-VM and asserts
# the HTTP surface + data plane over `vmcell-daemon-client`. Runs under a systemd-delegated cgroup scope
# so the `limits_enforced` assertion sees real enforcement. Requires `just bless` (runner) + artifacts.
test-daemon:
    cargo build --locked -p vmcelld -p vmcelld-ctl
    systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh \
        env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcelld --run-ignored all

# Unprivileged integration suite under no elevation (keeps the unprivileged path honest).
test-unprivileged:
    # `--features qemu` (additive over the default set) builds QEMU's unprivileged
    # NAT leg too, so the M-TEST-8 `vmm_matrix_test!` exercises the smoltcp NAT on
    # both CH and QEMU rather than the CH leg alone.
    cargo nextest run --locked --profile integration -p vmcell --features qemu --run-ignored all -E 'kind(test) & (test(unprivileged) | test(smoltcp))'

# Everything the `lint` CI job runs, locally — a faithful mirror of .github/workflows/ci.yml.
# Shebang recipe so the whole job shares one shell: RUSTFLAGS=-D warnings is exported process-wide
# (matching CI's workflow-level env, which — unlike a clippy `-- -D warnings` arg — also denies
# warnings surfaced through path/patched deps). The feature-powerset step runs LAST and is now
# BLOCKING: the §10.5 host-stack collapse closed the former C-GATE-1 debt, so every ≤2-feature
# config compiles clean and a regression back to RED must fail the gate.
ci:
    #!/usr/bin/env bash
    set -uo pipefail
    export RUSTFLAGS="-D warnings"
    set -e
    cargo fmt --all --check
    # --locked policy: every RESOLVING cargo command below (build/clippy/nextest/run/tree/hack + the
    # doc gate) pins the lockfile, so a PR that bumps a dep but forgets to commit Cargo.lock fails here
    # instead of silently regenerating it — dep bumps then land only through reviewed dependabot PRs.
    # fmt/deny/machete/semver-checks don't accept --locked and don't mutate the lock; a resolving step
    # above them already catches any drift.
    cargo clippy --locked --workspace --all-targets --all-features
    cargo deny check
    # M-VEND-3: assert the carried vhost patch is actually applied. A caret version
    # bump would silently drop the `[patch.crates-io]` (only a "Patch was not used"
    # warning), regressing the QEMU-unprivileged SET_VRING_ENABLE quirk with a green
    # build. `cargo tree` prints a path dep with its path in parens, so require both
    # to resolve from vendor/.
    if ! cargo tree --locked -e normal --all-features 2>/dev/null | grep -qE 'vhost v0\.16\.0 \(.*vendor/vhost\)'; then echo "M-VEND-3: vhost 0.16.0 is not resolved from vendor/ — carried patch dropped (version bump?)"; exit 1; fi
    if ! cargo tree --locked -e normal --all-features 2>/dev/null | grep -qE 'vhost-user-backend v0\.22\.0 \(.*vendor/vhost-user-backend\)'; then echo "M-VEND-3: vhost-user-backend 0.22.0 is not resolved from vendor/ — carried patch dropped (version bump?)"; exit 1; fi
    # lean-agent invariant: the guest PID-1 member must omit the host stack AND compile standalone.
    # v15: the lean boundary is now a per-MEMBER structural property (§12.8 #4), so the check
    # targets the crate directly (`-p`) rather than a feature slice of the old single package.
    if cargo tree --locked -e no-dev -p vmcell-guest-agent | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-agent invariant violated — host stack leaked into the agent build"; exit 1; fi
    cargo clippy --locked -p vmcell-guest-agent --all-targets
    # lean-test-runner invariant: same host-stack ban + standalone compile for the privileged-window member.
    if cargo tree --locked -e no-dev -p vmcell-test-runner | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-test-runner invariant violated — host stack leaked into the test-runner build"; exit 1; fi
    cargo clippy --locked -p vmcell-test-runner --all-targets
    # lean-privilege invariant (§18.1): the shared blessing/capability crate is linked by BOTH the
    # runner and the daemon, so it must stay as lean as the runner — no host async stack.
    if cargo tree --locked -e no-dev -p vmcell-privilege | grep -E '── (tokio|hyper|rtnetlink) v'; then echo "lean-privilege invariant violated — host stack leaked into vmcell-privilege"; exit 1; fi
    cargo clippy --locked -p vmcell-privilege --all-targets
    # B9/design §12.4 (erratum-aware): the broker OWNS the engine — tokio + rtnetlink are LEGITIMATE
    # (it does the netns/tap/nft setup itself), so it is NOT governed by the full lean-tree ban above.
    # Its lean boundary is the network-facing WEB SERVER, which lives in `vmcell-daemon` (axum). Assert
    # the broker links NEITHER `vmcell-daemon` NOR `axum`, so the HTTP surface that parses network
    # input can never share the cap-holding process (§12.23 / P2). NOTE: `hyper` is deliberately NOT
    # asserted absent — it enters transitively and LEGITIMATELY through vmcell's egress proxy
    # (hudsucker) and HTTP clients (reqwest/oci-client), which the broker's net subset needs. The
    # meaningful marker of the *server* stack is axum + the vmcell-daemon crate. (Corrects the
    # v3/AGENTS.md "axum/hyper" phrasing to the built tree — see implementation-notes.md.)
    if cargo tree --locked -p vmcell-broker -e no-dev -i vmcell-daemon 2>/dev/null | grep -q .; then echo "vmcell-broker must not link vmcell-daemon (the web/server crate must not share the cap-holder)"; exit 1; fi
    if cargo tree --locked -p vmcell-broker -e no-dev -i axum 2>/dev/null | grep -q .; then echo "vmcell-broker must not link axum (network-input server stack must not share the cap-holder)"; exit 1; fi
    # guest-tools: build+clippy only (reqwest legitimately pulls hyper/tokio — see impl-notes, no lean-tree assertion).
    cargo clippy --locked -p vmcell-guest-tools --all-targets
    # Reduced-host-feature smoke (fast per-backend feedback before the full powerset below). After the
    # §10.5 host-stack collapse, each shipping backend in isolation pulls the full, coherent host stack
    # (host-common → net/proxy/metrics/pipeline), so a single-backend build compiles — including `qemu`,
    # which previously did not (the shared hyper HTTP-over-Unix client + serde_json are now host-common
    # deps). `metrics` is part of that stack, so CFG-1's "host without metrics" config is no longer
    # constructible — the CFG-1 class is closed by construction (its code fix remains as defense-in-depth).
    for feat in cloud-hypervisor firecracker qemu; do \
      echo "== reduced-host-feature clippy: --no-default-features --features $feat =="; \
      cargo clippy --locked -p vmcell --no-default-features --features "$feat" --all-targets; \
    done
    # The Firecracker and QEMU backends now live in their own crates (they depend on `vmcell`;
    # `vmcell` keeps only Cloud Hypervisor). Clippy each standalone so a backend crate that stops
    # compiling against `vmcell`'s shared surface fails here, not only inside the workspace build.
    # `vmcell-bench` is the composition root that wires all three backends (the `bench-vm` binary).
    cargo clippy --locked -p vmcell-firecracker -p vmcell-qemu -p vmcell-bench --all-targets
    # rustdoc gate (docs/51): RUSTDOCFLAGS=-D warnings turns EVERY rustdoc lint into a hard error —
    # broken/private intra-doc links, unresolved links — for the whole public surface. clippy does
    # NOT run rustdoc lints, and `cargo doc` runs nowhere else, so without this a broken doc link is
    # invisible until someone reads the HTML. `--all-features` documents the widest API; `--no-deps`
    # keeps it to our crates. (Benign cargo warning: the `vmcell` lib and the `vmcell` CLI bin share a
    # doc output path — cosmetic, not a rustdoc lint, so it does not fail the -D-warnings gate.)
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
    ./scripts/ban-global-state.sh
    ./scripts/test-ban-global-state.sh
    ./scripts/ban-legacy-terms.sh
    ./scripts/test-ban-legacy-terms.sh
    # AGENT-4/TEST-5: positive zero-`ip`-shellout gate for the guest agent + its red-on-inverse self-test.
    ./scripts/ban-agent-ip-shellout.sh
    ./scripts/test-ban-agent-ip-shellout.sh
    # P3/B12: the ONLY function that turns a client-supplied artifact name into a path is
    # resolve_artifact_path (crates/vmcell-daemon/src/name.rs). A daemon handler that builds
    # `<artifacts_dir>.join(<client name>)` itself is a traversal hole — grep-ban it in the daemon
    # crate; the self-test proves the ban fires on the bug and passes on the sanctioned validator.
    ./scripts/ban-artifact-path-join.sh
    ./scripts/test-ban-artifact-path-join.sh
    # The privileged-review preflight's three-way verdict (bless-only sentinel) — self-test only.
    # The real preflight probes a KVM host and runs at review time (not here), but its classifier —
    # bless-remediable (exit 2, BLOCKED-ON-BLESS) vs environmental (exit 1, NOT READY) — is
    # host-independent and must go red if it ever misroutes a bless-fixable failure to static-only.
    ./scripts/test-review-preflight-priv.sh
    # ---- Toolchain honesty + non-Rust-surface gates (rubric Part D) ----
    # Toolchain honesty: the declared MSRV (`[workspace.package] rust-version`) equals the pinned
    # `rust-toolchain.toml` channel (the latest stable). An UNDERSTATED rust-version lets MSRV-aware
    # resolvers hand consumers older, potentially-vulnerable dependency versions instead of the
    # advisory-clean ones the lockfile pins; kept in lockstep with clippy.toml's msrv by review.
    rv=$(sed -nE 's/^rust-version *= *"([0-9.]+)".*/\1/p' Cargo.toml | head -n1)
    ch=$(sed -nE 's/^channel *= *"([0-9.]+)".*/\1/p' rust-toolchain.toml | head -n1)
    [ -n "$rv" ] && [ "$rv" = "$ch" ] || { echo "MSRV drift: [workspace.package] rust-version=$rv vs rust-toolchain channel=$ch" >&2; exit 1; }
    # The ban scripts, preflight, bless path, and delegated-scope helper are load-bearing,
    # security-adjacent bash — lint them all.
    shellcheck scripts/*.sh
    # Workflow files: correctness (actionlint also shellchecks `run:` blocks) + security (zizmor:
    # script injection, over-broad permissions, unpinned actions — the suites run on a SELF-HOSTED
    # KVM runner, where a compromised action is lateral movement onto the host).
    actionlint
    zizmor .github/workflows/
    # Unused dependencies enlarge the audited, licensed, advisory-scanned surface. Macro-only false
    # positives get a per-crate [package.metadata.cargo-machete] ignored entry.
    cargo machete
    # Docs are a first-class artifact in this repo.
    typos
    cargo nextest run --locked --all-features
    # public-API semver intent (CI runs this PRs-only against the PR base; locally diff vs the main
    # merge-base). Runs on the pinned toolchain — 1.96.1 satisfies cargo-semver-checks' rustc floor.
    baseline="$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse main 2>/dev/null || true)"
    if [ -n "$baseline" ]; then cargo semver-checks --baseline-rev "$baseline" -p vmcell; else echo "semver-checks: no main baseline available locally, skipping (CI enforces it on PRs)"; fi
    # Feature-powerset LAST and BLOCKING (former C-GATE-1 debt, closed by the §10.5 host-stack collapse):
    # every ≤2-feature config must compile+clippy clean under -D warnings. This is the comprehensive
    # guard that the collapse holds; a newly mis-gated module regresses it back to RED and fails here.
    echo "== feature-powerset (BLOCKING; must be GREEN after the §10.5 collapse) =="
    cargo hack --locked --feature-powerset --depth 2 clippy -p vmcell --all-targets
