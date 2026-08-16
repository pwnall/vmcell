set shell := ["bash", "-uc"]

# v15 §12.8: the blessed runner is installed to a STABLE path OUTSIDE target/, so cargo's
# RUSTFLAGS/feature re-fingerprint churn never rewrites it (and so never strips its caps).
runner := ".vmcell-bin/debug/vmcell-test-runner"
runner-release := ".vmcell-bin/release/vmcell-test-runner"

# H-TEST-3: `require_cap!` records every capability-driven skip as `SKIP <vmm> <capability>` to
# $VMCELL_SKIP_MANIFEST. Without a set path it defaults to a per-PID temp file nobody ever reads —
# i.e. the "skip manifest is reviewed" rule was unenforced, gate theater by our own meta-rules. The
# suite recipes below export this run-scoped path and `skip-manifest-show` surfaces it (the CI kvm
# job calls both, so local ≡ CI). An externally-set VMCELL_SKIP_MANIFEST always wins.
skip-manifest := justfile_directory() + "/target/vmcell-skip-manifest.txt"

# §18.2: `vmcelld` is NOT blessed on the dev hot path. It gets its caps by being LAUNCHED THROUGH the
# blessed runner (`just daemon`, and integration tests), which raises the three caps into the ambient
# set and execs `vmcelld` — so the ever-changing daemon rebuilds with no `setcap` churn. Only the runner
# (which rarely changes) carries file-caps. A standalone/production `vmcelld` is capped by the service
# manager (systemd `AmbientCapabilities=`) or a one-off `setcap`, off this hot path.

# Grant the privileged suite's capabilities, durably (v15 §12.8). The FILE set is four:
# `vmcell_privilege::PRIVILEGED_CAPS` (net_admin/sys_admin/dac_override — delivered to the test over
# the ambient set) plus the TRANSIENT `cap_setpcap`, which exists only so the runner can actually
# perform `PR_CAPBSET_DROP`; the transition drops it back out of both the bounding set and
# permitted/effective before `exec`, so no test or VMM ever holds it. Builds the runner, copies
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
      # verify the stable copy STILL carries every blessed cap with the effective bit (+ep / =ep) AND
      # its 0700 owner-only mode; if any check fails, fall through and RE-bless rather than reporting
      # a no-op "already blessed" that leaves the runner effectively un-capped (review-preflight-priv
      # then reads that as skip==pass).
      # ONE LAW, ONE PREDICATE: "is this copy still blessed?" is asked here and by
      # scripts/review-preflight-priv.sh's `check_runner`, and the two copies had already diverged
      # on strictness (this one matched a bare `ep` SUBSTRING, which the getcap line's file PATH can
      # satisfy — …/deps/…, a username containing `ep` — so a `+p`-only runner read as "already
      # blessed"; L-BIN-2 hardened the preflight first). The recipe now CALLS the preflight's probe
      # (`--check-runner <path>`, exit 0 = blessed) rather than restating it, so the two can never
      # drift again. The 0700 mode check stays here: it is this recipe's own PRIV-1 obligation, not
      # a readiness question.
      if [[ -f "$stamp" && -f "$stable" && "$(cat "$stamp")" == "$h" ]] \
         && ./scripts/review-preflight-priv.sh --check-runner "$stable" >/dev/null 2>&1 \
         && [[ "$(stat -c %a "$stable" 2>/dev/null)" == "700" ]]; then
        echo "bless: $stable already blessed (runner sha256 unchanged, caps +ep, mode 0700); skipping setcap"
        return 0
      fi
      # STAGE-THEN-SWAP: bless a TEMP copy beside the target and only then rename it into place.
      # The obvious order (cp over the live path, then sudo setcap) DESTROYS a working blessing
      # whenever the setcap does not happen — a declined or unavailable sudo (`sudo: a terminal is
      # required to authenticate` in a non-interactive shell) leaves the stable path holding a
      # freshly-copied, cap-less binary, so the preflight flips from READY to BLOCKED-ON-BLESS and
      # the privileged suites stop running. Measured, not hypothetical. `mv` within the directory
      # is a rename, so the file capabilities set below survive it. The setcap failure is handled
      # EXPLICITLY rather than by a RETURN trap: under `set -e` a bare failing command exits the
      # whole shell, so the trap would never fire and the temp would be left behind.
      local tmp="$stable.blessing.$$"
      cp -f "$built" "$tmp"
      # PRIV-1: restrict the capability-carrying runner to its OWNER (0700) BEFORE setcap.
      # The blessed runner holds cap_sys_admin (≈ root); its file mode is the REAL security
      # boundary, not just a note — an other-executable +ep runner is a local priv-esc on a
      # shared host, and the path-confinement is only defense-in-depth. On a shared dev box
      # where a team shares one runner, use `chmod 0750` + a dedicated group instead of 0700.
      chmod 0700 "$tmp"
      if ! sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override,cap_setpcap+ep "$tmp"; then
        rm -f "$tmp"
        echo "bless: setcap failed for $stable — the previous blessing is UNCHANGED (nothing was replaced)" >&2
        return 1
      fi
      mv -f "$tmp" "$stable"
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

# The unit suite under the HOSTED-RUNNER condition: a cgroup tree this process cannot write to.
#
# A developer box runs the tests inside a systemd *user* scope, which IS delegated, so
# `HostEnv::hermetic()`'s real `DefaultCgroupFs` happily creates `/sys/fs/cgroup/<base>/vmcell-vm-N`
# and every test passes. A GitHub hosted runner sits under `system.slice/hosted-compute-agent.service`,
# which is not delegated, and 21 KVM-free tests failed there with
# `Cgroup("create cgroup …: Permission denied (os error 13)")` while `just test-unit` stayed green —
# for weeks. This recipe is the local mirror of that condition, so the delegation gate can be
# exercised without pushing.
#
# `bwrap` binds a root-owned, unwritable directory over /sys/fs/cgroup while leaving
# /proc/self/cgroup reporting the real base — the runner's exact shape (real base, EACCES on mkdir),
# not a mocked one. `unshare -Urm` cannot be used here: kernel.apparmor_restrict_unprivileged_userns
# blocks it, while bwrap ships an AppArmor profile.
#
# THE ONE EXCLUSION (measured: drops exactly 1 of 782 tests). bwrap sets PR_SET_NO_NEW_PRIVS on the
# whole tree, which defeats `jail_hardening`'s own red-on-inverse control — the test asserts that a
# DISABLED jail leaves NoNewPrivs=0, and under bwrap it is already 1. That is an artifact of the
# harness, not a failure of the product: the test passes unwrapped and on CI. It is excluded by exact
# name rather than by binary so the other three tests in that file still run.
test-unit-undelegated:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v bwrap >/dev/null || { echo "bwrap (bubblewrap) is required for this recipe" >&2; exit 1; }
    bwrap --dev-bind / / --bind /srv /sys/fs/cgroup --chdir {{justfile_directory()}} -- \
        cargo nextest run --locked --all-features \
            -E 'not test(=apply_jail_sets_no_new_privs_and_the_core_rlimit)'

# Privileged integration suite via the capability runner. `just bless` installs it 0700 (owner-only)
# — that mode is the security boundary (PRIV-1); on a shared host use a dedicated group + 0750.
# Wraps every test binary with vmcell-test-runner via the cargo target-runner hook.
# The in-guest test-helper (the four applets ip/curl/kvm-ok/echo-server, one multicall binary) is
# baked into the rootfs by `vmcell build`, not built here — so a suite whose guest side needs a NEW
# applet (the raw dial's and the segment gates' `echo-server`) must re-run that build first; a warm
# rootfs fails it with a missing /vmcell-tools path. `--features` is scoped to the `vmcell` member that owns the integration tests.
# The `kind(test)` predicate scopes to the integration-test BINARIES only (all in the
# `serial-host` nextest group), excluding the ~172 `kind(lib)` unit tests that `-p vmcell`
# would otherwise pull in. Those lib tests are NOT in serial-host, so under the old filter they
# ran at test-threads=num_cpus CONCURRENTLY with the single serial VM test, oversubscribing the
# host CPU and stretching a guest's boot+steward-handshake past the connect/exec deadline — the
# root cause of the intermittent "Steward … timed out" flake. They still run in `just test-unit` /
# `just ci`, so no coverage is lost by excluding them here.
test-privileged:
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
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
        env VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcelld --run-ignored all

# Unprivileged integration suite under no elevation (keeps the unprivileged path honest).
test-unprivileged:
    # `--features qemu` (additive over the default set) builds QEMU's unprivileged
    # NAT leg too, so the M-TEST-8 `vmm_matrix_test!` exercises the smoltcp NAT on
    # both CH and QEMU rather than the CH leg alone.
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
        cargo nextest run --locked --profile integration -p vmcell --features qemu --run-ignored all -E 'kind(test) & (test(unprivileged) | test(smoltcp))'

# The artifact-conformance battery's LIVE smoke suite (`vmcell-artifact-validator`, the §10.4
# downstream contract surface): the known-good pair must pass `Level::Full` with zero failures, and
# a garbage kernel must FAIL with a §5.4-clause message. Both tests are `#[ignore]`d (they boot real
# Cloud Hypervisor VMs), and until this recipe existed NO invocation in the tree selected them —
# every `--run-ignored all` was scoped to another package — so the only proof that the battery can
# go red was compiled and skipped. `--no-tests=fail` makes a filter that selects zero tests an
# error, which is the failure mode that hid this one.
#
# Needs KVM and the built artifacts (the getters run the at-most-once rootfs build; the kernel is
# built out-of-band by `vmcell build --kernel-source host-make`). Runs through the blessed runner
# like the other live suites, so the Extended/Full capability-gated checks (tap networking,
# virtio-fs, cgroup limits) actually RUN instead of recording skips — the validator's own report
# lists any that still skip, and `validate` refuses outright without /dev/kvm rather than emitting a
# green all-skipped report. Wrap it in a delegated scope for the cgroup leg, exactly like the other
# live suites: `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-validator`.
#
# Live artifact-conformance battery: the known-good pair must pass Level::Full, a garbage kernel must fail.
test-validator:
    # H-TEST-3, like every sibling suite recipe: the validator records its skips in the report the
    # tests print, but the export keeps a `require_cap!` skip from any vmcell-side helper out of the
    # per-PID temp file nobody reads.
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell-artifact-validator --run-ignored all \
        --no-tests=fail -E 'binary(smoke)'

# Opt-in crosvm live matrix. crosvm is a secondary backend whose binary is NOT installed on the
# build/CI hosts, so it is deliberately kept OUT of `test-privileged` (adding it there would hard-fail
# every KVM host lacking a `crosvm` binary). Its KVM-FREE gates (unit tests, capability-honesty pins,
# seccomp golden, clippy) run in `just ci`/`just test-unit` already. This recipe is where the crosvm
# RUNTIME claims are validated — and they HAVE been, live on a KVM host with a `crosvm` binary
# present (2026-08-12: 28/28, including snapshot/restore, the raw dial's two legs — the echo round
# trip and the half-close-forwards leg the in-kernel AF_VSOCK arm passes — and the five §6.5 segment
# legs delta 8 added, which is crosvm's first segment validation; run it under
# `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh`, since
# `metrics_limits::crosvm` asserts REAL cgroup enforcement and fails without a delegated scope);
# it stays opt-in because CI has no `crosvm` binary, not
# because the claims are unverified. Re-run it ($VMCELL_CROSVM_BIN or `crosvm` on PATH, on a KVM
# host) whenever the backend changes. `--no-tests=fail` catches a mis-scoped filter that selects nothing.
test-crosvm:
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell --features crosvm --run-ignored all \
        --no-tests=fail -E 'kind(test) & test(crosvm) & !(test(unprivileged) | test(smoltcp))'

# v30 delta 9 (FR-V5): host-USB passthrough live validation — QEMU only, opt-in.
# Needs KVM, a blessed runner, and a designated test device: VMCELL_TEST_USB_DEVICE=<vid>:<pid>.
# The guest kernel is the `usbhost` label built through the §5.6 toolkit (a vmcell-owned GENERIC
# xhci/USB-core fragment — never the consumer usbip/gadget closure; design §2.4 defends this).
# Build it first with
#   cargo run -p vmcell-cli -- build-kernels          # builds every `kernels` label
# and point VMCELL_KERNEL at the resulting `<artifacts>/vmlinux-usbhost`. (The fragment PINS the
# xhci/USB-core symbols; it does not conjure them — measured 2026-08-12, `make olddefconfig`
# inherits CONFIG_USB_XHCI_PCI=y from the x86_64 defconfig, so the fragment-less labels carry it
# too. Pinning is the point: an upstream defconfig change must not silently drop USB.) `usbhost` and its
# `kernel_fragments.USBHOST` text live in the committed pins.json (gated by
# `usbhost_kernel_label_and_fragment_are_pinned`). `test-privileged` also compiles and selects
# this test (its filter excludes only unprivileged/smoltcp), so with no designated device it records a
# capability skip to $VMCELL_SKIP_MANIFEST instead of hard-failing every KVM host — this recipe is
# the only place it actually exercises a device.
#
# HOST DRIVER, measured 2026-08-14: QEMU's `usb-host` detaches the device's kernel driver to claim
# it and does NOT re-bind on the paths vmcell uses (teardown ends in a process-group SIGKILL, and a
# killed QEMU never runs libusb's re-attach), so passing the laptop camera used to leave
# `Driver=[none]` on both interfaces with no `/dev/video*`. vmcell now restores it: the
# interface->driver map is captured before the spawn and re-bound by the ONE teardown helper both
# `kill()` and `Drop` call, asserted end to end by this test. The device should still be one you can
# afford to lose for the duration of a run — it belongs to the guest while the VM is up, and a
# restore that fails is warned, not fatal.
test-usb-passthrough:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${VMCELL_TEST_USB_DEVICE:?set VMCELL_TEST_USB_DEVICE=<vid>:<pid> (a designated, disposable test device)}"
    # H-TEST-3, like every sibling suite recipe: without the run-scoped export the test's capability
    # skips (a missing `usbip`/device-class prerequisite the test records rather than hard-fails)
    # land in the per-PID temp file nobody reads, i.e. a skip nobody can review.
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell --features qemu --run-ignored all \
        --no-tests=fail -E 'kind(test) & test(usb_passthrough)'

# Reset the run-scoped capability-skip manifest. Run BEFORE a suite sequence (the CI kvm job does)
# so the surfaced skips belong to this run and not to an accumulated history.
skip-manifest-reset:
    mkdir -p "$(dirname "${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}")"
    : > "${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}"

# Surface the capability-skip manifest (count + contents). A skip is only auditable if someone reads
# it: this is the "skip manifest reviewed" rubric row's enforcement point, called as the CI kvm job's
# final step. Never fails the build — a skip is a recorded fact to review, not a gate.
skip-manifest-show:
    #!/usr/bin/env bash
    set -uo pipefail
    manifest="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}"
    if [ ! -f "$manifest" ]; then
      echo "skip manifest: $manifest does not exist — no suite ran, or none recorded a skip"
      exit 0
    fi
    n=$(grep -c '^SKIP ' "$manifest" || true)
    echo "skip manifest: $n capability skip(s) recorded in $manifest"
    if [ "$n" -gt 0 ]; then sort "$manifest" | uniq -c | sort -rn; fi

# THE ONE ROSTER of repo gates: every ban/check script, every red-on-inverse self-test, and the
# shellcheck pass over the load-bearing bash. `just ci` calls this recipe and
# .github/workflows/ci.yml invokes it as `run: just gates` — so a script added HERE is covered in CI
# BY CONSTRUCTION, because there is no second list to add it to.
#
# WHY IT IS A RECIPE AND NOT A CI STEP (AGENTS rule 3: "A CI step that hand-copies a `just` recipe
# drifts from it — invoke the recipe so local ≡ CI by construction"). ci.yml hand-copied this list
# and the copy drifted THREE times, twice in a single wave: `ban-readiness-timeout-literal.sh` and
# `ban-test-support-in-production.sh` both landed in the justfile and never reached ci.yml. Each
# omission was worse than a lost duplicate. The readiness ban is the backstop for the ONE route the
# structural fix leaves open (a bare literal handed to `wait_for_socket`), and the test-support ban's
# entire rationale is that cargo's feature unification makes the fixtures visible to lib targets
# under `--all-targets` — which is what CI runs and a plain `cargo build` does not. Running only
# locally was precisely the wrong half of each.
#
# The first entry below is the gate for that class: it fails if ci.yml ever names a `scripts/*.sh`
# directly again, and it asserts this roster is EXACTLY the set of gate-shaped scripts on disk (both
# directions — an orphan script and a stale entry). It runs first because it is pure text and a
# broken roster invalidates every verdict after it.
gates:
    #!/usr/bin/env bash
    set -euo pipefail
    # The meta-gate, first: one roster, no hand-copy, no orphan. See its header for the three
    # drift instances that motivated it.
    ./scripts/ban-ci-script-handcopy.sh
    ./scripts/test-ban-ci-script-handcopy.sh
    # `AGENTS.md` is the DEPLOYED copy of `docs/*claude-agents*.md` — two paths, one document. The
    # docs/81 campaign rewrote AGENTS.md in seven hunks and the source document in one, leaving every
    # corrected count still wrong in the file AGENTS.md is deployed from — inside the very wave whose
    # mandate was "rosters quoted in docs are checked against the tree, never from memory". The two
    # were byte-identical before the campaign, so the invariant existed; it was merely unwritten, and
    # an unwritten invariant is not a gate.
    ./scripts/check-agents-md-sync.sh
    ./scripts/test-check-agents-md-sync.sh
    # M-VEND-3: assert the carried vhost patch is actually applied. A caret version
    # bump would silently drop the `[patch.crates-io]` (only a "Patch was not used"
    # warning), regressing the QEMU-unprivileged SET_VRING_ENABLE quirk with a green
    # build. ONE predicate, here and downstream (v30 delta 2): this call REPLACES the two
    # inline cargo-tree greps that used to live here — they had already diverged from the
    # downstream copy on pattern strictness, the duplication-hides-divergence trap. The
    # script is path-independent so a git-dep consumer runs the SAME check in its own
    # workspace (design §10.4).
    ./scripts/check-vendored-vhost.sh
    ./scripts/test-check-vendored-vhost.sh
    # lean-member invariants (§12.8 #4 / §18.1): the guest PID-1 steward, the privileged-window
    # test-runner, and the `vmcell-privilege` crate BOTH the runner and the daemon link must omit
    # the host async stack. (Each must also COMPILE standalone; those three `cargo clippy -p …`
    # calls stay in `ci`/ci.yml beside the other compile gates — this roster is scripts only.)
    # The three inline `cargo tree | grep` copies that used to live here (and their three twins in
    # ci.yml) are gone: they were the duplication-hides-divergence trap AND they were DEAD in CI,
    # because `CARGO_TERM_COLOR: always` makes cargo emit `\e[2m├──\e[0m tokio v…` and the
    # `── tokio v` pattern then matches nothing. One predicate now, with `--color never` inside it,
    # plus its red-on-inverse self-test — which runs the predicate under the CI colour condition,
    # the leg whose absence let the bans die.
    # `--all` and not a crate list: the script's LEAN_MATRIX is the law, and re-typing three of its
    # four rows here was a second roster of exactly the kind this recipe exists to abolish — it had
    # already gone stale on `vmcell-daemon-client`, which the script checked anyway while printing
    # "replace the crate list with --all so the matrix cannot go stale again".
    ./scripts/check-lean-tree.sh --all
    ./scripts/test-check-lean-tree.sh
    # B9/design §12.4 (erratum-aware): the broker OWNS the engine — tokio + rtnetlink are LEGITIMATE
    # (it does the netns/tap/nft setup itself), so it is NOT governed by the full lean-tree ban above.
    # Its lean boundary is the network-facing WEB SERVER, which lives in `vmcell-daemon` (axum). Assert
    # the broker links NEITHER `vmcell-daemon` NOR `axum`, so the HTTP surface that parses network
    # input can never share the cap-holding process (§12.23 / P2). NOTE: `hyper` is deliberately NOT
    # asserted absent — it enters transitively and LEGITIMATELY through vmcell's egress proxy
    # (hudsucker) and HTTP clients (reqwest/oci-client), which the broker's net subset needs. The
    # meaningful marker of the *server* stack is axum + the vmcell-daemon crate. (Corrects the
    # v3/AGENTS.md "axum/hyper" phrasing to the built tree — see implementation-notes.md.)
    # One predicate + its self-test, for the same reason as the lean-member ban above and one more:
    # the two inline `2>/dev/null | grep -q .` copies could not fail. `cargo tree -i <absent pkg>`
    # exits 101 with its message on STDERR, so a rename, an ambiguous spec, or a stale lockfile read
    # as "absent" exactly like the real thing — a negative security gate with no positive control.
    ./scripts/check-broker-lean.sh
    ./scripts/test-check-broker-lean.sh
    ./scripts/ban-global-state.sh
    ./scripts/test-ban-global-state.sh
    ./scripts/ban-legacy-terms.sh
    ./scripts/test-ban-legacy-terms.sh
    # AGENT-4/TEST-5: positive zero-`ip`-shellout gate for the steward + its red-on-inverse self-test.
    ./scripts/ban-agent-ip-shellout.sh
    ./scripts/test-ban-agent-ip-shellout.sh
    # P3/B12: the ONLY function that turns a client-supplied artifact name into a path is
    # resolve_artifact_path (crates/vmcell-daemon/src/name.rs). A daemon handler that builds
    # `<artifacts_dir>.join(<client name>)` itself is a traversal hole — grep-ban it in the daemon
    # crate; the self-test proves the ban fires on the bug and passes on the sanctioned validator.
    ./scripts/ban-artifact-path-join.sh
    ./scripts/test-ban-artifact-path-join.sh
    # S2 / delta 8 ("one law, one predicate"): `net_sys::setns_net` is the one home for `setns(2)`,
    # the `build_vmm_cmd` pre_exec site its one exemption (its safety proof is site-specific). The
    # review found two inline duplicates; nothing but review stopped a third, so grep-ban it. The
    # self-test proves all three halves red: the call pattern, the one-call cap inside an exempt
    # file, and the stale-exemption check.
    ./scripts/ban-inline-setns.sh
    ./scripts/test-ban-inline-setns.sh
    # docs/81 §8/§9 ("one law, one predicate"): the kernel ARTIFACT-KEY (`kernel-<label>`) and
    # PIN-KEY (`kernel_<label>_<sub>`) laws were triplicated and unexported — a private method in
    # `artifact::kernel`, a byte-duplicate in `vmcell-kernel-builder`, and the pin key composed
    # inline in the pins flattener. Both are now `pub fn kernel_artifact_key` / `kernel_pin_key`
    # with every site routed through them. Neither drift is a compile error (a lost artifact-map
    # entry, or a runtime `Missing kernel_… pin`), so grep-ban a second composed spelling. The
    # self-test proves all four halves red: each arm's pattern, the exact-count check inside the
    # sanctioned home (extra AND missing composer), and the stale-home check.
    ./scripts/ban-kernel-key-composers.sh
    ./scripts/test-ban-kernel-key-composers.sh
    # docs/81 §8 ("one law, one predicate"): the 1 s VMM-control-socket readiness ceiling was six
    # inline `1000`s across CH/FC/QEMU/crosvm. The fix is structural — `register_and_await_ready`
    # and `wait_for_vmm_socket` take NO timeout argument, so a literal there is a compile error —
    # and this bans the one route left open, a bare number handed to the lower-level
    # `wait_for_socket` (which keeps its parameter for virtiofsd's profile-paced wait). The
    # self-test proves all three halves red: each arm's pattern, the wrapped-call join, and the
    # vacuity check that a tree with no readiness call is a misconfiguration rather than an "ok".
    ./scripts/ban-readiness-timeout-literal.sh
    ./scripts/test-ban-readiness-timeout-literal.sh
    # docs/81 §9: `vmcell`'s `test-support` feature exposes `metrics::FakeCgroupFs` and
    # `vmm::VmmProcessGroup::already_reaped_for_test` so the backends stop hand-rolling copies. Each
    # backend takes it as a DEV-dependency, so `cargo build -p <backend>` cannot see them — but
    # cargo's feature unification DOES make them visible to lib targets under `--all-targets`, which
    # is what CI runs. Ban a production reference outright; the self-test proves five halves red:
    # the production hit, the comment/`#[cfg(test)]`/`tests/` exclusions, a moved definition site, a
    # definition whose feature gate was dropped, and a banned symbol nobody uses (a stale roster).
    ./scripts/ban-test-support-in-production.sh
    ./scripts/test-ban-test-support-in-production.sh
    # AGENTS rule 1, the CARGO_TERM_COLOR class: CI exports `CARGO_TERM_COLOR: always` at WORKFLOW
    # level, so `cargo tree` dims its glyphs and every pattern anchored on the glyph/name boundary
    # silently stops matching. Two shipped instances — three lean-member bans passing while proving
    # nothing, and the downstream example's absent-tree fixture filtering nothing (a red job with a
    # misleading message). `just ci` does not export the variable, so local ≢ CI and neither showed
    # up here. Ban parsing colourisable cargo output outright; the self-test pins both directions.
    ./scripts/ban-uncolored-cargo-parse.sh
    ./scripts/test-ban-uncolored-cargo-parse.sh
    # The privileged-review preflight's three-way verdict (bless-only sentinel) — self-test only.
    # The real preflight probes a KVM host and runs at review time (not here), but its classifier —
    # bless-remediable (exit 2, BLOCKED-ON-BLESS) vs environmental (exit 1, NOT READY) — is
    # host-independent and must go red if it ever misroutes a bless-fixable failure to static-only.
    ./scripts/test-review-preflight-priv.sh
    # The ban scripts, preflight, bless path, and delegated-scope helper are load-bearing,
    # security-adjacent bash — lint them all.
    # ...including the downstream example's contract check (v30 delta 5): it must live beside the
    # workspace it checks, so the lint glob comes to it rather than the script moving to scripts/.
    # `scripts/git-pre-commit` is listed EXPLICITLY: a git hook carries no `.sh` extension, so the
    # glob silently skipped the one hook that runs on every commit. This is a GLOB, not a roster, so
    # it cannot go stale on a new script — which is why it belongs here rather than in ci.yml.
    shellcheck scripts/*.sh scripts/git-pre-commit examples/downstream-kernel/*.sh

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
    # THE ONE GATE ROSTER, invoked — never copied. Every ban/check script, every red-on-inverse
    # self-test, and the shellcheck pass live in the `gates` recipe above; .github/workflows/ci.yml
    # runs that SAME recipe (`run: just gates`). The list used to be duplicated into ci.yml and the
    # copy drifted three times, most recently dropping two whole bans (see `gates`'s header). A
    # recursive `just` is what makes the roster have exactly one home.
    {{just_executable()}} gates
    # lean-member invariants (§12.8 #4 / §18.1), compile half: the tree-SHAPE assertion is
    # `check-lean-tree.sh` inside `gates`; graph inspection is not enough, so each of the three
    # members is also clippied standalone here — a broken build (e.g. an un-gated host dep) must be
    # caught in this job, not on a KVM host.
    cargo clippy --locked -p vmcell-steward --all-targets
    cargo clippy --locked -p vmcell-test-runner --all-targets
    cargo clippy --locked -p vmcell-privilege --all-targets
    # guest-tools: build+clippy only (reqwest legitimately pulls hyper/tokio — see impl-notes, no lean-tree assertion).
    cargo clippy --locked -p vmcell-guest-tools --all-targets
    # Reduced-host-feature smoke (fast per-backend feedback before the full powerset below). After the
    # §10.5 host-stack collapse, each shipping backend in isolation pulls the full, coherent host stack
    # (host-common → net/proxy/metrics/pipeline), so a single-backend build compiles — including `qemu`,
    # which previously did not (the shared hyper HTTP-over-Unix client + serde_json are now host-common
    # deps). `metrics` is part of that stack, so CFG-1's "host without metrics" config is no longer
    # constructible — the CFG-1 class is closed by construction (its code fix remains as defense-in-depth).
    for feat in cloud-hypervisor firecracker qemu crosvm; do \
      echo "== reduced-host-feature clippy: --no-default-features --features $feat =="; \
      cargo clippy --locked -p vmcell --no-default-features --features "$feat" --all-targets; \
    done
    # The Firecracker and QEMU backends now live in their own crates (they depend on `vmcell`;
    # `vmcell` keeps only Cloud Hypervisor). Clippy each standalone so a backend crate that stops
    # compiling against `vmcell`'s shared surface fails here, not only inside the workspace build.
    # `vmcell-bench` is the composition root that wires all backends (the `bench-vm` binary).
    cargo clippy --locked -p vmcell-firecracker -p vmcell-qemu -p vmcell-crosvm -p vmcell-bench --all-targets
    # rustdoc gate (docs/51): RUSTDOCFLAGS=-D warnings turns EVERY rustdoc lint into a hard error —
    # broken/private intra-doc links, unresolved links — for the whole public surface. clippy does
    # NOT run rustdoc lints, and `cargo doc` runs nowhere else, so without this a broken doc link is
    # invisible until someone reads the HTML. `--all-features` documents the widest API; `--no-deps`
    # keeps it to our crates. (Benign cargo warning: the `vmcell` lib and the `vmcell` CLI bin share a
    # doc output path — cosmetic, not a rustdoc lint, so it does not fail the -D-warnings gate.)
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
    # ---- Toolchain honesty + non-Rust-surface gates (rubric Part D) ----
    # Toolchain honesty: the declared MSRV (`[workspace.package] rust-version`) equals the pinned
    # `rust-toolchain.toml` channel (the latest stable). An UNDERSTATED rust-version lets MSRV-aware
    # resolvers hand consumers older, potentially-vulnerable dependency versions instead of the
    # advisory-clean ones the lockfile pins; kept in lockstep with clippy.toml's msrv by review.
    rv=$(sed -nE 's/^rust-version *= *"([0-9.]+)".*/\1/p' Cargo.toml | head -n1)
    ch=$(sed -nE 's/^channel *= *"([0-9.]+)".*/\1/p' rust-toolchain.toml | head -n1)
    [ -n "$rv" ] && [ "$rv" = "$ch" ] || { echo "MSRV drift: [workspace.package] rust-version=$rv vs rust-toolchain channel=$ch" >&2; exit 1; }
    # (shellcheck over the load-bearing bash runs inside `gates`, with the roster it lints.)
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
    # v30 delta 2: `vmcell-artifact-validator` is downstream CONTRACT surface (§10.4), so it is
    # semver-gated exactly like `vmcell` — a silent breaking change to the validator battery is the
    # same defect as one to the library, and "discovered by a consumer's build breaking" is the
    # failure mode the ledgered bump exists to prevent.
    baseline="$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse main 2>/dev/null || true)"
    if [ -n "$baseline" ]; then cargo semver-checks --baseline-rev "$baseline" -p vmcell -p vmcell-artifact-validator; else echo "semver-checks: no main baseline available locally, skipping (CI enforces it on PRs)"; fi
    # Feature-powerset LAST and BLOCKING (former C-GATE-1 debt, closed by the §10.5 host-stack collapse):
    # every ≤2-feature config must compile+clippy clean under -D warnings. This is the comprehensive
    # guard that the collapse holds; a newly mis-gated module regresses it back to RED and fails here.
    echo "== feature-powerset (BLOCKING; must be GREEN after the §10.5 collapse) =="
    cargo hack --locked --feature-powerset --depth 2 clippy -p vmcell --all-targets
