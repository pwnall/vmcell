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

# §11.2: `vmcelld` is NOT blessed on the dev hot path. It gets its caps by being LAUNCHED THROUGH the
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
# content-hash `.blessed` stamp keyed on the RUNNER binary only (never test binaries): a re-run takes
# no sudo prompt and replaces nothing until the runner genuinely changes — it only RE-DATES the stable
# copy, which is what keeps `review-preflight-priv.sh`'s cargo-free freshness proxy clearable (see
# `redate_for_freshness_proxy` below). Because cargo only ever rewrites target/, the stable copy keeps
# its caps across all the unrelated rebuild churn.
bless:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --locked -p vmcell-test-runner
    cargo build --locked --release -p vmcell-test-runner
    # THE OTHER HALF OF THE PREFLIGHT'S FRESHNESS PROXY (docs/90 G9). `review-preflight-priv.sh` has
    # to answer "is the blessed copy the CURRENT build?" WITHOUT cargo, so besides the content-hash
    # stamp it asks one proxy question: is anything under crates/vmcell-test-runner/src,
    # crates/vmcell-privilege/src or Cargo.lock NEWER (mtime) than the stable copy? THIS recipe holds
    # the authoritative answer — it hashes the freshly BUILT runner against the stable copy — so every
    # exit where those hashes agree must leave the copy dated no earlier than that comparison.
    # Otherwise an edit after the last bless (a comment-only change, or a bare directory-mtime bump
    # from a temp file, which cargo does not even rebuild for) pins the preflight at STALE while the
    # blessed bytes are exactly what the sources produce — and `just bless` cannot clear it, because
    # its hash check takes the skip path and nothing re-dates the copy. That wedges the documented
    # reviewer path (AGENTS "probe, don't presume"). `touch` moves timestamps ONLY: the
    # security.capability xattr and the 0700 mode survive it.
    redate_for_freshness_proxy() {
      touch "$@"
    }
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
        # The hash comparison above is the AUTHORITATIVE "the stable copy is this build"; the
        # preflight's cargo-free proxy can only read mtimes, so say it there too (see the helper's
        # header — without this line a post-bless source edit leaves a permanent STALE no bless clears).
        redate_for_freshness_proxy "$stable" "$stamp"
        echo "bless: $stable already blessed (runner sha256 unchanged, caps +ep, mode 0700); skipping setcap (stable copy + stamp re-dated for the preflight's freshness proxy)"
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
      # The SAME rule at the other exit where the hash is known to match (here by construction: this
      # copy IS the built runner). `cp` without `-p` already stamps it with the current time and `mv`
      # within the directory preserves that, so this makes the requirement explicit instead of
      # incidental to a cp flag — and it is deliberately BEFORE the sudo prompt below: a source edited
      # while setcap waits for a password must still read STALE (a false CURRENT certifies the wrong
      # binary for a whole review; a false STALE costs one bless).
      redate_for_freshness_proxy "$tmp"
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

# Run `vmcelld` for manual poking (§11), LAUNCHED THROUGH the blessed runner so it gets its caps
# without being blessed itself (§11.2) — so it rebuilds with no `setcap` churn. Requires `just bless`
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

# The DOCUMENTED EXAMPLES on the public API, compiled and run. `cargo nextest` cannot run doctests
# (upstream limitation, stated in its own docs, which prescribe exactly this pairing), so
# `test-unit`'s and `ci`'s nextest invocation compiled not one `///` example — every doctest in the
# tree was correct by luck rather than by construction. Most of them sit on `vmcell`, a §10.4
# contract-surface crate, and on the entry points a new consumer reads first (`MicroVm::start`,
# `MicroVm::restore`, `VmConfigBuilder::build`): change one of those signatures, or `HostEnv::shared`'s,
# and the example that teaches a consumer how to call it silently stops compiling while every gate
# stays green. (No count is quoted here on purpose — this recipe IS the roster; run it.)
#
# The rustdoc gate in `ci` (`RUSTDOCFLAGS="-D warnings" cargo doc`) is NOT this gate: it checks doc
# LINKS and never compiles doc CODE. Its own comment says "`cargo doc` runs nowhere else", which was
# true of links and silent about code. This recipe is the missing half — and the second-order value
# is the larger one: with doctests gated, adding worked examples to the front door becomes safe.
#
# `--workspace` so a doctest in ANY member counts (the validator's `KconfigValues` module example
# lives outside `vmcell`); `--all-features` documents the widest API, matching the rustdoc gate.
# `ci` invokes this recipe and .github/workflows/ci.yml invokes the SAME recipe (`run: just
# test-doc`) — never a copied cargo line (AGENTS rule 3).
#
# RED ON THE INVERSE: break any documented example (rename a method it calls, change an argument)
# and this fails to compile it. Nothing else in the tree does.
test-doc:
    cargo test --locked --workspace --all-features --doc

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
    # THE VACUITY GUARD. This recipe's entire premise is that /sys/fs/cgroup is UNWRITABLE inside
    # the sandbox — that IS the runner condition it mirrors. Nothing asserted it, so on a host
    # where the operator owns the bind source the bind still succeeds, `create_dir_all` still
    # succeeds, and a green run reads as "the undelegated condition passes" when it never held.
    # That is this repo's own zero-file-scan doctrine one level out: a gate pointed at nothing
    # must say `gate misconfigured`, never a reassuring green. The probe is an actual `mkdir`
    # rather than a permission-bit reading, because the question is empirical — the bind source
    # could be root-owned and still writable through an ACL or a group the operator is in.
    probe=vmcell-undelegated-vacuity-probe
    if bwrap --dev-bind / / --bind /srv /sys/fs/cgroup -- mkdir "/sys/fs/cgroup/${probe}" 2>/dev/null
    then
        # The bind is over the REAL /srv, so a probe that succeeded left residue there. A gate's
        # own fixtures are residue too, on the failure path as much as the success path.
        rmdir "/srv/${probe}" 2>/dev/null || echo "warning: leftover /srv/${probe}" >&2
        echo "gate misconfigured: /sys/fs/cgroup is WRITABLE inside the sandbox." >&2
        echo "  This recipe would then exercise the DELEGATED path under an undelegated name —" >&2
        echo "  the 21 KVM-free cgroup tests would pass for the wrong reason and the runner" >&2
        echo "  condition would stay unmirrored. The bind source (/srv) must be a directory this" >&2
        echo "  user cannot write; on this host it is not." >&2
        exit 1
    fi
    bwrap --dev-bind / / --bind /srv /sys/fs/cgroup --chdir {{justfile_directory()}} -- \
        cargo nextest run --locked --all-features \
            -E 'not test(=apply_jail_sets_no_new_privs_and_the_core_rlimit)'

# Privileged integration suite via the capability runner. `just bless` installs it 0700 (owner-only)
# — that mode is the security boundary (PRIV-1); on a shared host use a dedicated group + 0750.
# Wraps every test binary with vmcell-test-runner via the cargo target-runner hook.
# The in-guest test-helper is ONE multicall binary baked into the rootfs by `vmcell build`, not built
# here — so a suite whose guest side needs a NEW applet (the raw dial's and the segment gates'
# `echo-server`) must re-run that build first; a warm rootfs fails it with a missing /vmcell-tools
# path. Its applet ROSTER is not restated here: read `vmcell_protocol::GUEST_TOOLS_APPLETS`, which the
# dispatch table is `const`-asserted against element-wise and the rootfs injection manifest emits
# from, so it cannot go stale. (The copy that used to sit on this line did: it still named four
# applets after `mini-init` and `xattr` landed in v33 deltas 5 and 7 — the embedded-roster failure
# AGENTS.md's docs rule names.) `--features` is scoped to the `vmcell` member that owns the integration tests.
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

# The `bench-vm` harness's LIVE legs — the exact defect `test-validator`'s header above records,
# one package further over. `test_benchmark_fc`, `test_benchmark_qemu` and `test_benchmark_crosvm` are
# `#[ignore = "needs KVM"]`, and until this recipe existed NO invocation in the tree selected them:
# every `--run-ignored all` was scoped elsewhere (`-p vmcell` in five recipes, `-p vmcelld`,
# `-p vmcell-artifact-validator`), and `just ci`/`just test-unit` pass no `--run-ignored` at all. So
# the composition root that wires all four backends — the ONE place with an edge to every backend —
# had its can-it-go-red proof compiled and skipped. `grep -n vmcell-bench justfile` used to return
# only `cargo clippy` lines.
#
# `--no-tests=fail` is the clause that makes a mis-scoped filter loud rather than green; it is what
# would have surfaced this one.
#
# FEATURE SCOPING, not a narrower filter: the crosvm leg is `#[cfg(feature = "crosvm")]`, so
# `--no-default-features --features cloud-hypervisor,firecracker,qemu` means it is never COMPILED and
# therefore cannot be selected. That is deliberate and mirrors `test-privileged`'s `firecracker,qemu`:
# `crosvm` is in `vmcell-bench`'s DEFAULT feature set, so a plain `--run-ignored all` here would
# hard-fail every host lacking a `crosvm` binary — which is every CI host. The crosvm leg's home is
# the same opt-in shape `test-crosvm` uses, this recipe with an explicit list:
#   just test-bench cloud-hypervisor,crosvm      # needs $VMCELL_CROSVM_BIN or `crosvm` on PATH
#
# WRAPPED ONCE, AND ONLY ONCE. The runner export below wraps the TEST BINARY; `bench-vm` is then
# spawned directly by the tests and inherits PRIVILEGED_CAPS through the ambient set — the same shape
# `test-daemon` uses for `vmcelld`. A second wrap cannot work: the first one shrinks the bounding set
# to PRIVILEGED_CAPS, dropping the transient CAP_SETPCAP that is still in the runner FILE's `+ep`
# capabilities, and `execve` returns EPERM ("insufficient to execute correctly") rather than
# degrading. That is exactly what shipped — `assert_cmd`'s `cargo_bin` door reads this very variable —
# and all five tests died at 0.008s with a bare `os error 1`. The law and its four gates live in
# crates/vmcell-bench/tests/common/mod.rs; `assert_bench_vm` now names the cause if it recurs.
#
# Needs KVM, the built artifacts (the tests touch the harness getters so the rootfs builds at most
# once per session before `bench-vm` reads them) and the blessed runner — `bench-vm` pins the CPU
# governor through `cpufreq::CpuFreqPin`, which needs CAP_DAC_OVERRIDE and otherwise prints
# "NOT pinned (need CAP_DAC_OVERRIDE via vmcell-test-runner)", and its privileged sub-benches want the
# net caps. (That pair is the measured proof the single wrap delivers: wrapped, the report says
# "cpufreq: pinned N CPU(s)"; the same binary run by hand says "NOT pinned".)
# Run it under a delegated scope like every other live suite:
#   systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-bench
# Each leg is one `bench-vm --backend <b> --iterations 1 --warmup 0` at the DEFAULT `--mode latency`
# (cold boot + warm restore), not the whole §16 sub-bench set — a couple of boots per backend, and
# the assertion is that the report prints `p50=` at all, i.e. that the wiring works.
test-bench features="cloud-hypervisor,firecracker,qemu":
    #!/usr/bin/env bash
    set -euo pipefail
    # The features list is an ACCEPTED INPUT, so it is honored or REJECTED here (AGENTS "fail loud"):
    # `bench-vm` carries `required-features = ["cloud-hypervisor"]`, so a list omitting it builds no
    # binary at all — while cargo still sets `CARGO_BIN_EXE_bench-vm` (measured: `cargo build --tests
    # --no-default-features --features firecracker` compiles the test target and leaves
    # target/debug/bench-vm untouched). The harness would therefore exercise whatever STALE binary an
    # earlier, differently-featured build left there, and report it as this run — or, on a clean tree,
    # fail at spawn with ENOENT. Neither is an answer about the features asked for, so it is refused
    # here, by name, before cargo runs.
    case ",{{features}}," in
      *,cloud-hypervisor,*) ;;
      *) echo "test-bench: features must include cloud-hypervisor (bench-vm's required-features); got '{{features}}'" >&2; exit 1 ;;
    esac
    # H-TEST-3, like every sibling suite recipe: without the run-scoped export a `require_cap!` skip
    # from the shared harness getters lands in the per-PID temp file nobody reads.
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell-bench \
        --no-default-features --features {{features}} --run-ignored all \
        --no-tests=fail -E 'binary(benchmark)'

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
#   cargo run -p vmcell-cli -- build-kernels usbhost   # v33 delta 6: selection is explicit
#                                                     # (`--all` builds every `kernels` label)
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

# v33 delta 9: the systemd proof cell — the capstone over placement (4), the service steward (5),
# the registry (6) and xattr policy (7). Boots the digest-registered `debian-systemd` image with
# REAL systemd as PID 1, the steward installed as one of its units under
# `StewardPlacement::Service`, drives the control plane end to end (`exec`, `put_file`, sessions),
# asserts the §7.4 provenance and §8.1's per-op refusal, and runs the §10.6 conformance kit over
# the composition. Needs KVM and a blessed runner.
#
# OPT-IN, and the opt-in is IN THE TEST, not in this filter. `test-privileged`'s filterset excludes
# only unprivileged/smoltcp, so it selects `test(systemd_cell)` too — writing a narrower filter here
# would not keep the ~59 MB image pull off every KVM host. So the legs self-skip (recording a
# reviewable capability skip) unless VMCELL_TEST_SYSTEMD is set, exactly as `usb_passthrough`
# self-skips without a designated device, and this is the one place that sets it. The wiring is
# gated in both directions by `systemd_cell::the_opt_in_is_declared_by_the_systemd_recipe_and_by_no_other`
# — which reddens if this export moves, disappears, or shows up in another recipe.
#
# Its KVM-free halves (the registry laws, the placement matrix, the feature vocabulary, the xattr
# policy) run everywhere under the ordinary unit gates; only the boot is opt-in.
#
# Run it under a delegated scope like every other live suite:
#   systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-systemd
test-systemd:
    # H-TEST-3, like every sibling suite recipe: without the run-scoped export the legs' own
    # capability skips land in the per-PID temp file nobody reads.
    VMCELL_TEST_SYSTEMD=1 \
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell --run-ignored all \
        --no-tests=fail -E 'kind(test) & test(systemd_cell)'

# The out-of-tree consumer workspace (design §10.4) — the gate that holds the downstream
# contract's *guidance* by compiling against it. Breaking this is the intended failure mode of
# contract drift; "fixing" the example to stay green instead of versioning the contract inverts
# the gate.
#
# It exists as a recipe for AGENTS.md rule 3: `ci.yml`'s `example-downstream` job used to restate
# these two commands, and a CI step that hand-copies a recipe drifts from it. There was no recipe
# to call, which is why the class had no home. KVM-free, so it runs anywhere.
#
# `cargo build --locked` in the example's OWN workspace: a stale example Cargo.lock fails here
# rather than being silently regenerated, exactly as in the main workspace. `ci-check.sh` then
# covers overlay resolution, the harness-getter contract both ways, the documented CLI
# invocations, and the vendored-vhost assertion trio.
example-downstream:
    cd {{justfile_directory()}}/examples/downstream-kernel && cargo build --locked
    cd {{justfile_directory()}}/examples/downstream-kernel && ./ci-check.sh

# Install the repo-tracked git hooks. `scripts/git-pre-commit` shipped with a "symlink this into
# .git/hooks/pre-commit" note in its own header and nothing that performs it — a deploy step
# written as prose is a deploy step that does not happen, which is why the hook was installed in
# no checkout including this one. A SYMLINK, never a copy: a copy is the hand-copy class the two
# meta-gates exist for, one directory over, and it silently keeps running the version it was
# copied from.
#
# Not on any CI path by design (a hook is a local convenience; CI runs the real gates), so it is
# a rostered human entry point in `scripts/ban-orphan-recipe.sh`.
install-hooks:
    #!/usr/bin/env bash
    set -euo pipefail
    hooks="$(git -C {{justfile_directory()}} rev-parse --git-path hooks)"
    mkdir -p "$hooks"
    # `-f` so re-running is idempotent; the relative target keeps the link valid if the checkout moves.
    ln -sfn ../../scripts/git-pre-commit "$hooks/pre-commit"
    test -x {{justfile_directory()}}/scripts/git-pre-commit \
        || { echo "scripts/git-pre-commit is not executable; a symlink to it would be inert" >&2; exit 1; }
    echo "installed: $hooks/pre-commit -> $(readlink "$hooks/pre-commit")"

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
    # The same class, the OTHER half: a copied recipe BODY. The scanner above bans ci.yml from naming
    # a `scripts/*.sh`; nothing banned an aggregate from restating a recipe's commands, and that had
    # shipped twice — ci.yml inlining `test-unprivileged`'s nextest line and then dropping
    # `--features qemu` (a whole backend's matrix legs stopped COMPILING in CI, M14), and `just ci`
    # carrying a verbatim copy of the `test-unit` body, found by a human rather than by a gate. Both
    # are fixed by calling the recipe; this is the class. It reads bodies back through `just --show`
    # (the recipe is the authority) and matches interpolated lines as globs, so an EXPANDED copy is
    # caught too. Its self-test drives both files' arms plus the controls that must stay clean
    # (shared boilerplate, an interpolation-only body) and every vacuity arm.
    ./scripts/ban-recipe-body-handcopy.sh
    ./scripts/test-ban-recipe-body-handcopy.sh
    # `AGENTS.md` is the DEPLOYED copy of `docs/*claude-agents*.md` — two paths, one document. The
    # docs/81 campaign rewrote AGENTS.md in seven hunks and the source document in one, leaving every
    # corrected count still wrong in the file AGENTS.md is deployed from — inside the very wave whose
    # mandate was "rosters quoted in docs are checked against the tree, never from memory". The two
    # were byte-identical before the campaign, so the invariant existed; it was merely unwritten, and
    # an unwritten invariant is not a gate.
    ./scripts/check-agents-md-sync.sh
    ./scripts/test-check-agents-md-sync.sh
    # The same class as the sync gate above, one step out: a documented POINTER that resolves to
    # nothing. Two shipped together — AGENTS.md's "read before changing anything" list sent every
    # agent to `docs/99-claude-fable-automated-quality-v9.md` after that document was retired into
    # `docs/historical/` (the one file every agent reads first, pointing at a file that is not there),
    # and the daemon's served OpenAPI sent consumers to a `design §D` (allow-dangling-design-ref: quoted
    # defect) that renumbering had deleted (docs/90 D2 — a Rust string literal, so closing that instance
    # meant extending the `§` arm over the code, which `ban-dangling-design-ref.sh` below now does).
    # Prose is not compiled, so this is its compiler: every `docs/…` pointer in the root markdown and
    # the live `docs/*.md` must resolve — honoring the conventions the repo actually uses (the
    # arbitrary-digit `9` glob, extension-less document-NUMBER shorthand resolving live or historical,
    # and the retirement fallback scoped to the one as-built ledger whose dated entries AGENTS.md
    # forbids "fixing") — and every `§`/`Appendix X` in the root markdown must name a real heading of
    # the DISCOVERED newest design document, never a pinned filename (v31→v32→v33 broke gates that
    # hardcoded one). The self-test drives every resolving form, the retired-live-path break AND its
    # correction, the ledger scope both ways, a missing section, a missing appendix, and the vacuity
    # arms; two genuinely dangling pointers are exempted BY NAME in the script, each with its reason
    # and both directions gated (an exemption nobody names, and one that now resolves, both fail).
    ./scripts/check-docs-pointers.sh
    ./scripts/test-check-docs-pointers.sh
    # The pointer-over-figure rule for the FRONT DOOR (AGENTS.md, "Docs and dependencies"). The README
    # carried an embedded crosvm pass/total that had gone stale by the time anyone read it; docs/90
    # deleted it and wrote a pointer at the recipe instead — and nothing gated the class, so the next
    # pasted p50, boot time or image size would land exactly the same way. Two arms, because the answer
    # depends on where the number sits: NO performance unit (ns/µs/ms, a fractional second, a rate, a
    # percentile bound to a value) anywhere in README.md — narrow enough that a pinned version, a file
    # mode, a port and a `.mem_mib(512)` config example all stay clean — and, INSIDE the benchmark
    # section, no unit-bearing number at all, which is where a size or a percentage becomes a figure.
    # Code fences are deliberately in scope: pasting a bench-vm report block is how this lands. The
    # section is FOUND (exactly one heading naming a benchmark), so the gate also holds that section in
    # place. A clean README yields zero hits, so proof of life is a CANARY each arm must match plus a
    # collapse check that ARM 1 must NOT match ARM 2's; the self-test drives every arm, both marker
    # directions, and all four vacuity arms.
    ./scripts/ban-benchmark-figure-in-readme.sh
    ./scripts/test-ban-benchmark-figure-in-readme.sh
    # The SAME pointer class everywhere OUTSIDE the markdown — the follow-up the script above records.
    # docs/90 D2 was `design §D` (allow-dangling-design-ref: quoted defect) in the daemon's served
    # OpenAPI `description`: a dangling pointer in a document the daemon hands to CLIENTS.
    # `check-docs-pointers.sh` closed that class for the root markdown; the daemon lane's in-crate gate
    # was scoped to its own tier so it could not redden another agent's files. There are ~2000 `§`
    # references under `crates/*/src` alone (the design is cited in the rustdoc of nearly every law), so
    # a renumbering can invalidate any of them silently. The roster is FIVE kinds, because scanning only
    # `crates/*/src` left a blind spot between this gate and the markdown one that held fifteen live
    # dangling references: the crate sources AND tests, every `Cargo.toml` (the contract ledgers cite
    # the design at every version edge), this justfile, and `scripts/` minus the `test-*.sh` self-tests
    # — whose red-on-inverse fixtures are references that must NOT resolve, so scanning them would make
    # the gate and its own self-test mutually unsatisfiable. Each kind's file count is in the verdict
    # and each has its own vacuity arm, because a roster built out of five globs dies one glob at a
    # time. Every reference resolves against the DISCOVERED newest design document's real headings. The
    # first escape hatch is self-documenting rather than a roster: a reference into another numbering
    # must say which (`v30 §9.4`, `docs/78 §5`, `design 62 §22` — the number must name a document that
    # exists) and is skipped. The second is a per-line `allow-dangling-design-ref: <reason>` marker for
    # the few lines that QUOTE a dangling reference as the defect they report (this comment is one),
    # gated in both directions: a marker whose line's references all resolve excuses nothing and fails.
    # The heading resolver lives in `scripts/design-headings.sh` — one home for "which document is the
    # design and what headings does it have", shared with the section arm of `check-docs-pointers.sh`
    # (whose own copy predates it; collapsing the two is a caller change, recorded as a followup). That
    # helper is NOT gate-shaped and so is not on this roster and cannot be: it makes no claim about the
    # tree, and its three misconfiguration arms are driven by the self-test beside it.
    ./scripts/ban-dangling-design-ref.sh
    ./scripts/test-ban-dangling-design-ref.sh
    # ONE MSRV FACT, and now ONE place that asserts it: `rust-toolchain.toml`'s pinned channel equals
    # the declared `[workspace.package] rust-version`. This call REPLACES the two inline `sed`
    # comparisons that used to live in the `ci` recipe below and in ci.yml's "toolchain honesty" step —
    # whose own comment admitted it mirrored the recipe. A mirrored ASSERTION is worse than a mirrored
    # roster: it drifts in STRICTNESS silently, and whichever copy the reader opens tells them the law.
    # The script is strictly stronger than either copy, each strictness with a defect behind it: it is
    # TOML-section-aware (the `sed` would have accepted a `rust-version` under any table), it REFUSES a
    # non-pinned channel (`stable` makes the equality unstatable while the gate stays green), and it
    # compares EVERY literal spelling of the number — `fuzz/` and `examples/downstream-kernel/` are
    # separate workspaces that cannot inherit via `rust-version.workspace`, and `clippy.toml`'s `msrv`
    # comment already claimed this assertion covered it. It did not.
    ./scripts/check-msrv-sync.sh
    ./scripts/test-check-msrv-sync.sh
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
    # lean-member invariants (v15 §12.8 #4 / §15.2): the guest PID-1 steward, the privileged-window
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
    # input can never share the cap-holding process (§13 / P2). NOTE: `hyper` is deliberately NOT
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
    # §4.7 / v33 delta 8 ("one law, one predicate"): `RootfsSource::root_device_read_only` is the one
    # home for "is the root disk attached writable". It exists because all FOUR backends had each
    # open-coded that decision and all four had drifted the same way — attaching a `Block` root
    # read-WRITE beneath a cmdline that mounts it `ro`, i.e. a write path with no reader, with N
    # zygote clones sharing the one image. The drift is not a compile error (a hardcoded
    # `readonly: false` builds fine), so grep-ban it: any production file that names BOTH
    # `effective_image` and a device-writability token must read the law. The self-test drives the
    # regression, the two exempt shapes (the definition site, a non-wiring sidecar reader) and the
    # vacuity arm.
    ./scripts/ban-root-disk-writability-literal.sh
    ./scripts/test-ban-root-disk-writability-literal.sh
    # S2 / delta 8 ("one law, one predicate"): `net_sys::setns_net` is the one home for `setns(2)`,
    # the `build_vmm_cmd` pre_exec site its one exemption (its safety proof is site-specific). The
    # review found two inline duplicates; nothing but review stopped a third, so grep-ban it. The
    # self-test proves all three halves red: the call pattern, the one-call cap inside an exempt
    # file, and the stale-exemption check.
    ./scripts/ban-inline-setns.sh
    ./scripts/test-ban-inline-setns.sh
    # The O_CLOEXEC half of the same module's law. `net_sys`'s `/dev/net/tun` open goes through
    # `std::fs::OpenOptions`, which sets O_CLOEXEC; C's `open(2)` does not, and `vmcelld` fork/execs
    # VMMs concurrently with that call, so a leaked tun fd is an ATTACHED TAP QUEUE and the VMM's own
    # TUNSETIFF fails EBUSY. The drift is neither a compile error nor test-observable (the failure
    # needs a concurrent fork to race the open, and the fn is `pub(crate)`), which is exactly the
    # shape AGENTS.md says earns a grep-ban. The self-test proves the call pattern, every raw
    # spelling, the comment-stripping, and both anchor-moved refusals red.
    ./scripts/ban-raw-fd-open.sh
    ./scripts/test-ban-raw-fd-open.sh
    # The netns LAYOUT half of the same net law (F2-adjacent): `/var/run/netns/<name>` is composed
    # only from `net::tap::NETNS_DIR`. `net/tap.rs`'s `netns_layout_gate` pins that roster in both
    # directions, but it walks `env!("CARGO_MANIFEST_DIR")/src` — so its whole verdict is about
    # `crates/vmcell/src`, and `netns_path`/`netns_dir` are `pub(crate)`, meaning no other crate can
    # route through them even if it wanted to. This is the COMPLEMENT, not a second copy: it scans every
    # other crate's src and DELEGATES that one tree to the in-source gate, failing loud if that gate
    # (or the const it reads its needle out of) is gone. It also bans the ALIAS — `/var/run` is
    # conventionally a symlink to `/run`, so `"/run/netns/…"` reaches the same directory while matching
    # nothing anchored on the law's own text, the alias class AGENTS.md's F3 rule names. The self-test
    # drives both arms, the three ways the delegation goes stale, and both vacuity arms (including the
    # one peculiar to a complement gate: a tree that is ONLY the delegated crate).
    ./scripts/ban-inline-netns-path.sh
    ./scripts/test-ban-inline-netns-path.sh
    # AGENTS rule 3, one level ABOVE the orphan-SCRIPT class `ban-ci-script-handcopy.sh` ARM 4
    # already covers: a `just` RECIPE that nothing invokes is maintained, shellchecked, documented
    # work that runs nowhere and therefore cannot go red. Both directions, like its sibling — an
    # un-called recipe must be rostered WITH the reason a human is its only caller (the opt-in live
    # suites' named absent facility; the operator verbs), and a roster entry whose recipe has since
    # ACQUIRED a caller is a stale exemption, i.e. a widened blind spot. Bodies are read back
    # through `just --show`, so an interpolated `{{{{just_executable()}}}}` call reads as it runs.
    ./scripts/ban-orphan-recipe.sh
    ./scripts/test-ban-orphan-recipe.sh
    # E1: "what does a guest-kernel fault look like on the console" is ONE law
    # (`vmcell::vmm::fault`), because the host already had two readers of the same bytes — the
    # boolean panic detector's three inline literals and the validator's §5.4 clause literals — and
    # their agreement (the validator deliberately does not claim `Kernel panic`) was enforced by
    # nothing. This scanner reads its needles OUT of the `*_SIGNATURES` consts, so a needle added to
    # the law is banned elsewhere from that moment on and the gate can never disagree with the code.
    # The self-test proves every arm red, including the one that already bit: a line-at-a-time
    # extractor loses every literal of a rustfmt-COLLAPSED const and then scoops unrelated strings —
    # the first cut guarded 11 of the wrong needles and let a real inline `contains("Kernel panic")`
    # through while printing "ok".
    ./scripts/ban-inline-kernel-fault-signature.sh
    ./scripts/test-ban-inline-kernel-fault-signature.sh
    # A6/A9 ("one law, one predicate"): the cross-process id-claim law — WHERE the registry is
    # (`SHARED_{VMID,SEGID}_CLAIM_DIR`) and HOW owner liveness is decided (`FsIdClaim::owner_is_live`'s
    # `/proc/{pid}` probe). Both halves drift SILENTLY and fail OPEN: a second spelling compiles, passes
    # every unit test (they inject their own directories), and makes the sweeps read an empty registry —
    # which reaps a LIVE sibling's netns/tap/cgroup/scratch while logging a successful orphan reclaim.
    # Comment-stripped, so the many rustdoc mentions and a `/proc/{pid}/stat` READ are not false
    # positives. The self-test proves both arms, the const check inside the law's own home, the
    # stale-exemption report (two rostered sites) and the empty-scan misconfiguration red.
    ./scripts/ban-id-claim-law-copies.sh
    ./scripts/test-ban-id-claim-law-copies.sh
    # Design §17's LAST open "one law, one predicate" item, closed: `bench-vm` hand-rolled the
    # library's workspace-root ascent for as long as `vmcell::artifact::workspace_root` was
    # `pub(crate)`, and §17 named the coupling to watch — the `crates/vmcell-protocol/Cargo.toml`
    # marker. It is watched here rather than remembered. A drifted ascent is not a compile error and
    # not visible to the parity test beside it: a BYTE-IDENTICAL copy resolves the same root today
    # and is free to drift tomorrow (both directions demonstrated when this landed). The roster names
    # the one file that may still spell the marker — the guest-tools closure error that quotes it at
    # an operator — and the home's count is split production vs `#[cfg(test)]`, because a production
    # copy plus a deleted fixture keeps the file's total unchanged.
    ./scripts/ban-workspace-root-ascent-copies.sh
    ./scripts/test-ban-workspace-root-ascent-copies.sh
    # design §3.5 / AGENTS.md "a gate binds the CALL SITES, not just the extracted predicate":
    # `mini-init` is PID 1 in the service proof cell, and its restart loop spelled its pacing twice
    # and unevenly — a literal `Duration::from_millis(200)` on the spawn-failure arm, and NOTHING on
    # the exit arm, so a program that exits instantly burned the whole rapid-failure cap in
    # microseconds and wrote a console line per iteration into the persisted serial-log artifact.
    # The pause now comes back from `mini_init_restart_after` (with the strike count) over the one
    # `retry_backoff`. The unit tests hold the CURVE and stay green while a call site ignores the
    # answer and sleeps its own literal again; this scan holds the call sites. Scoped to the
    # guest-tools tree on purpose (the steward's non-retry polls are legitimately literal), it names
    # its delegate, and it treats a zero-file scan, a sleep-free production text, and a missing
    # delegate all as `gate misconfigured` rather than a green verdict.
    ./scripts/ban-unpaced-guest-retry.sh
    ./scripts/test-ban-unpaced-guest-retry.sh
    # The one script `ban-ci-script-handcopy.sh` EXEMPTS from its no-scripts-in-ci.yml arm, and the
    # one every live suite runs through — and it had no can-it-fail proof of any kind. Its four
    # warn-and-continue arms are each `if !`-guarded, so `set -euo pipefail` is inert on all four
    # and a regression degrades every cgroup leg in the tree to "ran without delegation" silently.
    # The self-test fabricates a cgroup tree under `bwrap` (the wrapper computes the same `cg_base`
    # it would in production, because /proc/self/cgroup is untouched) and drives every arm plus the
    # `exec "$@"` contract, red-on-inverse against mutated copies.
    ./scripts/test-with-delegated-scope.sh
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
    # §10.5 / v33 delta 6: the ROOTFS half of the same law, added with the kind it guards. The
    # rootfs hazard is strictly worse than the kernel's in one respect — the flat
    # `rootfs_image`/`rootfs_digest` pins are read by `resolve_builder_base`, which picks the image
    # that builds KERNELS, so a drift on the default label repoints a consumer it was never about.
    ./scripts/ban-rootfs-key-composers.sh
    ./scripts/test-ban-rootfs-key-composers.sh
    # §10.5 / v33 delta 6: the HANDLER half. Added WITH the kind rather than after a duplicate has
    # already diverged, which is the only reason either sibling above exists.
    ./scripts/ban-handler-key-composers.sh
    ./scripts/test-ban-handler-key-composers.sh
    # §10.5 / v33 delta 6c, F7: the dev-override ENTRY KEY is spelled once, in
    # `registry::UNPINNED_PATH_KEY`. Six sites read it (both entry parsers, both flattener arms,
    # both stages' override arms, and `bundle`'s refusal scan) and the dangerous drift direction is
    # SILENT — a refusal scan looking for a different spelling bundles an unpinned registration,
    # which is the one thing F7 promises vmcell will not do. The self-test proves five halves red:
    # the literal scan, the exact-count check inside the sanctioned home (extra AND missing), the
    # stale-home check, and the non-vacuity check; plus four near misses that must stay clean
    # (prose, the identifier, a `#[cfg(test)]` JSON fixture, a `tests/` fixture).
    ./scripts/ban-unpinned-path-literal.sh
    ./scripts/test-ban-unpinned-path-literal.sh
    # §10.5 / v33 delta 6c, F7 again: the registry DIGEST-FORMAT check ("registration is a digest")
    # had two copies — `handler.rs`'s own function and an inline one in `artifact/mod.rs` — whose
    # bodies matched and whose MESSAGES did not, so one malformed value told two operators two
    # things; and when the check was tightened to reject uppercase hex, only one would have moved.
    # One `registry::reject_unpinned_digest` now, and this bans a second re-derivation. The
    # self-test pins the two spellings that actually shipped, both count halves, the stale home, the
    # non-vacuity check, and the near misses that must stay clean — the `strip_prefix("sha256:")`
    # sites that COMPARE bytes, which banning would delete the verification F7 exists to enable.
    ./scripts/ban-registry-digest-check.sh
    ./scripts/test-ban-registry-digest-check.sh
    # docs/90 A2: `vmcell::artifact::ch_binary_path()` is the one resolver for the §10.4 contract
    # variable `$VMCELL_CH_BIN`. The review found a THIRD byte-identical copy — in `vmcell-cli`, the one
    # every VM-lifecycle verb went through — while design §17's open-consolidation register, whose job
    # is to inventory exactly this, named only two of the three. A parity assertion cannot close it
    # (`ch_bin() == ch_binary_path()` passes with the variable UNSET, which is every test run, and
    # `set_var` is banned here), so the law is scanned. The CLI now carries an in-source call-site gate,
    # but `include_str!("main.rs")` is its whole universe; this is the class, repo-wide, where the next
    # copy will be. The roster names the four files that may spell the variable — the daemon's
    # flag-then-env precedence, the daemon suite's PATH-searching variant, `bench-vm`'s parity-asserted
    # table, and the CLI gate's own needle — each with an EXACT count in both directions, so an extra
    # read cannot hide behind an entry and a stale entry cannot widen the blind spot.
    ./scripts/ban-ch-binary-resolver-copies.sh
    ./scripts/test-ban-ch-binary-resolver-copies.sh
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
    # The OTHER half of that same reviewer path — self-test only for the same reason, and BEHAVIOURAL
    # rather than textual: `just bless` must leave the stable blessed copy dated no earlier than the
    # moment it established that copy IS the current build. It did not. The recipe's idempotence skip
    # fires when the freshly built runner's hash equals the `.blessed` stamp, and it then replaced
    # nothing — so the preflight's conservative `find -newer` freshness proxy kept reporting STALE and
    # `just bless` could not clear it. That wedged the documented reviewer path permanently at
    # BLOCKED-ON-BLESS: preflight says "ask the maintainer to run `just bless`", the maintainer runs it,
    # the verdict does not move, and "probe, don't presume" routes every privileged review through that
    # probe. The fix (`redate_for_freshness_proxy` at both exits where the hash is known to match)
    # landed with no gate; this is it. It proves the law by copying the REAL justfile and REAL
    # preflight into throwaway fixture repos and running `just bless` there with cargo/getcap/sudo/cp
    # stubbed on PATH — never by restating the recipe's logic, which would be the hand-copy class one
    # level down. Both call sites are pinned independently. No cargo, no sudo, no KVM, and the repo's
    # own ./.vmcell-bin is asserted untouched rather than assumed to be.
    ./scripts/test-bless-redates-blessed-copy.sh
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
    # lean-member invariants (v15 §12.8 #4 / §15.2), compile half: the tree-SHAPE assertion is
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
    # The `ext4-producer` OFF arm (§4.7, §18 delta 8). `--lib`, deliberately WITHOUT
    # `--all-targets`: `vmcell`'s dev-dependency cycle (vmcell → vmcell-artifact-validator → vmcell)
    # re-enables `default`, and therefore this feature, the moment dev-deps are resolved — so
    # neither the loop above nor `cargo hack --feature-powerset` below can ever compile the typed
    # capability refusal. This line is the only thing that does.
    echo "== ext4-producer OFF arm: --lib --no-default-features --features cloud-hypervisor,pipeline =="
    cargo clippy --locked -p vmcell --lib --no-default-features --features cloud-hypervisor,pipeline
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
    # (Toolchain honesty — the declared `[workspace.package] rust-version` equals the pinned
    # `rust-toolchain.toml` channel — is `scripts/check-msrv-sync.sh` inside `gates`, invoked above.
    # It was an inline `sed` comparison HERE and a mirrored `run:` block in ci.yml; two copies of one
    # law is what AGENTS rule 3 bans, and an assertion drifts in strictness more quietly than a roster
    # does. The script is strictly stronger than the pair it replaces — see its entry in `gates`.)
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
    # INVOKED, NEVER COPIED (AGENTS rule 3) — this line was a verbatim copy of the `test-unit` recipe
    # body, the exact drift shape ci.yml was already fixed for: its copy of this same command had
    # dropped a `--features` flag one job over and a whole backend's matrix legs stopped compiling in
    # CI, invisibly. A recursive `just` gives the command one home, the way `gates` above has one.
    {{just_executable()}} test-unit
    # …and the half nextest structurally cannot run: doctests. See the `test-doc` recipe's header —
    # ci.yml's test-unit job invokes this same recipe.
    {{just_executable()}} test-doc
    # public-API semver intent (CI runs this PRs-only against the PR base; locally diff vs the main
    # merge-base). Runs on the pinned toolchain — 1.98.0 satisfies cargo-semver-checks' rustc floor.
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
