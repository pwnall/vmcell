#!/usr/bin/env bash
# The KVM-free half of the downstream toolkit contract gate (design v30 §5.6 / §10.4; §18 delta 5).
#
# Four groups of legs, all runnable on a plain ubuntu runner:
#
#   1. the contract test binary          — overlay resolution, the sidecar naming rule + parser,
#                                          and this example's survival predicates with their inverses
#   2. the harness getters, both ways    — §10.4: the full `VMCELL_*` override set returns the named
#                                          paths; WITHOUT it the getters fail loud naming the
#                                          two-step route (separate processes: `ensure_test_artifacts`
#                                          memoizes its outcome per process)
#   3. the DOCUMENTED CLI invocations    — `vmcell build-kernels <label>…|--all --pins …` and
#                                          `vmcell oci2-erofs … --inject/--tools/--work-dir …`, the
#                                          half of the contract `cargo semver-checks` cannot see.
#                                          Mostly exercised on their fail-fast contract boundaries so
#                                          the leg needs no network and no 6-minute kernel compile;
#                                          the real labelled build is the live leg on the KVM job.
#                                          The v33 delta-7 pair is the exception that proves the rest
#                                          of the group's shape: it runs the BUILT BINARY from a
#                                          directory with no vmcell checkout above it — the
#                                          consumer's actual position — and pins that a repack there
#                                          refuses without `--tools` and proceeds with it. It still
#                                          stops short of completing a pack, which needs a real pull.
#   4. the vendored-vhost assertion trio — green (this workspace IS delta 2's positive control),
#                                          red on a dropped stanza, and not-applicable.
#
# Reddening this script is the intended failure mode of contract drift: fix or version the contract,
# never this example (design §10.4; rubric B15).
#
# Linting: `just ci`'s shell-lint glob was widened from `scripts/*.sh` to also cover
# `examples/downstream-kernel/*.sh` — this script must live beside the workspace it checks
# (docs/76 specifies the path), so the gate moved to it rather than the other way round.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The vmcell checkout this example consumes. Used for exactly two things: the documented CLI
# invocations (which §5.6 documents as run "from a vmcell checkout") and the one-law vendored-patch
# script. The example CRATE never reaches into it — only its `[dependencies]` path do.
repo="$(cd "$here/../.." && pwd)"
overlay="$here/pins-overlay.json"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
group() { printf '\n=== %s\n' "$1"; }

# Runs "$@", then checks the exit status against $2 ("0", "nonzero", or a literal code) and the
# combined output against the $3 regex. One helper for every leg so no leg can quietly forget to
# check one of the two halves.
expect() {
    local name="$1" want_rc="$2" want_re="$3"
    shift 3
    local out rc
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    local rc_ok=1
    case "$want_rc" in
        nonzero) [ "$rc" -ne 0 ] || rc_ok=0 ;;
        *) [ "$rc" = "$want_rc" ] || rc_ok=0 ;;
    esac
    if [ "$rc_ok" -eq 0 ]; then
        echo "FAIL [$name]: exit $rc, expected $want_rc"
        printf '  ---- output ----\n%s\n' "$out"
        fail=1
        return
    fi
    # `--` before the pattern: several legs assert that a FLAG is named in the refusal, and a
    # pattern beginning `--tools` would otherwise be eaten by grep as an option.
    if ! grep -qE -- "$want_re" <<<"$out"; then
        echo "FAIL [$name]: output does not match /$want_re/"
        printf '  ---- output ----\n%s\n' "$out"
        fail=1
        return
    fi
    echo "ok   [$name]"
}

# The inverse of `expect`'s output check, for the one place a leg's meaning IS an absence: with
# `--tools`, the repack must no longer fail on `vmcell-guest-tools`. A bare "it failed differently"
# would prove little on its own, so it is only ever used as the second half of a discriminating
# pair — the same command with the flag removed, asserted to name that string.
expect_absent() {
    local name="$1" want_rc="$2" absent_re="$3"
    shift 3
    local out rc
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    local rc_ok=1
    case "$want_rc" in
        nonzero) [ "$rc" -ne 0 ] || rc_ok=0 ;;
        *) [ "$rc" = "$want_rc" ] || rc_ok=0 ;;
    esac
    if [ "$rc_ok" -eq 0 ]; then
        echo "FAIL [$name]: exit $rc, expected $want_rc"
        printf '  ---- output ----\n%s\n' "$out"
        fail=1
        return
    fi
    if grep -qE -- "$absent_re" <<<"$out"; then
        echo "FAIL [$name]: output still matches /$absent_re/"
        printf '  ---- output ----\n%s\n' "$out"
        fail=1
        return
    fi
    echo "ok   [$name]"
}

group "1. the consumer builds and its contract tests pass"
cd "$here"
cargo build --locked
cargo test --locked
bin="$here/target/debug/downstream-kernel"
[ -x "$bin" ] || { echo "FAIL: $bin was not built"; exit 1; }

group "2. the harness getters under the VMCELL_* env contract (§10.4)"
# The documented downstream configuration: an externally managed artifact pair. The getters only
# assert existence, so two touched files pin the identity contract with no VM and no build.
touch "$work/vmlinux" "$work/rootfs.erofs"
expect "getters return the named kernel path" 0 "^vmlinux=$work/vmlinux\$" \
    env VMCELL_ARTIFACTS_DIR="$work" VMCELL_KERNEL="$work/vmlinux" \
        VMCELL_ROOTFS="$work/rootfs.erofs" VMCELL_PINS="$overlay" "$bin" getters
expect "getters return the named rootfs path" 0 "^rootfs=$work/rootfs.erofs\$" \
    env VMCELL_ARTIFACTS_DIR="$work" VMCELL_KERNEL="$work/vmlinux" \
        VMCELL_ROOTFS="$work/rootfs.erofs" VMCELL_PINS="$overlay" "$bin" getters
# The leg that keeps §10.4 honest: with the overlay ALONE (no kernel/rootfs override) the getters
# must fail loud naming the two-step route — build through the toolkit, then point the two vars at
# the outputs — never silently attempt the vmcell workspace bootstrap against a consumer checkout.
expect "getters fail loud without the override set" nonzero \
    "VMCELL_KERNEL.*VMCELL_ROOTFS|VMCELL_ROOTFS.*VMCELL_KERNEL" \
    env VMCELL_ARTIFACTS_DIR="$work/empty" VMCELL_PINS="$overlay" "$bin" getters

group "3. the documented CLI invocations (§10.4), on their fail-fast boundaries"
cd "$repo"
cli=(cargo run --locked -q -p vmcell-cli --bin vmcell --)
# `--all` is not decoration: v33 delta 6 made `build-kernels`' selection explicit (§10.5), so a
# bare invocation now refuses itself naming both forms — and these two legs assert on OTHER
# messages, which is exactly the contract drift this script exists to surface. The migration is to
# name the selection, in the same commit that changed the verb.
#
# `--pins` is honored by the CLI, not only by the library: a typo'd top-level key must be rejected
# NAMING it. If `--pins` were ignored this resolves the baseline and the command proceeds.
printf '%s\n' '{"kernel_fragmets": {"IKCONFIG": "CONFIG_IKCONFIG=y\n"}}' > "$work/typo-overlay.json"
expect "build-kernels --pins rejects a typo'd overlay key" nonzero "kernel_fragmets" \
    "${cli[@]}" build-kernels --all --pins "$work/typo-overlay.json"
# A label/fragment set with the non-compiling producer is a typed error (§5.6): before v30 this arm
# silently dropped both and reported a labelled build that never happened.
expect "build-kernels --pins --kernel-source prebuilt is a typed error" nonzero "prebuilt" \
    "${cli[@]}" build-kernels --all --pins "$overlay" --kernel-source prebuilt
# …and the selection law itself, on the same documented surface: a bare `build-kernels` is a typed
# refusal naming BOTH forms (§10.5, v33 delta 6), never a silent build of the whole registry.
expect "build-kernels with no selection refuses naming both forms" nonzero \
    "pass one or more labels.*--all" \
    "${cli[@]}" build-kernels --pins "$overlay"
# `--inject`'s value parser: the positive control is that a well-formed triple PARSES (the command
# then stops on the un-pinned image digest, which is why this leg needs no network at all).
expect "oci2-erofs --inject accepts a well-formed triple" nonzero "digest-pinned" \
    "${cli[@]}" oci2-erofs debian:trixie-slim -o "$work/out.erofs" \
        --inject "dest=/opt/acme/probe,src=$here/README.md,mode=0755"
# …and the negative control for the same flag: an unknown key is named, not ignored.
expect "oci2-erofs --inject names an unknown key" nonzero "owner" \
    "${cli[@]}" oci2-erofs debian:trixie-slim -o "$work/out.erofs" \
        --inject "dest=/opt/acme/probe,src=$here/README.md,mode=0755,owner=root"
# §4.2 (v33 delta 7): `--tools` + `--work-dir`, on the same terms. Well-formed values PARSE and the
# command still stops on the un-pinned digest — the boundary is unmoved, which is what "both flags
# are additive" has to mean at the argument surface.
expect "oci2-erofs --tools/--work-dir accept well-formed paths" nonzero "digest-pinned" \
    "${cli[@]}" oci2-erofs debian:trixie-slim -o "$work/out.erofs" \
        --tools "$here/README.md" --work-dir "$work/wd-parse"
# …and each is refused BY NAME when it cannot be honored. These need a digest-PINNED image, which
# is itself the ordering they pin: the argument checks run before any registry is contacted, so a
# typo costs an error message rather than a pull. (`sha256:` + 64 hex; the bytes never matter, the
# run stops long before anything is fetched.)
pinned_image="debian:trixie-slim@sha256:$(printf 'a%.0s' $(seq 64))"
expect "oci2-erofs --tools names a path that is not there" nonzero "--tools" \
    "${cli[@]}" oci2-erofs "$pinned_image" -o "$work/out.erofs" \
        --tools "$work/no-such-guest-tools" --work-dir "$work/wd-parse"
touch "$work/not-a-directory"
expect "oci2-erofs --work-dir names a non-directory" nonzero "--work-dir" \
    "${cli[@]}" oci2-erofs "$pinned_image" -o "$work/out.erofs" \
        --tools "$here/README.md" --work-dir "$work/not-a-directory"

# THE CONSUMER-POSITION PAIR (§4.2, v33 delta 7) — the legs this script's own header used to say
# were missing: before delta 7 no rootfs pipeline had ever been run from the consumer's position in
# CI, only from its fail-fast argument boundaries.
#
# These run the BUILT BINARY, not `cargo run`, and that is load-bearing: cargo sets
# `CARGO_MANIFEST_DIR` for the process it launches, and vmcell's source-root ascent starts there —
# so a `cargo run` leg is inside the checkout whatever its CWD is, and the pair below would pass
# vacuously. `env -u CARGO_MANIFEST_DIR` plus a CWD under `$work` (a `mktemp -d`, outside this
# repo) is the consumer's real position.
cargo build --locked -q -p vmcell-cli --bin vmcell
vmcell_bin="${CARGO_TARGET_DIR:-$repo/target}/debug/vmcell"
[ -x "$vmcell_bin" ] || {
    echo "FAIL: $vmcell_bin was not built — the consumer-position legs need the binary itself"
    exit 1
}
outside="$work/consumer"
mkdir -p "$outside"
# A stand-in for each prebuilt input. Neither is inspected before the stage that uses it, and the
# pair below stops in the handler stage, so their contents are irrelevant — what matters is that
# `--steward-musl` skips the steward's own checkout dependency, leaving the handler as the only one.
printf 'steward\n' > "$outside/steward-musl"
printf 'tools\n' > "$outside/guest-tools"
cd "$outside"
# RED HALF: no `--tools` and no checkout is a refusal that NAMES the crate it cannot build — never
# a silent image with no applets in it, and never a `cargo build` fired into the consumer's own
# workspace (which is what `workspace_root()`'s always-answers fallback used to produce).
# The regex demands the REMEDY as well as the crate, deliberately: the pre-delta-7 tree already
# failed here with "vmcell-guest-tools binary source missing at <a path the operator never typed>",
# so a leg matching only the crate name would have passed before this delta existed.
expect "oci2-erofs outside a checkout refuses without --tools" nonzero \
    "vmcell-guest-tools.*--tools" \
    env -u CARGO_MANIFEST_DIR "$vmcell_bin" oci2-erofs "$pinned_image" \
        -o "$outside/out.erofs" --steward-musl "$outside/steward-musl" --work-dir "$outside/wd"
# GREEN HALF, as far as a network-free job can carry it: the SAME command plus `--tools` no longer
# fails on the handler at all — it gets past that stage and dies fetching the (deliberately
# unresolvable) image. One variable changes between the two legs, so the pair is discriminating.
# What this job does NOT do is complete the pack: that needs a real digest-pinned pull, which this
# script has no network for (see the header). The pack itself is proven at the stage level by
# `crates/vmcell/tests/repack_outside_checkout.rs`, which re-execs into this same position.
expect_absent "oci2-erofs outside a checkout gets past the handler with --tools" nonzero \
    "vmcell-guest-tools" \
    env -u CARGO_MANIFEST_DIR "$vmcell_bin" oci2-erofs "vmcell.invalid/acme@sha256:$(printf 'a%.0s' $(seq 64))" \
        -o "$outside/out.erofs" --steward-musl "$outside/steward-musl" \
        --tools "$outside/guest-tools" --work-dir "$outside/wd"
cd "$repo"

group "4. the vendored-vhost assertion (delta 2), this workspace being its positive control"
cd "$here"
check="$repo/scripts/check-vendored-vhost.sh"
# GREEN: run the real, path-independent predicate against THIS workspace's own resolution. It is
# meaningful only because the manifest selects a vhost-resolving feature set (`net-unprivileged`)
# AND replicates the `[patch.crates-io]` stanza — drop either and this leg reddens.
expect "vendor assertion is green in the consumer workspace" 0 "check-vendored-vhost: ok" "$check"

# The RED and NOT-APPLICABLE legs mutate the TREE, not the manifest, and that is deliberate:
# deleting the `[patch.crates-io]` stanza invalidates this workspace's Cargo.lock, so the predicate
# — which is `--locked` on purpose, so a "check" can never rewrite a consumer's lockfile — would
# fail with cargo's stale-lock message instead of the dropped-patch verdict under test. Stripping
# the `(…/vendor/vhost…)` source annotations from the real tree reproduces exactly what a consumer
# who forgot the stanza sees, anchored on this workspace's actual resolution rather than a fixture.
mkdir -p "$work/bin"
cat > "$work/bin/cargo" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = "tree" ]; then cat "$FAKE_TREE"; exit 0; fi
echo "stub cargo: unexpected subcommand ${1:-}" >&2; exit 127
STUB
chmod +x "$work/bin/cargo"
# `--color never` is LOAD-BEARING. `.github/workflows/ci.yml` sets `CARGO_TERM_COLOR: always` at
# WORKFLOW level, and `cargo tree` then dims the tree glyphs — `\e[2m├──\e[0m vhost v0.16.0 (…)`.
# The reset escape ends in the lowercase `m`, so `^[^a-z]*vhost` at :141 below can no longer reach
# the crate name and the filter removes NOTHING: the "absent" fixture is byte-identical to the real
# tree, the predicate finds the patched vhost in it, and the not-applicable leg fails with the
# useless message "output does not match /check not applicable/". That is the defect this line
# fixes, and it is a class — see scripts/check-lean-tree.sh and the ban at
# scripts/ban-uncolored-cargo-parse.sh. Fix the PRODUCER, not the consumer regex: a regex taught to
# skip ANSI would leave the next derived fixture to rediscover the trap.
cargo tree --color never --locked -e normal --all-features > "$work/real-tree.txt"
sed -E 's@ \(/[^)]*/vendor/vhost[^)]*\)@@' "$work/real-tree.txt" > "$work/unpatched-tree.txt"
grep -vE '^[^a-z]*vhost(-user-backend)? v' "$work/real-tree.txt" > "$work/absent-tree.txt" || true
# Non-vacuity: the doctoring must actually have changed something, or the two legs below prove
# nothing about this workspace (this is what catches "the feature set stopped resolving vhost").
if cmp -s "$work/real-tree.txt" "$work/unpatched-tree.txt"; then
    echo "FAIL [vendor red leg setup]: this workspace's tree carries no vendored vhost annotation"
    echo "  — the feature set no longer resolves the patched vhost, so the green leg above is vacuous."
    fail=1
fi
# The same non-vacuity assertion for the OTHER derived fixture. Its absence is precisely why the
# colour defect above shipped: the filter silently removed zero lines, so the "absent" tree still
# carried the patched vhost and the leg below reported a confusing regex mismatch instead of naming
# its own broken setup. A fixture that was not doctored proves nothing about anything.
if cmp -s "$work/real-tree.txt" "$work/absent-tree.txt"; then
    echo "FAIL [vendor absent leg setup]: the absent-tree filter removed no vhost lines"
    echo "  — the 'not applicable' leg below would assert against an unmodified tree."
    fail=1
fi
expect "vendor assertion reddens when the stanza is dropped" 1 "resolves from the REGISTRY" \
    env FAKE_TREE="$work/unpatched-tree.txt" PATH="$work/bin:$PATH" "$check"
expect "vendor assertion is not applicable without vhost" 0 "check not applicable" \
    env FAKE_TREE="$work/absent-tree.txt" PATH="$work/bin:$PATH" "$check"

if [ "$fail" -ne 0 ]; then
    printf '\ndownstream-kernel contract check FAILED\n'
    exit 1
fi
printf '\nok: downstream-kernel contract check passed (contract tests, getters both ways, documented CLI, vendor trio)\n'
