#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/check-lean-tree.sh (AGENTS.md rule 2: write the
# red-on-inverse first; a gate whose self-test cannot fail is theater).
#
# The whole point of this file is the ENVIRONMENT it runs the predicate in. The defect it guards is
# not "the pattern is wrong" but "the pattern is right and the input is coloured": `ci.yml` sets
# `CARGO_TERM_COLOR: always`, `cargo tree` then emits `\e[2m├──\e[0m tokio v…`, and a `── tokio v`
# grep matches zero lines. A self-test that ran in a plain dev shell would pass against the broken
# predicate — which is exactly how the six inline copies stayed green locally while proving nothing
# in CI. So this test EXPORTS the CI condition and asserts the predicate still bites.
#
#   RED legs   — `vmcell-daemon` genuinely links tokio and hyper (20 paths) AND axum and the
#                `vmcell` host lib. It is the positive control for BOTH ban patterns in the matrix,
#                and each leg asserts the LEAN-VIOLATION verdict specifically — not merely a
#                non-zero exit, which an argument error would also produce (a vacuous red leg is as
#                useless as a vacuous green one).
#   GREEN leg  — `--all` must pass under the same coloured env, so the RED legs cannot be satisfied
#                by a predicate that simply rejects everything. It is ALSO the arm that actually
#                exercises the whole matrix in `just ci` / CI.
#   ROSTER leg — the matrix must still contain every member it is supposed to govern. Deleting the
#                `vmcell-daemon-client` row would otherwise leave `--all` green and the client's
#                `default-features = false` DTO boundary ungated again (docs/81 m28).
#   SUBSET leg — a caller naming a strict subset still gets the omitted rows checked, because the
#                matrix is the law and the call site is not.
#   USAGE legs — no arguments, an empty `--ban`, an unknown flag and an ungoverned crate name are
#                all caller bugs, not vacuous passes.
#
# The legs together are non-vacuous in both directions: delete `--color never` from the predicate
# and both RED legs fail; widen a ban pattern to match anything and the GREEN leg fails; drop
# `default-features = false` from crates/vmcell-daemon-client/Cargo.toml and the GREEN leg fails
# (verified empirically, not by inspection).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check-lean-tree.sh"

# Reproduce the CI environment, not the developer's. This single line is what gives the test its
# power — without it the coloured-input hazard is never exercised.
export CARGO_TERM_COLOR=always

fail=0

# RED legs: the positive controls. `vmcell-daemon` is the workspace's fattest host member — it
# links tokio and hyper (it is the async server) and axum and `vmcell` (it is the server stack the
# client's `default-features = false` keeps out). One leg per ban pattern in the matrix, so a
# pattern that has stopped matching cannot hide behind the other one.
red_leg() {
  local ban="$1" expect="$2" out rc=0
  out=$("$check" --ban "$ban" vmcell-daemon 2>&1) || rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "FAIL [red leg: $ban]: check-lean-tree PASSED vmcell-daemon, which links $expect."
    echo "  The predicate is colour-blind again — CARGO_TERM_COLOR=always defeats the '── <crate> v'"
    echo "  pattern unless \`cargo tree\` is invoked with \`--color never\`."
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
    return
  fi
  # The verdict must be the lean violation itself. Without this, an argument-parsing error or a
  # cargo failure would satisfy the leg and the control would prove nothing.
  if ! grep -q 'lean invariant violated' <<<"$out"; then
    echo "FAIL [red leg: $ban]: rejected vmcell-daemon, but not with the lean-violation verdict —"
    echo "  the leg is vacuous (it is being satisfied by some other error)."
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
    return
  fi
  if ! grep -qE "── ($expect) v" <<<"$out"; then
    echo "FAIL [red leg: $ban]: the violation report names no '$expect' path."
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
  fi
}
red_leg 'tokio|hyper|rtnetlink' 'tokio|hyper'
red_leg 'axum|vmcell' 'axum|vmcell'

# GREEN leg: the whole matrix, under the same coloured env. This is the arm that carries the
# production coverage — `just ci` and ci.yml both run this self-test, so a governed member that
# stops being lean reddens here even if a call site never names it.
green_out=""
green_ok=1
if ! green_out=$("$check" --all 2>&1); then
  echo "FAIL [green leg]: check-lean-tree --all REJECTED a member that must be lean."
  printf '  ---- output ----\n%s\n' "$green_out"
  green_ok=0
  fail=1
fi

# ROSTER leg: every member the invariant governs must be named in the run. A row silently dropped
# from the matrix takes its gate with it. Only meaningful when the green leg produced a full run —
# otherwise it would just re-report the violation above as four missing rows.
if (( green_ok )); then
  for governed in vmcell-guest-agent vmcell-test-runner vmcell-privilege vmcell-daemon-client; do
    if ! grep -q -- "$governed" <<<"$green_out"; then
      echo "FAIL [roster leg]: --all did not check $governed — its row is missing from the lean matrix."
      printf '  ---- output ----\n%s\n' "$green_out"
      fail=1
    fi
  done
fi

# SUBSET leg: the two historical call sites name three crates. The matrix is the law, so the
# omitted governed member is checked anyway and the caller is told to switch to `--all`.
subset_out=""
if ! subset_out=$("$check" vmcell-guest-agent vmcell-test-runner vmcell-privilege 2>&1); then
  echo "FAIL [subset leg]: the three-crate call-site form failed."
  printf '  ---- output ----\n%s\n' "$subset_out"
  fail=1
fi
if ! grep -q 'vmcell-daemon-client' <<<"$subset_out"; then
  echo "FAIL [subset leg]: a caller naming three crates did not get vmcell-daemon-client checked —"
  echo "  a stale call-site roster is silently narrowing the matrix (docs/81 m28)."
  printf '  ---- output ----\n%s\n' "$subset_out"
  fail=1
fi

# USAGE legs: caller bugs must fail loud rather than report a vacuous "ok" (the L-HOST-1
# contracts-self-guard shape: an empty roster is a caller bug, not an in-band "nothing to check").
usage_leg() {
  local label="$1"; shift
  if "$check" "$@" >/dev/null 2>&1; then
    echo "FAIL [usage leg: $label]: \`check-lean-tree.sh $*\` exited 0 — it must fail loud."
    fail=1
  fi
}
usage_leg "no arguments"        # an empty crate list must not be an in-band "nothing to check"
usage_leg "empty --ban" --ban '' vmcell-daemon
usage_leg "unknown flag" --nope
usage_leg "ungoverned crate" vmcell-daemon
usage_leg "--all with crates" --all vmcell-privilege

if [[ $fail -ne 0 ]]; then
  echo "check-lean-tree self-test FAILED"
  exit 1
fi
echo "ok: check-lean-tree self-test passed (both ban patterns redden on vmcell-daemon under"
echo "    CARGO_TERM_COLOR=always; the full matrix — incl. vmcell-daemon-client — greens)"
