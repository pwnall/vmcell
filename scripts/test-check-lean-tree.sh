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
#   RED leg   — `vmcell-daemon` genuinely links tokio (20 paths) and hyper. The predicate MUST
#               reject it. A colour-blind predicate accepts it, and this leg fails.
#   GREEN leg — the three governed members must pass under the same env, so the RED leg cannot be
#               satisfied by a predicate that simply rejects everything.
#   USAGE leg — no arguments is a caller bug, not a vacuous pass.
#
# The two legs together are non-vacuous in both directions: delete `--color never` from the
# predicate and the RED leg fails; widen the grep to match anything and the GREEN leg fails.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check-lean-tree.sh"

# Reproduce the CI environment, not the developer's. This single line is what gives the test its
# power — without it the coloured-input hazard is never exercised.
export CARGO_TERM_COLOR=always

fail=0

# RED leg: the positive control. `vmcell-daemon` is the workspace's fattest host member.
if out=$("$check" vmcell-daemon 2>&1); then
  echo "FAIL [red leg]: check-lean-tree PASSED vmcell-daemon, which links tokio and hyper."
  echo "  The predicate is colour-blind again — CARGO_TERM_COLOR=always defeats the '── <crate> v'"
  echo "  pattern unless \`cargo tree\` is invoked with \`--color never\`."
  printf '  ---- output ----\n%s\n' "$out"
  fail=1
fi

# GREEN leg: the members the invariant actually governs, under the same coloured env.
for crate in vmcell-guest-agent vmcell-test-runner vmcell-privilege; do
  if ! out=$("$check" "$crate" 2>&1); then
    echo "FAIL [green leg]: check-lean-tree REJECTED $crate, which must be lean."
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
  fi
done

# USAGE leg: an argument-less invocation must fail loud rather than report a vacuous "ok" (the
# L-HOST-1 contracts-self-guard shape: an empty roster is a caller bug, not an in-band "nothing to
# check" sentinel).
if "$check" >/dev/null 2>&1; then
  echo "FAIL [usage leg]: check-lean-tree with no crates exited 0 — an empty roster must fail loud."
  fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo "check-lean-tree self-test FAILED"
  exit 1
fi
echo "ok: check-lean-tree self-test passed (reddens on vmcell-daemon under CARGO_TERM_COLOR=always, greens on the three lean members)"
