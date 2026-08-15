#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/check-agents-md-sync.sh.
#
# The gate asserts AGENTS.md is byte-identical to its source document under docs/. A gate whose
# self-test only proves the green path is theater (AGENTS.md rule 2), so every arm below is driven
# from a fixture tree the check is pointed at, and each is asserted to FAIL:
#   * a one-character divergence between the two copies              → must fail;
#   * the exact real-world shape that got past no gate at all — the
#     deployed copy corrected while the source document kept the
#     stale number                                                   → must fail;
#   * a missing source document (so a roster that resolves to
#     nothing cannot print a reassuring "ok")                        → must fail;
#   * a missing AGENTS.md                                            → must fail;
#   * version-numbered source discovery: a `-v8` reissue that
#     matches must PASS without editing this gate, and a stale `-v7`
#     left beside it must not be the one compared                    → must pass on the newest.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check-agents-md-sync.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0

# Builds a tree whose two copies agree. `body` varies so each arm is independent.
mk_tree() {
  root="$1"; body="$2"; doc="${3:-80-claude-agents-v7.md}"
  mkdir -p "$root/docs"
  printf '%s\n' "$body" > "$root/AGENTS.md"
  printf '%s\n' "$body" > "$root/docs/$doc"
}

expect_pass() {
  label="$1"; root="$2"
  if "$check" "$root" >/dev/null 2>&1; then
    echo "  ok   [$label] passes when the copies agree"
  else
    echo "  FAIL [$label] the check must PASS here, but it failed" >&2
    fail=1
  fi
}

expect_fail() {
  label="$1"; root="$2"
  if "$check" "$root" >/dev/null 2>&1; then
    echo "  FAIL [$label] the check must FAIL here, but it passed — the gate cannot go red" >&2
    fail=1
  else
    echo "  ok   [$label] reddens"
  fi
}

echo "test-check-agents-md-sync:"

# --- Green baseline. Without this the failing arms below prove nothing: a check that always fails
# --- is as useless as one that never does.
mk_tree "$work/green" "# vmcell agents
Deploy at the repository root as \`AGENTS.md\`.
Current version: read it from Cargo.toml."
expect_pass "identical copies" "$work/green"

# --- Arm 1: a one-character divergence.
mk_tree "$work/onechar" "# vmcell agents
Deploy at the repository root as \`AGENTS.md\`."
# shellcheck disable=SC2016  # the backticks are literal markdown in the fixture, not shell expansion
printf '# vmcell agents\nDeploy at the repository root as `AGENTS.md`!\n' > "$work/onechar/AGENTS.md"
expect_fail "one-character divergence" "$work/onechar"

# --- Arm 2: THE REAL SHAPE. The docs/81 campaign corrected AGENTS.md's stale facts and left the
# --- source document carrying the pre-campaign answers. This is the regression the gate is named
# --- for; if this arm ever stops reddening the gate has lost its reason to exist.
mk_tree "$work/realshape" "# vmcell agents
Current version: \`vmcell\` 0.13.
nextest invokes \`.vmcell-bin/release/vmcell-test-runner\`, which holds the three file capabilities."
{
  printf '# vmcell agents\n'
  printf 'Crate versions are not quoted here — read the version from the crate Cargo.toml.\n'
  # shellcheck disable=SC2016  # literal markdown backticks in the fixture, not shell expansion
  printf 'nextest invokes `.vmcell-bin/debug/vmcell-test-runner`, which carries BLESSED_FILE_CAPS (four).\n'
} > "$work/realshape/AGENTS.md"
expect_fail "deployed corrected, source left stale" "$work/realshape"

# --- Arm 3: no source document at all. A roster resolving to nothing must not print "ok" — the
# --- docs/81 M13 defect (`ban-legacy-terms.sh` reported scanning a file it never opened).
mkdir -p "$work/nosource/docs"
printf 'x\n' > "$work/nosource/AGENTS.md"
expect_fail "no source document under docs/" "$work/nosource"

# --- Arm 4: no deployed copy.
mkdir -p "$work/nodeployed/docs"
printf 'x\n' > "$work/nodeployed/docs/80-claude-agents-v7.md"
expect_fail "no AGENTS.md" "$work/nodeployed"

# --- Arm 5: reissue-proof discovery. The design doc went v31 -> v32 mid-campaign and broke two
# --- gates that had hardcoded its filename; this gate must survive the same move. The NEWEST doc is
# --- the one compared, so a matching `-v8` passes even with a stale `-v7` still on disk.
mk_tree "$work/reissue" "# vmcell agents v8" "81-claude-agents-v8.md"
printf '# vmcell agents v7 — superseded, still on disk\n' > "$work/reissue/docs/80-claude-agents-v7.md"
expect_pass "newest source document wins (v8 beside a stale v7)" "$work/reissue"

# --- Arm 5b: and the newest one is really the one compared — diverging it must redden even though
# --- the stale v7 is untouched.
printf '# vmcell agents v8 CHANGED\n' > "$work/reissue/AGENTS.md"
expect_fail "divergence against the NEWEST source, not the stale one" "$work/reissue"

if [[ "$fail" -ne 0 ]]; then
  echo "test-check-agents-md-sync: FAIL" >&2
  exit 1
fi
echo "test-check-agents-md-sync: ok (all arms driven, both directions)"
