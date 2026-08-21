#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-orphan-recipe.sh (AGENTS.md rule 2: a gate whose
# self-test cannot fail is theater). It drives the REAL gate against throwaway fixture repos —
# a justfile plus a .github/workflows tree — so every arm is exercised against the same `just`
# the gate reads through, not against a mock of it:
#
#   * a recipe nothing invokes and nothing exempts             → ARM 1 reddens;
#   * a roster entry whose recipe HAS acquired a caller        → ARM 2 reddens;
#   * a roster entry naming a recipe that does not exist       → ARM 3 reddens;
#   * a justfile with no recipes at all, and a missing one     → ARM 4 reddens (never a green ok:).
#
# The must-stay-clean fixtures are what make the red ones mean anything: a recipe called by
# ANOTHER RECIPE, one called only by a workflow, and one called through the interpolated
# `{{just_executable()}}` spelling a recursive recipe is required to use — each must pass.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-orphan-recipe.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fails=0
pass() { printf '  ok  %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }

# expect_green <label> <repo>
expect_green() {
  if bash "$ban" "$2" >/dev/null 2>&1; then pass "$1"; else
    bad "$1 — expected the gate to PASS; it failed:"; bash "$ban" "$2" 2>&1 | awk '{ print "      " $0 }'
  fi
}
# expect_red <label> <repo> <needle>
expect_red() {
  local out
  if out="$(bash "$ban" "$2" 2>&1)"; then
    bad "$1 — expected the gate to FAIL; it passed:"; awk '{ print "      " $0 }' <<<"$out"
  elif ! grep -qi -- "$3" <<<"$out"; then
    bad "$1 — failed, but not for the asserted reason (no /$3/):"; awk '{ print "      " $0 }' <<<"$out"
  else
    pass "$1"
  fi
}

# A fixture repo carrying a COPY of the gate whose roster we can edit per-case. The gate reads its
# roster out of its own text, so an arm about the roster has to vary that text — the copy is the
# only way to vary it without mutating the shipped script.
mk_repo() { # mk_repo <dir> <justfile-body> <workflow-body|-> <roster-entries...>
  local dir="$1" jf="$2" wf="$3"; shift 3
  mkdir -p "$dir/scripts" "$dir/.github/workflows"
  printf '%s\n' "$jf" > "$dir/justfile"
  [[ "$wf" != "-" ]] && printf '%s\n' "$wf" > "$dir/.github/workflows/ci.yml"
  # Rewrite the shipped gate's roster array with this fixture's entries.
  awk -v entries="$*" '
    /^roster=\(/ { print "roster=("; n = split(entries, a, " "); for (i = 1; i <= n; i++) print "  " a[i]; print ")"; skip = 1; next }
    skip && /^\)$/ { skip = 0; next }
    skip { next }
    { print }
  ' "$ban" > "$dir/scripts/ban-orphan-recipe.sh"
  chmod +x "$dir/scripts/ban-orphan-recipe.sh"
}
# run the FIXTURE's copy (its roster differs), against the fixture repo
fixture_gate() { bash "$1/scripts/ban-orphan-recipe.sh" "$1"; }
expect_fixture_green() {
  if fixture_gate "$2" >/dev/null 2>&1; then pass "$1"; else
    bad "$1 — expected PASS; got:"; fixture_gate "$2" 2>&1 | awk '{ print "      " $0 }'
  fi
}
expect_fixture_red() {
  local out
  if out="$(fixture_gate "$2" 2>&1)"; then
    bad "$1 — expected FAIL; it passed:"; awk '{ print "      " $0 }' <<<"$out"
  elif ! grep -qi -- "$3" <<<"$out"; then
    bad "$1 — failed for the wrong reason (no /$3/):"; awk '{ print "      " $0 }' <<<"$out"
  else
    pass "$1"
  fi
}

CLEAN_JF='gates:
    echo gate

inner:
    echo inner

outer:
    just inner

recursive:
    {{just_executable()}} gates

only-ci:
    echo built-in-ci
'
CLEAN_WF='jobs:
  a:
    steps:
      - run: just outer
      - run: just recursive
      - run: just only-ci
'

echo "== must stay green =="
# `gates`, `inner` and `only-ci` all have callers; `outer`/`recursive` are called by the workflow.
mk_repo "$work/clean" "$CLEAN_JF" "$CLEAN_WF"
expect_fixture_green "a recipe called by another recipe, by a workflow, and via {{just_executable()}}" "$work/clean"

# The SHIPPED gate against the SHIPPED repo: the roster in the script under test must actually
# describe this repo. Without this leg every arm below could pass while the real roster rotted.
expect_green "the shipped roster describes the shipped justfile" "$(cd "$here/.." && pwd)"

echo "== ARM 1: an orphan recipe =="
mk_repo "$work/orphan" "$CLEAN_JF"'
stranded:
    echo nobody calls me
' "$CLEAN_WF"
expect_fixture_red "a recipe with no caller and no roster entry" "$work/orphan" "orphan recipe"

echo "== ARM 1 (inverse control): the same orphan, rostered =="
mk_repo "$work/orphan-ok" "$CLEAN_JF"'
stranded:
    echo nobody calls me
' "$CLEAN_WF" stranded
expect_fixture_green "…passes once it is on the roster with a reason" "$work/orphan-ok"

echo "== ARM 2: a stale roster entry (the recipe acquired a caller) =="
# `inner` IS called by `outer`, so exempting it is describing a hole that closed.
mk_repo "$work/stale" "$CLEAN_JF" "$CLEAN_WF" inner
expect_fixture_red "a rostered recipe that now has a caller" "$work/stale" "stale roster entry"

echo "== ARM 3: a ghost roster entry =="
mk_repo "$work/ghost" "$CLEAN_JF" "$CLEAN_WF" test-deleted-long-ago
expect_fixture_red "a roster entry naming no existing recipe" "$work/ghost" "ghost roster entry"

echo "== ARM 4: non-vacuity =="
mkdir -p "$work/empty"
printf '# a justfile with only comments and no recipes\n' > "$work/empty/justfile"
expect_red "a justfile with zero recipes is 'gate misconfigured', not ok" "$work/empty" "gate misconfigured"
mkdir -p "$work/nojustfile"
expect_red "a tree with no justfile at all is 'gate misconfigured', not ok" "$work/nojustfile" "gate misconfigured"

echo "== the workflow half is load-bearing =="
# Same justfile, workflows REMOVED: the three recipes the workflow was the only caller of must now
# be reported. This is what proves the gate reads the workflows at all rather than only the bodies.
mk_repo "$work/nowf" "$CLEAN_JF" -
expect_fixture_red "dropping the workflows exposes the recipes only CI called" "$work/nowf" "orphan recipe"

echo
if (( fails )); then
  echo "test-ban-orphan-recipe.sh: $fails leg(s) FAILED"
  exit 1
fi
echo "test-ban-orphan-recipe.sh: all legs pass — every arm of ban-orphan-recipe.sh can go red"
