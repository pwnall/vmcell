#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-recipe-body-handcopy.sh (AGENTS rule 3, the copied-recipe-
# BODY half of the hand-copy class — the half `ban-ci-script-handcopy.sh` does not cover). Builds
# fixture roots (a justfile with an aggregate `ci` recipe + a workflow file) and drives both arms of
# every half:
#   * the aggregate recipe restating another recipe's body is flagged, naming the recipe and the
#     `{{just_executable()}} <recipe>` call that replaces it — the `just ci` / `test-unit` defect;
#   * the WORKFLOW restating a recipe's body is flagged, verbatim …
#   * … and also with the recipe's `{{ … }}` interpolations EXPANDED, which is what a real hand-copy
#     looks like (the M14 shape: ci.yml inlined test-unprivileged's nextest line and the copy then
#     dropped `--features qemu`, so a whole backend's matrix legs stopped compiling in CI);
#   * a recipe that merely SHARES boilerplate with the aggregate (`set -euo pipefail`) is the
#     positive control that must stay clean — the rule is whole-body containment, not line overlap;
#   * an interpolation-ONLY body, whose glob would otherwise match anything, must stay clean (the
#     "at least one line matched verbatim" condition);
#   * an aggregate that invokes no recipe, a workflow that invokes no recipe, a missing aggregate, an
#     empty aggregate body, and a one-recipe justfile are MISCONFIGURATIONS, not passes — the way
#     every containment gate dies quietly.
# Deleting any one of those checks from the scanner turns the matching case below green, which is
# what makes this a red-on-inverse test rather than a smoke test.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-recipe-body-handcopy.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline every fixture starts from: two unit recipes (one plain, one interpolating), an
# aggregate that CALLS both, and a workflow that CALLS them too.
mk_clean_tree() {
  local root="$1"
  mkdir -p "$root/.github/workflows"

  cat > "$root/justfile" <<'JUSTFILE'
skip := "/tmp/demo-skip.txt"

# A plain one-line unit recipe.
test-unit:
    cargo nextest run --locked --all-features

# An interpolating suite recipe, the shape every live suite has.
suite:
    SKIP="{{ skip }}" \
        cargo nextest run --locked -p demo --run-ignored all

# Shares boilerplate with the aggregate but nothing else: the positive control.
helper:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "helper-only-command"

ci:
    #!/usr/bin/env bash
    set -euo pipefail
    {{just_executable()}} test-unit
    {{just_executable()}} suite
    {{just_executable()}} helper
JUSTFILE

  cat > "$root/.github/workflows/ci.yml" <<'WORKFLOW'
name: ci
jobs:
  test-unit:
    runs-on: ubuntu-latest
    steps:
      - name: nextest
        run: just test-unit
  test-integration:
    runs-on: ubuntu-24.04
    steps:
      - name: suite
        run: just suite
WORKFLOW
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -qF "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -qF "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the well-formed tree MUST pass (the positive control) --------------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
before=$fail
expect_rc 0 "aggregate and workflow both invoke every recipe"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
# The shared `set -euo pipefail` line and the interpolation-only shapes must not be read as copies.
expect_clean 'recipe "helper"'
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: the aggregate recipe restating a recipe body MUST be flagged --------------------------
# The exact `just ci` / `test-unit` defect: the aggregate runs the recipe's command instead of the
# recipe, so the two can diverge with every gate green.
mk_clean_tree "$work/agg-copy"
sed -i 's|^    {{just_executable()}} test-unit$|    cargo nextest run --locked --all-features|' \
  "$work/agg-copy/justfile"
run_ban "$work/agg-copy"
before=$fail
expect_rc 1 "aggregate recipe restates test-unit's body"
expect_flag 'the whole body of recipe "test-unit" is restated'
expect_flag "recipe (justfile) instead of being invoked"
expect_flag '{{just_executable()}} test-unit'   # the report says what to write instead
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: the workflow restating a recipe body VERBATIM MUST be flagged -------------------------
mk_clean_tree "$work/wf-copy"
python3 - "$work/wf-copy/.github/workflows/ci.yml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("        run: just test-unit\n",
              "        run: cargo nextest run --locked --all-features\n", 1)
open(p, "w").write(s)
PY
run_ban "$work/wf-copy"
before=$fail
expect_rc 1 "workflow restates test-unit's body verbatim"
expect_flag 'the whole body of recipe "test-unit" is restated'
expect_flag ".github/workflows/ci.yml instead of being invoked"
expect_flag 'run: just test-unit'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: the workflow restating an INTERPOLATING recipe, expanded -----------------------------
# What a real hand-copy looks like — the M14 shape. Verbatim comparison alone cannot see this, so
# deleting the glob half of `match_line` turns this case green.
mk_clean_tree "$work/wf-expanded"
python3 - "$work/wf-expanded/.github/workflows/ci.yml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace(
    "        run: just suite\n",
    '        run: |\n'
    '          SKIP="/var/tmp/somewhere-else.txt" \\\n'
    "              cargo nextest run --locked -p demo --run-ignored all\n",
    1,
)
open(p, "w").write(s)
PY
run_ban "$work/wf-expanded"
before=$fail
expect_rc 1 "workflow restates the suite recipe with its interpolations expanded"
expect_flag 'the whole body of recipe "suite" is restated'
expect_flag 'run: just suite'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: shared boilerplate only is CLEAN -----------------------------------------------------
# The rule is WHOLE-body containment. A recipe sharing `set -euo pipefail` (and nothing else) with
# the aggregate must not be reported, or the gate would flag every shebang recipe in the tree and be
# switched off within a day.
mk_clean_tree "$work/partial"
python3 - "$work/partial/justfile" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
# The aggregate gains helper's boilerplate line a second time, but never its actual command.
s = s.replace("    {{just_executable()}} helper\n",
              "    set -euo pipefail\n    {{just_executable()}} helper\n", 1)
open(p, "w").write(s)
PY
run_ban "$work/partial"
before=$fail
expect_rc 0 "boilerplate overlap is not a restated body"
expect_clean 'recipe "helper"'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: an interpolation-ONLY body is CLEAN --------------------------------------------------
# Its glob is `*`, which matches any line in either haystack; without the "at least one line matched
# verbatim" condition the scanner would report a copy that does not exist. Removing that condition
# turns this case red, which is the point.
mk_clean_tree "$work/globonly"
cat >> "$work/globonly/justfile" <<'JUSTFILE'

# Body is a single BARE interpolation, so its glob is `*` — it matches every line in either
# haystack. Only the "matched verbatim" condition keeps that from reading as a copy.
solo:
    {{just_executable()}}
JUSTFILE
python3 - "$work/globonly/justfile" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("    {{just_executable()}} helper\n",
              "    {{just_executable()}} helper\n    {{just_executable()}} solo\n", 1)
open(p, "w").write(s)
PY
run_ban "$work/globonly"
before=$fail
expect_rc 0 "an interpolation-only body is not evidence of a copy"
expect_clean 'recipe "solo"'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: an aggregate that invokes no recipe is a MISCONFIGURATION ----------------------------
mk_clean_tree "$work/no-calls"
python3 - "$work/no-calls/justfile" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
head, sep, _ = s.partition("ci:\n")
open(p, "w").write(head + sep + '    #!/usr/bin/env bash\n    echo "aggregating nothing"\n')
PY
run_ban "$work/no-calls"
before=$fail
expect_rc 1 "aggregate invokes no recipe at all"
expect_flag 'invokes no other recipe'
[[ $fail -ne $before ]] && dump "case 7"

# --- Case 8: a workflow that invokes no recipe is a MISCONFIGURATION -----------------------------
mk_clean_tree "$work/wf-no-calls"
sed -i 's|^        run: just .*$|        run: echo "nothing"|' \
  "$work/wf-no-calls/.github/workflows/ci.yml"
run_ban "$work/wf-no-calls"
before=$fail
expect_rc 1 "workflow invokes no recipe at all"
expect_flag "with none, ARM 3 below is vacuous"
[[ $fail -ne $before ]] && dump "case 8"

# --- Case 9: no aggregate recipe at all ----------------------------------------------------------
mk_clean_tree "$work/no-agg"
cat > "$work/no-agg/justfile" <<'JUSTFILE'
test-unit:
    cargo nextest run --locked --all-features

other:
    echo other
JUSTFILE
run_ban "$work/no-agg"
before=$fail
expect_rc 1 "justfile has no aggregate recipe"
expect_flag "That recipe IS the local CI definition"
[[ $fail -ne $before ]] && dump "case 9"

# --- Case 10: an empty aggregate body ------------------------------------------------------------
mk_clean_tree "$work/empty-agg"
cat > "$work/empty-agg/justfile" <<'JUSTFILE'
test-unit:
    cargo nextest run --locked --all-features

ci:
JUSTFILE
run_ban "$work/empty-agg"
before=$fail
expect_rc 1 "aggregate recipe has an empty body"
expect_flag 'empty body'
[[ $fail -ne $before ]] && dump "case 10"

# --- Case 11: a single-recipe justfile is vacuous ------------------------------------------------
mk_clean_tree "$work/one-recipe"
cat > "$work/one-recipe/justfile" <<'JUSTFILE'
ci:
    echo "the only recipe"
JUSTFILE
run_ban "$work/one-recipe"
before=$fail
expect_rc 1 "fewer than two recipes"
expect_flag 'fewer than two recipes'
[[ $fail -ne $before ]] && dump "case 11"

if [[ $fail -ne 0 ]]; then
  echo "ban-recipe-body-handcopy self-test FAILED"
  exit 1
fi
echo "ok: ban-recipe-body-handcopy self-test passed"
