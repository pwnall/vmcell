#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-ci-script-handcopy.sh (AGENTS rule 3, the hand-copied-CI-
# step class). Builds fixture roots — a workflow file, a justfile carrying a `gates` recipe, and a
# scripts/ directory — and drives BOTH arms of every half of the scanner:
#   * a direct `scripts/*.sh` invocation in the workflow is flagged, with its line number …
#   * … while the same path inside a COMMENT, and the allowlisted `with-delegated-scope.sh` wrapper,
#     are the positive controls that must stay clean;
#   * a workflow that stops invoking `just gates` is flagged (without that call every other arm is
#     vacuous — a roster nothing runs is not a gate);
#   * a gate-shaped script on disk that the recipe never runs is flagged (the ORPHAN: exactly the
#     `ban-readiness-timeout-literal.sh` / `ban-test-support-in-production.sh` defect, one step
#     earlier, before ci.yml even enters the picture);
#   * a recipe entry with no file, and one that exists but is not executable, are flagged;
#   * an allowlist entry the workflow no longer uses is a STALE exemption, not a pass;
#   * a recipe that invokes nothing at all is a misconfiguration, not an "ok" — the way every
#     list-driven gate dies.
# Deleting any one of those checks from the scanner turns the matching case below green, which is
# what makes this a red-on-inverse test rather than a smoke test.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-ci-script-handcopy.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline every fixture starts from: four gate-shaped scripts, a `gates` recipe naming
# exactly those four, and a workflow that invokes the recipe — plus the two spellings that must
# never be flagged (a script named inside a comment, and the delegated-scope wrapper).
mk_clean_tree() {
  local root="$1"
  mkdir -p "$root/.github/workflows" "$root/scripts"

  for s in ban-foo test-ban-foo check-bar test-check-bar; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$root/scripts/$s.sh"
    chmod +x "$root/scripts/$s.sh"
  done
  # Not gate-shaped (no ban-/check-/test- prefix), so it is NOT part of the roster and its absence
  # from the recipe must not be reported as an orphan.
  printf '#!/usr/bin/env bash\nexec "$@"\n' > "$root/scripts/with-delegated-scope.sh"
  chmod +x "$root/scripts/with-delegated-scope.sh"

  cat > "$root/justfile" <<'JUSTFILE'
# The one gate roster.
gates:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/ban-foo.sh
    ./scripts/test-ban-foo.sh
    ./scripts/check-bar.sh
    ./scripts/test-check-bar.sh

ci:
    just gates
JUSTFILE

  cat > "$root/.github/workflows/ci.yml" <<'WORKFLOW'
name: ci
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      # The roster lives in ONE recipe; this file must NOT restate ./scripts/ban-foo.sh here.
      - name: repo gates
        run: just gates
  test-integration:
    runs-on: ubuntu-24.04
    steps:
      # The exempt wrapper: the delegated cgroup scope must be entered around the recipe, so it
      # cannot live inside it.
      - name: unprivileged suite
        run: systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-unprivileged
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
expect_rc 0 "well-formed single-roster tree"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: a hand-copied script invocation in the workflow MUST be flagged ----------------------
# The exact defect: ci.yml restating the roster instead of invoking the recipe. Both a script the
# recipe already runs and a brand-new one are the same violation.
mk_clean_tree "$work/handcopy"
cat >> "$work/handcopy/.github/workflows/ci.yml" <<'WORKFLOW'
      - name: bans (hand-copied — the defect)
        run: |
          ./scripts/ban-foo.sh
          ./scripts/ban-newly-added.sh
WORKFLOW
run_ban "$work/handcopy"
before=$fail
expect_rc 1 "hand-copied script invocations in the workflow"
expect_flag './scripts/ban-foo.sh'
expect_flag './scripts/ban-newly-added.sh'
expect_flag 'ci.yml:'                      # the report names file:line, not just the token
expect_flag 'instead of going through a'   # …and says what to do instead
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: the exempt wrapper and a commented-out path stay CLEAN -------------------------------
# Without this the ban could be "passing" by flagging everything, and the allowlist would be untested.
mk_clean_tree "$work/exempt"
cat >> "$work/exempt/.github/workflows/ci.yml" <<'WORKFLOW'
      - name: privileged suite
        run: systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged
      - name: downstream example (live)
        # historical note: this used to call ../../scripts/check-vendored-vhost.sh directly
        run: cd examples/downstream-kernel && ../../scripts/with-delegated-scope.sh cargo run -- live
WORKFLOW
run_ban "$work/exempt"
before=$fail
expect_rc 0 "exempt wrapper + commented path"
expect_clean 'with-delegated-scope.sh:'          # never reported as a violation line
expect_clean 'check-vendored-vhost.sh'           # a path inside a comment is prose, not a call
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a workflow that never invokes the recipe MUST be flagged -----------------------------
# This is the arm that keeps the whole structure honest: the roster is only a gate if CI runs it.
mk_clean_tree "$work/unwired"
grep -v 'run: just gates' "$work/unwired/.github/workflows/ci.yml" > "$work/unwired/ci.tmp"
mv "$work/unwired/ci.tmp" "$work/unwired/.github/workflows/ci.yml"
run_ban "$work/unwired"
before=$fail
expect_rc 1 "workflow no longer invokes the recipe"
expect_flag 'never invokes'
expect_flag 'just gates'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a gate-shaped script the recipe never runs is an ORPHAN ------------------------------
# The campaign's actual defect, one step earlier: a ban lands in scripts/ and is wired nowhere.
mk_clean_tree "$work/orphan"
printf '#!/usr/bin/env bash\nexit 0\n' > "$work/orphan/scripts/ban-readiness-timeout-literal.sh"
chmod +x "$work/orphan/scripts/ban-readiness-timeout-literal.sh"
run_ban "$work/orphan"
before=$fail
expect_rc 1 "gate-shaped script absent from the recipe"
expect_flag 'scripts/ban-readiness-timeout-literal.sh'
expect_flag 'gates nothing'
# The non-gate-shaped wrapper is legitimately absent from the roster and must not be reported.
expect_clean 'scripts/with-delegated-scope.sh'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a recipe entry with no file behind it is a stale roster line -------------------------
mk_clean_tree "$work/stale-entry"
rm "$work/stale-entry/scripts/check-bar.sh"
run_ban "$work/stale-entry"
before=$fail
expect_rc 1 "recipe names a script that does not exist"
expect_flag 'no such file'
expect_flag 'scripts/check-bar.sh'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: a rostered script committed without its mode bit -------------------------------------
mk_clean_tree "$work/nonexec"
chmod -x "$work/nonexec/scripts/test-ban-foo.sh"
run_ban "$work/nonexec"
before=$fail
expect_rc 1 "recipe names a non-executable script"
expect_flag 'not executable'
expect_flag 'scripts/test-ban-foo.sh'
[[ $fail -ne $before ]] && dump "case 7"

# --- Case 8: an exemption the workflow no longer uses is STALE, not a pass ------------------------
mk_clean_tree "$work/stale-exempt"
grep -v 'with-delegated-scope.sh' "$work/stale-exempt/.github/workflows/ci.yml" > "$work/stale-exempt/ci.tmp"
mv "$work/stale-exempt/ci.tmp" "$work/stale-exempt/.github/workflows/ci.yml"
run_ban "$work/stale-exempt"
before=$fail
expect_rc 1 "allowlisted wrapper no longer used by the workflow"
expect_flag 'exempted from the hand-copy ban'
expect_flag 'with-delegated-scope.sh'
[[ $fail -ne $before ]] && dump "case 8"

# --- Case 9: an empty roster is a misconfiguration, never an "ok" ---------------------------------
mk_clean_tree "$work/vacuous"
cat > "$work/vacuous/justfile" <<'JUSTFILE'
gates:
    #!/usr/bin/env bash
    echo "nothing to see here"
JUSTFILE
run_ban "$work/vacuous"
before=$fail
expect_rc 1 "recipe invokes no scripts at all"
expect_flag 'invokes no'
[[ $fail -ne $before ]] && dump "case 9"

# --- Case 10: no `gates` recipe at all --------------------------------------------------------
mk_clean_tree "$work/norecipe"
cat > "$work/norecipe/justfile" <<'JUSTFILE'
ci:
    echo hi
JUSTFILE
run_ban "$work/norecipe"
before=$fail
expect_rc 1 "justfile has no gates recipe"
# shellcheck disable=SC2016  # the backticks are literal text in the scanner's message, not a subshell (intended)
expect_flag 'has no `gates` recipe'
[[ $fail -ne $before ]] && dump "case 10"

if [[ $fail -ne 0 ]]; then
  echo "ban-ci-script-handcopy self-test FAILED"
  exit 1
fi
echo "ok: ban-ci-script-handcopy self-test passed"
