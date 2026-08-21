#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/with-delegated-scope.sh (AGENTS.md rule 2).
#
# WHY THIS ONE MATTERS MORE THAN ITS SIZE SUGGESTS. That wrapper is the SOLE entry of
# `scripts/ban-ci-script-handcopy.sh`'s exemption allowlist — the one script ci.yml is allowed to
# name directly — and every live suite in this repo runs *through* it (`test-daemon` wraps itself
# in it; every other live recipe is wrapped at the call site, the way ci.yml invokes them). It had
# no can-it-fail proof of any kind. It also has FOUR warn-and-continue arms on which
# `set -euo pipefail` is inert, each being `if !`-guarded, so a silent regression there degrades
# every cgroup leg in the tree to "ran without delegation" without reddening anything.
#
# HOW THE ARMS ARE REACHED WITHOUT ROOT AND WITHOUT A REAL DELEGATED SCOPE. `bwrap --dev-bind / /
# --bind <fixture> /sys/fs/cgroup` puts a fabricated cgroup tree where the wrapper looks, while
# `/proc/self/cgroup` keeps reporting this process's REAL relative path (bwrap does not unshare
# the cgroup namespace) — so the wrapper computes exactly the `cg_base` it would in production and
# meets whatever that fixture placed there. That is the same "the runner's exact shape, not a
# mocked one" discipline `just test-unit-undelegated` uses one file over.
#
# THE LEGS:
#   * the wrapped command runs, its argv arrives intact, and its exit status propagates;
#   * cgroup base absent                       → WARN, and the command STILL runs;
#   * a controller missing from cgroup.controllers → WARN naming it, command still runs;
#   * subtree_control unwritable               → WARN naming the controller, command still runs;
#   * the supervisor leaf unjoinable           → WARN, command still runs;
#   * the supervisor leaf uncreatable          → WARN, command still runs.
# and, red-on-inverse, against MUTATED COPIES of the wrapper:
#   * delete `exec "$@"`                       → the command never runs      → this test reddens;
#   * unguard the subtree_control write        → `set -e` aborts before exec → reddens;
#   * unguard the supervisor mkdir             → same                        → reddens.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wrapper="$here/with-delegated-scope.sh"
work="$(mktemp -d)"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

command -v bwrap >/dev/null || {
  echo "gate misconfigured: bwrap (bubblewrap) is required to fabricate the cgroup tree this"
  echo "self-test drives the wrapper against. Without it every leg below would silently assert"
  echo "nothing — which is the vacuous-pass shape this repo treats as red, not as a skip."
  exit 1
}

fails=0
pass() { printf '  ok  %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }

# The REAL relative cgroup path this process reports — the wrapper will compute `cg_base` from it,
# so a fixture that wants to be FOUND must materialize exactly this path under its own root.
cg_rel="$(awk -F: '/^0::/{print $3}' /proc/self/cgroup)"
[[ -n "$cg_rel" ]] || {
  echo "gate misconfigured: /proc/self/cgroup reports no unified (0::) entry, so the wrapper's own"
  echo "cg_base computation has no input here and none of the fixtures below could be placed."
  exit 1
}

# run_case <fixture-root> <script> <args...> -> prints "<status>|<stdout>|<stderr>"
run_case() {
  local root="$1" script="$2"; shift 2
  local out err status
  out="$work/.out"; err="$work/.err"
  set +e
  bwrap --dev-bind / / --bind "$root" /sys/fs/cgroup -- "$script" "$@" >"$out" 2>"$err"
  status=$?
  set -e
  printf '%s|%s|%s' "$status" "$(cat "$out")" "$(cat "$err")"
}

# A fixture whose cgroup base EXISTS, with the controller list and permissions the case wants.
mk_tree() { # mk_tree <root> <controllers> <subtree_mode> [presupervisor_mode]
  local root="$1" controllers="$2" subtree_mode="$3" sup_mode="${4:-}"
  local base="$root$cg_rel"
  mkdir -p "$base"
  printf '%s\n' "$controllers" > "$base/cgroup.controllers"
  : > "$base/cgroup.subtree_control"
  chmod "$subtree_mode" "$base/cgroup.subtree_control"
  if [[ -n "$sup_mode" ]]; then
    mkdir -p "$base/supervisor"
    : > "$base/supervisor/cgroup.procs"
    chmod "$sup_mode" "$base/supervisor/cgroup.procs"
  fi
}

# A mutated copy of the wrapper, for the red-on-inverse legs.
mutate() { # mutate <name> <python-replacement-expr...>  -> path to the copy
  local name="$1"; shift
  local dst="$work/$name.sh"
  python3 - "$wrapper" "$dst" "$@" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
for i in range(3, len(sys.argv), 2):
    old, new = sys.argv[i], sys.argv[i + 1]
    assert s.count(old) == 1, f"mutation anchor not unique/found: {old!r}"
    s = s.replace(old, new)
open(dst, "w").write(s)
PY
  chmod +x "$dst"
  printf '%s' "$dst"
}

echo "== the load-bearing contract: the wrapper runs its command =="
mkdir -p "$work/absent"
# shellcheck disable=SC2016  # the single quotes are deliberate: `$0`/`$@` must reach the inner sh
r="$(run_case "$work/absent" "$wrapper" /bin/sh -c 'printf "ARGV[%s]" "$0" "$@"; exit 7' aa bb)"
status="${r%%|*}"; rest="${r#*|}"; stdout="${rest%%|*}"; stderr="${rest#*|}"
if [[ "$status" == 7 ]]; then
  pass "the wrapped command's exit status propagates (7)"
else
  bad "exit status was '$status', expected 7 — the trailing exec is the wrapper's whole job"
fi
# `sh -c <script> aa bb` binds $0=aa and $@=bb, so both trailing words arriving is exactly what
# proves the wrapper forwarded its argv rather than swallowing or re-quoting it.
if [[ "$stdout" == 'ARGV[aa]ARGV[bb]' ]]; then
  pass "argv arrives intact"
else
  bad "argv was '$stdout', expected ARGV[aa]ARGV[bb]"
fi

echo "== arm: cgroup base absent =="
if grep -q "cgroup base .* not found" <<<"$stderr"; then
  pass "WARNs that the base is missing"
else
  bad "no 'cgroup base … not found' WARN in: $stderr"
fi

echo "== arm: a controller is not available in this scope =="
mk_tree "$work/nocontroller" "memory cpu" 0644
r="$(run_case "$work/nocontroller" "$wrapper" /bin/true)"
status="${r%%|*}"; stderr="${r##*|}"
if [[ "$status" == 0 ]]; then pass "…and the command still runs"; else bad "status '$status', expected 0"; fi
if grep -q "controller 'pids' not available" <<<"$stderr" &&
   grep -q "controller 'io' not available" <<<"$stderr"; then
  pass "WARNs by name for each absent controller"
else
  bad "missing per-controller WARNs in: $stderr"
fi

echo "== arm: subtree_control is unwritable =="
mk_tree "$work/rosubtree" "memory cpu pids io" 0444
r="$(run_case "$work/rosubtree" "$wrapper" /bin/true)"
status="${r%%|*}"; stderr="${r##*|}"
if [[ "$status" == 0 ]]; then pass "…and the command still runs"; else bad "status '$status', expected 0"; fi
if grep -q "could not delegate controller 'memory'" <<<"$stderr"; then
  pass "WARNs naming the controller it could not delegate"
else
  bad "no delegation WARN in: $stderr"
fi

echo "== arm: the supervisor leaf cannot be joined =="
mk_tree "$work/nojoin" "memory cpu pids io" 0644 0444
r="$(run_case "$work/nojoin" "$wrapper" /bin/true)"
status="${r%%|*}"; stderr="${r##*|}"
if [[ "$status" == 0 ]]; then pass "…and the command still runs"; else bad "status '$status', expected 0"; fi
if grep -q "could not move into supervisor leaf" <<<"$stderr"; then
  pass "WARNs that it could not move into the leaf"
else
  bad "no supervisor-leaf WARN in: $stderr"
fi

echo "== arm: the supervisor leaf cannot be created =="
mk_tree "$work/nomkdir" "memory cpu pids io" 0644
chmod 0555 "$work/nomkdir$cg_rel"
r="$(run_case "$work/nomkdir" "$wrapper" /bin/true)"
chmod 0755 "$work/nomkdir$cg_rel"
status="${r%%|*}"; stderr="${r##*|}"
if [[ "$status" == 0 ]]; then
  pass "…and the command still runs"
else
  bad "status '$status', expected 0 — an uncreatable leaf must degrade like its four sibling arms"
fi
if grep -q "could not create supervisor leaf" <<<"$stderr"; then
  pass "WARNs that it could not create the leaf"
else
  bad "no supervisor-mkdir WARN in: $stderr"
fi

echo "== RED ON THE INVERSE =="
noexec="$(mutate noexec 'exec "$@"' 'true')"
r="$(run_case "$work/absent" "$noexec" /bin/sh -c 'exit 7')"
if [[ "${r%%|*}" != 7 ]]; then
  pass "deleting the wrapper's trailing exec breaks the exit-status leg"
else
  bad "removing the exec did NOT change the outcome — the leg proves nothing"
fi

# shellcheck disable=SC2016  # these are literal SOURCE FRAGMENTS of the wrapper, not expansions
unguarded="$(mutate unguarded \
  '      if ! echo "+$c" >"$cg_base/cgroup.subtree_control" 2>/dev/null; then
        echo "with-delegated-scope: WARN could not delegate controller '"'"'$c'"'"'" >&2
      fi' \
  '      echo "+$c" >"$cg_base/cgroup.subtree_control"')"
r="$(run_case "$work/rosubtree" "$unguarded" /bin/true)"
if [[ "${r%%|*}" != 0 ]]; then
  pass "unguarding the subtree_control write makes set -e abort before exec"
else
  bad "unguarding it changed nothing — the guard is not what keeps that arm non-fatal"
fi

# shellcheck disable=SC2016  # literal source fragments again, for the same reason
unguarded_mkdir="$(mutate unguarded-mkdir \
  '  if ! mkdir -p "$cg_base/supervisor" 2>/dev/null; then
    echo "with-delegated-scope: WARN could not create supervisor leaf ($cg_base/supervisor)" >&2
  fi' \
  '  mkdir -p "$cg_base/supervisor"')"
chmod 0555 "$work/nomkdir$cg_rel"
r="$(run_case "$work/nomkdir" "$unguarded_mkdir" /bin/true)"
chmod 0755 "$work/nomkdir$cg_rel"
if [[ "${r%%|*}" != 0 ]]; then
  pass "unguarding the supervisor mkdir makes set -e abort before exec"
else
  bad "unguarding the mkdir changed nothing — that arm's guard proves nothing"
fi

echo
if (( fails )); then
  echo "test-with-delegated-scope.sh: $fails leg(s) FAILED"
  exit 1
fi
echo "test-with-delegated-scope.sh: all legs pass — every arm of with-delegated-scope.sh can go red"
