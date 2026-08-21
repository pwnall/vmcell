#!/usr/bin/env bash
# Keeps every retry pause in the guest-tools binary on ONE pacing law (design §3.5, AGENTS.md
# "One law, one predicate" and "A gate binds the call sites, not just the extracted predicate").
#
# WHY THIS EXISTS. `mini-init` is PID 1 in the service-placement proof cell, and its restart loop
# had its pacing spelled twice and unevenly: the spawn-failure arm slept a literal
# `Duration::from_millis(200)` at the call site, and the exit arm — the one a supervised program
# that exits instantly actually takes — slept nothing at all. So `/bin/false` burned the whole
# rapid-failure cap in microseconds, giving no transient time to clear and writing a console line
# per iteration into a serial log the host persists as a per-VM artifact. The echo-server's accept
# loops had already learned this (`accept_error_pacing`); the restart loop had not.
#
# The fix put both arms on `mini_init_restart_after`, which returns the pause together with the
# strike count, computed by the binary's one `retry_backoff`. THE UNIT TESTS CANNOT SEE THE
# REGRESSION COMING BACK: `every_rapid_restart_is_paced_and_the_whole_burst_stays_inside_the_window`
# proves the predicate answers a pause, and stays green while a call site ignores that answer and
# sleeps a literal of its own again. That call-site half is this scan.
#
# THE LAW. In the guest-tools binary's production Rust text, no `thread::sleep(` may build its
# duration at the call site: the argument is a value a pacing predicate returned (`delay`, `pause`),
# never `Duration::from_…` and never a bare number. A new cadence gets a named const and a
# predicate, the way `MINI_INIT_RESTART_BACKOFF_BASE` and `ACCEPT_ERROR_BACKOFF_BASE` are.
#
# SCOPE, deliberately narrow. Only the guest-tools tree. `vmcell-steward` sleeps short literal
# polls in places that are not retry loops at all, and its accept loop is rate-limited by its own
# reason-keyed `recovery_backoff` (L-GUEST-4) rather than by an exponential curve; scanning it here
# would either flag legitimate code or force this gate to grow exceptions, which is how a scan
# stops meaning anything.
#
# What counts as production text, per the in-repo source-scan convention: `//` line comments
# stripped first (so prose naming a literal is never a false positive) and the file truncated at
# the first `#[cfg(test)]` (a unit test may sleep whatever keeps it fast).
#
# NON-VACUITY, both arms. The scan must SEE at least one `thread::sleep` AND find the delegate it
# defers to — `retry_backoff`, whose curve is proven by the unit tests named above. Zero sleeps
# means the pacing was deleted or the tree moved; a missing `retry_backoff` means the law lost its
# home. Either way this prints "gate misconfigured" and exits non-zero rather than a green "ok:"
# earned by opening nothing (docs/90 G4).
#
# Usage: ban-unpaced-guest-retry.sh [DIR ...]   (defaults to crates/vmcell-guest-tools)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates/vmcell-guest-tools)
fi

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources
# is to have been pointed at the wrong place (a move/reorg, or an explicit-path typo).
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

violations=""
sleeps_seen=0
delegate_seen=0

for f in "${files[@]}"; do
  result="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      if (index(code, "#[cfg(test)]") > 0) { nextfile }
      gsub(/^[ \t]+|[ \t]+$/, "", code)
      prod = prod " " code
    }
    END {
      # The delegate: the one backoff computation this scan defers to for the CURVE.
      if (prod ~ /fn retry_backoff\(/) print "DELEGATE\t1"
      n = 0
      rest = prod
      while ((at = index(rest, "sleep(")) > 0) {
        rest = substr(rest, at + length("sleep("))
        end = index(rest, ";")
        call = (end > 0) ? substr(rest, 1, end - 1) : rest
        n++
        # A duration built AT the call site: `Duration::from_millis(200)`, or a bare number.
        if (call ~ /Duration::/ || call ~ /(^|[^A-Za-z0-9_])[0-9]/) {
          print "LITERAL\t" FN "\tthread::sleep(" call
        }
      }
      if (n > 0) print "SLEEPS\t" n
    }
  ' "$f")"

  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      SLEEPS) sleeps_seen=$((sleeps_seen + a)) ;;
      DELEGATE) delegate_seen=1 ;;
      LITERAL) violations+="  $a: $b"$'\n' ;;
    esac
  done <<<"$result"
done

if [[ $sleeps_seen -eq 0 ]]; then
  echo "gate misconfigured: no \`thread::sleep\` in production text under: ${dirs[*]}"
  echo "Either the retry pacing was deleted — which is the very regression this gate exists for —"
  echo "or the scan is pointed at the wrong tree. A scan that matches nothing proves nothing."
  exit 1
fi

if [[ $delegate_seen -eq 0 ]]; then
  echo "gate misconfigured: this scan's delegate, \`fn retry_backoff(\`, is not under: ${dirs[*]}"
  echo "The curve itself is gated by the unit tests"
  echo "\`every_rapid_restart_is_paced_and_the_whole_burst_stays_inside_the_window\` and"
  echo "\`accept_error_pacing_bounds_both_the_retry_rate_and_the_log\`; this scan only holds the"
  echo "CALL SITES to it. If the law was renamed, update this script — do not delete the scan."
  exit 1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A guest retry pause is built at its call site instead of coming from the pacing law."
  echo "\`mini-init\` is PID 1: an unpaced restart is a hot spin that floods the persisted serial"
  echo "log, and a literal beside a predicate is the same law spelled twice (it already shipped —"
  echo "a 200 ms literal on one arm and no pause at all on the other). Take the pause from"
  echo "\`mini_init_restart_after\` / \`accept_error_pacing\`, or give the new cadence its own named"
  echo "const and predicate:"
  printf '%s' "$violations"
  exit 1
fi

echo "ok: all $sleeps_seen guest retry pause(s) in production text come from the pacing law"
echo "(delegate \`retry_backoff\` present; scanned: ${dirs[*]})"
