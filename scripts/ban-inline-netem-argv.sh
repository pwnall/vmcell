#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the NETEM ARGV law: the words that make a
# `tc … netem …` invocation are composed in exactly one place,
# `vmcell::net::Impairment::netem_args`, and every other site builds an `Impairment` and hands it
# to `NetSegment::impair_member` (design §17, Segment refinements — "a typed netem/impairment
# API").
#
# Why this class needs a gate rather than a type: the law's output is a Vec<String> handed to a
# SUBPROCESS, so a second, divergent copy is not a compile error anywhere. The tree already had
# one — `crates/vmcell/tests/segment.rs` spelled its own `["qdisc", "add", "dev", tap, "root",
# "netem", "delay", "50ms"]` twice, each with its own units and its own add-vs-replace choice,
# which is exactly how "the shipped mechanism is stable names + the harness's own tc" (§17) turns
# into two harnesses that impair links differently.
#
# THE FLAGGED SHAPE is the Rust string literal `"netem"` — the qdisc kind, which any second
# composer must name to reach netem at all. Line comments are stripped before matching, so a `///`
# doc comment or a rationale note writing the word is never a false positive; prose inside a
# non-comment string (`"adding netem delay on {tap} failed"`) does not match either, because the
# pattern requires the quotes to bracket the word exactly.
#
# THE SANCTIONED HOME below is matched by path suffix and permits an EXACT number of matches, so a
# second composer added *inside* the home is still flagged, and a home that lost its composers is
# reported as a stale exemption rather than a silent blind spot. Its three sanctioned occurrences
# are: the `impair_member` argv, the `clear_impairment` postcondition read (`… .contains("netem")`),
# and the unit test that runs the composed argv past the installed iproute2 parser.
#
# Usage: ban-inline-netem-argv.sh [DIR ...]   (defaults to the workspace member trees under crates/)
# A roster that resolves to zero Rust sources is a caller bug and exits 1 — never a reassuring "ok"
# (docs/90 G4).
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source (lib + bins + tests + benches) lives under crates/.
  dirs=(crates)
fi

sanctioned_suffix="/vmcell/src/net/segment.rs"
sanctioned_count=3

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources
# is to have been pointed at the wrong place (a move/reorg, or an explicit-path typo).
if [[ ${#files[@]} -eq 0 ]]; then
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
fi

scan() { # scan <file> <awk-regex>
  awk -v FN="$1" -v PAT="$2" '
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose is not code)
      if (code ~ PAT) { print FN ":" FNR ": " $0 }
    }
  ' "$1"
}
count() {
  if [[ -z "${1//[$'\n']/}" ]]; then echo 0; else printf '%s\n' "$1" | grep -c ''; fi
}

netem_re='"netem"'
home_seen=0
home_count=0
home_hits=""
violations=""

for f in "${files[@]}"; do
  hits="$(scan "$f" "$netem_re")"
  if [[ "$f" == *"$sanctioned_suffix" ]]; then
    home_seen=1
    home_count="$(count "$hits")"
    home_hits="$hits"
    continue
  fi
  [[ -n "${hits//[$'\n']/}" ]] && violations+="$hits"$'\n'
done

if [[ $home_seen -eq 0 ]]; then
  echo "gate misconfigured: the sanctioned home $sanctioned_suffix was not found under: ${dirs[*]}"
  echo "The netem argv law moved or the file was renamed — update the roster in"
  echo "scripts/ban-inline-netem-argv.sh. An exemption that matches nothing is a retired gate, not"
  echo "a pass."
  exit 1
fi

failed=0
if [[ "$home_count" -ne "$sanctioned_count" ]]; then
  echo "The sanctioned home $sanctioned_suffix holds $home_count netem spelling(s)"
  echo "(expected $sanctioned_count). One ADDED here is a second copy wearing the home's exemption; one GONE"
  echo "means the law moved and this gate is now blind. Fix the code, or update the count in"
  echo "scripts/ban-inline-netem-argv.sh deliberately — never delete the scan."
  printf '%s' "${home_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A second spelling of the netem argv law — build a \`vmcell::net::Impairment\` and apply it"
  echo "with \`NetSegment::impair_member\` (or compose the words with \`Impairment::netem_args\` if"
  echo "you must drive \`tc\` yourself) instead of hand-writing the argv (AGENTS.md \"One law, one"
  echo "predicate\"; design §17, Segment refinements). A hand-written copy drifts in units, in"
  echo "add-vs-replace, and in what it validates — and none of that is a compile error:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the netem argv law is composed only in $sanctioned_suffix"
echo "($sanctioned_count sanctioned spellings); every other site goes through"
echo "Impairment / NetSegment::impair_member (scanned: ${dirs[*]})"
