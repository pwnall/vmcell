#!/usr/bin/env bash
# The README quotes no benchmark figure — it points at what produces one (AGENTS.md, "Docs and
# dependencies": "Prefer a **pointer** to the recipe that produces a number over an embedded figure
# that goes stale silently").
#
# WHY THIS EXISTS. The README carried an embedded crosvm pass/total that had gone stale by the time
# anyone read it; the docs/90 pass deleted it and wrote a pointer at the recipe instead ("run the
# recipe, which **is** the number's source"). Nothing gated the class, so the next paste of a p50, a
# throughput or a boot time into the front-door document would land exactly the same way — and a
# stale figure is worse than no figure, because a reader has no way to tell which one they are
# looking at. Two documents own measured numbers and both state their own substrate and method:
# `docs/benchmark-results.md` (canonical) and the design's Performance section. The README is not one
# of them.
#
# THE LAW, in two arms, because "is this number a benchmark figure?" has two different answers
# depending on where in the README it sits:
#
#   ARM 1 — ANYWHERE IN THE README, no number may carry a PERFORMANCE unit: a time in ns/µs/ms (or a
#   fractional second), a throughput rate, or a percentile with a value bound to it (`p95 = 322`).
#   Those units have no legitimate non-benchmark use in this document, which is what makes the arm
#   precise enough to run over ordinary prose: a pinned version (`v53.0`), a port, a file mode, a
#   memory size in a config example and a distro release all pass untouched, and each of them exists
#   in the README today.
#
#   ARM 2 — INSIDE THE BENCHMARK SECTION, the bar is stricter: any number bound to a unit at all —
#   a size, a share, a ratio, a plain count of seconds — is a figure, because in that section there
#   is nothing else for a measured quantity to be. This is what catches the shapes ARM 1 deliberately
#   allows elsewhere: an image size in MB, a dedup percentage, a "≈5× faster". A bare number
#   (a section reference, a percentile LABEL such as `p50/p95/p99`) is untouched — naming the shape
#   of a report is the point of that section.
#
# The section is FOUND, never hardcoded to a heading number: exactly one README heading must match
# /benchmark/i. Zero matches means the section this law is about is gone (or renamed past
# recognition) and ARM 2 would scan nothing; two means the law has no single home. Both are reported
# as a misconfiguration, so this gate also holds the section itself in place.
#
# NON-VACUITY, both directions (docs/90 G4). A clean README yields zero hits, so "found nothing"
# cannot be this gate's proof of life — a broken extractor looks identical. Instead each arm's
# pattern is run against a built-in CANARY line first and must match it; a missing or empty README,
# a missing/ambiguous benchmark heading, and an empty section body are all misconfigurations. And an
# `allow-benchmark-figure:` marker that no longer excuses a real hit is a widened blind spot, not a
# pass.
#
# THE ESCAPE HATCH, self-documenting rather than a roster (ban-dangling-design-ref.sh's shape):
# `allow-benchmark-figure: <reason>` on the SAME line, reason non-empty. It is for a number that
# wears a unit without being a measurement — a documented CLI flag value such as a `30s` timeout.
# It is NOT for a figure someone wants to keep.
#
# Usage: ban-benchmark-figure-in-readme.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

# Byte collation, so the `µ` in `µs` is matched as the two UTF-8 bytes it is regardless of the
# caller's locale, and `[[:space:]]`/`\b` mean the same thing everywhere.
export LC_ALL=C

root="${1:-}"
if [[ -z "$root" ]]; then
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
if [[ ! -d "$root" ]]; then
  echo "gate misconfigured: no such root directory: $root" >&2
  exit 1
fi
root="$(cd "$root" && pwd)"
readme="$root/README.md"
readme_rel="README.md"

if [[ ! -s "$readme" ]]; then
  echo "gate misconfigured: no non-empty $readme_rel under $root"
  echo "This gate's whole scope is that one file; with it absent the scan is vacuous."
  exit 1
fi

# --- The two arms' patterns ------------------------------------------------------------------------
# ARM 1: a time (ns/µs/ms, or a FRACTIONAL second — a whole-number `s` is left to ARM 2 because
# `5000s` is how the README's prose pluralizes a port), a throughput rate, or a percentile bound to
# a value.
arm1_re='[0-9]([.,][0-9]+)?[[:space:]]?(ns|µs|μs|ms)\b'
arm1_re+='|[0-9]+[.,][0-9]+[[:space:]]?s\b'
arm1_re+='|[0-9]([.,][0-9]+)?[[:space:]]?((Ki|Mi|Gi|Ti|k|K|M|G|T)?[Bb]/s|[kKMG]?bps|(req|ops|iops)/s)'
arm1_re+='|\bp(50|75|90|95|99|999)[[:space:]]*[=:][[:space:]]*[0-9]'
# ARM 2 adds: any second count, a byte size, a percentage, a ratio.
arm2_re="$arm1_re"
arm2_re+='|[0-9]([.,][0-9]+)?[[:space:]]?s\b'
arm2_re+='|[0-9]([.,][0-9]+)?[[:space:]]?((Ki|Mi|Gi|Ti)?B|[kKMGT]B)\b'
arm2_re+='|[0-9]([.,][0-9]+)?[[:space:]]?(%|×)'
arm2_re+='|[0-9]([.,][0-9]+)?[[:space:]]?x\b'

# CANARY, the proof of life a clean file cannot give (see NON-VACUITY above). Each arm must match its
# own canary and ARM 1 must NOT match ARM 2's extra shapes, or the two arms have collapsed into one
# and the "stricter inside the section" half is not being enforced.
arm1_canary='cold boot is 305 ms at p95 = 322'
arm2_canary='the rootfs is 79 MB'
if ! grep -qE "$arm1_re" <<<"$arm1_canary"; then
  echo "gate misconfigured: the ARM 1 pattern does not match its own canary line."
  echo "  canary: $arm1_canary"
  echo "A clean README yields zero hits, so a broken extractor is indistinguishable from a clean"
  echo "file — this canary is the only thing that tells them apart."
  exit 1
fi
if ! grep -qE "$arm2_re" <<<"$arm2_canary"; then
  echo "gate misconfigured: the ARM 2 pattern does not match its own canary line."
  echo "  canary: $arm2_canary"
  exit 1
fi
if grep -qE "$arm1_re" <<<"$arm2_canary"; then
  echo "gate misconfigured: ARM 1 matches ARM 2's canary, so the two arms have collapsed."
  echo "ARM 1 runs over the WHOLE README and must stay narrow (a size in a config example is"
  echo "legitimate prose); only the benchmark section gets the strict bar."
  exit 1
fi

# --- Find the benchmark section --------------------------------------------------------------------
mapfile -t heading_lines < <(grep -nE '^#{2,6}[[:space:]].*[Bb]enchmark' "$readme" | cut -d: -f1)
if [[ ${#heading_lines[@]} -eq 0 ]]; then
  echo "gate misconfigured: $readme_rel has no heading naming a benchmark."
  echo "That section IS this law's other half — it is where the README points a reader at"
  echo "\`scripts/perf-matrix.sh\`, \`just test-bench\` and docs/benchmark-results.md instead of"
  echo "quoting numbers. If it was renamed, update the heading match in"
  echo "scripts/ban-benchmark-figure-in-readme.sh; do not delete the scan."
  exit 1
fi
if [[ ${#heading_lines[@]} -gt 1 ]]; then
  echo "gate misconfigured: $readme_rel has ${#heading_lines[@]} headings naming a benchmark"
  echo "(lines: ${heading_lines[*]}), so the strict arm has no single home. Keep one section."
  exit 1
fi
sec_start="${heading_lines[0]}"
sec_level="$(sed -n "${sec_start}p" "$readme" | grep -oE '^#+' | tr -d '\n' | wc -c)"
# The section ends at the next heading of the same or a higher level, else at EOF.
sec_end="$(
  awk -v start="$sec_start" -v level="$sec_level" '
    NR > start && /^#+[[:space:]]/ {
      match($0, /^#+/)
      if (RLENGTH <= level) { print NR - 1; found = 1; exit }
    }
    END { if (!found) print NR }
  ' "$readme"
)"
if [[ -z "$sec_end" || "$sec_end" -le "$sec_start" ]]; then
  echo "gate misconfigured: the benchmark section at $readme_rel:$sec_start has an empty body."
  echo "ARM 2 would scan nothing while reporting ok."
  exit 1
fi

marker_re='allow-benchmark-figure:[[:space:]]*[^[:space:]]'
violations=""
marked_hits=0
marked_lines=0

while IFS=: read -r lineno rest; do
  [[ -z "$lineno" ]] && continue
  if grep -qE "$marker_re" <<<"$rest"; then
    marked_hits=$((marked_hits + 1))
    continue
  fi
  violations+="  $readme_rel:$lineno: [any-section] $rest"$'\n'
done < <(grep -nE "$arm1_re" "$readme" || true)

while IFS=: read -r lineno rest; do
  [[ -z "$lineno" ]] && continue
  (( lineno > sec_start && lineno <= sec_end )) || continue
  if grep -qE "$marker_re" <<<"$rest"; then
    marked_hits=$((marked_hits + 1))
    continue
  fi
  # A line ARM 1 already reported is one violation, not two.
  if grep -qE "$arm1_re" <<<"$rest"; then continue; fi
  violations+="  $readme_rel:$lineno: [benchmark-section] $rest"$'\n'
done < <(grep -nE "$arm2_re" "$readme" || true)

# Both directions: a marker must still excuse a real hit.
marked_lines="$(grep -cE "$marker_re" "$readme" || true)"
failed=0
if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "ban-benchmark-figure-in-readme: FAIL — $readme_rel quotes a measured figure."
  echo "  A number in the front-door document has no substrate and no method attached to it, and"
  echo "  nothing re-measures it: it is stale from the next optimization onward, and a reader cannot"
  echo "  tell. Point at what produces it instead — \`scripts/perf-matrix.sh\` (the matrix),"
  echo "  \`just test-bench\` (the wiring gate), docs/benchmark-results.md (canonical for every"
  echo "  number, with its own substrate) — the way the crosvm pass/total line was fixed:"
  printf '%s' "$violations"
  failed=1
fi
if [[ "$marked_lines" -gt 0 && "$marked_hits" -eq 0 ]]; then
  echo "gate misconfigured: $marked_lines line(s) carry an \`allow-benchmark-figure\` marker and none"
  echo "of them holds a figure any more. A marker excusing nothing is a widened blind spot — drop it."
  failed=1
fi
if [[ $failed -ne 0 ]]; then exit 1; fi

total_lines="$(wc -l <"$readme")"
echo "ok: $readme_rel quotes no benchmark figure"
echo "(scanned $total_lines line(s); the strict arm covers the benchmark section at lines"
echo "$sec_start-$sec_end; $marked_hits marked exemption(s), each still excusing a real hit)"
