#!/usr/bin/env bash
# The ONE home for "which document is the current design, and what headings does it actually have".
#
# WHY IT IS A SEPARATE SCRIPT AND NOT A THIRD SPELLING. `scripts/check-docs-pointers.sh` resolves the
# `§`/`Appendix X` references in the ROOT MARKDOWN against the design document's real headings, and
# `scripts/ban-dangling-design-ref.sh` does the same for everything OUTSIDE the markdown — the crate
# sources and tests, every `Cargo.toml`, the justfile and the gate scripts. (docs/90 D2 was one of
# those: a `design §D` (allow-dangling-design-ref: quoted defect) in a document the daemon SERVES to
# clients.) That is one question asked by two gates, and the question is subtle enough to get wrong
# twice:
#
#   * THE DOCUMENT IS DISCOVERED, NEVER PINNED. The design went v31 → v32 → v33 and each move broke a
#     gate that had hardcoded the filename. `sort -V`, because the numeric prefixes sort wrong under a
#     plain `sort` (`9-` lands after `83-`).
#   * BYTE COLLATION IS LOAD-BEARING. Under a UTF-8 locale `sort -u` collates by locale rules, which
#     ignore punctuation for equality — so `1.1` and `11` compare EQUAL and `sort -u` keeps one of
#     them. That silently deleted seven top-level section ids (11–17, each shadowed by an `11.x`/`1.x`
#     sibling) from the heading roster on check-docs-pointers.sh's first run, turning valid references
#     into reported failures. `LC_ALL=C` is not a style preference here.
#
# This script is a HELPER, not a gate: it makes no claim about the tree and has no red-on-inverse
# self-test of its own. Its three misconfiguration arms are driven by
# `scripts/test-ban-dangling-design-ref.sh`, which points it at fixture roots that break each one.
# `check-docs-pointers.sh` still carries its own copy of this logic (it predates this file and is
# owned by another lane); collapsing it onto this script is the recorded follow-up — a caller change,
# not a behavior change, because the output below is exactly what its two `mapfile`s build.
#
# Usage: design-headings.sh [ROOT]        (defaults to the repo root above this script)
# Output: TSV on stdout, one record per line —
#   DESIGN    <path of the design document, relative to ROOT>
#   VERSION   <the version its filename declares, e.g. v33>
#   SECTION   <a numbered heading id, e.g. 12.4>
#   APPENDIX  <an appendix heading, normalised to single spaces, e.g. "Appendix A">
# A missing root, a missing design document, or a document with no numbered headings is a
# `gate misconfigured:` line on stderr and exit 1 — never an empty-but-successful roster, which is how
# every list-driven gate dies (docs/90 G4).
set -euo pipefail

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

# Discovered, never hardcoded — and the NEWEST wins, which is what `sort -V` is for.
design=""
while IFS= read -r candidate; do design="$candidate"; done < <(
  [[ -d "$root/docs" ]] && find "$root/docs" -maxdepth 1 -type f -name '*design-v*.md' | sort -V
)
if [[ -z "$design" ]]; then
  echo "gate misconfigured: no docs/*design-v*.md design document found under $root/docs" >&2
  echo "Every \`§\` reference is resolved against its headings; with no design document that check is" >&2
  echo "vacuous and would silently pass." >&2
  exit 1
fi

mapfile -t sections < <(
  grep -oE '^#{1,6}[[:space:]]+[0-9]+(\.[0-9]+)*' "$design" | sed -E 's/^#+[[:space:]]+//' | sort -u
)
if [[ ${#sections[@]} -eq 0 ]]; then
  echo "gate misconfigured: ${design#"$root"/} yields no numbered headings." >&2
  echo "Every reference would then be unresolvable (or, with the comparison inverted, every reference" >&2
  echo "would pass) — either way the check is not measuring the document." >&2
  exit 1
fi
# Appendices are NOT required to be non-empty: a design reissue may legitimately fold them away, and
# a reference to a gone appendix must then FAIL rather than turn the whole gate into a misconfiguration.
mapfile -t appendices < <(
  grep -oE '^#{1,6}[[:space:]]+Appendix[[:space:]]+[A-Z]' "$design" \
    | sed -E 's/^#+[[:space:]]+//; s/[[:space:]]+/ /g' | sort -u
)

printf 'DESIGN\t%s\n' "${design#"$root"/}"
printf 'VERSION\t%s\n' "$(sed -E 's/.*design-v([0-9]+).*/v\1/' <<<"$(basename "$design")")"
printf 'SECTION\t%s\n' "${sections[@]}"
[[ ${#appendices[@]} -gt 0 ]] && printf 'APPENDIX\t%s\n' "${appendices[@]}"
exit 0
