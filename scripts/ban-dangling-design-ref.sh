#!/usr/bin/env bash
# Every `§` and `Appendix X` reference OUTSIDE the markdown names a real heading of the current design
# document — in the code, the manifests, the justfile and the gate scripts alike.
#
# WHY THIS EXISTS. docs/90 D2: the daemon's served OpenAPI `description` pointed consumers at
# "design §D" (allow-dangling-design-ref: quoted defect), a section that has not existed since the
# design was renumbered — a dangling pointer in a document the daemon SERVES to clients.
# `scripts/check-docs-pointers.sh` closed that class for the root markdown, and the daemon lane added an
# in-crate gate scoped to its own tier so it could not redden another agent's files. Neither covered the
# tree: there are ~2000 `§` references under `crates/*/src` — the design is cited in rustdoc on nearly
# every law — and a renumbering silently invalidates any of them. A reader who follows a dead pointer
# concludes the fact is unwritten and either re-derives it or re-argues a settled reversal. Prose is not
# compiled; this is its compiler.
#
# WHY THE ROSTER IS FIVE KINDS AND NOT ONE. The first cut of this gate scanned `crates/*/src` only, and
# `check-docs-pointers.sh` scanned the root markdown plus `docs/*.md`. Between the two sat a BLIND SPOT
# holding fifteen live dangling references — every one of them in a file kind nothing scanned: the
# contract-ledger comments in `Cargo.toml` (`v24 §20` and `v25 §21`, both written unqualified), the
# justfile's own recipe prose (`v27 §18.1`, `v27 §18.2`, `v15 §12.8 #4`, `v27 §12.23`, and the retired
# LETTERED daemon-section id in the `daemon` recipe — all written unqualified), and the three gate
# scripts whose headers state the law they enforce (`check-lean-tree.sh`, `check-broker-lean.sh`,
# `ban-legacy-terms.sh`). Those are exactly the files a reader lands in from a gate failure or a version
# bump, so a dead pointer there costs the same re-derivation as one in rustdoc. Widening this gate's
# roster is also why there is no THIRD resolver: `scripts/design-headings.sh` answers "which document is
# the design and what headings does it have" for both gates.
#
# THE LAW, in four arms:
#
#   ARM 1 — SECTIONS. Every `§<id>` in the roster below names a numbered heading of the design document
#   `scripts/design-headings.sh` discovers. Comments are NOT stripped: a dangling pointer in rustdoc or
#   in a `#` comment is the whole defect, and D2's instance was a string literal.
#
#   ARM 2 — APPENDICES. Every `Appendix <letter>` names a real appendix heading. Appendix A carries the
#   load-bearing reversals that AGENTS.md says to cite rather than re-argue, so a pointer that misses
#   it costs a re-argued reversal. The one letter NOT resolved is `X`, this repo's METAVARIABLE for
#   "some lettered appendix" — AGENTS.md's own prose writes `Appendix <X>`, and the daemon's in-crate
#   citation gate tells its reader that "a lettered appendix is cited as \"Appendix X\"". Demanding
#   that correct prose be rewritten to keep a gate green is the inversion AGENTS.md names for the
#   downstream example; the honest cost, stated rather than hidden, is that a citation which MEANT
#   `Appendix A` and typed `X` goes unflagged. The count of metavariable skips is in the verdict, so a
#   rule that starts swallowing real citations is visible rather than silent.
#
#   ARM 3 — NON-VACUITY, PER KIND AND OVERALL. Zero files, or an extractor that finds no reference at
#   all, is a gate MISCONFIGURATION and exits 1 (docs/90 G4). Per kind as well as overall: a roster
#   built out of five globs dies one glob at a time, and a total that is merely non-zero cannot see
#   that. Each kind whose ANCHOR is present must contribute at least one file — `crates/` present but
#   no `crates/*/src/**/*.rs`, a `crates/*/tests` directory with no Rust in it, a workspace root
#   `Cargo.toml` that the manifest find does not reach, a `scripts/` directory that yields nothing —
#   each is a misconfiguration, not a clean tree. And the SKIP rule must not swallow everything: if
#   nothing is left to check, the qualifier logic broke.
#
#   ARM 4 — THE EXEMPTION MARKER CANNOT OUTLIVE WHAT IT EXCUSES. See below.
#
# THE FIRST ESCAPE HATCH IS SELF-DOCUMENTING, so this gate needs no exemption roster for it. A reference
# into ANOTHER document's numbering must say which document, in one of the three forms this repo uses:
#   * a VERSION qualifier — `v15 §12.8`, `v30 §9.4` — naming that design version's numbering;
#   * a DOCUMENT-PATH qualifier — `docs/78 §5`, `docs/81 §9` — naming a review's own sections;
#   * a DOCUMENT-NUMBER qualifier — `design 62 §22`, `design 44 §3` — the shorthand
#     `check-docs-pointers.sh` arm (b) already resolves for `docs/…` pointers, here introduced by the
#     word `design`. The number must name a document that EXISTS (live or under `docs/historical/`), so
#     a typo'd document number fails rather than buying a free pass; and the introducing word must be
#     `design`, so `delta 5 §3.5` — where the bare number is a DELTA, not a document — stays checked.
# All three are skipped and counted. An unqualified `§` is a pointer into the CURRENT design by this
# repo's convention — which is exactly the convention that makes an un-versioned pointer rot invisibly,
# so it is the one this gate holds to.
#
# THE SECOND ESCAPE HATCH IS A PER-LINE MARKER, because a few lines in this repo QUOTE a dangling
# reference as the defect they report: the D2 finding's dangling lettered pointer appears verbatim in
# this file, in `check-docs-pointers.sh`, in `design-headings.sh` and in the justfile's gate roster,
# because quoting the broken string is how each of them teaches the defect. Rewriting the
# quotation would destroy the evidence, and a whole-file exemption would blind the gate to every other
# reference in the file it is enforcing itself with. So the marker is per line, in the shape
# `ban-legacy-terms.sh` established (`allow-legacy-term: <reason>`): put
# `allow-dangling-design-ref: <reason>` on the SAME line as the reference, reason non-empty.
# BOTH DIRECTIONS ARE GATED. A marked line whose references ALL resolve is a suppression excusing
# nothing — it would silently absorb the next real break on that line — and is a misconfiguration.
# THE HONEST COST, stated rather than hidden: a marker on a line carrying no reference this gate CHECKS
# (none at all, or only qualified/metavariable ones) is INERT rather than an error, because this
# script's own extraction regex and the prose documenting the marker both carry the token; the
# marker-count is in the verdict so a rule that starts swallowing real citations is visible.
#
# SCOPE, five kinds:
#   1. `crates/*/src/**/*.rs`   — library and binary sources, the code a reader lands in from a symbol.
#   2. `crates/*/tests/**/*.rs` — the integration suites, which cite the battery roster (§15.4) and the
#                                 law each leg guards as densely as the sources do.
#   3. every `Cargo.toml` outside — the contract ledgers cite the design at every version edge. This
#      `target/` and `vendor/`      reaches the `fuzz/` and `examples/downstream-kernel/` manifests too,
#                                   which are their own workspaces but this repo's prose; `target/` is
#                                   generated and `vendor/` is third-party prose it does not own.
#   4. the `justfile`           — the recipe comments ARE the gate roster's documentation.
#   5. `scripts/` except        — the gate scripts state the law they enforce in their headers. The
#      `scripts/test-*.sh`         self-tests are excluded as a CLASS: a red-on-inverse self-test's
#                                  fixtures are references that MUST NOT resolve (a section number no
#                                  design carries, an appendix letter no design carries), so scanning
#                                  them would make this gate and those self-tests mutually
#                                  unsatisfiable — and enumerating their fixture ids here would turn
#                                  "add a fixture" into a failure of this gate.
#                                  That is the same reasoning `ban-legacy-terms.sh` records for keeping
#                                  `scripts/` out of its own default roster. The excluded count is in
#                                  the verdict, and `scripts/test-ban-dangling-design-ref.sh` drives
#                                  the rule both ways: the same fixture reference passes under a
#                                  `test-` name and reddens without one.
# NOT the markdown: `check-docs-pointers.sh` owns the root files, and `docs/*.md` legitimately cite
# other documents' numbering and quote defects verbatim, so they need a per-document resolver.
#
# Usage: ban-dangling-design-ref.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

# The `§` byte pattern and the heading comparison must not depend on the caller's locale — see
# design-headings.sh's header for the collation defect this prevents.
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
headings_script="$here/design-headings.sh"

root="${1:-}"
if [[ -z "$root" ]]; then
  root="$(cd "$here/.." && pwd)"
fi
if [[ ! -d "$root" ]]; then
  echo "gate misconfigured: no such root directory: $root"
  exit 1
fi
root="$(cd "$root" && pwd)"

if [[ ! -x "$headings_script" ]]; then
  echo "gate misconfigured: $headings_script is missing or not executable."
  echo "It is the ONE home for \"which document is the design and what headings does it have\", shared"
  echo "with scripts/check-docs-pointers.sh's section arm — this gate does not carry a second copy of"
  echo "that resolver, so without it there is nothing to resolve against."
  exit 1
fi

# --- The design document's real headings, from the one resolver ------------------------------------
# Its `gate misconfigured:` arms (no design document, no numbered headings) are the reason this is not
# guarded here a second time: it exits non-zero and `set -e` carries that out of this gate.
design_rel=""
design_ver=""
declare -A is_section=()
section_n=0
appendix_n=0
while IFS=$'\t' read -r kind value; do
  case "$kind" in
    DESIGN) design_rel="$value" ;;
    VERSION) design_ver="$value" ;;
    SECTION) is_section["$value"]=1; section_n=$((section_n + 1)) ;;
    APPENDIX) is_section["$value"]=1; appendix_n=$((appendix_n + 1)) ;;
  esac
done < <("$headings_script" "$root")
if [[ -z "$design_rel" || -z "$design_ver" || $section_n -eq 0 ]]; then
  echo "gate misconfigured: $headings_script produced no usable design roster"
  echo "(document='$design_rel' version='$design_ver' sections=$section_n)."
  echo "With an empty roster every reference would be reported dangling, or — with the comparison"
  echo "inverted — every reference would pass. Either way the arm is not measuring the document."
  exit 1
fi

# --- The scan roster: five kinds, each counted separately -------------------------------------------
# Counted separately because a five-glob roster dies one glob at a time (ARM 3): the per-kind numbers
# below are both the vacuity guards and the verdict's evidence of what was actually opened.
src_files=()
test_files=()
manifest_files=()
just_files=()
script_files=()
selftest_files=()

if [[ -d "$root/crates" ]]; then
  mapfile -d '' -t src_files < <(find "$root"/crates/*/src -type f -name '*.rs' -print0 2>/dev/null)
  mapfile -d '' -t test_files < <(find "$root"/crates/*/tests -type f -name '*.rs' -print0 2>/dev/null)
fi
# `-prune` on the build and vendor trees: `target/` holds thousands of generated manifests and
# `vendor/vhost*` is third-party prose (a `=`-pinned patch this repo carries, not writes).
mapfile -d '' -t manifest_files < <(
  find "$root" \( -type d \( -name target -o -name vendor -o -name .git \) -prune \) -o \
    \( -type f -name 'Cargo.toml' -print0 \)
)
[[ -f "$root/justfile" ]] && just_files=("$root/justfile")
if [[ -d "$root/scripts" ]]; then
  # Every regular file, not just `*.sh`: `scripts/git-pre-commit` carries no extension and would
  # otherwise be a hole in the roster for the sake of a suffix.
  mapfile -d '' -t script_files < <(
    find "$root/scripts" -type f -not -name 'test-*.sh' -print0
  )
  mapfile -d '' -t selftest_files < <(find "$root/scripts" -type f -name 'test-*.sh' -print0)
fi

files=(
  "${src_files[@]}" "${test_files[@]}" "${manifest_files[@]}"
  "${just_files[@]}" "${script_files[@]}"
)

# --- ARM 3, first half: each kind whose ANCHOR is present must have contributed ---------------------
misconfig=""
if [[ -d "$root/crates" && ${#src_files[@]} -eq 0 ]]; then
  misconfig+="  crates/ exists but no crates/*/src/**/*.rs was opened"$'\n'
fi
if compgen -G "$root/crates/*/tests" >/dev/null 2>&1 && [[ ${#test_files[@]} -eq 0 ]]; then
  misconfig+="  a crates/*/tests directory exists but no *.rs in it was opened"$'\n'
fi
if [[ -f "$root/Cargo.toml" && ${#manifest_files[@]} -eq 0 ]]; then
  misconfig+="  $root/Cargo.toml exists but the manifest find reached no Cargo.toml"$'\n'
fi
if [[ -d "$root/scripts" && ${#script_files[@]} -eq 0 ]]; then
  misconfig+="  scripts/ exists but yielded no non-self-test file"$'\n'
fi
if [[ ${#files[@]} -eq 0 ]]; then
  misconfig+="  the whole roster resolved to zero files under $root"$'\n'
fi
if [[ -n "${misconfig//[$'\n']/}" ]]; then
  echo "gate misconfigured: the scan roster is not measuring what it claims:"
  printf '%s' "$misconfig"
  echo "A roster built out of five globs dies one glob at a time, and a scan that opens nothing reports"
  echo "'ok' while checking nothing — every source-scanning gate dies this way (docs/90 G4)."
  exit 1
fi

# --- Extraction ------------------------------------------------------------------------------------
# One pass, both reference kinds, with the two qualifier words and the per-line marker flag. Records:
#   S <file> <line> <id> <qual1> <qual2> <marked>      a `§<id>` reference
#   A <file> <line> <"Appendix X"> - - <marked>        an `Appendix <letter>` reference
# `/` and `.` stay in the qualifier word class so a `docs/78`-style qualifier survives intact; `§` is
# two bytes in UTF-8, so it is stripped by `sub()` and never by byte arithmetic.
#
# This script is INSIDE its own roster (kind 5), which the two patterns below survive by construction
# rather than by luck: `§[A-Za-z0-9]` cannot match the literal text `§[A-Za-z0-9]+…` (the next byte is
# `[`, not alphanumeric) and `Appendix[[:space:]]+[A-Z]` cannot match its own source text either (the
# next byte after `Appendix` is `[`, not whitespace). Change either pattern and check that still holds.
extract_refs() {
  awk '
    # An ABSENT qualifier is emitted as `-`, never as an empty field: tab is an IFS *whitespace*
    # character, so bash `read` collapses two adjacent tabs into one delimiter and every later field
    # shifts left — which silently moved the marker flag into the qualifier and read the marker as
    # unset on exactly the lines that carry it. `-` is outside the qualifier word class
    # (`[A-Za-z0-9/.]`), so it cannot collide with a real qualifier.
    function emit(kind, tok, q1, q2, marked) {
      print kind "\t" FILENAME "\t" FNR "\t" tok "\t" (q1 == "" ? "-" : q1) "\t" \
        (q2 == "" ? "-" : q2) "\t" marked
    }
    {
      line = $0
      marked = (line ~ /allow-dangling-design-ref:[[:space:]]*[^[:space:]]/) ? 1 : 0
      pos = 1
      while (match(substr(line, pos), /§[A-Za-z0-9]+(\.[0-9]+)*/)) {
        start = pos + RSTART - 1
        tok = substr(line, start, RLENGTH)
        sub(/^§/, "", tok)
        before = substr(line, 1, start - 1)
        gsub(/[^A-Za-z0-9\/.]+$/, "", before)
        n = split(before, w, /[^A-Za-z0-9\/.]+/)
        emit("S", tok, (n > 0 ? w[n] : ""), (n > 1 ? w[n - 1] : ""), marked)
        pos = start + RLENGTH
      }
      pos = 1
      while (match(substr(line, pos), /Appendix[[:space:]]+[A-Z]/)) {
        start = pos + RSTART - 1
        tok = substr(line, start, RLENGTH)
        gsub(/[[:space:]]+/, " ", tok)
        emit("A", tok, "-", "-", marked)
        pos = start + RLENGTH
      }
    }
  ' "$@"
}

# A bare document NUMBER introduced by the word `design` (`design 62 §22`) is the document-number
# shorthand check-docs-pointers.sh arm (b) resolves for `docs/…` pointers. It only qualifies when a
# document actually carries that number — live or retired — so a typo is not a free pass.
document_number_exists() {
  compgen -G "$root/docs/$1-*" >/dev/null 2>&1 || compgen -G "$root/docs/historical/$1-*" >/dev/null 2>&1
}

checked=0
skipped=0
metavar=0
bad=""
declare -A marked_seen=()      # "<file>:<line>" -> 1, every marked line carrying a reference
declare -A marked_excused=()   # "<file>:<line>" -> 1, marked lines that actually excused a failure
while IFS=$'\t' read -r kind file lineno ref qual1 qual2 marked; do
  [[ -z "$ref" ]] && continue
  if [[ "$kind" == "S" ]]; then
    # An explicitly OTHER design version names that document's numbering, not this one's.
    if [[ "$qual1" =~ ^v[0-9]+$ && "$qual1" != "$design_ver" ]]; then
      skipped=$((skipped + 1)); continue
    fi
    # A document-path qualifier (`docs/78 §5`) names that document's own sections.
    if [[ "$qual1" == docs/* ]]; then
      skipped=$((skipped + 1)); continue
    fi
    # A document-NUMBER qualifier (`design 62 §22`).
    if [[ "$qual1" =~ ^[0-9]+$ && "${qual2,,}" == "design" ]] && document_number_exists "$qual1"; then
      skipped=$((skipped + 1)); continue
    fi
    what="§$ref — no such section in $design_rel"
  else
    # The metavariable, not a citation — see the header's ARM 2.
    if [[ "$ref" == "Appendix X" ]]; then
      metavar=$((metavar + 1)); continue
    fi
    what="$ref — no such appendix in $design_rel"
  fi
  checked=$((checked + 1))
  [[ "$marked" == "1" ]] && marked_seen["$file:$lineno"]=1
  if [[ -z "${is_section[$ref]+set}" ]]; then
    if [[ "$marked" == "1" ]]; then
      marked_excused["$file:$lineno"]=1
      continue
    fi
    bad+="  ${file#"$root"/}:$lineno: $what"$'\n'
  fi
done < <(extract_refs "${files[@]}")

# --- ARM 3, second half: the extractor and the skip rule must both have done something --------------
if [[ $((checked + skipped + metavar)) -eq 0 ]]; then
  echo "gate misconfigured: ${#files[@]} file(s) scanned and not one \`§\`/\`Appendix X\` reference"
  echo "found. This tree cites the design in the rustdoc of nearly every law, in every contract-ledger"
  echo "entry and in every gate script's header, so an empty extraction means the extractor broke —"
  echo "reporting 'ok' while checking nothing."
  exit 1
fi
if [[ $checked -eq 0 ]]; then
  echo "gate misconfigured: all $skipped reference(s) were skipped as another document's numbering and"
  echo "none was checked. The qualifier rule is meant to spare \`v30 §…\`/\`docs/78 §…\`/\`design 62 §…\`,"
  echo "not to swallow the unqualified pointers that are this gate's whole subject."
  exit 1
fi

# --- ARM 4: a marker that excuses nothing is a widened blind spot -----------------------------------
failed=0
marked_lines=${#marked_seen[@]}
stale=""
for key in "${!marked_seen[@]}"; do
  if [[ -z "${marked_excused[$key]+set}" ]]; then
    stale+="  ${key#"$root"/}"$'\n'
  fi
done
if [[ -n "${stale//[$'\n']/}" ]]; then
  echo "ban-dangling-design-ref: FAIL — an \`allow-dangling-design-ref\` marker excuses nothing. Every"
  echo "reference on the line resolves, so the marker is not suppressing a finding — it is standing by"
  echo "to absorb the NEXT break on that line silently. Drop the marker:"
  printf '%s' "$stale" | sort
  failed=1
fi

if [[ -n "${bad//[$'\n']/}" ]]; then
  echo "ban-dangling-design-ref: FAIL — a comment, a manifest, a recipe or a string names a design"
  echo "section that does not exist. This is docs/90 D2 exactly: the pointer survived a renumbering and"
  echo "now sends the reader hunting for a section that was folded away. Re-point it at the section that"
  echo "carries the fact; if it deliberately cites an OLDER document, qualify it (\`v30 §9.4\`,"
  echo "\`docs/78 §5\`, \`design 62 §22\`) so it reads as history; if the line QUOTES a dangling reference"
  echo "as the defect it reports, mark that line \`allow-dangling-design-ref: <reason>\`:"
  printf '%s' "$bad" | sort
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: $checked design reference(s) all name real headings in $design_rel"
echo "($section_n numbered + $appendix_n appendix), across ${#files[@]} file(s) — ${#src_files[@]} crate source,"
echo "${#test_files[@]} crate test, ${#manifest_files[@]} Cargo.toml, ${#just_files[@]} justfile, ${#script_files[@]} script; ${#selftest_files[@]} self-test file(s)"
echo "excluded as red-on-inverse fixtures. $skipped reference(s) skipped as another document's numbering"
echo "(a \`v<N>\`/\`docs/<n>\`/\`design <n>\` qualifier), $metavar as the \`Appendix X\` metavariable, and"
echo "$marked_lines line(s) carry an \`allow-dangling-design-ref\` marker, each still excusing a real dangling"
echo "reference"
