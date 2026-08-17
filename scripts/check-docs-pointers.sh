#!/usr/bin/env bash
# Every documented pointer resolves — the `docs/…` paths this repo's prose sends a reader to, and the
# `design §…` sections it sends them to inside the design document.
#
# WHY THIS EXISTS. Two dangling pointers were found by a human in one review pass:
#   * the served OpenAPI `description` sent consumers to "design §D" (allow-dangling-design-ref: quoted
#     defect), a section that has not existed since the design was renumbered (docs/90 D2);
#   * AGENTS.md's "read before changing anything" list pointed at
#     `docs/99-claude-fable-automated-quality-v9.md`, which resolved to NOTHING after that document was
#     retired into `docs/historical/` — the one file every agent is told to read first, sending them to
#     a document that is not there.
# Nothing gated either. A pointer is the cheapest thing in a doc to break (retire a file, renumber a
# section) and the most expensive to discover: the reader concludes the fact is unwritten and either
# re-derives it or re-argues a settled reversal. Prose is not compiled, so this is the compiler.
#
# THE LAW, in three arms:
#
#   ARM 1 — EVERY `docs/…` POINTER RESOLVES. Scanned in every markdown file at the repo root and every
#   non-historical `docs/*.md`. Resolution honors three conventions this repo actually uses:
#     (a) THE ARBITRARY-DIGIT CONVENTION. AGENTS.md writes `docs/99-claude-fable-design-v99.md` and
#         says "`9` represents an arbitrary digit, use the newest version you find" — so a pointer
#         resolves BY GLOB with each `9` read as `[0-9]`, never literally. (A real `9` in a filename
#         still glob-matches itself, so the rule needs no exception.)
#     (b) DOCUMENT-NUMBER SHORTHAND. The prose says `docs/45`, `docs/81 pass`, `docs/historical/70` —
#         a document NUMBER, not a path, and the document it names is usually retired by now. An
#         extension-less pointer therefore resolves by its number prefix, live or historical.
#         A pointer that names a FILE (`docs/<n>-<slug>.md`) gets no such latitude: it must resolve at
#         the path it writes. That strictness is the point — the AGENTS.md break above was exactly a
#         live-looking filename whose document had moved under `docs/historical/`, and the correction
#         was to SAY `docs/historical/…`, which is what a reader needs.
#     (c) THE AS-BUILT LEDGER, and only it, keeps the retirement fallback: inside
#         `docs/implementation-notes.md` a filename pointer may resolve to
#         `docs/historical/<same basename>`. Its entries are dated records of passes that happened
#         while those documents were live, and AGENTS.md forbids "fixing" them — retiring a document
#         must not rewrite the history of the pass that cited it. New pointers in the ledger are still
#         gated: a name that exists in neither place still fails.
#   `docs/historical/**` is NOT scanned: a retired document's pointers legitimately name what was live
#   when it was written, and rewriting them is exactly what retirement is not. It IS a resolution
#   target (arm (b)).
#
#   ARM 2 — EVERY `§` SECTION REFERENCE RESOLVES against the newest non-historical design document's
#   actual headings (and `Appendix X` against its appendix headings). Scoped to the markdown files at
#   the REPO ROOT, where every `§` is a pointer into the current design: AGENTS.md carries no numbered
#   sections of its own, and README.md's own numbered sections are excluded by requiring the reference
#   to be qualified (`design §11`) in any file that numbers its own headings. A reference qualified
#   with a DIFFERENT design version (`v15 §12.8`) names that version's numbering and is skipped.
#   Deliberately NOT extended over `docs/*.md`: those legitimately cite other documents' numbering (the
#   retired perf-config design's `docs/44 §1b`) and quote defects verbatim — docs/90's D2 finding quotes
#   the wrong `design §D` it reports (allow-dangling-design-ref: quoted defect) — so they need a
#   per-document resolver this check does not have. The `§` references OUTSIDE the markdown (the code,
#   the manifests, the justfile, the gate scripts) are `scripts/ban-dangling-design-ref.sh`'s roster.
#
#   ARM 3 — NON-VACUITY, BOTH DIRECTIONS. A roster that opens no file, an extractor that finds no
#   pointer, a design document that is missing or yields no headings: each is a gate MISCONFIGURATION
#   and exits 1, never a reassuring `ok:` (docs/90 G4). And an EXEMPTION that no longer matches — a
#   pointer removed from the prose, or one that now resolves — is a widened blind spot, not a pass.
#
# Usage: check-docs-pointers.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

# BYTE COLLATION, deliberately. Under a UTF-8 locale `sort -u` collates by locale rules, which IGNORE
# punctuation for equality — so `1.1` and `11` compare EQUAL and `sort -u` keeps only one of them. That
# silently deleted seven top-level section ids (11-17, each shadowed by an `11.x`/`1.x` sibling) from
# this gate's own heading roster on the first run, turning valid references into reported failures. A
# byte locale is also what keeps the `§` byte pattern below independent of the caller's environment.
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

# Pointers that are known NOT to resolve, each with its reason. An entry must still APPEAR in the
# prose and must still NOT resolve — both directions are checked below, so an exemption cannot outlive
# the thing it excuses.
allowed=(
  # docs/implementation-notes.md's QEMU-restore record cites this write-up twice as the experiment
  # that gated Task A. No such file is in the tree (it was never committed, or went with the pass it
  # belonged to), so the ledger names a document a reader cannot open. Reported as a docs followup
  # rather than edited away: this gate does not own docs/, and the ledger's entries are not "fixed".
  "docs/qemu-follow-ups.md"
  # The design document's opening citation of the UPSTREAM serial-nexus requirements document
  # ("serial-nexus `docs/vmcell-requirements.md`, requests R1–R7"). That is a path in THAT repo; this
  # repo's own requirements copy is `docs/requirements.md`. A foreign `docs/…` path is
  # indistinguishable from a local one by shape alone, so it is named here instead of guessed at.
  "docs/vmcell-requirements.md"
)

# The as-built ledger(s): the ONE scope where a filename pointer may resolve to
# `docs/historical/<same basename>` instead of the path it writes (see the header, arm (c)). Every
# entry must be a file the scan actually opens — a roster naming a moved file is a silently widened
# fallback, so it is checked below.
ledgers=(
  # docs/implementation-notes.md — dated, append-only reconciliations. Each entry names the documents
  # of its own pass at the paths they had then; AGENTS.md says do not "fix" its entries, and a
  # retirement must not rewrite the record of a pass that happened while the document was live.
  "docs/implementation-notes.md"
)

# --- The scan roster ------------------------------------------------------------------------------
# Root markdown (AGENTS.md, CLAUDE.md, README.md) + the non-historical docs/*.md. `-maxdepth 1` on
# docs/ is what keeps docs/historical/ out of the SCAN while leaving it a resolution target.
mapfile -d '' -t root_md < <(find "$root" -maxdepth 1 -type f -name '*.md' -print0 | sort -z)
mapfile -d '' -t docs_md < <(
  [[ -d "$root/docs" ]] && find "$root/docs" -maxdepth 1 -type f -name '*.md' -print0 | sort -z
)
files=("${root_md[@]}" "${docs_md[@]}")
if [[ ${#files[@]} -eq 0 ]]; then
  echo "gate misconfigured: no markdown files under $root or $root/docs"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
fi
if [[ ${#root_md[@]} -eq 0 ]]; then
  echo "gate misconfigured: no markdown files at the repo root ($root)"
  echo "AGENTS.md and README.md are the two deployed entry points and the whole scope of the section-"
  echo "reference arm; with neither present that arm scans nothing."
  exit 1
fi

failed=0

# --- ARM 1: extract every `docs/…` pointer ---------------------------------------------------------
# The token must START at a non-path character, so a LONGER path that merely contains `docs/`
# (`vendor/vhost/docs/vhost_architecture.drawio`) is not mistaken for a repo-relative pointer to a
# document — that file is real and lives elsewhere, and flagging it would be a false positive.
# Backticks, brackets and parentheses are not in the token class, so markdown delimiters fall away.
extract_pointers() {
  awk '
    {
      line = $0
      pos = 1
      while (match(substr(line, pos), /docs\/[A-Za-z0-9._*?\/-]+/)) {
        start = pos + RSTART - 1
        tok = substr(line, start, RLENGTH)
        prev = (start > 1) ? substr(line, start - 1, 1) : ""
        if (prev !~ /[A-Za-z0-9._\/-]/) print FILENAME "\t" FNR "\t" tok
        pos = start + RLENGTH
      }
    }
  ' "$@"
}

# `compgen -G` answers "does any path match this glob?" without printing or globbing in the caller's
# scope; a metacharacter-free pattern degrades to a plain existence test, which is what makes it the
# one resolver for all four forms below.
matches_glob() { compgen -G "$root/$1" >/dev/null 2>&1; }

# resolve <token> <in-ledger:0|1> — true when the pointer names something a reader can open at the
# path it writes. The patterns, in order:
#   1. the token itself (a literal path, or an explicit glob the prose wrote: `docs/*-code-review.md`);
#   2. the same with every `9` read as `[0-9]` (the arbitrary-digit convention);
#   3-4. for an extension-LESS token, its document-NUMBER prefix, live and historical — that form is a
#        citation of a document number, and the numbered document is usually retired;
#   5-6. for a FILENAME token inside an as-built ledger only, the same basename under
#        docs/historical/ (header arm (c)). Outside a ledger a retired document must be NAMED
#        `docs/historical/…`; silently accepting the live-looking path is the AGENTS.md break itself.
resolve() {
  local tok="$1"
  local in_ledger="$2"
  local rel="${tok#docs/}"
  local pats=() p numpfx
  pats+=("$tok" "${tok//9/[0-9]}")
  if [[ "$tok" != *.* ]]; then
    # `docs/45`, `docs/81-pass` (prose hyphenating "the docs/81 pass"), `docs/historical/89-`: a
    # document number, not a filename. Truncate at the number and glob. A token with no number at all
    # keeps its whole text as the prefix.
    numpfx="$(sed -E 's|^(docs/(historical/)?[0-9]+).*|\1|' <<<"$tok")"
    pats+=("$numpfx*" "docs/historical/${numpfx#docs/}*")
  elif [[ "$in_ledger" -eq 1 ]]; then
    pats+=("docs/historical/$rel" "docs/historical/${rel//9/[0-9]}")
  fi
  for p in "${pats[@]}"; do
    matches_glob "$p" && return 0
  done
  return 1
}

declare -A exempt_seen=()
declare -A exempt_resolves=()
for a in "${allowed[@]}"; do exempt_seen["$a"]=0; exempt_resolves["$a"]=0; done

# The ledger roster, resolved to absolute paths and checked for staleness: an entry naming a file the
# scan never opens would silently widen the retirement fallback to nothing (or, after a rename, leave
# the real ledger without it and redden a record nobody may edit).
declare -A is_ledger=()
for l in "${ledgers[@]}"; do
  if [[ ! -f "$root/$l" ]]; then
    echo "gate misconfigured: \`$l\` is listed as an as-built ledger (the one scope where a filename"
    echo "pointer may resolve under docs/historical/) but no such file exists. Update the \`ledgers\`"
    echo "roster in scripts/check-docs-pointers.sh to the file's new path, or drop the entry."
    exit 1
  fi
  is_ledger["$root/$l"]=1
done

pointer_count=0
dangling=""
declare -A seen_pointer=()
while IFS=$'\t' read -r file lineno tok; do
  [[ -z "$file" ]] && continue
  # Trailing sentence punctuation is prose, not path. Stripped one character at a time so
  # `(docs/90-…-code-review.md).` reduces cleanly; `*`/`-` are NOT stripped (a glob and a
  # number-prefix pointer end in them legitimately).
  while :; do
    case "$tok" in
      *. | *, | *\; | *: | *\) | *\] | *\} | *\' | *\") tok="${tok%?}" ;;
      *) break ;;
    esac
  done
  [[ -z "$tok" || "$tok" == "docs/" ]] && continue
  pointer_count=$((pointer_count + 1))
  rel_file="${file#"$root"/}"
  in_ledger="${is_ledger[$file]:-0}"
  if [[ -n "${exempt_seen[$tok]+set}" ]]; then
    exempt_seen["$tok"]=1
    if resolve "$tok" "$in_ledger"; then exempt_resolves["$tok"]=1; fi
    continue
  fi
  # One report per distinct pointer PER FILE-CLASS: a name repeated in twelve places is one broken
  # pointer, and a dozen identical lines buries the others. The ledger flag is part of the key because
  # the same name legitimately resolves there and not elsewhere.
  if [[ -n "${seen_pointer[$in_ledger:$tok]+set}" ]]; then continue; fi
  seen_pointer["$in_ledger:$tok"]=1
  if ! resolve "$tok" "$in_ledger"; then
    dangling+="  $rel_file:$lineno: $tok"$'\n'
  fi
done < <(extract_pointers "${files[@]}")

if [[ $pointer_count -eq 0 ]]; then
  echo "gate misconfigured: ${#files[@]} markdown file(s) scanned and not one \`docs/…\` pointer found."
  echo "This repo's prose is built out of them, so an empty extraction means the extractor broke —"
  echo "which would report 'ok' while checking nothing."
  exit 1
fi

if [[ -n "${dangling//[$'\n']/}" ]]; then
  echo "check-docs-pointers: FAIL — a documented pointer resolves to nothing."
  echo "  A reader following it concludes the fact is unwritten, then re-derives it or re-argues a"
  echo "  settled reversal (docs/90 D2's class). Point it at the document's CURRENT path: a retired"
  echo "  document keeps its basename but must be NAMED \`docs/historical/<basename>\` — the live-looking"
  echo "  path is the break, not a shorthand for it. A document number with no filename (\`docs/45\`)"
  echo "  resolves either way, so a failure there means no document carries that number at all:"
  printf '%s' "$dangling"
  failed=1
fi

for a in "${allowed[@]}"; do
  if [[ "${exempt_seen[$a]}" -eq 0 ]]; then
    echo "gate misconfigured: \`$a\` is exempted from the pointer check but no scanned document names"
    echo "it any more. An exemption that matches nothing is a widened blind spot, not a pass — drop the"
    echo "entry from the \`allowed\` roster in scripts/check-docs-pointers.sh."
    failed=1
  elif [[ "${exempt_resolves[$a]}" -eq 1 ]]; then
    echo "gate misconfigured: \`$a\` is exempted as unresolvable, but it now RESOLVES. The exemption is"
    echo "excusing nothing and would hide the next break of the same pointer — drop the entry from the"
    echo "\`allowed\` roster in scripts/check-docs-pointers.sh."
    failed=1
  fi
done

# --- ARM 2: `§` section references against the design document's real headings ----------------------
# Discovered, never hardcoded: the design went v31 -> v32 -> v33 and each move broke a gate that had
# pinned its filename. `sort -V` because the prefixes are numbers — plain sort puts `9-` after `83-`.
design=""
while IFS= read -r candidate; do design="$candidate"; done < <(
  [[ -d "$root/docs" ]] && find "$root/docs" -maxdepth 1 -type f -name '*design-v*.md' | sort -V
)
if [[ -z "$design" ]]; then
  echo "gate misconfigured: no docs/*design-v*.md design document found under $root/docs"
  echo "Every \`§\` reference is resolved against its headings; with no design document that arm is"
  echo "vacuous and would silently pass."
  exit 1
fi
design_rel="${design#"$root"/}"
design_ver="$(sed -E 's/.*design-v([0-9]+).*/v\1/' <<<"$(basename "$design")")"

mapfile -t sections < <(
  grep -oE '^#{1,6}[[:space:]]+[0-9]+(\.[0-9]+)*' "$design" | sed -E 's/^#+[[:space:]]+//' | sort -u
)
mapfile -t appendices < <(
  grep -oE '^#{1,6}[[:space:]]+Appendix[[:space:]]+[A-Z]' "$design" \
    | sed -E 's/^#+[[:space:]]+//; s/[[:space:]]+/ /g' | sort -u
)
if [[ ${#sections[@]} -eq 0 ]]; then
  echo "gate misconfigured: $design_rel yields no numbered headings."
  echo "Every reference would then be unresolvable (or, with the comparison inverted, every reference"
  echo "would pass) — either way the arm is not measuring the document."
  exit 1
fi
declare -A is_section=()
for s in "${sections[@]}"; do is_section["$s"]=1; done
for a in "${appendices[@]}"; do is_section["$a"]=1; done

# A file that numbers its OWN headings (README.md's `### 6. Privileged Test Runner`) uses `§6` for
# itself, so only an explicitly qualified reference is a design pointer there.
file_numbers_own_sections() { grep -qE '^#{1,6}[[:space:]]+[0-9]+\.?[[:space:]]' "$1"; }

extract_section_refs() {
  awk '
    {
      line = $0
      pos = 1
      while (match(substr(line, pos), /§[A-Za-z0-9]+(\.[0-9]+)*/)) {
        start = pos + RSTART - 1
        tok = substr(line, start, RLENGTH)
        sub(/^§/, "", tok)      # by sub(), never byte arithmetic: `§` is two bytes in UTF-8
        before = substr(line, 1, start - 1)
        gsub(/[^A-Za-z0-9]+$/, "", before)
        n = split(before, w, /[^A-Za-z0-9]+/)
        print FILENAME "\t" FNR "\t" tok "\t" (n > 0 ? w[n] : "")
        pos = start + RLENGTH
      }
    }
  ' "$1"
}

ref_checked=0
ref_skipped=0
bad_refs=""
for f in "${root_md[@]}"; do
  qualified_only=0
  file_numbers_own_sections "$f" && qualified_only=1
  rel_file="${f#"$root"/}"
  while IFS=$'\t' read -r _ lineno ref qual; do
    [[ -z "$ref" ]] && continue
    # An explicitly older/other design version names THAT document's numbering — not this one's.
    if [[ "$qual" =~ ^v[0-9]+$ && "$qual" != "$design_ver" ]]; then
      ref_skipped=$((ref_skipped + 1)); continue
    fi
    if [[ $qualified_only -eq 1 && "${qual,,}" != "design" && "$qual" != "$design_ver" ]]; then
      ref_skipped=$((ref_skipped + 1)); continue
    fi
    ref_checked=$((ref_checked + 1))
    if [[ -z "${is_section[$ref]+set}" ]]; then
      bad_refs+="  $rel_file:$lineno: §$ref — no such section in $design_rel"$'\n'
    fi
  done < <(extract_section_refs "$f")

  while IFS=: read -r lineno hit; do
    [[ -z "$hit" ]] && continue
    hit="$(sed -E 's/[[:space:]]+/ /g' <<<"$hit")"
    ref_checked=$((ref_checked + 1))
    if [[ -z "${is_section[$hit]+set}" ]]; then
      bad_refs+="  $rel_file:$lineno: $hit — no such appendix in $design_rel"$'\n'
    fi
  done < <(grep -onE 'Appendix[[:space:]]+[A-Z]\b' "$f" || true)
done

if [[ $ref_checked -eq 0 ]]; then
  echo "gate misconfigured: no \`§\` or \`Appendix X\` reference found in the ${#root_md[@]} root"
  echo "markdown file(s). AGENTS.md is built out of design references, so an empty extraction means"
  echo "the extractor broke — reporting 'ok' while checking nothing."
  exit 1
fi

if [[ -n "${bad_refs//[$'\n']/}" ]]; then
  echo "check-docs-pointers: FAIL — a \`§\` reference names a section the design document does not have."
  echo "  This is docs/90 D2 exactly: the pointer survived a renumbering and now sends the reader"
  echo "  hunting for a section that was folded away. Re-point it at the section that carries the fact:"
  printf '%s' "$bad_refs"
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: $pointer_count \`docs/…\` pointer(s) across ${#files[@]} markdown file(s) all resolve"
echo "(${#allowed[@]} named exemption(s), each still present and still unresolvable; ${#ledgers[@]} as-built"
echo "ledger(s) where a retired basename resolves under docs/historical/); $ref_checked section"
echo "reference(s) in the ${#root_md[@]} root file(s) all name real headings in $design_rel"
echo "(${#sections[@]} numbered + ${#appendices[@]} appendix), $ref_skipped skipped as another document's numbering"
