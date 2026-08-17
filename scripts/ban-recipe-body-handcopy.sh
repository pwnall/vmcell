#!/usr/bin/env bash
# Keeps an AGGREGATE recipe from restating a recipe it should invoke — AGENTS.md rule 3, the
# hand-copy class, applied to the two files that aggregate everything else: the `ci` recipe and
# `.github/workflows/ci.yml`.
#
# WHY THIS EXISTS. `scripts/ban-ci-script-handcopy.sh` closed the class for the GATE ROSTER (a
# workflow naming `scripts/*.sh` directly). It says nothing about a copied recipe BODY, and that
# half had shipped twice:
#   * ci.yml's integration step inlined the `test-unprivileged` nextest command instead of invoking
#     the recipe, and the copy then dropped `--features qemu` — so the QEMU smoltcp-NAT leg of
#     `vmm_matrix_test!` was never even COMPILED in CI (M14). Invisible coverage loss, not a
#     recorded skip. Fixed by invoking the recipe.
#   * `just ci` carried a verbatim copy of the `test-unit` recipe body (`cargo nextest run --locked
#     --all-features`), so the local CI definition and the recipe developers actually run could
#     diverge silently — the identical shape, one file over, found by a human rather than a gate.
# Adding the missing `just <recipe>` call fixes an instance and leaves the class intact. This is the
# class: an aggregate must CALL, never restate.
#
# THE LAW, in three arms:
#
#   ARM 1 — WIRING (the positive control). The aggregate recipe must invoke at least one other
#   recipe, and ci.yml must invoke at least one. If neither file calls a recipe, the convention this
#   scanner polices does not exist in this tree and every verdict below is vacuous.
#
#   ARM 2 — NO RESTATED RECIPE IN THE AGGREGATE RECIPE. If every body line of some other recipe
#   appears in `ci`'s body, `ci` is running that recipe's commands instead of the recipe.
#
#   ARM 3 — NO RESTATED RECIPE IN THE WORKFLOW. Same containment test against ci.yml.
#
# HOW LINES ARE COMPARED, and the honest limit of it. Comments and indentation are stripped, then a
# body line without `{{ … }}` must match VERBATIM, while a line carrying interpolations is matched
# as a glob with each `{{ … }}` replaced by `*` (so an expanded copy — `/home/u/repo/.vmcell-bin/…`
# where the recipe wrote `{{ justfile_directory() }}/{{ runner }}` — is still caught). To keep a
# glob built out of an interpolation-only body from matching unrelated text, a violation must
# additionally include at least one line matched verbatim. Consequence, stated rather than hidden: a
# copy that rewrote or re-wrapped the command's text is not caught here; that is what review and the
# `--no-tests=fail` / feature-scoping gates on the suites themselves are for.
#
# Recipe bodies are read back through `just --show`, never by parsing the justfile: the recipe is the
# authority, and a second parser here would be the very duplication this file bans.
#
# Usage: ban-recipe-body-handcopy.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

root="${1:-}"
if [[ -z "$root" ]]; then
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
if [[ ! -d "$root" ]]; then
  echo "gate misconfigured: no such root directory: $root" >&2
  exit 1
fi
root="$(cd "$root" && pwd)"

workflow_rel=".github/workflows/ci.yml"
workflow="$root/$workflow_rel"
justfile="$root/justfile"
# The aggregate recipe: the local mirror of the CI job list, and the one recipe allowed to name many
# others. Every OTHER recipe is a unit it must call.
aggregate="ci"

for f in "$workflow" "$justfile"; do
  if [[ ! -f "$f" ]]; then
    echo "gate misconfigured: expected file does not exist: $f" >&2
    exit 1
  fi
done
if ! command -v just >/dev/null 2>&1; then
  echo "gate misconfigured: \`just\` is not on PATH, so no recipe body can be read back." >&2
  echo "This scanner is invoked BY the \`gates\` recipe, so a missing \`just\` means the caller is" >&2
  echo "not the recipe — install just (CI: taiki-e/install-action) rather than skipping the check." >&2
  exit 1
fi

# Comments (a `#` at line start or after whitespace, in both YAML and the recipe shells), leading and
# trailing whitespace, and blank lines removed. Stripping can only hide a hit, never invent one.
normalize() {
  awk '
    {
      line = $0
      sub(/(^|[ \t])#.*$/, "", line)
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line != "") print line
    }
  '
}

# A recipe body with its doc comments, any attributes, and the recipe HEADER line removed. `just
# --show` emits the doc comment(s) and the header at column 0 and the body indented, so: skip
# leading blank/`#`/`[` lines, drop the one header line, keep the rest.
recipe_body() {
  just --justfile "$justfile" --working-directory "$root" --show "$1" 2>/dev/null | awk '
    BEGIN { past_header = 0 }
    {
      if (!past_header) {
        if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^#/ || $0 ~ /^\[/) next
        past_header = 1
        next
      }
      print
    }
  '
}

mapfile -t recipes < <(
  just --justfile "$justfile" --working-directory "$root" --summary 2>/dev/null \
    | tr ' ' '\n' \
    | awk 'NF'
)
if [[ ${#recipes[@]} -lt 2 ]]; then
  echo "gate misconfigured: the justfile at $justfile exposes fewer than two recipes, so there is"
  echo "nothing for the \`$aggregate\` recipe to invoke and this comparison would be vacuous."
  exit 1
fi

aggregate_present=0
for r in "${recipes[@]}"; do
  if [[ "$r" == "$aggregate" ]]; then aggregate_present=1; fi
done
if [[ $aggregate_present -eq 0 ]]; then
  echo "gate misconfigured: the justfile at $justfile has no \`$aggregate\` recipe."
  echo "That recipe IS the local CI definition — without it there is no aggregate to police."
  exit 1
fi

aggregate_lines="$(recipe_body "$aggregate" | normalize)"
if [[ -z "$aggregate_lines" ]]; then
  echo "gate misconfigured: the \`$aggregate\` recipe has an empty body, so ARM 2 could never fire."
  exit 1
fi
# A workflow step spells a one-line command as `run: <command>` (a block scalar's lines arrive bare,
# so those need nothing). Emit the stripped remainder ALONGSIDE the original so a single-line copy is
# comparable to the recipe body it came from — without it, exactly the terse spelling this scanner
# most needs to catch reads as clean.
workflow_lines="$(
  normalize <"$workflow" | awk '
    {
      print
      line = $0
      sub(/^-[[:space:]]*/, "", line)
      if (sub(/^run:[[:space:]]*/, "", line) && line != "" && line !~ /^[|>]-?$/) print line
    }
  '
)"
if [[ -z "$workflow_lines" ]]; then
  echo "gate misconfigured: $workflow_rel has no content left after comment stripping, so ARM 3"
  echo "could never fire."
  exit 1
fi

# Does this haystack call `just <recipe>`? Both spellings count: a bare `just test-unit` (ci.yml) and
# the recursive `{{ just_executable() }} test-unit` a recipe must use, whose interpolation leaves
# `}} test-unit`.
invokes_recipe() {
  local name="$1" hay="$2"
  grep -qE "(just|\}\})[[:space:]]+${name}([^A-Za-z0-9_-]|\$)" <<<"$hay"
}

# Verbatim first; glob only for a line carrying interpolations, so no `[`/`*` inside ordinary shell
# code is ever read as a pattern.
match_line() {
  local line="$1" hay="$2" pat hayline
  if grep -qxF -- "$line" <<<"$hay"; then
    return 0
  fi
  if [[ "$line" == *'{{'* ]]; then
    pat="$(sed -E 's/\{\{[^}]*\}\}/*/g' <<<"$line")"
    while IFS= read -r hayline; do
      # shellcheck disable=SC2053  # $pat is a GLOB on purpose: it is the interpolated line's shape.
      if [[ "$hayline" == $pat ]]; then return 0; fi
    done <<<"$hay"
  fi
  return 1
}

failed=0

# --- ARM 1: the aggregate and the workflow must actually invoke recipes ----------------------------
agg_calls=0
wf_calls=0
for r in "${recipes[@]}"; do
  if [[ "$r" == "$aggregate" ]]; then continue; fi
  if invokes_recipe "$r" "$aggregate_lines"; then agg_calls=$((agg_calls + 1)); fi
  if invokes_recipe "$r" "$workflow_lines"; then wf_calls=$((wf_calls + 1)); fi
done
if [[ $agg_calls -eq 0 ]]; then
  echo "The \`$aggregate\` recipe invokes no other recipe at all. It is the local CI definition, so it"
  echo "aggregates by CALLING (\`{{just_executable()}} <recipe>\`) — a body that only restates commands"
  echo "has nothing for the arms below to compare against, and this check would pass while gating"
  echo "nothing (AGENTS rule 3)."
  failed=1
fi
if [[ $wf_calls -eq 0 ]]; then
  echo "$workflow_rel invokes no \`just <recipe>\` at all. Every suite/gate step is supposed to run a"
  echo "recipe so local ≡ CI by construction; with none, ARM 3 below is vacuous."
  failed=1
fi

# --- ARM 2 + ARM 3: no recipe body is restated in the aggregate, or in the workflow ----------------
report() { # report <recipe> <where> <how-to-fix>
  echo "the whole body of recipe \"$1\" is restated in $2 instead of being invoked. That is the"
  echo "hand-copy AGENTS rule 3 forbids: the two copies drift, and the drift is invisible until"
  echo "someone diffs them by eye — it has shipped twice (see this file's header; one copy silently"
  echo "stopped compiling a whole backend's matrix legs). Replace the restated lines with:"
  echo "    $3"
}

check_target() { # check_target <label> <haystack> <fix-template>
  local label="$1" hay="$2" fix="$3"
  local r body line n_lines n_literal missing
  for r in "${recipes[@]}"; do
    if [[ "$r" == "$aggregate" ]]; then continue; fi
    body="$(recipe_body "$r" | normalize)"
    if [[ -z "$body" ]]; then continue; fi
    n_lines=0
    n_literal=0
    missing=0
    while IFS= read -r line; do
      if [[ -z "$line" ]]; then continue; fi
      n_lines=$((n_lines + 1))
      if match_line "$line" "$hay"; then
        if [[ "$line" != *'{{'* && ${#line} -ge 12 ]]; then
          n_literal=$((n_literal + 1))
        fi
      else
        missing=1
        break
      fi
    done <<<"$body"
    # `n_literal > 0`: at least one line matched VERBATIM, so a glob built from an
    # interpolation-only body can never be the sole evidence of a copy.
    if [[ $missing -eq 0 && $n_lines -gt 0 && $n_literal -gt 0 ]]; then
      report "$r" "$label" "${fix//RECIPE/$r}"
      failed=1
    fi
  done
}

check_target "the \`$aggregate\` recipe (justfile)" "$aggregate_lines" '{{just_executable()}} RECIPE'
check_target "$workflow_rel" "$workflow_lines" 'run: just RECIPE'

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: neither the \`$aggregate\` recipe nor $workflow_rel restates any of the other"
echo "${#recipes[@]} recipe(s); the aggregate invokes $agg_calls and the workflow $wf_calls of them"
