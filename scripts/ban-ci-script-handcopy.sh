#!/usr/bin/env bash
# Keeps the repo's gate roster in ONE place — AGENTS.md rule 3: "A CI step that hand-copies a `just`
# recipe drifts from it — invoke the recipe (`run: just test-unprivileged`) so local ≡ CI by
# construction."
#
# WHY THIS EXISTS. `.github/workflows/ci.yml` used to carry its own copy of the ban/check script
# list. Being a copy, it drifted — three times, twice inside a single wave:
#   * docs/81 M13: the first recorded instance of the class.
#   * `scripts/ban-readiness-timeout-literal.sh` (+ self-test) landed in the justfile and never
#     reached ci.yml. That ban is the backstop for the ONE route the structural fix leaves open (a
#     bare literal handed to `wait_for_socket`), so the backstop could not go red in CI.
#   * `scripts/ban-test-support-in-production.sh` (+ self-test), same wave, same omission. Its whole
#     rationale is that cargo's feature unification makes the `test-support` fixtures visible to lib
#     targets under `--all-targets` — which is what CI runs and a plain `cargo build` does not.
#     Running only locally was exactly the wrong half.
# Adding the four missing lines would have fixed the instance and left the class intact. The fix is
# structural: the roster lives in ONE `just` recipe (`gates`), `just ci` calls it, ci.yml invokes it
# as `run: just gates`, and this scanner makes a new hand-copy impossible to land silently.
#
# THE LAW, in four arms:
#
#   ARM 1 — WIRING. ci.yml must invoke `just <recipe>`. Without that call every other arm is
#   vacuous: a roster nothing runs is not a gate.
#
#   ARM 2 — NO HAND-COPY. No line of ci.yml may name a `scripts/*.sh` path (line comments stripped
#   first, so prose naming a script is never a false positive). The single exemption class is a
#   WRAPPER that must sit OUTSIDE the recipe it wraps and therefore carries no roster of its own;
#   the roster of those is below, by basename, each with its reason.
#
#   ARM 3 — STALE EXEMPTION. An allowlisted wrapper that ci.yml no longer uses is a widened blind
#   spot, not a pass — report it as a misconfiguration, the way ban-inline-setns.sh treats a
#   sanctioned site that moved away.
#
#   ARM 4 — ONE ROSTER, COMPLETE, BOTH DIRECTIONS. Every gate-shaped script on disk
#   (`scripts/{ban,check,test}-*.sh`) must be invoked by the recipe — an orphan script is the
#   defect this file is named for, one step earlier. And every script the recipe names must exist
#   and be executable — a stale entry, or one committed without its mode bit, fails the recipe at
#   run time and would otherwise be found by a red CI job rather than here.
#
# The recipe body is read back through `just --show`, never by parsing the justfile: the recipe is
# the authority, and re-implementing just's parser here would be a second copy of exactly the kind
# this gate exists to forbid.
#
# Usage: ban-ci-script-handcopy.sh [ROOT]   (defaults to the repo root above this script)
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
scripts_dir="$root/scripts"
recipe="gates"

# ci.yml may name a `scripts/*.sh` directly ONLY for a wrapper that has to be entered BEFORE the
# recipe starts, and that therefore holds no list of its own to drift. By basename, with its reason:
allowed=(
  # `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-…`:
  # the delegated cgroup subtree must exist around the recipe's whole process tree, so the wrapper
  # cannot live inside the recipe it wraps. It runs no gate and carries no roster.
  "with-delegated-scope.sh"
)

for f in "$workflow" "$justfile"; do
  if [[ ! -f "$f" ]]; then
    echo "gate misconfigured: expected file does not exist: $f" >&2
    exit 1
  fi
done
if [[ ! -d "$scripts_dir" ]]; then
  echo "gate misconfigured: no scripts directory at $scripts_dir" >&2
  exit 1
fi
if ! command -v just >/dev/null 2>&1; then
  echo "gate misconfigured: \`just\` is not on PATH, so the \`$recipe\` roster cannot be read." >&2
  echo "This scanner is itself invoked BY that recipe, so a missing \`just\` means the caller is" >&2
  echo "not the recipe — install just (CI: taiki-e/install-action) rather than skipping the check." >&2
  exit 1
fi

# ci.yml with YAML/shell line comments removed. A `#` only starts a comment at line start or after
# whitespace — in both YAML and the `run:` shells — so an inline `#` inside a value survives.
# Stripping can only hide a hit, never invent one, so this direction of imprecision is safe.
strip_comments() { sed -E 's/(^|[[:space:]])#.*$//'; }

# Materialised ONCE rather than piped into each check: `set -o pipefail` plus a short-circuiting
# `grep -q` reader makes the writer die of SIGPIPE and reddens the whole pipeline, which silently
# inverts an `if !` test. (Observed, not hypothetical — this scanner's first run reported the real
# ci.yml as never invoking `just gates` while the same grep matched fine on its own.)
workflow_code="$(strip_comments <"$workflow")"

failed=0

# --- ARM 1: ci.yml must actually invoke the recipe ------------------------------------------------
if ! grep -qE "(^|[^A-Za-z0-9_-])just[[:space:]]+$recipe([^A-Za-z0-9_-]|\$)" <<<"$workflow_code"; then
  echo "$workflow_rel never invokes \`just $recipe\`. The gate roster lives in that ONE recipe"
  echo "(justfile) so local ≡ CI by construction — a workflow that does not call it runs none of"
  echo "the bans, and every other arm of this check becomes vacuous (AGENTS rule 3)."
  failed=1
fi

# --- ARM 2 + ARM 3: no hand-copied script invocations; no stale exemption --------------------------
hits="$(
  awk '
    {
      code = $0
      sub(/(^|[ \t])#.*$/, "", code)
      while (match(code, /(\.\.\/)*(\.\/)?scripts\/[A-Za-z0-9._-]+\.sh/)) {
        tok = substr(code, RSTART, RLENGTH)
        print FNR "\t" tok
        code = substr(code, RSTART + RLENGTH)
      }
    }
  ' "$workflow"
)"

declare -A allow_seen=()
for a in "${allowed[@]}"; do allow_seen["$a"]=0; done

violations=""
while IFS=$'\t' read -r lineno tok; do
  [[ -z "$lineno" ]] && continue
  base="${tok##*/}"
  if [[ -n "${allow_seen[$base]+set}" ]]; then
    allow_seen["$base"]=1
    continue
  fi
  violations+="  $workflow_rel:$lineno: $tok"$'\n'
done <<<"$hits"

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "$workflow_rel invokes a script directly instead of going through a \`just\` recipe."
  echo "That is the hand-copy AGENTS rule 3 forbids: the workflow's copy of the roster drifts from"
  echo "the justfile's, and the omission is invisible until someone diffs the two lists by eye"
  echo "(it has shipped three times — see this file's header). Add the script to the \`$recipe\`"
  echo "recipe instead; ci.yml already runs it via \`just $recipe\`:"
  printf '%s' "$violations"
  failed=1
fi

for a in "${allowed[@]}"; do
  if [[ "${allow_seen[$a]}" -eq 0 ]]; then
    echo "gate misconfigured: \`$a\` is exempted from the hand-copy ban but $workflow_rel no longer"
    echo "names it. An exemption that matches nothing is a widened blind spot, not a pass — drop the"
    echo "entry from the \`allowed\` roster in scripts/ban-ci-script-handcopy.sh."
    failed=1
  fi
done

# --- ARM 4: the recipe's roster is exactly the gate-shaped scripts on disk -------------------------
if ! recipe_body="$(just --justfile "$justfile" --working-directory "$root" --show "$recipe" 2>/dev/null)"; then
  echo "gate misconfigured: the justfile at $justfile has no \`$recipe\` recipe."
  echo "That recipe IS the single gate roster; without it there is nothing for ci.yml to invoke."
  exit 1
fi

mapfile -t in_recipe < <(
  printf '%s\n' "$recipe_body" \
    | strip_comments \
    | grep -oE '\./scripts/[A-Za-z0-9._-]+\.sh' \
    | sed 's|^\./scripts/||' \
    | sort -u
)
mapfile -t on_disk < <(
  find "$scripts_dir" -maxdepth 1 -type f -name '*.sh' -printf '%f\n' \
    | grep -E '^(ban|check|test)-' \
    | sort -u
)

if [[ ${#in_recipe[@]} -eq 0 ]]; then
  echo "gate misconfigured: the \`$recipe\` recipe invokes no \`./scripts/*.sh\` at all."
  echo "An empty roster reports 'ok' while gating nothing — the way every list-driven gate dies."
  exit 1
fi
if [[ ${#on_disk[@]} -eq 0 ]]; then
  echo "gate misconfigured: no gate-shaped scripts (scripts/{ban,check,test}-*.sh) found under"
  echo "$scripts_dir — the completeness comparison below would be vacuous."
  exit 1
fi

orphans=""
for d in "${on_disk[@]}"; do
  found=0
  for r in "${in_recipe[@]}"; do
    if [[ "$d" == "$r" ]]; then found=1; break; fi
  done
  [[ $found -eq 0 ]] && orphans+="  scripts/$d"$'\n'
done
if [[ -n "${orphans//[$'\n']/}" ]]; then
  echo "A gate-shaped script exists but the \`$recipe\` recipe never runs it, so it gates nothing"
  echo "anywhere — not locally, not in CI. Wire it into \`$recipe\` (both the check and its"
  echo "red-on-inverse self-test), or rename it out of the ban-/check-/test- roster if it is not a gate:"
  printf '%s' "$orphans"
  failed=1
fi

missing=""
for r in "${in_recipe[@]}"; do
  if [[ ! -f "$scripts_dir/$r" ]]; then
    missing+="  scripts/$r: named by the \`$recipe\` recipe but no such file"$'\n'
  elif [[ ! -x "$scripts_dir/$r" ]]; then
    missing+="  scripts/$r: named by the \`$recipe\` recipe but not executable"$'\n'
  fi
done
if [[ -n "${missing//[$'\n']/}" ]]; then
  echo "The \`$recipe\` recipe names a script that cannot run. A renamed-away entry or a missing mode"
  echo "bit turns the whole roster red at run time; catch it here, named, instead:"
  printf '%s' "$missing"
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: $workflow_rel invokes \`just $recipe\` and names no script of its own"
echo "(exempt wrappers: ${allowed[*]}); the recipe's roster is exactly the ${#on_disk[@]} gate-shaped"
echo "script(s) under scripts/, all present and executable"
