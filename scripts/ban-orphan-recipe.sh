#!/usr/bin/env bash
# Enforces AGENTS.md rule 3 ("CI executes what it claims") one level ABOVE the orphan-SCRIPT class.
#
# THE CLASS. `scripts/ban-ci-script-handcopy.sh` ARM 4 asserts the `gates` roster equals the
# gate-shaped scripts on disk in BOTH directions — an orphan script and a stale entry are equally
# red. The identical argument applies to `just` recipes and had no gate at all: a recipe that
# nothing invokes is a maintained, shellchecked, documented body of work that runs nowhere, and it
# rots exactly the way the three hand-copies this repo has already recorded rotted — silently,
# because a thing nobody runs cannot go red.
#
# WHY A ROSTER AND NOT A BARE "EVERY RECIPE HAS A CALLER". Some recipes legitimately have no
# machine caller: the opt-in live suites (`test-crosvm`, `test-systemd`, `test-usb-passthrough`)
# are kept off CI for a NAMED reason — an absent binary, a full-Debian pull, a designated device —
# the reviewer/operator entry points (`ci`, `daemon`, `install-hooks`,
# `test-unit-undelegated`) are typed by a human by design, and the A/B measurements
# (`bench-ab-prepare`, `bench-ab`) produce a tracked metric rather than a verdict, so there is
# nothing for a machine caller to assert on. Demanding a caller for those would
# force a fake one, which is worse than the hole. So the gate asserts the two-way equality
# instead: an un-called recipe must be ON the roster below with its reason, and a roster entry
# that HAS acquired a caller (or names a recipe that no longer exists) is stale — i.e. a
# widened blind spot, the same failure ARM 4 treats as red.
#
# THE ROSTER — every entry is a recipe with no machine caller, and the reason it has none:
#
#   bench-ab                The A/B comparison itself (design §16). It boots VMs through two
#                           PREPARED arms and a blessed runner, and a benchmark is a tracked
#                           metric, never a pass/fail gate — a CI caller would be asserting on a
#                           number that legitimately moves with the host.
#   bench-ab-prepare        Builds and stages one arm from a git ref (a full release build in its
#                           own worktree, plus that arm's own rootfs in a builder micro-VM). WHICH
#                           two refs are being compared is the human's question by definition.
#   ci                      The aggregate. AGENTS.md's "Done means" row is `just ci` green LOCALLY;
#                           ci.yml deliberately invokes its constituents as separate jobs (for
#                           parallelism and per-job runners) rather than the aggregate, so nothing
#                           calls it and that is the design.
#   daemon                  Runs `vmcelld` locally against the dev artifacts. An operator verb.
#   install-hooks           Installs the repo-tracked git hooks into THIS checkout. Local by
#                           definition; CI runs the real gates rather than a pre-commit hook.
#   test-crosvm             Opt-in live matrix (§2.5). The crosvm binary is absent on CI, which is
#                           why it is not in `test-privileged` — AGENTS.md states this.
#   test-systemd            Opt-in proof cell (§18 delta 9). Pulls a full-Debian image; its
#                           KVM-free halves run everywhere via the normal suites.
#   test-usb-passthrough    Opt-in. Needs a designated device (`VMCELL_TEST_USB_DEVICE`); without
#                           one `test-privileged` records a capability skip instead.
#   test-unit-undelegated   The LOCAL mirror of the hosted-runner's undelegated-cgroup condition.
#                           It exists precisely to be run where CI is not, and needs `bwrap`.
#
# THE ARMS:
#
#   ARM 1 — ORPHAN. A recipe invoked by no other recipe and by no workflow, and absent from the
#   roster, is red. Add a caller, or add a roster entry saying why a human is the only caller.
#
#   ARM 2 — STALE ENTRY. A roster entry whose recipe now HAS a caller is red: the exemption is
#   describing a hole that closed, and an exemption nobody re-reads is how a blind spot widens.
#
#   ARM 3 — GHOST ENTRY. A roster entry naming a recipe that does not exist is red, for the same
#   reason ARM 4 of the sibling gate treats a stale script entry as red.
#
#   ARM 4 — NON-VACUITY. Zero recipes discovered is `gate misconfigured`, never a green `ok:` —
#   the only way to enumerate no recipes is to have been pointed at no justfile (docs/90 G4).
#
# THE RECIPE LIST AND THE BODIES ARE READ BACK THROUGH `just`, never parsed out of the file: the
# recipe is the authority, which is the same discipline `scripts/ban-recipe-body-handcopy.sh`
# applies to bodies. A body that INTERPOLATES its callee (`{{just_executable()}} gates`) therefore
# reads here exactly as it will run.
#
# Usage: ban-orphan-recipe.sh [REPO_ROOT]   (defaults to the workspace root)
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$root/justfile" ]] || {
  echo "gate misconfigured: no justfile under $root"
  echo "This gate enumerates recipes through \`just\`; with no justfile it would assert about an"
  echo "empty roster and report a clean tree it never looked at."
  exit 1
}

# THE ROSTER, as data. Kept beside the prose above so the two cannot drift: the prose explains an
# entry, this list IS the entry.
roster=(
  bench-ab
  bench-ab-prepare
  ci
  daemon
  install-hooks
  test-crosvm
  test-systemd
  test-usb-passthrough
  test-unit-undelegated
)

mapfile -t recipes < <(just --justfile "$root/justfile" --summary 2>/dev/null | tr ' ' '\n' | sed '/^$/d' | sort)

# --- ARM 4: an empty enumeration is a caller bug, never a clean tree ------------------------------
[[ ${#recipes[@]} -eq 0 ]] && {
  echo "gate misconfigured: \`just --summary\` enumerated no recipes under $root"
  echo "Every source-scanning gate in this repo dies this way: pointed at nothing, reporting ok."
  exit 1
}

# The workflows are the other half of "who invokes a recipe". Absent workflows are not fatal — a
# consumer checkout may carry none — but they ARE reported, because a silently missing workflow set
# would turn every CI-called recipe into an apparent orphan.
workflow_text=""
if compgen -G "$root/.github/workflows/*.yml" >/dev/null; then
  workflow_text="$(cat "$root"/.github/workflows/*.yml)"
fi

# Every recipe's body, read back through `just --show` so an interpolated call reads as it runs.
declare -A bodies=()
for r in "${recipes[@]}"; do
  bodies["$r"]="$(just --justfile "$root/justfile" --show "$r" 2>/dev/null || true)"
done

# has_caller <recipe> — a recipe is called if some OTHER recipe's body invokes it, or a workflow
# does. The needle allows either spelling a body can carry: the interpolated
# `{{just_executable()}} <r>` a recursive recipe must use, and a plain `just <r>`.
has_caller() {
  local target="$1" other
  for other in "${recipes[@]}"; do
    [[ "$other" == "$target" ]] && continue
    # `just --show` NORMALIZES interpolation to `{{ just_executable() }}` (with the inner spaces)
    # regardless of how the justfile spells it, so the needle tolerates both — reading the body
    # back through `just` is the whole point, and a needle matching only the source spelling would
    # have silently found no recursive caller at all. The self-test's `{{just_executable()}}` leg
    # is what caught this.
    if grep -qE "(just_executable\(\)[[:space:]]*\}\}|(^|[^-[:alnum:]_])just)[[:space:]]+${target}([[:space:]]|\$)" \
         <<<"${bodies[$other]}"; then
      return 0
    fi
  done
  if [[ -n "$workflow_text" ]] && \
     grep -qE "(^|[^-[:alnum:]_])just[[:space:]]+${target}([[:space:]]|\"|'|\$)" <<<"$workflow_text"; then
    return 0
  fi
  return 1
}

in_roster() {
  local needle="$1" e
  for e in "${roster[@]}"; do [[ "$e" == "$needle" ]] && return 0; done
  return 1
}

orphans=()
stale=()
ghosts=()

for r in "${recipes[@]}"; do
  if has_caller "$r"; then
    in_roster "$r" && stale+=("$r")
  else
    in_roster "$r" || orphans+=("$r")
  fi
done

for e in "${roster[@]}"; do
  found=0
  for r in "${recipes[@]}"; do [[ "$r" == "$e" ]] && { found=1; break; }; done
  (( found )) || ghosts+=("$e")
done

fail=0

# --- ARM 1 ---------------------------------------------------------------------------------------
if (( ${#orphans[@]} )); then
  fail=1
  echo "orphan recipe(s) — invoked by no other recipe and by no workflow, and not on the roster:"
  printf '  %s\n' "${orphans[@]}"
  echo
  echo "A recipe nothing runs cannot go red, and rots the way the three ci.yml hand-copies this"
  echo "repo has recorded rotted. Either give it a caller (another recipe, or \`run: just <name>\`"
  echo "in a workflow), or add it to the roster in scripts/ban-orphan-recipe.sh WITH the reason a"
  echo "human is its only caller — an opt-in suite's absent facility, or an operator verb."
fi

# --- ARM 2 ---------------------------------------------------------------------------------------
if (( ${#stale[@]} )); then
  fail=1
  echo "stale roster entry(ies) — these recipes now HAVE a caller and no longer need an exemption:"
  printf '  %s\n' "${stale[@]}"
  echo
  echo "Remove them from the roster in scripts/ban-orphan-recipe.sh. An exemption that has stopped"
  echo "describing a real hole is a blind spot nobody re-reads — the same failure this gate's"
  echo "sibling (ban-ci-script-handcopy.sh ARM 4) treats as red in the other direction."
fi

# --- ARM 3 ---------------------------------------------------------------------------------------
if (( ${#ghosts[@]} )); then
  fail=1
  echo "ghost roster entry(ies) — no such recipe exists:"
  printf '  %s\n' "${ghosts[@]}"
  echo
  echo "The recipe was renamed or deleted and its exemption outlived it. Update or drop the entry."
fi

(( fail )) && exit 1

echo "ok: all ${#recipes[@]} recipe(s) are invoked by a recipe or a workflow, except the"
echo "${#roster[@]} rostered human entry point(s) (${roster[*]}), each of which is still un-called"
if [[ -z "$workflow_text" ]]; then
  echo "note: no .github/workflows/*.yml under $root — recipe-to-recipe calls were the only evidence"
fi
