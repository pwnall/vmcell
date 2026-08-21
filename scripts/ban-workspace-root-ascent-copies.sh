#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the WORKSPACE-ROOT ASCENT — design §17's last
# open consolidation item — as a POSITIVE structural gate over its one coupling: the marker string.
#
# THE LAW. `vmcell::artifact::workspace_root()` is the designated home: ascend from
# `CARGO_MANIFEST_DIR` (else the absolute CWD) to the ancestor that owns the member crates, and fall
# back to the start dir when there is none (a downstream consumer's workspace has no vmcell
# checkout). Its private core `find_vmcell_source_root` is the ONE place the marker path is spelled,
# and `workspace_root` is `pub` — as of the C4 pass — precisely so an out-of-crate harness calls it
# instead of re-deriving the root. `vmcell::artifact::artifacts_dir()` and `vmcell_source_root()`
# are the two other public answers built on that same core.
#
# WHY THIS EXISTS. `bench-vm` carried a hand-rolled third copy of the ascent for exactly as long as
# the library's was `pub(crate)`, and design §17 kept it on the open register with the note that "the
# coupling to watch is the marker string". It is watched here rather than remembered. A drifted copy
# is NOT a compile error and NOT visible to a parity test: `bench-vm`'s
# `snap_dir_anchors_on_the_library_one_workspace_root` pins the resolved root against a structurally
# derived one, which a BYTE-IDENTICAL copy passes — it resolves the same directory today and is free
# to drift tomorrow. What drift costs, concretely: the harness anchors `--snap-dir` on one directory
# and boots artifacts out of another, and reports both as one measurement.
#
# WHAT IT CANNOT DO, stated rather than implied: a copy that spells the marker WRONG is invisible
# here — the needle is exact, and a typo is not the needle. That half is the parity test's, and the
# two are complements, demonstrated both ways when this gate landed: a hand-rolled ascent with a
# typo'd marker reddens the test and passes this scan; a BYTE-IDENTICAL one reddens this scan and
# passes the test. Neither alone closes C4.
#
# WHAT IT FLAGS: the marker path `crates/vmcell-protocol/Cargo.toml` anywhere under `crates/`, line
# comments stripped first — so the ascent's own rustdoc, and `bench-vm`'s note about the collapse,
# are never false positives. The needle is unquoted on purpose, unlike the `$VMCELL_CH_BIN` sibling:
# the marker also appears inside a user-facing STRING (the guest-tools closure's "no checkout above
# {}" error), and that mention is a real coupling — if the marker moved, that message would send an
# operator hunting for a file that no longer marks anything.
#
# SCOPE, stated rather than implied. This gate watches the MARKER, not every derivation of a root
# path. `crates/vmcelld/tests/integration.rs` walks two `parent()`s from its own
# `CARGO_MANIFEST_DIR`: that is not a copy of this law — it cannot drift WITH the marker, it knows
# its own depth, and it breaks loudly if the crate moves. Banning it would name no home to send the
# reader to (the library's ascent answers a different question: "where is the root FROM AN ARBITRARY
# start dir, and what if there is none"). Rust sources only (`crates/**/*.rs`), matching the sibling
# scanners; the marker's other in-tree spellings live in docs and in the manifests themselves, which
# are the layout, not a copy of the predicate over it.
#
# THE ROSTER below is the whole list of files that may name the marker, by path suffix, each with an
# EXACT count and the reason it is there — counts in BOTH directions, the shape
# ban-ch-binary-resolver-copies.sh uses. A spelling ADDED inside a rostered file is a second ascent
# wearing that entry's exemption; a count that dropped to zero means the reason the entry was granted
# is gone, i.e. a widened blind spot. The home is split PRODUCTION vs `#[cfg(test)]`, because its
# three test spellings materialize synthetic checkouts (they must create the marker file) and lumping
# them with the law would let a second production ascent hide inside the total.
#
# Usage: ban-workspace-root-ascent-copies.sh [DIR ...]   (defaults to the member trees under crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source (lib + bins + tests + benches) lives under crates/.
  # `examples/downstream-kernel/` is a SEPARATE workspace — a consumer has no vmcell checkout and so
  # never finds this marker at all, which is the fallback arm, not a copy of the ascent.
  dirs=(crates)
fi

# The marker the ascent looks for, and the one function allowed to look for it.
marker="crates/vmcell-protocol/Cargo.toml"
law="vmcell::artifact::workspace_root"

# The home, by path suffix, plus the definitions it must still contain (a home that no longer holds
# the ascent is a moved law, not a pass; a home that no longer EXPORTS it is the `pub(crate)` state
# that forced the third copy in the first place).
home_suffix="/vmcell/src/artifact/mod.rs"
home_defines=("fn find_vmcell_source_root" "pub fn workspace_root")
# Production half: the ONE `.join(marker)` inside `find_vmcell_source_root`.
home_prod_count=1
# `#[cfg(test)]` half: three fixtures that CREATE the marker to build a synthetic checkout
# (the in-checkout root, the "outside any checkout" control, and the broken-closure tree).
home_test_count=3

# Every OTHER file that may name the marker: path suffix, exact count, reason.
exempt_suffix=(
  # The guest-tools source-closure error, which quotes the marker AT AN OPERATOR: "no vmcell
  # checkout (no `crates/vmcell-protocol/Cargo.toml` above {})". Prose inside a string literal, not
  # a path composition — but a real coupling, which is why it is rostered rather than excluded.
  "/vmcell/src/artifact/guest_tools.rs"
)
exempt_count=(1)

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources is
# to have been pointed at the wrong place (a move/reorg, or an explicit-path typo). Eight bans wore a
# green verdict on an empty tree before docs/90 G4 swept the class.
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

# `index()`, not a regex: the needle is a literal path and belongs in no pattern.
scan() { # scan <file> [only] -> matching lines, prefixed file:line. `only` = prod | test | all
  awk -v FN="$1" -v NEEDLE="$marker" -v ONLY="${2:-all}" '
    /^#\[cfg\(test\)\]/ { intest = 1 }
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose is not an ascent)
      if (index(code, NEEDLE) == 0) next
      if (ONLY == "prod" && intest) next
      if (ONLY == "test" && !intest) next
      print FN ":" FNR ": " $0
    }
  ' "$1"
}
count() { if [[ -z "${1//[$'\n']/}" ]]; then echo 0; else printf '%s\n' "$1" | grep -c ''; fi }

home_seen=0
home_prod_found=0
home_test_found=0
home_prod_hits=""
home_test_hits=""
seen=()
found=()
hits=()
for _ in "${exempt_suffix[@]}"; do seen+=(0); found+=(0); hits+=(""); done
violations=""

for f in "${files[@]}"; do
  if [[ "$f" == *"$home_suffix" ]]; then
    home_seen=1
    home_prod_hits="$(scan "$f" prod)"
    home_test_hits="$(scan "$f" test)"
    home_prod_found="$(count "$home_prod_hits")"
    home_test_found="$(count "$home_test_hits")"
    for def in "${home_defines[@]}"; do
      if ! grep -q "$def" "$f"; then
        echo "gate misconfigured: $home_suffix no longer defines \`$def\`."
        echo "The one ascent moved, was renamed, or lost its \`pub\` export — so this gate is counting"
        echo "marker spellings against a home that does not hold the law, and an out-of-crate harness"
        echo "has nothing to call. Point \`home_suffix\`/\`home_defines\` in"
        echo "scripts/ban-workspace-root-ascent-copies.sh at the law's new shape in the same change."
        exit 1
      fi
    done
    continue
  fi
  hit="$(scan "$f")"
  n="$(count "$hit")"
  idx=-1
  for i in "${!exempt_suffix[@]}"; do
    if [[ "$f" == *"${exempt_suffix[i]}" ]]; then idx=$i; break; fi
  done
  if [[ $idx -ge 0 ]]; then
    seen[idx]=1
    found[idx]="$n"
    hits[idx]="$hit"
    continue
  fi
  [[ $n -gt 0 ]] && violations+="$hit"$'\n'
done

failed=0

# --- The home: present, and spelling the marker EXACTLY as often as the law says -------------------
if [[ $home_seen -eq 0 ]]; then
  echo "gate misconfigured: the sanctioned home $home_suffix was not found under: ${dirs[*]}"
  echo "The law moved or the file was renamed — update the roster in"
  echo "scripts/ban-workspace-root-ascent-copies.sh. An exemption that matches nothing is a retired"
  echo "gate, not a pass."
  exit 1
fi
if [[ "$home_prod_found" -ne "$home_prod_count" ]]; then
  echo "The sanctioned home $home_suffix spells \`$marker\` $home_prod_found time(s) in production"
  echo "code (expected $home_prod_count). An extra spelling is a second ascent inside the law's own file; a"
  echo "missing one means the ascent no longer looks for the marker at all and every caller silently"
  echo "resolved its own start dir instead of the workspace root."
  printf '%s' "${home_prod_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi
if [[ "$home_test_found" -ne "$home_test_count" ]]; then
  echo "The sanctioned home $home_suffix spells \`$marker\` $home_test_found time(s) under"
  echo "\`#[cfg(test)]\` (expected $home_test_count). Those fixtures CREATE the marker to build synthetic"
  echo "checkouts; a change to the count is a change to what the ascent is proven against, so move it"
  echo "deliberately in scripts/ban-workspace-root-ascent-copies.sh — a test half is also the likeliest"
  echo "hiding place for a real second ascent."
  printf '%s' "${home_test_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

# --- The roster: every entry still present, still spelling it exactly as declared ------------------
for i in "${!exempt_suffix[@]}"; do
  if [[ ${seen[$i]} -eq 0 ]]; then
    echo "gate misconfigured: ${exempt_suffix[$i]} is on the roster of files that may name the marker"
    echo "\`$marker\` but no such file was scanned under: ${dirs[*]}. An entry that matches nothing is a"
    echo "widened blind spot, not a pass — drop it, or point it at the file's new path."
    failed=1
  elif [[ "${found[$i]}" -ne "${exempt_count[$i]}" ]]; then
    echo "${exempt_suffix[$i]} names \`$marker\` ${found[$i]} time(s) (roster says ${exempt_count[$i]})."
    echo "An extra spelling is a second ascent wearing this entry's exemption; a missing one means the"
    echo "reason the entry was granted is gone. Fix the code, or update the count in"
    echo "scripts/ban-workspace-root-ascent-copies.sh deliberately — never delete the scan."
    printf '%s' "${hits[$i]:-}" | grep -vE '^[[:space:]]*$' || true
    failed=1
  fi
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A copy of the workspace-root ascent: this file spells the marker \`$marker\` itself instead of"
  echo "calling \`$law()\` (AGENTS.md \"One law, one predicate\"; design §17, where \`bench-vm\`'s"
  echo "hand-rolled third copy was the last open entry). A drifted ascent does not fail to compile —"
  echo "it silently anchors on a DIFFERENT directory than every other vmcell path:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  echo "If the caller genuinely needs to name the marker (an error message quoting it at an operator,"
  echo "a fixture creating it), say so on the roster in scripts/ban-workspace-root-ascent-copies.sh"
  echo "with its count and its reason — the ${#exempt_suffix[@]} entry/entries there earned it."
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the marker \`$marker\` is spelled only by $law's core in $home_suffix"
echo "($home_prod_count in production, $home_test_count in its fixtures), plus the ${#exempt_suffix[@]} rostered file(s) at their"
echo "declared counts; every other site under ${dirs[*]} calls the one ascent (${#files[@]} file(s) scanned)"
