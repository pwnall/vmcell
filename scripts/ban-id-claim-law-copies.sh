#!/usr/bin/env bash
# Enforces the one-law-one-predicate rule for the **cross-process id-claim law** — the lock files
# `VmidAllocator::shared` / `SegmentIdAllocator::shared` write and the orphan sweeps read back to
# decide whether a live process still owns an id (AGENTS.md "One law, one predicate";
# `vmcell::orchestrator::IdClaim`).
#
# Why a scanner rather than review: both halves of this law drift SILENTLY and fail OPEN. The
# writer and the reader agree only by naming the same directory and reading liveness the same way,
# and neither agreement is a compile error — a second spelling still builds, still passes every
# unit test (which inject their own directories), and simply reports "nobody owns this id" for
# every id on the host. The consequence is the recorded A6 hazard in its worst form: the sweep
# deletes a *running* sibling's namespace, tap, cgroup slice and scratch dir, and the log line says
# it reclaimed an orphan.
#
# TWO ARMS, because the law has two halves and each can be copied on its own:
#
# ARM 1 — WHERE the registry is. A `"/tmp/vmcell-vmid"` or `"/tmp/vmcell-segid"` string literal
# anywhere but the two `const SHARED_*_CLAIM_DIR` definitions. Line comments (including `///` and
# `//!` doc comments) are stripped before matching, so the many rustdoc mentions of the path are
# never false positives — only a literal in CODE is a second spelling.
#
# ARM 2 — HOW liveness is decided. A bare `/proc/{pid}` existence probe — the "is the owner still
# alive?" test — outside `FsIdClaim::owner_is_live`. Matched only when the interpolation is the
# WHOLE path (`format!("/proc/{pid}")`), so reading a file under it (`/proc/{pid}/stat`,
# `/proc/{pid}/status`) is not flagged: those answer questions about a process that is known to
# exist, which is a different question from whether it exists at all.
#
# THE SANCTIONED SITES are matched by path suffix and permit an EXACT count per arm, so a second
# copy added *inside* an exempt file is still flagged, and an exemption whose subject is gone is
# reported as stale rather than silently widening the blind spot. There are two, and the second is
# deliberate: the live segment battery asserts the lock file's whole lifecycle from OUTSIDE the
# crate, where the `pub(crate)` consts are unreachable — and it is the leg that would go red if
# production moved the directory, which is the coverage a scanner cannot supply.
#
# Usage: ban-id-claim-law-copies.sh [DIR ...]   (defaults to the workspace member trees under crates/)
# A roster that resolves to zero Rust sources is a caller bug and exits 1 — never a reassuring "ok"
# (docs/90 G4).
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

# The roster: `<path suffix>:<claim-directory literals>:<liveness probes>`. The first entry is the
# law's HOME (two directory literals, one per id space; one liveness probe) and is additionally
# required to spell those literals as the `const SHARED_*_CLAIM_DIR` definitions. The second is the
# out-of-crate live assertion described above.
sanctioned=(
  "/vmcell/src/orchestrator.rs:2:1"
  "/vmcell/tests/segment.rs:1:0"
)
home="/vmcell/src/orchestrator.rs"
seen=()
got_dirs=()
got_probe=()
for _ in "${sanctioned[@]}"; do seen+=(0); got_dirs+=(0); got_probe+=(0); done

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

dir_violations=""
probe_violations=""
bad_const=""

for f in "${files[@]}"; do
  # ARM 1 — the claim-directory literal, in code only.
  hits_dir="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop line and doc comments before matching
      if (code ~ /"\/tmp\/vmcell-(vmid|segid)"/) { print FN ":" FNR ": " $0 }
    }
  ' "$f")"
  # ARM 2 — the bare `/proc/{…}` liveness probe: the interpolation must END the path, so
  # `/proc/{pid}/stat` (a read of a known process) does not match.
  hits_probe="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      if (code ~ /\/proc\/\{[A-Za-z0-9_]+\}"/) { print FN ":" FNR ": " $0 }
    }
  ' "$f")"

  cd=0; cp=0
  [[ -n "${hits_dir//[$'\n']/}" ]] && cd="$(printf '%s\n' "$hits_dir" | grep -c '')"
  [[ -n "${hits_probe//[$'\n']/}" ]] && cp="$(printf '%s\n' "$hits_probe" | grep -c '')"

  idx=-1
  for i in "${!sanctioned[@]}"; do
    suffix="${sanctioned[i]%%:*}"
    if [[ "$f" == *"$suffix" ]]; then idx=$i; seen[i]=1; break; fi
  done
  if [[ $idx -ge 0 ]]; then
    entry="${sanctioned[idx]}"
    exp_d="$(cut -d: -f2 <<<"$entry")"
    exp_p="$(cut -d: -f3 <<<"$entry")"
    got_dirs[idx]=$cd
    got_probe[idx]=$cp
    # Inside the HOME, the literals must BE the const definitions — a third literal, or one hiding
    # in a function body, is a second spelling wearing the home's exemption.
    if [[ "$f" == *"$home" ]]; then
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        grep -qE 'const SHARED_(VMID|SEGID)_CLAIM_DIR' <<<"$line" || bad_const+="$line"$'\n'
      done <<<"$hits_dir"
    fi
    [[ $cd -gt $exp_d ]] && dir_violations+="$hits_dir"$'\n'
    [[ $cp -gt $exp_p ]] && probe_violations+="$hits_probe"$'\n'
    continue
  fi
  [[ $cd -gt 0 ]] && dir_violations+="$hits_dir"$'\n'
  [[ $cp -gt 0 ]] && probe_violations+="$hits_probe"$'\n'
done

misconfig=""
for i in "${!sanctioned[@]}"; do
  entry="${sanctioned[i]}"
  suffix="${entry%%:*}"
  exp_d="$(cut -d: -f2 <<<"$entry")"
  exp_p="$(cut -d: -f3 <<<"$entry")"
  if [[ ${seen[$i]} -eq 0 ]]; then
    misconfig+="  $suffix: no such file under: ${dirs[*]}"$'\n'
    continue
  fi
  [[ ${got_dirs[$i]} -lt $exp_d ]] && \
    misconfig+="  $suffix: holds ${got_dirs[$i]} claim-directory literal(s), expected $exp_d"$'\n'
  [[ ${got_probe[$i]} -lt $exp_p ]] && \
    misconfig+="  $suffix: holds ${got_probe[$i]} /proc/{pid} liveness probe(s), expected $exp_p"$'\n'
done
if [[ -n "${misconfig//[$'\n']/}" ]]; then
  echo "gate misconfigured: the id-claim law's one home is stale (moved, renamed, or refactored)."
  echo "Update the roster in scripts/ban-id-claim-law-copies.sh — an exemption that matches nothing"
  echo "is a retired gate, not a pass:"
  printf '%s' "$misconfig"
  exit 1
fi

failed=0
if [[ -n "${bad_const//[$'\n']/}" ]]; then
  echo "A claim-directory literal inside the law's own home that is NOT one of the two"
  echo "\`const SHARED_*_CLAIM_DIR\` definitions — the allocators and the sweeps agree only by"
  echo "reading the same const:"
  printf '%s\n' "$bad_const" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ -n "${dir_violations//[$'\n']/}" ]]; then
  echo "An inline id-claim directory literal — read it from"
  echo "\`orchestrator::SHARED_VMID_CLAIM_DIR\` / \`SHARED_SEGID_CLAIM_DIR\` instead. A second"
  echo "spelling makes the sweep read an empty registry and reap a LIVE sibling's resources:"
  printf '%s\n' "$dir_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ -n "${probe_violations//[$'\n']/}" ]]; then
  echo "A second \`/proc/{pid}\` owner-liveness probe — route it through"
  echo "\`FsIdClaim::owner_is_live\`, the one law \`try_claim\` and both sweeps share, so"
  echo "\"claimed\" cannot come to mean two different things:"
  printf '%s\n' "$probe_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the id-claim directories and the owner-liveness probe are spelled only in"
echo "orchestrator.rs's one law (scanned: ${dirs[*]})"
