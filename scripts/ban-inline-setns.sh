#!/usr/bin/env bash
# Enforces the one-law-one-predicate rule for `setns(2)` (AGENTS.md "One law, one predicate";
# design delta 8 — `net_sys::setns_net` is the designated home) as a POSITIVE structural gate.
#
# Review finding S2 (`proxy-inline-setns-duplicates-net-sys`) was two inline `unsafe { libc::setns }`
# blocks in the proxy that duplicated `net_sys::setns_net`, each carrying its own hand-written SAFETY
# proof. Routing them through the one home fixed the instance; nothing stopped a THIRD copy from
# appearing, because the rule was enforced only by review. This scanner is that enforcement: every
# raw `setns` call in `crates/` outside the two sanctioned sites is a violation.
#
# What it flags (line comments stripped first, so a `SAFETY:` note or a doc comment writing
# `setns(2)`/`setns(CLONE_NEWNET)` is never a false positive): a call-shaped `setns(` whose name is
# not part of a longer identifier —
#     unsafe { libc::setns(fd, libc::CLONE_NEWNET) }      nix::sched::setns(fd, ..)      setns(fd, ..)
# It deliberately does NOT flag:
#   * `net_sys::setns_net(fd)` — the sanctioned wrapper call (a longer identifier);
#   * `("setns", libc::SYS_setns)` — the jail seccomp allow-list entry (a name, not a call);
#   * an error string such as `"Failed to setns"` (no call parenthesis follows the name).
#
# THE SANCTIONED SITES (below) are matched by path suffix and each permits EXACTLY ONE call-shaped
# line — so a second inline `setns` added *inside* an exempt file is still flagged, and an exemption
# whose call is gone is reported as stale instead of silently widening the ban's blind spot. That
# strictness also means the exemption roster is absolute: pointing the scan at a subtree that
# excludes a sanctioned file reports the stale-exemption misconfiguration, exactly as a rename would.
# There is no in-source escape hatch: a genuinely new home belongs on this roster, in review.
#
# Usage: ban-inline-setns.sh [DIR ...]   (defaults to the workspace member trees under crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source (lib + bins + tests + benches) lives under crates/.
  dirs=(crates)
fi

# The only two places a raw `setns(2)` may be called, by path suffix, with the reason it is exempt.
sanctioned=(
  # Delta 8's designated home: the one wrapper every namespace move goes through (S2).
  "/vmcell/src/net_sys.rs"
  # `build_vmm_cmd`'s `pre_exec`: its safety proof is site-specific (async-signal-safe between
  # `fork` and `execve`, on a pre-allocated path), so it cannot call the wrapper — review S2
  # exempts it explicitly.
  "/vmcell/src/vmm/mod.rs"
)
# Parallel per-entry state: whether the file was seen in the scan, and how many calls it holds.
seen=()
count=()
for _ in "${sanctioned[@]}"; do seen+=(0); count+=(0); done

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
[[ ${#files[@]} -eq 0 ]] && { echo "ok: no Rust sources under: ${dirs[*]}"; exit 0; }

violations=""
misconfig=""
for f in "${files[@]}"; do
  idx=-1
  for i in "${!sanctioned[@]}"; do
    if [[ "$f" == *"${sanctioned[i]}" ]]; then idx=$i; seen[i]=1; break; fi
  done
  out="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose/SAFETY notes are not calls)
      # A call-shaped `setns(`: the name must not continue an identifier on either side, so
      # `setns_net(` (the sanctioned wrapper) and `SYS_setns` (the seccomp entry) never match, and a
      # bare `"Failed to setns"` string has no call parenthesis to match.
      if (code ~ /(^|[^A-Za-z0-9_])setns[[:space:]]*\(/) { print FN ":" FNR ": " $0 }
    }
  ' "$f")"
  n=0
  [[ -n "$out" ]] && n="$(printf '%s\n' "$out" | grep -c '')"
  if [[ $idx -ge 0 ]]; then
    count[idx]=$n
    # One sanctioned call each; a second one in the same file is a new site wearing an old exemption.
    [[ $n -gt 1 ]] && violations+="$out"$'\n'
    continue
  fi
  [[ -n "$out" ]] && violations+="$out"$'\n'
done

# A sanctioned entry that is absent, or present with no call left, is a STALE exemption — the gate's
# blind spot without the site it was granted for. Report it as a misconfiguration, never a pass.
for i in "${!sanctioned[@]}"; do
  if [[ ${seen[$i]} -eq 0 ]]; then
    misconfig+="  ${sanctioned[$i]}: no such file under: ${dirs[*]}"$'\n'
  elif [[ ${count[$i]} -eq 0 ]]; then
    misconfig+="  ${sanctioned[$i]}: exempted but calls no setns"$'\n'
  fi
done

if [[ -n "${misconfig//[$'\n']/}" ]]; then
  echo "gate misconfigured: a sanctioned inline-setns site is stale (moved, renamed, or refactored)."
  echo "Update the roster in scripts/ban-inline-setns.sh — an exemption that matches nothing is a"
  echo "retired gate, not a pass:"
  printf '%s' "$misconfig"
  exit 1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "Inline \`setns\` outside its one home — route the namespace move through"
  echo "\`vmcell::net_sys::setns_net\` (AGENTS.md \"One law, one predicate\"; delta 8, review S2)"
  echo "instead of writing a second raw call with its own SAFETY proof:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi
echo "ok: every setns call goes through net_sys::setns_net or its one exempt pre-exec site (scanned: ${dirs[*]})"
