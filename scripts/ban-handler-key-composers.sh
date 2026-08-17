#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the two HANDLER KEY laws that a handler producer
# and a handler consumer must spell identically, as a POSITIVE structural gate.
#
# The third kind, guarded like the other two (`ban-kernel-key-composers.sh`,
# `ban-rootfs-key-composers.sh`) — added with the kind, not after a duplicate has already diverged,
# which is the only reason either sibling exists.
#
#   ARM 1 — the ARTIFACT-KEY law, `handler_artifact_key(label)`: the `StageOutputs`/`StageInputs`
#           artifact-map key (`"guest_tools"` / `"guest_tools-<label>"`) a handler producer registers
#           its binary under and the rootfs pack tail reads. Flagged shape: a string literal
#           composing `guest_tools-` immediately followed by an interpolation.
#
#   ARM 2 — the PIN-KEY law, `handler_pin_key(label, sub_key)`: the FLATTENED pins key
#           (`handler_build` / `handler_<label>_digest`) the pins flattener emits. Flagged shape: a
#           string literal composing `handler_` immediately followed by an interpolation.
#
# Why these shapes and not the bare literals: a drift between producer and consumer is only
# *possible* for the LABEL-AWARE spelling, and a label-aware duplicate must interpolate. The bare
# literals (`"guest_tools"`, `"handler_build"`) are how tests and fixtures PIN the law's output —
# banning those would delete the very fixtures that would go red if the law changed.
#
# THE SANCTIONED HOME is matched by path suffix and permits an EXACT number of matches per arm — so
# a second composer added *inside* the home is still flagged, and an exemption whose composers are
# gone is reported as stale instead of silently widening the blind spot.
#
# Usage: ban-handler-key-composers.sh [DIR ...]   (defaults to the workspace member trees under crates/)
# A roster that resolves to zero Rust sources is a caller bug and exits 1 — never a reassuring "ok"
# (docs/90 G4).
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

sanctioned_suffix="/vmcell/src/artifact/handler.rs"
# arm 1 (`"guest_tools-{`): `handler_artifact_key`'s labelled arm.
sanctioned_artifact=1
# arm 2 (`"handler_{`): `handler_pin_key`'s labelled and default arms.
sanctioned_pin=2

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources is
# to have been pointed at the wrong place (a move/reorg, or an explicit-path typo). This arm used to
# print "ok" and exit 0, which short-circuited even the stale-home report below (docs/90 G4).
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

# Every match of one arm's pattern in one file, line comments stripped first so a doc comment or a
# rationale note writing the shape is never a false positive.
scan() { # scan <file> <display-name> <awk-regex>
  awk -v FN="$2" -v PAT="$3" '
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose is not code)
      if (code ~ PAT) { print FN ":" FNR ": " $0 }
    }
  ' "$1"
}
count() {
  if [[ -z "${1//[$'\n']/}" ]]; then echo 0; else printf '%s\n' "$1" | grep -c ''; fi
}

artifact_re='"guest_tools-\{'
pin_re='"handler_\{'

home_seen=0
home_artifact=0
home_pin=0
artifact_violations=""
pin_violations=""

for f in "${files[@]}"; do
  a="$(scan "$f" "$f" "$artifact_re")"
  p="$(scan "$f" "$f" "$pin_re")"
  if [[ "$f" == *"$sanctioned_suffix" ]]; then
    home_seen=1
    home_artifact="$(count "$a")"
    home_pin="$(count "$p")"
    home_artifact_hits="$a"
    home_pin_hits="$p"
    continue
  fi
  [[ -n "${a//[$'\n']/}" ]] && artifact_violations+="$a"$'\n'
  [[ -n "${p//[$'\n']/}" ]] && pin_violations+="$p"$'\n'
done

failed=0

# A home that moved, was renamed, or lost its composers is a STALE exemption — the gate's blind spot
# without the site it was granted for. Report it as a misconfiguration, never a pass.
if [[ $home_seen -eq 0 ]]; then
  echo "gate misconfigured: the sanctioned home $sanctioned_suffix was not found under: ${dirs[*]}"
  echo "The two laws moved or the file was renamed — update the roster in"
  echo "scripts/ban-handler-key-composers.sh. An exemption that matches nothing is a retired gate,"
  echo "not a pass."
  exit 1
fi
if [[ "$home_artifact" -ne "$sanctioned_artifact" || "$home_pin" -ne "$sanctioned_pin" ]]; then
  echo "The sanctioned home $sanctioned_suffix holds $home_artifact artifact-key composer(s)"
  echo "(expected $sanctioned_artifact) and $home_pin pin-key composer(s) (expected $sanctioned_pin)."
  echo "A composer ADDED here is a second copy wearing the home's exemption; a composer GONE means"
  echo "the law moved and this gate is now blind. Either way: fix the code, or update the counts in"
  echo "scripts/ban-handler-key-composers.sh deliberately — never delete the scan."
  printf '%s' "${home_artifact_hits:-}" | grep -vE '^[[:space:]]*$' || true
  printf '%s' "${home_pin_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

if [[ -n "${artifact_violations//[$'\n']/}" ]]; then
  echo "A second spelling of the handler ARTIFACT-KEY law — call"
  echo "\`vmcell::artifact::handler::handler_artifact_key(label)\` instead of re-deriving"
  echo "\`guest_tools-<label>\` (AGENTS.md \"One law, one predicate\"; §10.5). A producer that"
  echo "registers under a key the rootfs pack tail does not read loses the handler silently — the"
  echo "resulting rootfs boots with no /vmcell-tools symlinks, and every custom-\`init=\` target in"
  echo "the suite becomes a guest kernel panic:"
  printf '%s\n' "$artifact_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ -n "${pin_violations//[$'\n']/}" ]]; then
  echo "A second spelling of the handler PIN-KEY law — call"
  echo "\`vmcell::artifact::handler::handler_pin_key(label, sub_key)\`, the one composer the pins"
  echo "FLATTENER emits through, instead of re-deriving \`handler_<label>_<sub_key>\` (AGENTS.md"
  echo "\"One law, one predicate\"; §10.5). An emitter/reader drift here is not a compile error:"
  printf '%s\n' "$pin_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the handler artifact-key and pin-key laws are composed only in"
echo "$sanctioned_suffix ($sanctioned_artifact + $sanctioned_pin sanctioned composers);"
echo "every other site calls handler_artifact_key / handler_pin_key (scanned: ${dirs[*]})"
