#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the two ROOTFS KEY laws that a rootfs producer
# and a rootfs consumer must spell identically, as a POSITIVE structural gate.
#
# The kernel sibling (`ban-kernel-key-composers.sh`) exists because the kernel artifact-key and
# pin-key laws HAD already been byte-duplicated by a builder and re-derived by two consumers before
# anyone noticed. v33 delta 6 (§10.5) mirrors that whole shape onto the rootfs kind, which means it
# mirrors the hazard too — and the rootfs hazard is strictly worse in one respect: the flat
# `rootfs_image`/`rootfs_digest` pins are read by `resolve_builder_base`, which picks the image that
# builds *kernels*. A drift there repoints a consumer the reshape was never about.
#
#   ARM 1 — the ARTIFACT-KEY law, `rootfs_artifact_key(label)`: the `StageOutputs`/`StageInputs`
#           artifact-map key (`"rootfs"` / `"rootfs-<label>"`) a producer registers its packed image
#           under and every downstream stage reads. Flagged shape: a string literal composing
#           `rootfs-` immediately followed by an interpolation — `format!("rootfs-{label}")`.
#
#   ARM 2 — the PIN-KEY law, `rootfs_pin_key(label, sub_key)`: the FLATTENED pins key
#           (`rootfs_image` / `rootfs_<label>_image`) the pins flattener emits and every rootfs
#           consumer reads. Flagged shape: a string literal composing `rootfs_` immediately followed
#           by an interpolation — `format!("rootfs_{label}_image")`.
#
# Why these shapes and not the bare literals: a drift between producer and consumer is only
# *possible* for the LABEL-AWARE spelling, and a label-aware duplicate must interpolate. The bare
# literals (`"rootfs_image"`, `"rootfs"`) are how tests and fixtures PIN the law's output — banning
# those would delete the very fixtures that would go red if the law changed. So this gate bans
# re-DERIVING the composition, not naming its result.
#
# Deliberately NOT flagged (verified against the tree, not from memory):
#   * `format!("rootfs-{}", hasher.finalize().to_hex())` — `RootfsStage::cache_key`'s cache-key
#     namespace prefix. It lives in the sanctioned home and is COUNTED there rather than
#     pattern-excluded, so the home cannot become a hiding place either.
#   * `"rootfs_image"` / `"rootfs"` written as a plain literal anywhere.
#
# THE SANCTIONED HOME is matched by path suffix and permits an EXACT number of matches per arm — so
# a second composer added *inside* the home is still flagged, and an exemption whose composers are
# gone is reported as stale instead of silently widening the blind spot.
#
# Usage: ban-rootfs-key-composers.sh [DIR ...]   (defaults to the workspace member trees under crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

sanctioned_suffix="/vmcell/src/artifact/rootfs/mod.rs"
# arm 1 (`"rootfs-{`): `rootfs_artifact_key`'s labelled arm + `RootfsStage::cache_key`'s prefix.
sanctioned_artifact=2
# arm 2 (`"rootfs_{`): `rootfs_pin_key`'s labelled and default arms.
sanctioned_pin=2

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
[[ ${#files[@]} -eq 0 ]] && { echo "ok: no Rust sources under: ${dirs[*]}"; exit 0; }

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

artifact_re='"rootfs-\{'
pin_re='"rootfs_\{'

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
  echo "scripts/ban-rootfs-key-composers.sh. An exemption that matches nothing is a retired gate,"
  echo "not a pass."
  exit 1
fi
if [[ "$home_artifact" -ne "$sanctioned_artifact" || "$home_pin" -ne "$sanctioned_pin" ]]; then
  echo "The sanctioned home $sanctioned_suffix holds $home_artifact artifact-key composer(s)"
  echo "(expected $sanctioned_artifact) and $home_pin pin-key composer(s) (expected $sanctioned_pin)."
  echo "A composer ADDED here is a second copy wearing the home's exemption; a composer GONE means"
  echo "the law moved and this gate is now blind. Either way: fix the code, or update the counts in"
  echo "scripts/ban-rootfs-key-composers.sh deliberately — never delete the scan."
  printf '%s' "${home_artifact_hits:-}" | grep -vE '^[[:space:]]*$' || true
  printf '%s' "${home_pin_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

if [[ -n "${artifact_violations//[$'\n']/}" ]]; then
  echo "A second spelling of the rootfs ARTIFACT-KEY law — call"
  echo "\`vmcell::artifact::rootfs::rootfs_artifact_key(label)\` instead of re-deriving"
  echo "\`rootfs-<label>\` (AGENTS.md \"One law, one predicate\"; §10.5). A producer that registers"
  echo "under a key the consumers do not read loses the artifact silently — there is no compile"
  echo "error for a map-key typo:"
  printf '%s\n' "$artifact_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ -n "${pin_violations//[$'\n']/}" ]]; then
  echo "A second spelling of the rootfs PIN-KEY law — call"
  echo "\`vmcell::artifact::rootfs::rootfs_pin_key(label, sub_key)\`, the one composer the pins"
  echo "FLATTENER emits through, instead of re-deriving \`rootfs_<label>_<sub_key>\` (AGENTS.md"
  echo "\"One law, one predicate\"; §10.5). An emitter/reader drift here is not a compile error — it"
  echo "is a runtime \`Missing rootfs_… pin\`, and on the DEFAULT label it silently repoints"
  echo "\`resolve_builder_base\`, which picks the image that builds kernels:"
  printf '%s\n' "$pin_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the rootfs artifact-key and pin-key laws are composed only in"
echo "$sanctioned_suffix ($sanctioned_artifact + $sanctioned_pin sanctioned composers);"
echo "every other site calls rootfs_artifact_key / rootfs_pin_key (scanned: ${dirs[*]})"
