#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the two KERNEL KEY laws that a kernel producer
# and a kernel consumer must spell identically, as a POSITIVE structural gate.
#
# Review docs/81 §8/§9: "the kernel artifact-key law is a private method byte-duplicated in
# `vmcell-kernel-builder`, and the `kernel_<label>_source_url` pin-key law is composed inline in the
# flattener and re-derived by both consumers — none exported"; §9: "triplicated and unexported, so a
# downstream builder must re-derive both spellings rather than call them". Both laws are now exported
# from `vmcell::artifact::kernel` and every site routes through them:
#
#   ARM 1 — the ARTIFACT-KEY law, `kernel_artifact_key(label)`: the `StageOutputs`/`StageInputs`
#           artifact-map key (`"kernel"` / `"kernel-<label>"`) a producer registers its `vmlinux`
#           under and every downstream stage reads. Flagged shape: a string literal composing
#           `kernel-` immediately followed by an interpolation — `format!("kernel-{label}")`,
#           `format!("kernel-{}", label)`.
#
#   ARM 2 — the PIN-KEY law, `kernel_pin_key(label, sub_key)`: the FLATTENED pins key
#           (`kernel_source_url` / `kernel_<label>_source_url`) the pins flattener emits and every
#           kernel producer reads. Flagged shape: a string literal composing `kernel_` immediately
#           followed by an interpolation — `format!("kernel_{label}_source_url")`,
#           `format!("kernel_{}_source_sha256", l)`.
#
# Why these shapes and not the bare literals: a drift between producer and consumer is only
# *possible* for the LABEL-AWARE spelling, and a label-aware duplicate must interpolate. The bare
# literals (`"kernel_source_url"`, `"kernel"`) are how tests, benches and the `blake3_cache_key`
# example PIN the law's output — banning those would delete the very fixtures that would go red if
# the law changed. So this gate bans re-DERIVING the composition, not naming its result.
#
# Deliberately NOT flagged (verified against the tree, not from memory):
#   * `format!("kernel_fragments_{name}")` — `fragment_pin_key`'s own law, a different key family
#     (the `{` does not immediately follow `kernel_`);
#   * `format!("kernel-prebuilt-{}", hash)` — the prebuilt stage's cache-key prefix (likewise);
#   * `"kernel_source_url"` / `"kernel"` written as a plain literal anywhere.
#
# THE SANCTIONED HOME (below) is matched by path suffix and permits an EXACT number of matches per
# arm — so a second composer added *inside* the home is still flagged, and an exemption whose
# composers are gone is reported as stale instead of silently widening the blind spot. Note the home
# legitimately holds ONE arm-1 match that is not the artifact-key law: `KernelStage::cache_key`'s
# `CacheKey(format!("kernel-{}", hash))` prefix, which is a cache-key namespace, not an artifact key
# — it is counted, not pattern-excluded, so it cannot become a hiding place either.
#
# Usage: ban-kernel-key-composers.sh [DIR ...]   (defaults to the workspace member trees under crates/)
# A roster that resolves to zero Rust sources is a caller bug and exits 1 — never a reassuring "ok"
# (docs/90 G4).
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source (lib + bins + tests + benches) lives under crates/.
  # `examples/downstream-kernel/` is a SEPARATE workspace (the out-of-tree consumer gate) and is
  # scanned only when named explicitly.
  dirs=(crates)
fi

# The one home for both laws, with the exact number of composed spellings it may hold.
sanctioned_suffix="/vmcell/src/artifact/kernel.rs"
# arm 1 (`"kernel-{`): `kernel_artifact_key`'s labelled arm + `KernelStage::cache_key`'s prefix.
sanctioned_artifact=2
# arm 2 (`"kernel_{`): `kernel_pin_key`'s labelled and default arms.
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
# `SAFETY:`/rationale note writing the shape is never a false positive.
scan() { # scan <file> <awk-regex>
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

artifact_re='"kernel-\{'
pin_re='"kernel_\{'

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
  echo "scripts/ban-kernel-key-composers.sh. An exemption that matches nothing is a retired gate,"
  echo "not a pass."
  exit 1
fi
if [[ "$home_artifact" -ne "$sanctioned_artifact" || "$home_pin" -ne "$sanctioned_pin" ]]; then
  echo "The sanctioned home $sanctioned_suffix holds $home_artifact artifact-key composer(s)"
  echo "(expected $sanctioned_artifact) and $home_pin pin-key composer(s) (expected $sanctioned_pin)."
  echo "A composer ADDED here is a second copy wearing the home's exemption; a composer GONE means"
  echo "the law moved and this gate is now blind. Either way: fix the code, or update the counts in"
  echo "scripts/ban-kernel-key-composers.sh deliberately — never delete the scan."
  printf '%s' "${home_artifact_hits:-}" | grep -vE '^[[:space:]]*$' || true
  printf '%s' "${home_pin_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

if [[ -n "${artifact_violations//[$'\n']/}" ]]; then
  echo "A second spelling of the kernel ARTIFACT-KEY law — call"
  echo "\`vmcell::artifact::kernel::kernel_artifact_key(label)\` (and \`config_artifact_key\` for its"
  echo "sidecar) instead of re-deriving \`kernel-<label>\` (AGENTS.md \"One law, one predicate\";"
  echo "docs/81 §8). A producer that registers under a key the consumers do not read loses the"
  echo "artifact silently — there is no compile error for a map-key typo:"
  printf '%s\n' "$artifact_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ -n "${pin_violations//[$'\n']/}" ]]; then
  echo "A second spelling of the kernel PIN-KEY law — call"
  echo "\`vmcell::artifact::kernel::kernel_pin_key(label, sub_key)\`, the one composer the pins"
  echo "FLATTENER emits through, instead of re-deriving \`kernel_<label>_<sub_key>\` (AGENTS.md"
  echo "\"One law, one predicate\"; docs/81 §8). An emitter/reader drift here is not a compile"
  echo "error — it is a runtime \`Missing kernel_… pin\` on a cold build:"
  printf '%s\n' "$pin_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the kernel artifact-key and pin-key laws are composed only in"
echo "$sanctioned_suffix ($sanctioned_artifact + $sanctioned_pin sanctioned composers);"
echo "every other site calls kernel_artifact_key / kernel_pin_key (scanned: ${dirs[*]})"
