#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the REGISTRY DIGEST FORMAT check — `sha256:`
# followed by 64 lowercase hex digits — whose one home is
# `vmcell::artifact::registry::reject_unpinned_digest` (design §10.5, invariant F7).
#
# WHY THIS EXISTS. F7 *is* this rule ("registration is a digest"), and it shipped written TWICE:
# `artifact::handler.rs` carried its own `reject_unpinned_digest` and `artifact/mod.rs` an inline
# copy inside `rootfs_registry_entry`. The two bodies were byte-equivalent and the two MESSAGES were
# not, so the same malformed value already told two different operators two different things — and
# when the check was tightened to reject uppercase hex (vmcell emits and compares digests lowercase,
# so an uppercase registration parsed clean and could then never verify), only one of the two copies
# would have moved. A third kind gaining a registration shape re-arms this on day one, and nothing
# about a duplicated format check is a compile error.
#
# THE FLAGGED SHAPE: a `strip_prefix("sha256:")` whose immediate neighbourhood also tests a length
# of 64 — i.e. someone re-deriving "is this a pinned digest", rather than calling the predicate.
# The window is the matching line plus the next 3, which is every spelling the two shipped copies
# used (`if hex.len() != 64 || !hex.chars().all(…)` and its `== 64 &&` inverse).
#
# DELIBERATELY NOT FLAGGED, verified against the tree rather than assumed:
#   * `handler::verify_handler_digest` and `handler::cached_blob_matches` — they strip the same
#     prefix to COMPARE bytes, and carry no length test. Comparing a digest is not deciding whether
#     it is well formed, and banning the strip itself would delete the verification the registry
#     exists to enable.
#   * `sha256_hex`, and any bare `"sha256:"` literal.
#
# SCOPE: `crates/vmcell/src` — the crate that owns the registry law and where both copies lived.
# Two same-shaped checks over DIFFERENT inputs live outside it and are deliberately out of scope,
# named here so the boundary is a decision rather than an oversight:
#   * `vmcell-cli`'s `validate_oci_digest` — the `oci2erofs --digest` CLI flag. No namespace, no
#     label, its own message, and it validates a pull reference the operator names directly rather
#     than a registration. (It does still accept uppercase; see the follow-up record.)
#   * `vmcell-daemon`'s upload sidecar hex check — a client-supplied `<name>.sha256` file's body,
#     not a `sha256:`-prefixed registration.
# Widening the scope would mean two permanent exemptions, and an exemption per near-miss is how a
# ban stops being one.
#
# THE SANCTIONED HOME is matched by path suffix and permits an EXACT number of matches, so a second
# check added *inside* the home is still flagged and a home that lost its check is reported as a
# stale exemption rather than a pass.
#
# Usage: ban-registry-digest-check.sh [DIR ...]   (defaults to crates/vmcell/src)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates/vmcell/src)
fi

sanctioned_suffix="/artifact/registry.rs"
# `reject_unpinned_digest`'s own `strip_prefix` + `len() == 64`.
sanctioned_count=1

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

# Production text only (comments stripped, truncated at the first `#[cfg(test)]`, per the in-repo
# source-scan convention), then: a `strip_prefix("sha256:")` line whose 4-line window mentions 64.
scan() { # scan <file> <display-name>
  awk -v FN="$2" '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      if (index(code, "#[cfg(test)]") > 0) { stop = 1 }
      if (stop) { next }
      lines[NR] = code
      raw[NR] = $0
      last = NR
    }
    END {
      for (i = 1; i <= last; i++) {
        if (index(lines[i], "strip_prefix(\"sha256:\")") == 0) continue
        window = ""
        for (j = i; j <= i + 3 && j <= last; j++) window = window " " lines[j]
        if (window ~ /64/) print FN ":" i ": " raw[i]
      }
    }
  ' "$1"
}
count() {
  if [[ -z "${1//[$'\n']/}" ]]; then echo 0; else printf '%s\n' "$1" | grep -c ''; fi
}

home_seen=0
home_count=0
home_hits=""
violations=""

for f in "${files[@]}"; do
  hits="$(scan "$f" "$f")"
  if [[ "$f" == *"$sanctioned_suffix" ]]; then
    home_seen=1
    home_count="$(count "$hits")"
    home_hits="$hits"
    continue
  fi
  [[ -n "${hits//[$'\n']/}" ]] && violations+="$hits"$'\n'
done

failed=0

if [[ $home_seen -eq 0 ]]; then
  echo "gate misconfigured: the sanctioned home $sanctioned_suffix was not found under: ${dirs[*]}"
  echo "The digest predicate moved or the file was renamed — update the roster in"
  echo "scripts/ban-registry-digest-check.sh. An exemption that matches nothing is a retired gate,"
  echo "not a pass."
  exit 1
fi

if [[ "$home_count" -ne "$sanctioned_count" ]]; then
  echo "The sanctioned home $sanctioned_suffix holds $home_count digest-format check(s)"
  echo "(expected $sanctioned_count). A check ADDED here is a second copy wearing the home's"
  echo "exemption; a check GONE means the law moved and this gate is now blind. Either way: fix the"
  echo "code, or update the count in scripts/ban-registry-digest-check.sh deliberately — never"
  echo "delete the scan."
  printf '%s' "${home_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A second spelling of the registry digest-format law — call"
  echo "\`registry::reject_unpinned_digest(namespace, label, digest)\` instead of re-deriving"
  echo "\`sha256:\` + 64 hex (AGENTS.md \"One law, one predicate\"; §10.5, F7). The two copies that"
  echo "shipped already disagreed about the MESSAGE, and a copy that keeps accepting uppercase hex"
  echo "accepts a registration that can then never verify:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the registry digest-format law is checked only in"
echo "$sanctioned_suffix ($sanctioned_count sanctioned check); every other site calls"
echo "reject_unpinned_digest (scanned: ${dirs[*]})"
