#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the F7 dev-override ENTRY KEY spelling —
# `unpinned_path` — which is single-sourced through `vmcell::artifact::registry::UNPINNED_PATH_KEY`
# (design §10.5, v33 delta 6c).
#
# WHY THIS EXISTS. The key is read by SIX independent sites: the `rootfs` entry parser, the
# `handlers` entry parser, both flattener arms, `RootfsStage::unpinned_path` / `GuestToolsStage`'s
# override arm, and `bundle`'s refusal scan (`unpinned_registration_pins`, which matches the
# flattened key's SUFFIX). A misspelling in any one of them is not a compile error and not a test
# failure in the obvious direction: a parser that accepts `unpinned-path` refuses the operator's
# `unpinned_path` as an unknown key (loud, fine), but a *refusal* scan that looks for the wrong
# suffix silently BUNDLES an unpinned registration — the one thing F7 says vmcell will not do, and
# the failure has no symptom until a consumer cites a manifest that means "whatever was at that
# path that day". So the spelling is a const, and this bans a second string literal of it.
#
# THE LAW: exactly one string literal `"unpinned_path"` exists in production Rust — the const's own
# definition. Every other site names the const.
#
# SCOPE, deliberately narrow (a gate that flags fixtures gets weakened until it flags nothing):
#   * only files under a `src/` directory — the in-repo source-scan convention. `tests/`,
#     `benches/`, `examples/` and `fuzz/` are dev targets whose JSON fixtures MUST spell the key
#     literally: a fixture that composed the key from the const could not detect the const changing.
#   * `//` line comments (and so `///` / `//!` doc comments) stripped before matching, so prose
#     naming the key — which the const's own rustdoc does twice — is never a false positive.
#   * truncated at the first `#[cfg(test)]`, same convention and same reason: the unit-test JSON
#     fixtures in `artifact/bundle.rs` and `vmcell-cli/src/main.rs` are the assertions, not copies
#     of the law. (Note `#[cfg(not(test))]` does not contain that literal and so does not truncate.)
#
# THE SANCTIONED HOME is matched by path suffix and permits an EXACT number of matches — so a
# second literal added *inside* the home is still flagged, and a home that lost its definition is
# reported as a stale exemption (a gate whose law moved away is blind, not green).
#
# Usage: ban-unpinned-path-literal.sh [DIR ...]   (defaults to crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

sanctioned_suffix="/vmcell/src/artifact/registry.rs"
# The const definition, and nothing else.
sanctioned_count=1
# The literal, quoted — the shape a second copy has to take. A bare `unpinned_path` in an
# identifier (`UNPINNED_PATH_KEY`, `unpinned_path()`) is not a spelling of the key.
literal_re='"unpinned_path"'

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -path '*/src/*' -print0
  done
)
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under a src/ directory in: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

# Production text only: comments stripped, truncated at the first `#[cfg(test)]`.
scan() { # scan <file> <display-name>
  awk -v FN="$2" -v PAT="$literal_re" '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      if (index(code, "#[cfg(test)]") > 0) { exit }
      if (index(code, PAT) > 0) { print FN ":" FNR ": " $0 }
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
  echo "UNPINNED_PATH_KEY moved or the file was renamed — update the roster in"
  echo "scripts/ban-unpinned-path-literal.sh. An exemption that matches nothing is a retired gate,"
  echo "not a pass."
  exit 1
fi

if [[ "$home_count" -ne "$sanctioned_count" ]]; then
  echo "The sanctioned home $sanctioned_suffix holds $home_count \`unpinned_path\` literal(s)"
  echo "(expected $sanctioned_count). A literal ADDED here is a second copy wearing the home's"
  echo "exemption; a literal GONE means UNPINNED_PATH_KEY no longer spells the key and this gate is"
  echo "now blind. Either way: fix the code, or update the count in"
  echo "scripts/ban-unpinned-path-literal.sh deliberately — never delete the scan."
  printf '%s' "${home_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A second spelling of the F7 dev-override entry key — name"
  echo "\`vmcell::artifact::registry::UNPINNED_PATH_KEY\` instead of writing \"unpinned_path\""
  echo "(AGENTS.md \"One law, one predicate\"; §10.5, F7). The six readers of this key cannot be"
  echo "kept in agreement by the compiler, and the dangerous direction is silent: a \`bundle\`"
  echo "refusal scanning for the wrong spelling BUNDLES an unpinned registration, which is the one"
  echo "thing F7 promises vmcell will not do:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: the F7 override key is spelled once, in"
echo "$sanctioned_suffix ($sanctioned_count sanctioned literal); every other production site names"
echo "UNPINNED_PATH_KEY (scanned: ${dirs[*]})"
