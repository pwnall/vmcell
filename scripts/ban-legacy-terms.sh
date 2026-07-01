#!/usr/bin/env bash
# Enforces design v14 §10.7: the crate-rename regression gate. After the imp-testing → vmcell
# rename, the legacy vocabulary must not creep back into non-historical code. This scanner flags
# the retired tokens so a stray re-introduction (a copy-pasted env var, an old binary name, the
# `rootless`/`TestVm` spellings, an `imp-*` internal prefix) fails CI instead of silently landing.
#
# Flagged tokens (in src/ tests/ benches/ by default; any file kind, not just *.rs):
#   * `TestVm`                                         (renamed harness type → VmCell/Imp)
#   * `[Rr]ootless`                                    (renamed network/integration tier → unprivileged)
#   * `imp[_-]testing` / `Imp-testing`                 (old crate / project name → vmcell)
#   * `imp-guest-agent` / `imp-test-runner` / `imp-guest-tools`   (old binary names → vmcell-*)
#   * `IMP_KERNEL` / `IMP_ROOTFS` / `IMP_ARTIFACTS_DIR` / `IMP_CH_BIN`   (old env vars → VMCELL_*)
#   * `(^|[^A-Za-z0-9_])imp-`                          (the imp-vm-/imp-net-/imp-tap/imp-drop/imp-fc/
#                                                       imp-vsock/imp-serial/imp-smoltcp/imp-bench/...
#                                                       internal hyphen-prefix family → vmcell-*)
#   * `imp_(vmid|host_paths|netns)`                    (old internal identifiers)
#
# Deliberately NOT flagged (per §10.7-C): the capitalized standalone word `Imp` (the origin test
# harness, retained by design) — `Imp` and `Imp's` are fine — and the ordinary English words
# `implementation` / `import`. Every banned `imp` pattern requires a trailing `-`/`_` (or the
# uppercase `IMP_` env form), so none of those legitimate spellings can match.
#
# Line comments are stripped before pattern-matching, so prose in a comment that mentions a banned
# word (e.g. a note about the old name) is not a false positive — but the exemption marker (below)
# is honoured first, before stripping.
#
# There are NO blanket whole-file exemptions. A genuinely-justified legacy mention must carry a
# per-line exemption marker on the same line:
#   let old = "imp-testing"; // allow-legacy-term: <reason>
# so every surviving legacy token is justified in place and shows up in review.
#
# Usage: ban-legacy-terms.sh [DIR ...]   (defaults to the workspace member trees under crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source (lib + bins + tests + benches) lives under crates/.
  dirs=(crates)
fi

violations=""
append() { if [[ -n "$1" ]]; then violations+="$1"$'\n'; fi; }

# Gather candidate files once (NUL-safe). Scan every file kind, not just *.rs — env vars and
# legacy names hide in shell/toml/markdown fixtures too.
mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -print0
  done
)
[[ ${#files[@]} -eq 0 ]] && { echo "ok: no files to scan under: ${dirs[*]}"; exit 0; }

for f in "${files[@]}"; do
  # Skip binary files: -I makes grep report no match for binary, `.` matches any text line.
  grep -Iq . "$f" 2>/dev/null || continue
  out="$(awk -v FN="$f" '
    function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
    {
      line = $0
      # Honour the per-line exemption marker first (it lives in the comment), before stripping.
      if (line ~ /allow-legacy-term:/) next
      code = line
      sub(/\/\/.*/, "", code)   # drop the line comment for pattern analysis
      if (code ~ /TestVm/ \
       || code ~ /[Rr]ootless/ \
       || code ~ /imp[_-]testing/ \
       || code ~ /Imp-testing/ \
       || code ~ /imp-guest-agent|imp-test-runner|imp-guest-tools/ \
       || code ~ /IMP_KERNEL|IMP_ROOTFS|IMP_ARTIFACTS_DIR|IMP_CH_BIN/ \
       || code ~ /(^|[^A-Za-z0-9_])imp-/ \
       || code ~ /imp_(vmid|host_paths|netns)/) {
        print FN ":" NR ": " trim(line)
      }
    }
  ' "$f")"
  append "$out"
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "Forbidden legacy term(s) — the imp-testing → vmcell rename (design v14 §10.7) must hold."
  echo "Rename to the vmcell vocabulary, or add a trailing '// allow-legacy-term: <reason>' marker"
  echo "if the mention is genuinely justified (e.g. a historical reference in non-historical code):"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi
echo "ok: no legacy imp-testing/rootless/TestVm/imp-* tokens (scanned: ${dirs[*]})"
