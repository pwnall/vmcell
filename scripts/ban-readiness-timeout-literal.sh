#!/usr/bin/env bash
# Keeps every socket-readiness ceiling NAMED (docs/81 §8, AGENTS.md "One law, one predicate").
#
# WHY THIS EXISTS. The 1 s ceiling for a VMM control socket to appear was spelled `1000` inline at
# six call sites — Cloud Hypervisor, Firecracker (twice), QEMU (twice) and crosvm — with nothing
# tying them together. Four backends independently retuning a shared latency budget is the exact
# divergence class "one law, one predicate" exists to stop, and it is invisible to review because
# every copy looks locally reasonable.
#
# The primary fix is STRUCTURAL: `vmcell::vmm::register_and_await_ready` and
# `vmcell::vmm::wait_for_vmm_socket` take no timeout argument at all — they ride the one
# `vmcell::vmm::VMM_SOCKET_READY_TIMEOUT_MS` — so re-introducing a literal at those call sites is a
# compile error, not a review miss. This scanner closes the one route left open: calling the
# lower-level `vmcell::vmm::wait_for_socket` (which KEEPS its `timeout_ms` parameter, because
# virtiofsd's wait is legitimately paced from the `VmConfig` timeout profile) with a bare number.
#
# THE LAW. In production Rust text, no `wait_for_socket(` call may pass a bare integer literal as
# its timeout. Every ceiling is a named const, so changing one is a diff on a documented value
# rather than a number in an argument list. What counts as production text, per the in-repo
# source-scan convention (`virtiofs_pacing_gate`): `//` line comments stripped first (so prose
# writing `1000` is never a false positive) and truncated at the first `#[cfg(test)]` (a unit test
# may pass whatever short ceiling keeps it fast — `vmcell`'s own gate does exactly that).
#
# NON-VACUITY. The scan must SEE at least one readiness call in the trees it is pointed at. A run
# that matched no call at all would print "ok" while proving nothing — the way every source-scanning
# gate dies — so that is reported as a misconfiguration instead.
#
# Usage: ban-readiness-timeout-literal.sh [DIR ...]   (defaults to crates/)
# A roster that resolves to zero Rust sources is a caller bug and exits 1 — never a reassuring "ok"
# (docs/90 G4).
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources is
# to have been pointed at the wrong place (a move/reorg, or an explicit-path typo). This arm used to
# print "ok" and exit 0, short-circuiting the non-vacuity check below (docs/90 G4).
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

violations=""
calls_seen=0

for f in "${files[@]}"; do
  # Production text of one file, joined into a single line so a rustfmt-wrapped call is still seen
  # whole; then every `wait_for_socket(` / `wait_for_vmm_socket(` / `register_and_await_ready(` call
  # is truncated at its statement's `;` and inspected.
  result="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      if (index(code, "#[cfg(test)]") > 0) { nextfile }
      gsub(/^[ \t]+|[ \t]+$/, "", code)
      prod = prod " " code
    }
    END {
      n = 0
      bad = 0
      rest = prod
      while ((at = index(rest, "wait_for_socket(")) > 0) {
        rest = substr(rest, at)
        # `wait_for_vmm_socket(` also ends in `wait_for_socket(`; it takes NO ceiling, so seeing it
        # counts toward non-vacuity but can never carry a literal.
        end = index(rest, ";")
        call = (end > 0) ? substr(rest, 1, end) : rest
        n++
        # A bare integer literal argument: `, 1000,` or `, 1000)` — a named const or an expression
        # (`cfg.timeouts…as u64`) never matches.
        if (call ~ /,[ ]*[0-9][0-9_]*[ ]*[,)]/) {
          bad++
          print "LITERAL\t" FN "\t" call
        }
        rest = substr(rest, length("wait_for_socket(") + 1)
      }
      rest = prod
      while ((at = index(rest, "register_and_await_ready(")) > 0) {
        rest = substr(rest, at)
        end = index(rest, ";")
        call = (end > 0) ? substr(rest, 1, end) : rest
        n++
        if (call ~ /,[ ]*[0-9][0-9_]*[ ]*[,)]/) {
          bad++
          print "LITERAL\t" FN "\t" call
        }
        rest = substr(rest, length("register_and_await_ready(") + 1)
      }
      if (n > 0) print "CALLS\t" n
    }
  ' "$f")"

  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      CALLS) calls_seen=$((calls_seen + a)) ;;
      LITERAL) violations+="  $a: $b"$'\n' ;;
    esac
  done <<<"$result"
done

if [[ $calls_seen -eq 0 ]]; then
  echo "gate misconfigured: no readiness call (\`wait_for_socket\`/\`wait_for_vmm_socket\`/"
  echo "\`register_and_await_ready\`) found in production text under: ${dirs[*]}"
  echo "A scan that matches nothing reports 'ok' while proving nothing. If the helpers were renamed,"
  echo "update scripts/ban-readiness-timeout-literal.sh — do not delete the scan."
  exit 1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A socket-readiness ceiling is spelled as a bare literal. Every ceiling is NAMED — the VMM"
  echo "control-socket one is \`vmcell::vmm::VMM_SOCKET_READY_TIMEOUT_MS\` (and its two entry"
  echo "points take no timeout argument at all); anything else gets its own documented const beside"
  echo "its call site. Six inline \`1000\`s across four backends is what this prevents (docs/81 §8):"
  printf '%s' "$violations"
  exit 1
fi

echo "ok: all $calls_seen readiness call(s) in production text carry a named ceiling or none"
echo "(scanned: ${dirs[*]})"
