#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-readiness-timeout-literal.sh (docs/81 §8).
#
# A ban script that cannot go red is theater (AGENTS.md rule 2), and a source scan's characteristic
# failure is passing VACUOUSLY. Every arm is driven here:
#
#   * a bare `1000` in a `wait_for_socket` call is flagged                 → deleting the pattern reddens;
#   * the same literal in a `register_and_await_ready` call is flagged     → the second arm reddens;
#   * a NAMED const, an expression argument, and the ceiling-less
#     `wait_for_vmm_socket` are NOT flagged                                → an over-broad grep reddens;
#   * a literal in a comment, or inside `#[cfg(test)]`, is NOT flagged     → over-broad matching reddens;
#   * a rustfmt-wrapped call (one argument per line) is still seen whole   → a line-at-a-time scan reddens;
#   * a tree with no readiness call at all is a misconfiguration, not "ok" → the vacuity arm reddens;
#   * a tree with no Rust sources at all is the same misconfiguration      → restoring the permissive
#     empty-scan arm reddens this leg (docs/90 G4).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-readiness-timeout-literal.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: every legitimate spelling the tree actually ships.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/vmm" "$root/vmcell-qemu/src" "$root/vmcell-firecracker/src"
  # The shared home: the ceiling is a named const and the public entry points take none.
  {
    printf 'pub const VMM_SOCKET_READY_TIMEOUT_MS: u64 = 1000;\n'
    printf 'pub async fn wait_for_vmm_socket(p: &Path, c: Option<&mut Child>, i: u64) -> Result<()> {\n'
    printf '    wait_for_socket(p, c, VMM_SOCKET_READY_TIMEOUT_MS, i).await\n}\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    async fn t() { let _ = wait_for_socket(&p, None, 100, 20).await; }\n'
    printf '}\n'
  } > "$root/vmcell/src/vmm/mod.rs"
  # A backend on the ceiling-less entry points, plus its own NAMED second ceiling.
  {
    printf '// The old shape passed 1000 here; the ceiling is named now.\n'
    printf 'const SMOLTCP_SOCKET_READY_TIMEOUT_MS: u64 = 2000;\n'
    printf 'async fn spawn(cfg: &VmConfig) -> Result<()> {\n'
    printf '    vmcell::vmm::wait_for_vmm_socket(&s, Some(&mut d), cfg.timeouts.poll as u64).await?;\n'
    printf '    vmcell::vmm::wait_for_socket(&s, None, SMOLTCP_SOCKET_READY_TIMEOUT_MS, cfg.poll as u64).await?;\n'
    printf '    let pgid = vmcell::vmm::register_and_await_ready(&mut p, c, &n, &s, cfg.poll as u64).await?;\n'
    printf '    Ok(())\n}\n'
  } > "$root/vmcell-qemu/src/lib.rs"
  # A rustfmt-wrapped, argument-per-line call with a named ceiling — must stay clean, and proves the
  # scanner joins lines before matching.
  {
    printf 'async fn probe() -> Result<()> {\n'
    printf '    vmcell::vmm::wait_for_socket(\n'
    printf '        &api_socket,\n'
    printf '        Some(&mut process),\n'
    printf '        PROBE_READY_MS,\n'
    printf '        cfg.timeouts.api_socket_poll.as_millis() as u64,\n'
    printf '    )\n'
    printf '    .await\n}\n'
  } > "$root/vmcell-firecracker/src/lib.rs"
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the clean tree MUST pass (the positive control) --------------------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
expect_rc 0 "named ceilings only"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
[[ $fail -ne 0 ]] && dump "case 1"

# --- Case 2: the exact §8 regression — a bare literal back at a backend call site -----------------
mk_clean_tree "$work/bad"
mkdir -p "$work/bad/vmcell-crosvm/src"
{
  printf 'async fn spawn(cfg: &VmConfig) -> Result<()> {\n'
  printf '    vmcell::vmm::wait_for_socket(&s, Some(&mut p), 1000, cfg.poll as u64).await?;\n'
  printf '    Ok(())\n}\n'
} > "$work/bad/vmcell-crosvm/src/lib.rs"
# …and the second arm, rustfmt-wrapped, so a line-at-a-time scan would miss it.
mkdir -p "$work/bad/vmcell-daemon/src"
{
  printf 'async fn start() -> Result<()> {\n'
  printf '    let pgid = vmcell::vmm::register_and_await_ready(\n'
  printf '        &mut process,\n'
  printf '        cgroups,\n'
  printf '        &name,\n'
  printf '        &sock,\n'
  printf '        1000,\n'
  printf '        20,\n'
  printf '    )\n'
  printf '    .await?;\n'
  printf '    Ok(())\n}\n'
} > "$work/bad/vmcell-daemon/src/bridge.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "bare literal ceilings"
expect_flag 'vmcell-crosvm/src/lib.rs'
expect_flag 'vmcell-daemon/src/bridge.rs'
# The legitimate spellings stay clean.
expect_clean 'vmcell-qemu/src/lib.rs'
expect_clean 'vmcell-firecracker/src/lib.rs'
expect_clean 'vmcell/src/vmm/mod.rs'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: a tree with no readiness call at all is a misconfiguration, not a pass ---------------
# This is the vacuity arm: without it, renaming the helpers would leave the scan hunting for a
# string that can never appear while still printing "ok".
mkdir -p "$work/empty/vmcell/src"
printf 'pub fn unrelated() -> u64 { 1000 }\n' > "$work/empty/vmcell/src/lib.rs"
run_ban "$work/empty"
before=$fail
expect_rc 1 "no readiness call in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a tree with no Rust at all is the same misconfiguration ------------------------------
# G4: this arm used to print "ok: no Rust sources under: …" and exit 0 BEFORE case 3's non-vacuity
# check could run, so a moved crate tree (or a typo'd explicit path) reported success having opened no
# file. Restoring that arm reddens this case.
mkdir -p "$work/nosrc/vmcell/src"
printf 'not rust\n' > "$work/nosrc/vmcell/src/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 4"

if [[ $fail -ne 0 ]]; then
  echo "ban-readiness-timeout-literal self-test FAILED"
  exit 1
fi
echo "ok: ban-readiness-timeout-literal self-test passed"
