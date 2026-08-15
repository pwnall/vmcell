#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-test-support-in-production.sh (docs/81 §9).
#
# A ban script that cannot go red is theater (AGENTS.md rule 2), and a source scan's characteristic
# failure is passing VACUOUSLY — matching nothing and reporting "ok". Every arm of the scanner is
# driven here against a fixture tree that mirrors the real crate layout (the exemptions are path
# suffixes, so the layout is load-bearing):
#
#   * a fixture named in a backend's PRODUCTION text is flagged            → deleting the scan reddens;
#   * the same name inside `#[cfg(test)]`, in a `tests/` target, or in a
#     comment is NOT flagged                                              → an over-broad grep reddens;
#   * a definition site that moved away is a stale exemption               → not a pass;
#   * a definition site that lost its `feature = "test-support"` gate is a
#     stale exemption                                                     → not a pass;
#   * a banned symbol nobody uses anywhere is a stale roster               → not a pass.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-test-support-in-production.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: both definition sites, gated; plus every legitimate NON-production spelling a
# real backend uses, which must stay un-flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/vmm" "$root/vmcell-firecracker/src" "$root/vmcell-qemu/src" \
           "$root/vmcell-crosvm/tests"
  # Definition site 1 — the cgroup fake, behind the feature gate.
  {
    printf '#[cfg(any(test, feature = "test-support"))]\n'
    printf '#[derive(Debug, Clone)]\n'
    printf 'pub struct FakeCgroupFs { state: Arc<Mutex<FakeCgroupState>> }\n'
    printf '#[cfg(test)]\nmod tests { use super::FakeCgroupFs; }\n'
  } > "$root/vmcell/src/metrics.rs"
  # Definition site 2 — the already-reaped constructor, behind the same gate.
  {
    printf 'impl VmmProcessGroup {\n'
    printf '    #[cfg(any(test, feature = "test-support"))]\n'
    printf '    pub fn already_reaped_for_test(pgid: Option<u32>) -> Self { Self { pgid, reaped: true } }\n'
    printf '}\n'
  } > "$root/vmcell/src/vmm/mod.rs"
  # MUST NOT be flagged: a use inside the crate's own `#[cfg(test)]` module.
  {
    printf 'pub fn spawn() -> Result<()> { Ok(()) }\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    use vmcell::metrics::FakeCgroupFs;\n'
    printf '    fn f() { let _ = FakeCgroupFs::new(); }\n'
    printf '    fn g() { let _ = vmcell::vmm::VmmProcessGroup::already_reaped_for_test(Some(1)); }\n'
    printf '}\n'
  } > "$root/vmcell-firecracker/src/lib.rs"
  # MUST NOT be flagged: prose naming a fixture in a comment above production code.
  {
    printf '// Replaces the former FakeCgroupFs copy this crate hand-rolled.\n'
    # shellcheck disable=SC2016  # the backticks are literal Rust doc text, not shell expansion (intended)
    printf '/// See `already_reaped_for_test` for the recycled-pgid fixture.\n'
    printf 'pub fn create() -> Result<()> { Ok(()) }\n'
  } > "$root/vmcell-qemu/src/lib.rs"
  # MUST NOT be flagged: a `tests/` target is a cargo dev target.
  printf 'use vmcell::metrics::FakeCgroupFs;\nfn t() { let _ = FakeCgroupFs::new(); }\n' \
    > "$root/vmcell-crosvm/tests/matrix.rs"
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

# --- Case 1: the sanctioned tree alone MUST pass (the positive control) ---------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
expect_rc 0 "definitions + test-only uses"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
[[ $fail -ne 0 ]] && dump "case 1"

# --- Case 2: a fixture wired into PRODUCTION code MUST be flagged --------------------------------
# The real hazard: under `--all-targets` cargo's feature unification makes the fixture visible to the
# lib target, so this compiles clean and ships a VM whose cgroup limits are invented.
mk_clean_tree "$work/bad"
mkdir -p "$work/bad/vmcell-crosvm/src"
{
  printf 'pub fn create(cgroups: Option<&dyn CgroupFs>) -> Result<()> {\n'
  printf '    let fs = vmcell::metrics::FakeCgroupFs::new();\n'
  printf '    spawn_with(&fs)\n}\n'
  printf '#[cfg(test)]\nmod tests { fn t() {} }\n'
} > "$work/bad/vmcell-crosvm/src/lib.rs"
# …and the other fixture, in a second crate, so one arm cannot cover for the other.
{
  printf 'pub fn adopt(pgid: Option<u32>) -> VmmProcessGroup {\n'
  printf '    vmcell::vmm::VmmProcessGroup::already_reaped_for_test(pgid)\n}\n'
} > "$work/bad/vmcell-qemu/src/teardown.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "fixture named in production code"
expect_flag 'vmcell-crosvm/src/lib.rs'
expect_flag 'vmcell-qemu/src/teardown.rs'
# The legitimate spellings stay clean.
expect_clean 'vmcell-firecracker/src/lib.rs'
expect_clean 'vmcell-qemu/src/lib.rs:'
expect_clean 'tests/matrix.rs'
expect_clean '/vmcell/src/metrics.rs:'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: a definition site that moved away is a STALE exemption, not a pass -------------------
mk_clean_tree "$work/moved"
rm "$work/moved/vmcell/src/metrics.rs"
run_ban "$work/moved"
before=$fail
expect_rc 1 "moved definition site"
expect_flag 'no such file'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a definition that LOST its feature gate is a stale exemption -------------------------
# Without the gate the fixture is unconditionally public — the exemption would then be hiding an
# ungated production symbol, which is the very thing the ban exists to prevent.
mk_clean_tree "$work/ungated"
{
  printf '#[derive(Debug, Clone)]\n'
  printf 'pub struct FakeCgroupFs { state: Arc<Mutex<FakeCgroupState>> }\n'
} > "$work/ungated/vmcell/src/metrics.rs"
run_ban "$work/ungated"
before=$fail
expect_rc 1 "definition without its test-support gate"
# shellcheck disable=SC2016  # the backticks are literal scanner-output text, not shell expansion
expect_flag 'NO `feature = "test-support"` gate'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a banned symbol nobody uses anywhere is a stale roster, not a pass -------------------
# This is the vacuity arm: without it, renaming a fixture would leave the scan hunting for a string
# that can never appear while still printing "ok".
mk_clean_tree "$work/vacuous"
rm "$work/vacuous/vmcell-crosvm/tests/matrix.rs"
{
  printf 'pub fn spawn() -> Result<()> { Ok(()) }\n'
  printf '#[cfg(test)]\nmod tests {\n'
  printf '    fn g() { let _ = vmcell::vmm::VmmProcessGroup::already_reaped_for_test(Some(1)); }\n'
  printf '}\n'
} > "$work/vacuous/vmcell-firecracker/src/lib.rs"
# `FakeCgroupFs` now appears only at its (production-text) definition and in a comment — nowhere in
# a test position.
printf 'pub fn create() -> Result<()> { Ok(()) }\n' > "$work/vacuous/vmcell-qemu/src/lib.rs"
printf '#[cfg(any(test, feature = "test-support"))]\npub struct FakeCgroupFs { s: u8 }\n' \
  > "$work/vacuous/vmcell/src/metrics.rs"
run_ban "$work/vacuous"
before=$fail
expect_rc 1 "banned symbol used nowhere outside production text"
expect_flag 'the roster is stale'
expect_flag 'FakeCgroupFs'
[[ $fail -ne $before ]] && dump "case 5"

if [[ $fail -ne 0 ]]; then
  echo "ban-test-support-in-production self-test FAILED"
  exit 1
fi
echo "ok: ban-test-support-in-production self-test passed"
