#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-inline-vmid-ceiling.sh (design §17, Networking).
#
# A ban script that cannot go red is theater (AGENTS.md rule 2), and a source scan's characteristic
# failure is passing VACUOUSLY. Every arm is driven here:
#
#   * a clean tree that reads the law everywhere passes                    → an over-broad needle reddens;
#   * each of the five historical inline homes — `% 254`, `1..=254`,
#     `3..=254`, `> 254`, `seeded_id_order(clock, 254)` — is flagged       → deleting the pattern reddens;
#   * the ceiling's OWN value (9999) inline elsewhere is flagged too       → a needle that only knew
#                                                                            about 254 reddens;
#   * the law's home keeps both numbers without being flagged              → a missing exemption reddens;
#   * a longer number (`12549`), an identifier (`CID_254`) and a decimal
#     tail (`1.254`) are NOT flagged                                       → a substring match reddens;
#   * the number in a comment, or after `#[cfg(test)]`, or under `tests/`
#     is NOT flagged                                                       → over-broad matching reddens;
#   * the needle FOLLOWS the law: moving MAX_VMID in the home moves what
#     the scan bans                                                        → a hardcoded needle reddens;
#   * a tree whose law home is missing is a misconfiguration, not "ok"     → the vacuity arm reddens;
#   * so is one whose consts were renamed out from under the sed;
#   * so is one whose named in-source delegate is gone;
#   * so is one with no production `MAX_VMID` reference at all;
#   * a tree with no Rust sources at all is the same misconfiguration      → restoring a permissive
#     empty-scan arm reddens this leg (docs/90 G4).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-inline-vmid-ceiling.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the law's home plus consumers that all read it.
mk_law() { # mk_law <root> [max_vmid]
  local root="$1" max="${2:-9999}"
  mkdir -p "$root/vmcell/src/net"
  {
    printf 'const THIRD_OCTET_SPACE: u32 = 254;\n'
    printf 'const SUBNETS_PER_THIRD_OCTET: u32 = 64;\n'
    printf 'pub const MAX_VMID: u32 = %s;\n' "$max"
    printf 'pub fn ip_math(vmid: u32) -> Result<()> {\n'
    printf '    if vmid == 0 || vmid > MAX_VMID { return Err(()); }\n'
    printf '    let octet = ((vmid %% THIRD_OCTET_SPACE) + 1) as u8;\n'
    printf '    Ok(())\n}\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    #[test]\n    fn the_vmid_ceiling_is_one_law_with_five_other_homes() {\n'
    printf '        assert!((1..=254).contains(&1));\n    }\n}\n'
  } > "$root/vmcell/src/net/mod.rs"
}

mk_clean_tree() { # mk_clean_tree <root> [max_vmid]
  local root="$1"
  mk_law "$@"
  mkdir -p "$root/vmcell/src/vmm" "$root/vmcell/src" "$root/vmcell/tests"
  # Consumers that read the law — the shape every home ships today.
  {
    printf 'pub const MIN_GUEST_CID: u32 = 3;\n'
    printf 'pub const MAX_GUEST_CID: u32 = MIN_GUEST_CID + crate::net::MAX_VMID - 1;\n'
    printf 'pub fn reserve(cid: u32) -> Result<()> {\n'
    printf '    if !(MIN_GUEST_CID..=MAX_GUEST_CID).contains(&cid) { return Err(()); }\n'
    printf '    Ok(())\n}\n'
  } > "$root/vmcell/src/vmm/mod.rs"
  {
    printf 'pub fn reserve(vmid: u32) -> Result<()> {\n'
    printf '    if !(1..=crate::net::MAX_VMID).contains(&vmid) { return Err(()); }\n'
    printf '    for id in seeded_id_order(clock, crate::net::MAX_VMID) { let _ = id; }\n'
    printf '    Ok(())\n}\n'
    # Near-misses a substring match would flag, and prose that legitimately cites the numbers.
    printf '// The old ceiling was 254, and the widened one is 9999 — see net::MAX_VMID.\n'
    printf 'const UNRELATED: u32 = 12549;\n'
    printf 'const CID_254: u32 = 7;\n'
    printf 'const RATIO: f64 = 1.254;\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    fn t() { assert!((1..=254).contains(&1)); assert_eq!(MAX, 9999); }\n'
    printf '}\n'
  } > "$root/vmcell/src/orchestrator.rs"
  # An integration-test tree: test text pins the ceiling loudly and is out of scope.
  printf 'fn t() { assert!((1..=254).contains(&1)); }\n' > "$root/vmcell/tests/lifecycle.rs"
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q -- "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q -- "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the clean tree MUST pass (the positive control) --------------------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
expect_rc 0 "every home reads the law"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
# The near-misses, the comment, the `#[cfg(test)]` tail and the tests/ tree all stay clean.
expect_clean 'orchestrator.rs'
expect_clean 'lifecycle.rs'
# …and the law's own home is exempt rather than merely unmatched.
expect_clean 'net/mod.rs'
[[ $fail -ne 0 ]] && dump "case 1"

# --- Case 2: each of the five historical inline homes, restored one file at a time ----------------
mk_clean_tree "$work/bad"
mkdir -p "$work/bad/vmcell/src/net" "$work/bad/vmcell-daemon/src"
# `ip_math`'s octet map, re-derived away from the law.
printf 'fn octet(vmid: u32) -> u8 { ((vmid %% 254) + 1) as u8 }\n' > "$work/bad/vmcell/src/net/tap.rs"
# The allocator's accepted window and its seeded search width.
{
  printf 'fn reserve(vmid: u32) -> Result<()> {\n'
  printf '    if !(1..=254).contains(&vmid) { return Err(()); }\n'
  printf '    for id in seeded_id_order(clock, 254) { let _ = id; }\n'
  printf '    Ok(())\n}\n'
} > "$work/bad/vmcell-daemon/src/launcher.rs"
# The guest CID space and the config boundary.
{
  printf 'fn cid(c: u32) -> bool { (3..=254).contains(&c) }\n'
  printf 'fn cfg(vmid: u32) -> bool { vmid > 254 }\n'
} > "$work/bad/vmcell-daemon/src/dto.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "five inline homes"
expect_flag 'net/tap.rs'
expect_flag 'launcher.rs'
expect_flag 'dto.rs'
# The clean files in the same tree stay clean, so this is a scan and not a blanket failure.
expect_clean 'vmm/mod.rs'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: the ceiling's OWN value inline elsewhere is flagged too ------------------------------
# A needle that only knew about 254 would let the widened number start a fresh set of copies.
mk_clean_tree "$work/ownvalue"
mkdir -p "$work/ownvalue/vmcell-cli/src"
printf 'const CEILING: u32 = 9999;\n' > "$work/ownvalue/vmcell-cli/src/main.rs"
run_ban "$work/ownvalue"
before=$fail
expect_rc 1 "the widened ceiling inline"
expect_flag 'vmcell-cli/src/main.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: the needle FOLLOWS the law ------------------------------------------------------------
# Same offending file, a different `MAX_VMID` in the home: 9999 stops being the ceiling, so it stops
# being banned, and the new value starts. A hardcoded needle reddens both halves.
mk_clean_tree "$work/moved" 4064
mkdir -p "$work/moved/vmcell-cli/src"
printf 'const CEILING: u32 = 9999;\n' > "$work/moved/vmcell-cli/src/main.rs"
run_ban "$work/moved"
before=$fail
expect_rc 0 "9999 is not the ceiling once the law moves"
mkdir -p "$work/moved/vmcell-bench/src"
printf 'const CEILING: u32 = 4064;\n' > "$work/moved/vmcell-bench/src/lib.rs"
run_ban "$work/moved"
expect_rc 1 "the new ceiling inline"
expect_flag 'vmcell-bench/src/lib.rs'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: the law's home is gone ----------------------------------------------------------------
mkdir -p "$work/nohome/vmcell/src"
printf 'pub fn unrelated() -> u32 { 254 }\n' > "$work/nohome/vmcell/src/lib.rs"
run_ban "$work/nohome"
before=$fail
expect_rc 1 "no law home in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: the consts were renamed out from under the sed ----------------------------------------
mk_clean_tree "$work/renamed"
sed -i 's/pub const MAX_VMID: u32/pub const VMID_CEILING: u32/' "$work/renamed/vmcell/src/net/mod.rs"
run_ban "$work/renamed"
before=$fail
expect_rc 1 "the law's const was renamed"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: the named in-source delegate is gone --------------------------------------------------
# This scanner is the roster's COMPLEMENT. With the roster deleted it would quietly become the only
# half left, proving far less than its "ok" claims.
mk_clean_tree "$work/nodelegate"
sed -i 's/the_vmid_ceiling_is_one_law_with_five_other_homes/some_unrelated_test/' \
  "$work/nodelegate/vmcell/src/net/mod.rs"
run_ban "$work/nodelegate"
before=$fail
expect_rc 1 "the in-source roster is gone"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

# --- Case 8: nothing in production text reads the law ----------------------------------------------
mk_law "$work/norefs"
mkdir -p "$work/norefs/vmcell/src"
printf 'pub fn unrelated() -> u32 { 7 }\n' > "$work/norefs/vmcell/src/lib.rs"
run_ban "$work/norefs"
before=$fail
expect_rc 1 "no production reference to the law"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 8"

# --- Case 9: a tree with no Rust at all is the same misconfiguration --------------------------------
# G4: a permissive empty-scan arm would report success having opened no file.
mk_law "$work/nosrc"
rm "$work/nosrc/vmcell/src/net/mod.rs"
mkdir -p "$work/nosrc/vmcell/src"
printf 'not rust\n' > "$work/nosrc/vmcell/src/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 9"

if [[ $fail -ne 0 ]]; then
  echo "ban-inline-vmid-ceiling self-test FAILED"
  exit 1
fi
echo "ok: ban-inline-vmid-ceiling self-test passed"
