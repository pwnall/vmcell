#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-ch-binary-resolver-copies.sh (AGENTS.md "One law, one
# predicate"; docs/90 A2 — the third byte-identical copy of `vmcell::artifact::ch_binary_path`).
# Builds fixture trees that mirror the real crate layout (home and roster are path suffixes, so the
# layout is load-bearing) and asserts every arm:
#   * deleting the scan lets an UNROSTERED copy of the resolver pass                      → this reddens;
#   * dropping the roster lets the four deliberately-different readers be flagged as copies → reddens;
#   * dropping the exact counts lets a SECOND read inside a rostered file pass, and lets a
#     rostered file that stopped reading the variable keep its exemption                   → reddens;
#   * dropping the home checks lets a moved/renamed law, or a home that no longer reads the
#     variable at all (every consumer silently on the default), pass                       → reddens;
#   * restoring a permissive empty-scan arm lets a Rust-less tree report "ok"              → reddens.
# The must-stay-clean fixtures matter as much as the flagged one: the roster's whole claim is that
# those four readers are legitimate, and a gate that flagged them would be deleted rather than obeyed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-ch-binary-resolver-copies.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the law's home reading the variable once, and each rostered file reading it
# exactly as many times as the roster declares, for the reason the roster declares.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/artifact" "$root/vmcelld/src" "$root/vmcelld/tests" \
           "$root/vmcell-bench/src/bin" "$root/vmcell-cli/src" \
           "$root/vmcell-artifact-validator/src" "$root/vmcell-daemon/src"
  # THE HOME: the one resolver, plus the rustdoc that NAMES the variable in prose (which must be
  # stripped, or the home's count is 2 and the law looks like its own violation).
  {
    # shellcheck disable=SC2016  # literal Rust doc text: the `$VMCELL_CH_BIN` must NOT expand (intended)
    printf '/// The cloud-hypervisor binary path: `$VMCELL_CH_BIN`, else bare `cloud-hypervisor`.\n'
    printf 'pub fn ch_binary_path() -> String {\n'
    printf '    std::env::var("VMCELL_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())\n}\n'
  } > "$root/vmcell/src/artifact/mod.rs"
  # A sibling in the same crate that COMMENTS about the variable without reading it (the snapshot
  # stage's real "SAME env var (VMCELL_CH_BIN)" note).
  printf 'fn snapshot() { // SAME env var (VMCELL_CH_BIN) — no per-call-site CH-binary drift.\n    let bin = crate::artifact::ch_binary_path();\n}\n' \
    > "$root/vmcell/src/artifact/snapshot.rs"
  # ROSTERED 1 — flag-then-env precedence (a different law, not a copy).
  printf 'fn ch(args: &Args) -> String { args.ch_bin.clone().or_else(|| std::env::var("VMCELL_CH_BIN").ok()).unwrap_or_else(default_ch) }\n' \
    > "$root/vmcelld/src/main.rs"
  # ROSTERED 2 — the PATH-searching test variant.
  {
    printf 'fn ch_bin() -> PathBuf {\n'
    printf '    if let Some(v) = std::env::var_os("VMCELL_CH_BIN") { return PathBuf::from(v); }\n'
    printf '    which_on_path("cloud-hypervisor").expect("a cloud-hypervisor binary")\n}\n'
  } > "$root/vmcelld/tests/integration.rs"
  # ROSTERED 3 — bench-vm's table (1) plus its injected-lookup test (1) = the declared 2.
  {
    printf 'const VMM_BIN_RESOLVERS: [(&str, &str, &str); 4] = [\n'
    printf '    ("cloud-hypervisor", "VMCELL_CH_BIN", "cloud-hypervisor"),\n];\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    #[test]\n    fn honors_overrides() {\n'
    printf '        let f = |v: &str| match v { "VMCELL_CH_BIN" => Some("/opt/ch".to_string()), _ => None };\n'
    printf '    }\n}\n'
  } > "$root/vmcell-bench/src/bin/bench-vm.rs"
  # ROSTERED 4 — the CLI's own call-site gate, which must name what it forbids.
  {
    printf 'fn ch_bin() -> String { vmcell::artifact::ch_binary_path() }\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    #[test]\n    fn the_cli_resolves_the_ch_binary_through_the_one_library_law() {\n'
    printf '        assert_eq!(code.matches("VMCELL_CH_BIN").count(), 0);\n'
    printf '    }\n}\n'
  } > "$root/vmcell-cli/src/main.rs"
  # MUST NOT be flagged: a consumer calling the one resolver, and one naming a DIFFERENT backend's
  # variable (which has no `vmcell`-side law and is out of this gate's scope by construction).
  printf 'fn boot() { let bin = vmcell::artifact::ch_binary_path(); }\n' \
    > "$root/vmcell-artifact-validator/src/harness.rs"
  printf 'fn fc() -> String { std::env::var("VMCELL_FC_BIN").unwrap_or_else(|_| "firecracker".into()) }\n' \
    > "$root/vmcell-daemon/src/launcher.rs"
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

# --- Case 1: the clean tree MUST pass — the roster is honored (the positive control) ---------------
mk_clean_tree "$work/good"
run_ban "$work/good"
before=$fail
expect_rc 0 "the law's home plus the four rostered readers"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
expect_clean 'vmcelld/src/main.rs'
expect_clean 'integration.rs'
expect_clean 'bench-vm.rs'
expect_clean 'vmcell-cli'
expect_clean 'snapshot.rs'
expect_clean 'launcher.rs'
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: an UNROSTERED copy is the A2 defect --------------------------------------------------
# The exact shape found in vmcell-cli, and the shape still in the validator harness: byte-identical to
# the law, in a crate that links the law and could call it.
mk_clean_tree "$work/bad"
printf 'pub fn ch_bin() -> String { std::env::var("VMCELL_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string()) }\n' \
  > "$work/bad/vmcell-artifact-validator/src/harness.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "an unrostered copy of the resolver"
expect_flag 'harness.rs'
expect_flag 'ch_binary_path'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: a SECOND read inside a rostered file wears that entry's exemption ---------------------
mk_clean_tree "$work/extra"
printf 'fn also(&self) -> String { std::env::var("VMCELL_CH_BIN").unwrap_or_default() }\n' \
  >> "$work/extra/vmcelld/src/main.rs"
run_ban "$work/extra"
before=$fail
expect_rc 1 "a second read inside a rostered file"
expect_flag 'vmcelld/src/main.rs'
expect_flag 'roster says 1'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a rostered file that stopped reading it is a STALE entry, not a pass ------------------
mk_clean_tree "$work/stale"
printf 'fn ch(args: &Args) -> String { args.ch_bin.clone().unwrap_or_else(default_ch) }\n' \
  > "$work/stale/vmcelld/src/main.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "a rostered file that no longer reads the variable"
expect_flag 'vmcelld/src/main.rs'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a rostered file that moved away is the same stale entry -------------------------------
mk_clean_tree "$work/moved"
rm "$work/moved/vmcell-bench/src/bin/bench-vm.rs"
run_ban "$work/moved"
before=$fail
expect_rc 1 "a rostered file that moved away"
expect_flag 'gate misconfigured'
expect_flag 'bench-vm.rs'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: the home's own two failure modes -----------------------------------------------------
# 6a: the law moved out of the rostered file — the gate would be counting reads against a home that
# does not hold the law, and every other reader would look sanctioned by comparison.
mk_clean_tree "$work/nohome"
printf 'pub fn something_else() -> String { std::env::var("VMCELL_CH_BIN").unwrap_or_default() }\n' \
  > "$work/nohome/vmcell/src/artifact/mod.rs"
run_ban "$work/nohome"
before=$fail
expect_rc 1 "the home no longer defines the resolver"
expect_flag 'gate misconfigured'
expect_flag 'ch_binary_path'
[[ $fail -ne $before ]] && dump "case 6a"

# 6b: the home stopped reading the variable. Nothing else in the tree changes, and the whole §10.4
# contract entry has quietly become dead: every consumer resolves the default and no override works.
mk_clean_tree "$work/homeblind"
printf 'pub fn ch_binary_path() -> String { "cloud-hypervisor".to_string() }\n' \
  > "$work/homeblind/vmcell/src/artifact/mod.rs"
run_ban "$work/homeblind"
before=$fail
expect_rc 1 "the home stopped reading the variable"
expect_flag 'expected 1'
[[ $fail -ne $before ]] && dump "case 6b"

# 6c: the home is gone from the scanned tree altogether.
mk_clean_tree "$work/gone"
rm "$work/gone/vmcell/src/artifact/mod.rs"
run_ban "$work/gone"
before=$fail
expect_rc 1 "the home is absent from the scan"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 6c"

# --- Case 7: a tree with no Rust at all is a misconfiguration, not a pass --------------------------
# G4: a source-scanning gate that opens nothing must never print `ok:` — the only way to match zero
# Rust sources is to have been pointed at the wrong place.
mkdir -p "$work/nosrc/vmcell/src"
printf 'not rust\n' > "$work/nosrc/vmcell/src/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

if [[ $fail -ne 0 ]]; then
  echo "ban-ch-binary-resolver-copies self-test FAILED"
  exit 1
fi
echo "ok: ban-ch-binary-resolver-copies self-test passed"
