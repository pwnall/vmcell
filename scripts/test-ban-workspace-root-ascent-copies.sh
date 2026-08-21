#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-workspace-root-ascent-copies.sh (AGENTS.md "One law, one
# predicate"; design §17's last open consolidation — `bench-vm`'s hand-rolled workspace-root ascent).
# Builds fixture trees mirroring the real crate layout (home and roster are path SUFFIXES, so the
# layout is load-bearing) and asserts every arm:
#   * deleting the scan lets `bench-vm`'s reintroduced ascent pass                        → this reddens;
#   * dropping the roster lets the operator-facing error message be flagged as a copy      → reddens;
#   * dropping the exact counts lets a SECOND ascent inside the law's own file pass, lets a
#     rostered file that stopped naming the marker keep its exemption, and lets the ascent
#     stop looking for the marker entirely                                                 → reddens;
#   * lumping the home's production and `#[cfg(test)]` halves lets a production copy hide
#     behind a deleted fixture (the total stays 4)                                         → reddens;
#   * dropping the home checks lets a moved/renamed law — or one demoted back to `pub(crate)`,
#     the state that FORCED the third copy — pass                                          → reddens;
#   * restoring a permissive empty-scan arm lets a Rust-less tree report "ok"               → reddens.
# The must-stay-clean fixtures matter as much as the flagged ones: `vmcelld`'s two-`parent()` walk is
# deliberately out of scope (it cannot drift with the marker), and a gate that flagged it would be
# deleted rather than obeyed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-workspace-root-ascent-copies.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

marker='crates/vmcell-protocol/Cargo.toml'

# The clean baseline: the law's home spelling the marker once in production and three times in its
# fixtures, plus the one rostered prose site, plus several sites that MUST NOT be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/artifact" "$root/vmcell-bench/src/bin" "$root/vmcelld/tests" \
           "$root/vmcell-cli/src" "$root/vmcell-artifact-validator/src"
  # THE HOME: the one ascent, the `pub` export that makes it callable out of crate, and the rustdoc
  # that NAMES the marker in prose (which must be stripped, or the home's count is 2 and the law
  # looks like its own violation). Then three `#[cfg(test)]` fixtures that CREATE the marker.
  {
    # shellcheck disable=SC2016  # literal Rust doc text: the backticks are markdown, not a subshell
    printf '/// The workspace root. The marker is `%s`, a stable landmark.\n' "$marker"
    printf '#[must_use]\npub fn workspace_root() -> PathBuf {\n'
    printf '    let start = source_search_start();\n'
    printf '    find_vmcell_source_root(&start).unwrap_or(start)\n}\n'
    printf 'fn find_vmcell_source_root(start: &Path) -> Option<PathBuf> {\n'
    printf '    start.ancestors().find(|dir| dir.join("%s").is_file()).map(Path::to_path_buf)\n}\n' "$marker"
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    #[test]\n    fn ascends_inside_a_checkout() {\n'
    printf '        std::fs::write(root.path().join("%s"), b"").unwrap();\n    }\n' "$marker"
    printf '    #[test]\n    fn falls_back_outside_a_checkout() {\n'
    printf '        std::fs::write(checkout.path().join("%s"), b"").unwrap();\n    }\n' "$marker"
    printf '    #[test]\n    fn a_broken_closure_is_loud() {\n'
    printf '        std::fs::write(broken.path().join("%s"), b"").unwrap();\n    }\n}\n' "$marker"
  } > "$root/vmcell/src/artifact/mod.rs"
  # ROSTERED 1 — the operator-facing error message that QUOTES the marker inside a string literal.
  {
    printf 'fn closure_root() -> Result<PathBuf> {\n'
    printf '    vmcell_source_root().ok_or_else(|| Error::Artifact(format!(\n'
    # shellcheck disable=SC2016  # literal Rust string text: the backticks are what the message prints
    printf '        "no vmcell checkout (no `%s` above {}), and a workspace build is the one way", cwd)))\n}\n' "$marker"
  } > "$root/vmcell/src/artifact/guest_tools.rs"
  # MUST NOT be flagged: the harness that now CALLS the one law, with the marker only in prose.
  {
    printf "/// The workspace root — vmcell's one ascent, called rather than mirrored (the marker\n"
    printf '/// string is spelled in exactly one file now).\n'
    printf 'fn workspace_root() -> PathBuf { vmcell::artifact::workspace_root() }\n'
  } > "$root/vmcell-bench/src/bin/bench-vm.rs"
  # MUST NOT be flagged: a walk of two `parent()`s from a crate that knows its own depth. Out of
  # scope BY CONSTRUCTION — it cannot drift with the marker, and it breaks loudly if the crate moves.
  {
    printf 'fn workspace_root() -> PathBuf {\n'
    printf '    Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).unwrap().to_path_buf()\n}\n'
  } > "$root/vmcelld/tests/integration.rs"
  # MUST NOT be flagged: ordinary consumers of the public answers built on the same core.
  printf 'fn dir() -> PathBuf { vmcell::artifact::artifacts_dir() }\n' > "$root/vmcell-cli/src/main.rs"
  printf 'fn root() -> PathBuf { vmcell::artifact::workspace_root() }\n' \
    > "$root/vmcell-artifact-validator/src/harness.rs"
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
expect_rc 0 "the law's home plus the one rostered prose site"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
expect_clean 'bench-vm.rs'
expect_clean 'integration.rs'
expect_clean 'vmcell-cli'
expect_clean 'harness.rs'
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: the C4 defect itself — `bench-vm` reintroduces the hand-rolled ascent -----------------
# Byte-for-byte what was there before the collapse. This is the arm the parity TEST cannot see: the
# copy resolves the same root today, so `snap_dir_anchors_on_the_library_one_workspace_root` stays
# green while the duplicate is free to drift.
mk_clean_tree "$work/bad"
{
  printf 'fn workspace_root() -> PathBuf {\n'
  printf '    let start = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)\n'
  printf '        .or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| PathBuf::from("."));\n'
  printf '    for dir in start.ancestors() {\n'
  printf '        if dir.join("%s").is_file() { return dir.to_path_buf(); }\n' "$marker"
  printf '    }\n    start\n}\n'
} > "$work/bad/vmcell-bench/src/bin/bench-vm.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "an unrostered copy of the ascent"
expect_flag 'bench-vm.rs'
expect_flag 'workspace_root'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 2b: the same copy in a crate that has no gate of its own ---------------------------------
# The next copy is always in whichever crate nobody was watching. The scan is repo-wide for that
# reason: it is the class, not the instance.
mk_clean_tree "$work/bad2"
printf 'fn root() -> PathBuf { p.ancestors().find(|d| d.join("%s").is_file()).unwrap().into() }\n' "$marker" \
  > "$work/bad2/vmcell-artifact-validator/src/harness.rs"
run_ban "$work/bad2"
before=$fail
expect_rc 1 "an unrostered copy in the validator harness"
expect_flag 'harness.rs'
[[ $fail -ne $before ]] && dump "case 2b"

# --- Case 3: a SECOND production ascent inside the law's own file ----------------------------------
# Inserted BEFORE the `#[cfg(test)]` line, so it lands in the production half: the home's total is 5
# either way, and only the split can tell the two apart.
mk_clean_tree "$work/extra"
awk -v M="$marker" '
  /^#\[cfg\(test\)\]/ && !done {
    print "fn other_root(p: &Path) -> Option<PathBuf> { p.ancestors().find(|d| d.join(\"" M "\").is_file()).map(Path::to_path_buf) }"
    done = 1
  } { print }' "$work/extra/vmcell/src/artifact/mod.rs" > "$work/extra/tmp.rs"
mv "$work/extra/tmp.rs" "$work/extra/vmcell/src/artifact/mod.rs"
run_ban "$work/extra"
before=$fail
expect_rc 1 "a second production ascent in the law's own file"
expect_flag '2 time(s) in production'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 3b: the home/test SPLIT is load-bearing --------------------------------------------------
# A production copy added AND a fixture deleted keeps the file's TOTAL at 4. A lumped count passes
# this tree; the split reddens on both halves.
mk_clean_tree "$work/split"
{
  printf '#[must_use]\npub fn workspace_root() -> PathBuf { find_vmcell_source_root(&start).unwrap_or(start) }\n'
  printf 'fn find_vmcell_source_root(start: &Path) -> Option<PathBuf> {\n'
  printf '    start.ancestors().find(|dir| dir.join("%s").is_file()).map(Path::to_path_buf)\n}\n' "$marker"
  printf 'fn other_root(p: &Path) -> PathBuf { p.ancestors().find(|d| d.join("%s").is_file()).unwrap().into() }\n' "$marker"
  printf '#[cfg(test)]\nmod tests {\n'
  printf '    #[test]\n    fn a() { std::fs::write(r.join("%s"), b"").unwrap(); }\n' "$marker"
  printf '    #[test]\n    fn b() { std::fs::write(c.join("%s"), b"").unwrap(); }\n}\n' "$marker"
} > "$work/split/vmcell/src/artifact/mod.rs"
run_ban "$work/split"
before=$fail
expect_rc 1 "a production copy hidden behind a deleted fixture (total unchanged)"
expect_flag '2 time(s) in production'
expect_flag '2 time(s) under'
[[ $fail -ne $before ]] && dump "case 3b"

# --- Case 4: the ascent stops looking for the marker at all ----------------------------------------
# Nothing else in the tree changes and everything still compiles — every caller silently resolves its
# own start dir instead of the workspace root, which is the failure this whole law exists to prevent.
mk_clean_tree "$work/blind"
{
  printf '#[must_use]\npub fn workspace_root() -> PathBuf { source_search_start() }\n'
  printf 'fn find_vmcell_source_root(_start: &Path) -> Option<PathBuf> { None }\n'
  printf '#[cfg(test)]\nmod tests {\n'
  printf '    #[test]\n    fn a() { std::fs::write(r.join("%s"), b"").unwrap(); }\n' "$marker"
  printf '    #[test]\n    fn b() { std::fs::write(c.join("%s"), b"").unwrap(); }\n' "$marker"
  printf '    #[test]\n    fn d() { std::fs::write(b2.join("%s"), b"").unwrap(); }\n}\n' "$marker"
} > "$work/blind/vmcell/src/artifact/mod.rs"
run_ban "$work/blind"
before=$fail
expect_rc 1 "the home no longer spells the marker in production"
expect_flag '0 time(s) in production'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a rostered file that stopped naming the marker is a STALE entry, not a pass -----------
mk_clean_tree "$work/stale"
printf 'fn closure_root() -> Result<PathBuf> { vmcell_source_root().ok_or_else(|| Error::Artifact("no checkout".into())) }\n' \
  > "$work/stale/vmcell/src/artifact/guest_tools.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "a rostered file that no longer names the marker"
expect_flag 'guest_tools.rs'
expect_flag 'roster says 1'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 5b: a SECOND spelling inside the rostered file wears that entry's exemption --------------
mk_clean_tree "$work/roster2"
printf 'fn probe() -> bool { Path::new("%s").is_file() }\n' "$marker" \
  >> "$work/roster2/vmcell/src/artifact/guest_tools.rs"
run_ban "$work/roster2"
before=$fail
expect_rc 1 "a second spelling inside a rostered file"
expect_flag '2 time(s)'
[[ $fail -ne $before ]] && dump "case 5b"

# --- Case 5c: a rostered file that moved away is the same stale entry ------------------------------
mk_clean_tree "$work/moved"
rm "$work/moved/vmcell/src/artifact/guest_tools.rs"
run_ban "$work/moved"
before=$fail
expect_rc 1 "a rostered file that moved away"
expect_flag 'gate misconfigured'
expect_flag 'guest_tools.rs'
[[ $fail -ne $before ]] && dump "case 5c"

# --- Case 6: the home's own failure modes ----------------------------------------------------------
# 6a: the ascent's core moved out of the rostered file — the gate would be counting marker spellings
# against a home that does not hold the law, and every other site would look sanctioned by comparison.
mk_clean_tree "$work/nohome"
printf '#[must_use]\npub fn workspace_root() -> PathBuf { elsewhere::ascend("%s") }\n' "$marker" \
  > "$work/nohome/vmcell/src/artifact/mod.rs"
run_ban "$work/nohome"
before=$fail
expect_rc 1 "the home no longer defines the ascent core"
expect_flag 'gate misconfigured'
expect_flag 'find_vmcell_source_root'
[[ $fail -ne $before ]] && dump "case 6a"

# 6b: the export is demoted back to `pub(crate)`. That is EXACTLY the state that forced the third
# copy: an out-of-crate harness has nothing to call, so the next one is hand-rolled again.
mk_clean_tree "$work/unexported"
sed -i 's/^pub fn workspace_root/pub(crate) fn workspace_root/' "$work/unexported/vmcell/src/artifact/mod.rs"
run_ban "$work/unexported"
before=$fail
expect_rc 1 "the ascent lost its pub export"
expect_flag 'gate misconfigured'
expect_flag 'pub fn workspace_root'
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

# --- Case 8: an explicit-path typo is the other way a scan goes vacuous ----------------------------
run_ban "$work/does-not-exist"
before=$fail
expect_rc 1 "a nonexistent scan root"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 8"

if [[ $fail -ne 0 ]]; then
  echo "ban-workspace-root-ascent-copies self-test FAILED"
  exit 1
fi
echo "ok: ban-workspace-root-ascent-copies self-test passed"
