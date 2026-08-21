#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-inline-netem-argv.sh (AGENTS.md "one law, one
# predicate" for the netem argv; design §17, Segment refinements). Builds fixture trees that mirror
# the real crate layout (the exemption is a path suffix, so the layout is load-bearing) and asserts
# every half of the scanner can fail:
#   * deleting the violation scan lets a harness hand-write its own `"netem"` argv pass → reddens;
#   * deleting the exact-count check lets a FOURTH composer added inside the sanctioned home pass,
#     or a law that MOVED OUT of the home (leaving the gate blind) pass                 → reddens;
#   * deleting the home-present check lets a renamed/moved home pass                    → reddens;
#   * restoring a permissive empty-scan arm lets a Rust-less tree report "ok"           → reddens
#     (docs/90 G4);
#   * the near-miss spellings (prose in a comment, the word inside a message string, a call to
#     `netem_args()`) must stay un-flagged, so the scanner is precise rather than merely loud.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-inline-netem-argv.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the sanctioned home with EXACTLY its three spellings, plus every legitimate
# near-miss that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/net" "$root/vmcell/tests" "$root/vmcell-daemon/src"
  {
    printf 'impl Impairment {\n'
    # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
    printf '    /// The one composer. A caller that must drive `tc` itself calls this.\n'
    printf '    pub fn netem_args(&self) -> Vec<String> { self.words.clone() }\n}\n'
    printf 'impl NetSegment {\n'
    printf '    pub fn impair_member(&self, vmid: u32, i: &Impairment) -> Result<()> {\n'
    printf '        let mut args = vec!["qdisc".into(), "replace".into(), "root".into(), "netem".to_string()];\n'
    printf '        args.extend(i.netem_args());\n'
    printf '        self.run_tc(&args)\n    }\n'
    printf '    pub fn clear_impairment(&self, vmid: u32) -> Result<()> {\n'
    printf '        if !listed.contains("netem") { return Ok(()); }\n'
    printf '        Err(e)\n    }\n}\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    fn probe() { let a = vec!["root".to_string(), "netem".to_string()]; run(&a); }\n}\n'
  } > "$root/vmcell/src/net/segment.rs"
  # Near-miss 1: a live leg that goes through the typed API, and mentions netem only in prose and
  # in a failure message. Flagging either would delete the very call sites the law exists for.
  {
    printf 'async fn delay_leg() {\n'
    # shellcheck disable=SC2016  # literal Rust comment text (intended)
    printf '    // netem on the root qdisc of each member tap delays every frame the bridge forwards.\n'
    printf '    let slow = Impairment::builder().delay(Duration::from_millis(50)).build().unwrap();\n'
    printf '    segment.impair_member(vmid, &slow).expect("adding netem delay must work");\n}\n'
  } > "$root/vmcell/tests/segment.rs"
  # Near-miss 2: a consumer composing the words through the one law.
  printf 'fn argv(i: &Impairment) -> Vec<String> { let mut a = base(); a.extend(i.netem_args()); a }\n' \
    > "$root/vmcell-daemon/src/lib.rs"
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

# --- Case 1: the sanctioned tree alone MUST pass (the positive control) ---------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
before=$fail
expect_rc 0 "sanctioned home only"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the sanctioned tree"; fail=1; fi
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: the EXACT pre-v33 regression — a harness spelling its own netem argv -----------------
# This is the shape the tree actually shipped: tests/segment.rs composing `["qdisc", "add", "dev",
# tap, "root", "netem", "delay", "50ms"]` twice, each with its own units and its own add-vs-replace.
mk_clean_tree "$work/dup"
{
  printf 'async fn delay_leg() {\n'
  printf '    let out = tc(&["qdisc", "add", "dev", tap, "root", "netem", "delay", "50ms"]);\n'
  printf '    let p = tc(&["qdisc", "add", "dev", b, "root", "netem", "loss", "100%%"]);\n}\n'
} > "$work/dup/vmcell/tests/segment.rs"
printf 'fn shape(dev: &str) { cmd.args(["qdisc", "replace", "dev", dev, "root", "netem"]); }\n' \
  > "$work/dup/vmcell-daemon/src/lib.rs"
run_ban "$work/dup"
before=$fail
expect_rc 1 "netem argv re-spelled outside the home"
expect_flag 'A second spelling of the netem argv law'
expect_flag 'vmcell/tests/segment.rs:2'
expect_flag 'vmcell/tests/segment.rs:3'
expect_flag 'vmcell-daemon/src/lib.rs'
expect_clean 'src/net/segment.rs'   # the home itself stays clean
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: near-miss precision — every legitimate spelling stays un-flagged ---------------------
mk_clean_tree "$work/near"
run_ban "$work/near"
before=$fail
expect_rc 0 "near-miss spellings"
expect_clean 'vmcell/tests/segment.rs'
expect_clean 'vmcell-daemon/src/lib.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a FOURTH composer inside the sanctioned home wears the home's exemption --------------
printf 'fn sneak() { let a = vec!["root".to_string(), "netem".to_string()]; }\n' \
  >> "$work/near/vmcell/src/net/segment.rs"
run_ban "$work/near"
before=$fail
expect_rc 1 "extra composer inside the home"
expect_flag 'holds 4 netem spelling(s)'
expect_flag 'expected 3'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a law that MOVED OUT of the home leaves the gate blind — not a pass ------------------
mk_clean_tree "$work/moved_law"
printf 'pub use super::impairment::netem_args;\nfn nothing() {}\n' \
  > "$work/moved_law/vmcell/src/net/segment.rs"
run_ban "$work/moved_law"
before=$fail
expect_rc 1 "law moved out of the sanctioned home"
expect_flag 'holds 0 netem spelling(s)'
expect_flag 'this gate is now blind'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a home that moved or was renamed is a STALE exemption, not a pass --------------------
mk_clean_tree "$work/stale"
mv "$work/stale/vmcell/src/net/segment.rs" "$work/stale/vmcell/src/net/impairment.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "renamed sanctioned home"
expect_flag 'gate misconfigured'
expect_flag 'was not found'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: the scan must not be vacuous on a subtree that excludes the home ---------------------
mkdir -p "$work/empty/vmcell-daemon/src"
printf 'fn f() {}\n' > "$work/empty/vmcell-daemon/src/lib.rs"
run_ban "$work/empty"
before=$fail
expect_rc 1 "subtree without the home"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

# --- Case 8: a tree with no Rust at all is the same misconfiguration ------------------------------
# G4: an "ok: no Rust sources" arm here would exit 0 BEFORE case 7's stale-home report could run, so
# a moved crate tree (or a typo'd explicit path) would report success having opened no file.
mkdir -p "$work/nosrc/vmcell/src/net"
printf 'not rust\n' > "$work/nosrc/vmcell/src/net/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 8"

if [[ $fail -ne 0 ]]; then
  echo "ban-inline-netem-argv self-test FAILED"
  exit 1
fi
echo "ok: ban-inline-netem-argv self-test passed"
