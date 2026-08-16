#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-handler-key-composers.sh (§10.5 "one law, one predicate"
# for the handler artifact-key and pin-key laws, v33 delta 6). Builds fixture trees that mirror the
# real crate layout (the exemption is a path suffix, so the layout is load-bearing) and asserts every
# half of the scanner can fail:
#   * deleting the arm-1 pattern lets a re-derived `guest_tools-<label>` artifact key pass → reddens;
#   * deleting the arm-2 pattern lets a re-derived `handler_<label>_<sub>` pin key pass  → reddens;
#   * deleting the exact-count check lets a THIRD composer added inside the sanctioned home pass, or
#     a law that MOVED OUT of the home (leaving the gate blind) pass                     → reddens;
#   * deleting the home-present check lets a renamed/moved home pass                     → reddens;
#   * the near-miss spellings (the plain literals fixtures pin the law with, and a doc comment
#     writing the shape) must stay un-flagged, so the scanner is precise rather than merely loud.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-handler-key-composers.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the sanctioned home with EXACTLY its one arm-1 and two arm-2 composers, plus
# every legitimate spelling that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/artifact" "$root/vmcell-cli/src" "$root/vmcell-daemon/src"
  {
    # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
    printf '/// The flattened pins key: `handler_<label>_<sub_key>` or `handler_<sub_key>`.\n'
    printf 'pub fn handler_pin_key(label: Option<&str>, sub_key: &str) -> String {\n'
    printf '    match label {\n'
    printf '        Some(l) => format!("handler_{l}_{sub_key}"),\n'
    printf '        None => format!("handler_{sub_key}"),\n'
    printf '    }\n}\n'
    printf 'pub fn handler_artifact_key(label: Option<&str>) -> String {\n'
    printf '    match label {\n'
    printf '        Some(l) => format!("guest_tools-{l}"),\n'
    printf '        None => "guest_tools".to_string(),\n'
    printf '    }\n}\n'
  } > "$root/vmcell/src/artifact/handler.rs"
  # A consumer that CALLS both laws, plus the plain literals a fixture pins the law's output with —
  # never flagged, or the gate would delete its own proof.
  {
    printf 'fn keys(label: Option<&str>) -> (String, String) {\n'
    printf '    (handler::handler_pin_key(label, "digest"), handler::handler_artifact_key(label))\n}\n'
    printf 'fn fixture(i: &mut StageInputs) {\n'
    printf '    i.pins.insert("handler_build".into(), "workspace:x".into());\n'
    printf '    assert_eq!(handler::handler_artifact_key(None), "guest_tools");\n}\n'
  } > "$root/vmcell-daemon/src/lib.rs"
  # Prose writing the banned shape in a comment is not code.
  {
    # shellcheck disable=SC2016  # literal Rust comment text (intended)
    printf '// the flattener emits format!("handler_{label}_digest") — do not re-derive it\n'
    printf 'fn bundle() { let k = vmcell::artifact::handler::handler_artifact_key(Some(l)); }\n'
  } > "$root/vmcell-cli/src/main.rs"
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

# --- Case 2: the regression this gate exists for — both laws re-derived outside the home ----------
mk_clean_tree "$work/dup"
{
  printf 'fn digest_pin_key(label: &Option<String>) -> String {\n'
  printf '    match label {\n'
  printf '        Some(l) => format!("handler_{l}_digest"),\n'
  printf '        None => "handler_digest".to_string(),\n'
  printf '    }\n}\n'
  printf 'fn artifact_key(label: &Option<String>) -> String {\n'
  printf '    match label {\n'
  printf '        Some(l) => format!("guest_tools-{l}"),\n'
  printf '        None => "guest_tools".to_string(),\n'
  printf '    }\n}\n'
} > "$work/dup/vmcell-daemon/src/lib.rs"
# The positional-argument spelling of the same bug: no inline capture, same drift.
printf 'fn bundle(label: &str) { candidates.push((format!("guest_tools-{}", label), p)); }\n' \
  > "$work/dup/vmcell-cli/src/main.rs"
run_ban "$work/dup"
before=$fail
expect_rc 1 "both laws re-derived outside the home"
expect_flag 'ARTIFACT-KEY law'
expect_flag 'PIN-KEY law'
expect_flag 'vmcell-daemon/src/lib.rs:3'   # the pin-key duplicate
expect_flag 'vmcell-daemon/src/lib.rs:9'   # the artifact-key duplicate
expect_flag 'vmcell-cli/src/main.rs'
expect_clean 'artifact/handler.rs'         # the home itself stays clean
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: near-miss precision — every legitimate spelling stays un-flagged ---------------------
mk_clean_tree "$work/near"
printf 'fn f() { let a = "handler_build"; let b = "guest_tools"; let c = format!("guest-tools-{}", h); }\n' \
  > "$work/near/vmcell-daemon/src/lib.rs"
run_ban "$work/near"
before=$fail
expect_rc 0 "near-miss spellings"
expect_clean 'vmcell-daemon/src/lib.rs'
expect_clean 'vmcell-cli/src/main.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a SECOND composer inside the sanctioned home wears the home's exemption --------------
mk_clean_tree "$work/extra"
printf 'fn sneak(l: &str) -> String { format!("guest_tools-{l}") }\n' \
  >> "$work/extra/vmcell/src/artifact/handler.rs"
run_ban "$work/extra"
before=$fail
expect_rc 1 "extra composer inside the home"
expect_flag 'holds 2 artifact-key composer(s)'
expect_flag 'expected 1'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a law that MOVED OUT of the home leaves the gate blind — not a pass ------------------
mk_clean_tree "$work/moved_law"
printf 'pub use super::keys::handler_pin_key;\npub fn handler_artifact_key(l: Option<&str>) -> String { match l { Some(l) => format!("guest_tools-{l}"), None => "guest_tools".into() } }\n' \
  > "$work/moved_law/vmcell/src/artifact/handler.rs"
run_ban "$work/moved_law"
before=$fail
expect_rc 1 "law moved out of the sanctioned home"
expect_flag '0 pin-key composer(s)'
expect_flag 'this gate is now blind'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a home that moved or was renamed is a STALE exemption, not a pass --------------------
mk_clean_tree "$work/stale"
mv "$work/stale/vmcell/src/artifact/handler.rs" "$work/stale/vmcell/src/artifact/handler_keys.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "renamed sanctioned home"
expect_flag 'gate misconfigured'
expect_flag 'was not found'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: the scan must not be vacuous on a subtree that excludes the home ---------------------
mkdir -p "$work/empty/vmcell-broker/src"
printf 'fn f() {}\n' > "$work/empty/vmcell-broker/src/lib.rs"
run_ban "$work/empty"
before=$fail
expect_rc 1 "subtree without the home"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

if [[ $fail -ne 0 ]]; then
  echo "ban-handler-key-composers self-test FAILED"
  exit 1
fi
echo "ok: ban-handler-key-composers self-test passed"
