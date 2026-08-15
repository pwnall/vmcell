#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-kernel-key-composers.sh (docs/81 §8/§9 "one law, one
# predicate" for the kernel artifact-key and pin-key laws). Builds fixture trees that mirror the real
# crate layout (the exemption is a path suffix, so the layout is load-bearing) and asserts every half
# of the scanner can fail:
#   * deleting the arm-1 pattern lets a re-derived `kernel-<label>` artifact key pass  → this reddens;
#   * deleting the arm-2 pattern lets a re-derived `kernel_<label>_<sub>` pin key pass → reddens;
#   * deleting the exact-count check lets a THIRD composer added inside the sanctioned home pass, or
#     a law that MOVED OUT of the home (leaving the gate blind) pass                   → reddens;
#   * deleting the home-present check lets a renamed/moved home pass                   → reddens;
#   * the near-miss spellings (`kernel_fragments_{name}`, `kernel-prebuilt-{}`, the plain literals
#     tests pin the law with, and a doc comment writing the shape) must stay un-flagged, so the
#     scanner is precise rather than merely loud.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-kernel-key-composers.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline every fixture starts from: the sanctioned home with EXACTLY its two arm-1 and
# two arm-2 composers, plus every legitimate spelling that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/artifact" "$root/vmcell-kernel-builder/src" "$root/vmcell-cli/src"
  # THE HOME: both exported laws, plus the cache-key prefix that legitimately shares arm 1's text.
  {
    # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
    printf '/// The flattened pins key: `kernel_<label>_<sub_key>` or `kernel_<sub_key>`.\n'
    printf 'pub fn kernel_pin_key(label: Option<&str>, sub_key: &str) -> String {\n'
    printf '    match label {\n'
    printf '        Some(l) => format!("kernel_{l}_{sub_key}"),\n'
    printf '        None => format!("kernel_{sub_key}"),\n'
    printf '    }\n}\n'
    printf 'pub fn kernel_artifact_key(label: Option<&str>) -> String {\n'
    printf '    match label {\n'
    printf '        Some(l) => format!("kernel-{l}"),\n'
    printf '        None => "kernel".to_string(),\n'
    printf '    }\n}\n'
    # Near-miss 1: a DIFFERENT key family whose brace does not immediately follow `kernel_`.
    printf 'pub fn fragment_pin_key(name: &str) -> String { format!("kernel_fragments_{name}") }\n'
    # Near-miss 2: the cache-key namespace prefixes. The bare one is COUNTED by arm 1 (it is the
    # home's second sanctioned match); the `-prebuilt-` one must not match at all.
    printf 'fn ck(h: &str) -> String { format!("kernel-{}", h) }\n'
    printf 'fn ckp(h: &str) -> String { format!("kernel-prebuilt-{}", h) }\n'
  } > "$root/vmcell/src/artifact/kernel.rs"
  # A consumer that CALLS both laws (the shape the consolidation lands), plus the plain literals a
  # test fixture pins the law's output with — never flagged, or the gate would delete its own proof.
  {
    printf 'fn keys(label: &Option<String>) -> (String, String) {\n'
    printf '    (kernel::kernel_pin_key(label.as_deref(), "source_url"),\n'
    printf '     kernel::kernel_artifact_key(label.as_deref()))\n}\n'
    printf 'fn fixture(i: &mut StageInputs) {\n'
    printf '    i.pins.insert("kernel_source_url".into(), "u".into());\n'
    printf '    assert_eq!(kernel::kernel_artifact_key(None), "kernel");\n}\n'
  } > "$root/vmcell-kernel-builder/src/lib.rs"
  # Near-miss 3: prose writing the banned shape in a comment is not code.
  {
    # shellcheck disable=SC2016  # literal Rust comment text (intended)
    printf '// the flattener emits format!("kernel_{label}_source_url") — do not re-derive it\n'
    printf 'fn bundle() { let k = vmcell::artifact::kernel::kernel_artifact_key(Some(l)); }\n'
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

# --- Case 2: the EXACT docs/81 §8 regression — both laws re-derived outside the home --------------
# This is the pre-consolidation shape: `vmcell-kernel-builder` byte-duplicating the artifact key and
# both pin keys, the flattener composing the pin key inline, and the CLI re-spelling the artifact key.
mk_clean_tree "$work/dup"
{
  printf 'fn url_pin_key(label: &Option<String>) -> String {\n'
  printf '    match label {\n'
  printf '        Some(l) => format!("kernel_{l}_source_url"),\n'
  printf '        None => "kernel_source_url".to_string(),\n'
  printf '    }\n}\n'
  printf 'fn artifact_key(label: &Option<String>) -> String {\n'
  printf '    match label {\n'
  printf '        Some(l) => format!("kernel-{l}"),\n'
  printf '        None => "kernel".to_string(),\n'
  printf '    }\n}\n'
} > "$work/dup/vmcell-kernel-builder/src/lib.rs"
printf 'fn flatten(label: &str, url: &str) { out.insert(format!("kernel_{label}_source_url"), url.to_string()); }\n' \
  > "$work/dup/vmcell/src/artifact/mod.rs"
# The positional-argument spelling of the same bug: no inline capture, same drift.
printf 'fn bundle(label: &str) { candidates.push((format!("kernel-{}", label), p)); }\n' \
  > "$work/dup/vmcell-cli/src/main.rs"
run_ban "$work/dup"
before=$fail
expect_rc 1 "both laws re-derived outside the home"
expect_flag 'ARTIFACT-KEY law'
expect_flag 'PIN-KEY law'
expect_flag 'vmcell-kernel-builder/src/lib.rs:3'   # the pin-key duplicate
expect_flag 'vmcell-kernel-builder/src/lib.rs:9'   # the artifact-key duplicate
expect_flag 'artifact/mod.rs'
expect_flag 'vmcell-cli/src/main.rs'
expect_clean 'artifact/kernel.rs'                   # the home itself stays clean
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: near-miss precision — every legitimate spelling stays un-flagged ---------------------
# Guards the scanner against becoming loud-but-useless: `kernel_fragments_{…}` is a different key
# family, `kernel-prebuilt-{}` a different cache namespace, the plain literals are the law's PINS,
# and a comment is not code. All four live in the clean tree, so case 1's rc 0 already proves it —
# assert the file names explicitly so a widened pattern names the regression instead of a bare rc.
mk_clean_tree "$work/near"
printf 'fn f() { let a = format!("kernel_fragments_{n}"); let b = format!("kernel-prebuilt-{}", h); }\n' \
  > "$work/near/vmcell-cli/src/main.rs"
run_ban "$work/near"
before=$fail
expect_rc 0 "near-miss spellings"
expect_clean 'vmcell-cli/src/main.rs'
expect_clean 'vmcell-kernel-builder/src/lib.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a THIRD composer inside the sanctioned home wears the home's exemption ---------------
printf 'fn sneak(l: &str) -> String { format!("kernel-{l}") }\n' >> "$work/near/vmcell/src/artifact/kernel.rs"
run_ban "$work/near"
before=$fail
expect_rc 1 "extra composer inside the home"
expect_flag 'holds 3 artifact-key composer(s)'
expect_flag 'expected 2'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a law that MOVED OUT of the home leaves the gate blind — not a pass ------------------
mk_clean_tree "$work/moved_law"
# The pin-key law relocated (e.g. to a new module) without updating the roster: the home now holds
# zero arm-2 composers, so every duplicate elsewhere would be scanned against a stale exemption.
printf 'pub use super::keys::kernel_pin_key;\npub fn kernel_artifact_key(l: Option<&str>) -> String { match l { Some(l) => format!("kernel-{l}"), None => "kernel".into() } }\nfn ck(h: &str) -> String { format!("kernel-{}", h) }\n' \
  > "$work/moved_law/vmcell/src/artifact/kernel.rs"
run_ban "$work/moved_law"
before=$fail
expect_rc 1 "law moved out of the sanctioned home"
expect_flag '0 pin-key composer(s)'
expect_flag 'this gate is now blind'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a home that moved or was renamed is a STALE exemption, not a pass --------------------
mk_clean_tree "$work/stale"
mv "$work/stale/vmcell/src/artifact/kernel.rs" "$work/stale/vmcell/src/artifact/kernel_keys.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "renamed sanctioned home"
expect_flag 'gate misconfigured'
expect_flag 'was not found'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: the scan must not be vacuous on an empty subtree ------------------------------------
# An empty tree reports "no Rust sources" and exits 0 — but pointing the real gate at a subtree that
# excludes the home must be the stale-exemption misconfiguration, never a silent pass.
mkdir -p "$work/empty/vmcell-daemon/src"
printf 'fn f() {}\n' > "$work/empty/vmcell-daemon/src/lib.rs"
run_ban "$work/empty"
before=$fail
expect_rc 1 "subtree without the home"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

if [[ $fail -ne 0 ]]; then
  echo "ban-kernel-key-composers self-test FAILED"
  exit 1
fi
echo "ok: ban-kernel-key-composers self-test passed"
