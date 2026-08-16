#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-rootfs-key-composers.sh (§10.5 "one law, one predicate"
# for the rootfs artifact-key and pin-key laws, v33 delta 6). Builds fixture trees that mirror the
# real crate layout (the exemption is a path suffix, so the layout is load-bearing) and asserts every
# half of the scanner can fail:
#   * deleting the arm-1 pattern lets a re-derived `rootfs-<label>` artifact key pass  → this reddens;
#   * deleting the arm-2 pattern lets a re-derived `rootfs_<label>_<sub>` pin key pass → reddens;
#   * deleting the exact-count check lets a THIRD composer added inside the sanctioned home pass, or
#     a law that MOVED OUT of the home (leaving the gate blind) pass                   → reddens;
#   * deleting the home-present check lets a renamed/moved home pass                   → reddens;
#   * the near-miss spellings (the plain literals fixtures pin the law with, and a doc comment
#     writing the shape) must stay un-flagged, so the scanner is precise rather than merely loud.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-rootfs-key-composers.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline every fixture starts from: the sanctioned home with EXACTLY its two arm-1 and
# two arm-2 composers, plus every legitimate spelling that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/artifact/rootfs" "$root/vmcell-rootfs-builder/src" "$root/vmcell-cli/src"
  {
    # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
    printf '/// The flattened pins key: `rootfs_<label>_<sub_key>` or `rootfs_<sub_key>`.\n'
    printf 'pub fn rootfs_pin_key(label: Option<&str>, sub_key: &str) -> String {\n'
    printf '    match label {\n'
    printf '        Some(l) => format!("rootfs_{l}_{sub_key}"),\n'
    printf '        None => format!("rootfs_{sub_key}"),\n'
    printf '    }\n}\n'
    printf 'pub fn rootfs_artifact_key(label: Option<&str>) -> String {\n'
    printf '    match label {\n'
    printf '        Some(l) => format!("rootfs-{l}"),\n'
    printf '        None => "rootfs".to_string(),\n'
    printf '    }\n}\n'
    # Near-miss: the cache-key namespace prefix. It is COUNTED by arm 1 as the home's second
    # sanctioned match rather than pattern-excluded, so the home cannot become a hiding place.
    printf 'fn ck(h: &str) -> String { CacheKey(format!("rootfs-{}", h)) }\n'
  } > "$root/vmcell/src/artifact/rootfs/mod.rs"
  # A consumer that CALLS both laws, plus the plain literals a fixture pins the law's output with —
  # never flagged, or the gate would delete its own proof.
  {
    printf 'fn keys(label: Option<&str>) -> (String, String) {\n'
    printf '    (rootfs::rootfs_pin_key(label, "image"), rootfs::rootfs_artifact_key(label))\n}\n'
    printf 'fn fixture(i: &mut StageInputs) {\n'
    printf '    i.pins.insert("rootfs_image".into(), "img".into());\n'
    printf '    assert_eq!(rootfs::rootfs_artifact_key(None), "rootfs");\n}\n'
  } > "$root/vmcell-rootfs-builder/src/lib.rs"
  # Prose writing the banned shape in a comment is not code.
  {
    # shellcheck disable=SC2016  # literal Rust comment text (intended)
    printf '// the flattener emits format!("rootfs_{label}_image") — do not re-derive it\n'
    printf 'fn bundle() { let k = vmcell::artifact::rootfs::rootfs_artifact_key(Some(l)); }\n'
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
# The rootfs analogue of the docs/81 §8 kernel defect: a builder byte-duplicating the artifact key
# and the pin key, the flattener composing the pin key inline, and the CLI re-spelling the artifact
# key. On the DEFAULT label the pin-key half silently repoints `resolve_builder_base`.
mk_clean_tree "$work/dup"
{
  printf 'fn image_pin_key(label: &Option<String>) -> String {\n'
  printf '    match label {\n'
  printf '        Some(l) => format!("rootfs_{l}_image"),\n'
  printf '        None => "rootfs_image".to_string(),\n'
  printf '    }\n}\n'
  printf 'fn artifact_key(label: &Option<String>) -> String {\n'
  printf '    match label {\n'
  printf '        Some(l) => format!("rootfs-{l}"),\n'
  printf '        None => "rootfs".to_string(),\n'
  printf '    }\n}\n'
} > "$work/dup/vmcell-rootfs-builder/src/lib.rs"
printf 'fn flatten(label: &str, img: &str) { out.insert(format!("rootfs_{label}_image"), img.to_string()); }\n' \
  > "$work/dup/vmcell/src/artifact/mod.rs"
# The positional-argument spelling of the same bug: no inline capture, same drift.
printf 'fn bundle(label: &str) { candidates.push((format!("rootfs-{}", label), p)); }\n' \
  > "$work/dup/vmcell-cli/src/main.rs"
run_ban "$work/dup"
before=$fail
expect_rc 1 "both laws re-derived outside the home"
expect_flag 'ARTIFACT-KEY law'
expect_flag 'PIN-KEY law'
expect_flag 'vmcell-rootfs-builder/src/lib.rs:3'   # the pin-key duplicate
expect_flag 'vmcell-rootfs-builder/src/lib.rs:9'   # the artifact-key duplicate
expect_flag 'artifact/mod.rs'
expect_flag 'vmcell-cli/src/main.rs'
expect_clean 'artifact/rootfs/mod.rs'              # the home itself stays clean
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: near-miss precision — every legitimate spelling stays un-flagged ---------------------
mk_clean_tree "$work/near"
printf 'fn f() { let a = "rootfs_image"; let b = format!("rootfs.erofs"); let c = format!("rootfs-{}", h); }\n' \
  > "$work/near/vmcell-rootfs-builder/src/lib.rs"
run_ban "$work/near"
before=$fail
# The third spelling above IS the banned arm-1 shape, deliberately: a cache-key prefix OUTSIDE the
# home is exactly the duplicate this gate refuses, so this case asserts it is caught while the
# plain literal and the `.erofs` filename beside it are not.
expect_rc 1 "a cache-key prefix outside the home is still a duplicate"
expect_flag 'vmcell-rootfs-builder/src/lib.rs'
expect_clean 'vmcell-cli/src/main.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a THIRD composer inside the sanctioned home wears the home's exemption ---------------
mk_clean_tree "$work/extra"
printf 'fn sneak(l: &str) -> String { format!("rootfs-{l}") }\n' >> "$work/extra/vmcell/src/artifact/rootfs/mod.rs"
run_ban "$work/extra"
before=$fail
expect_rc 1 "extra composer inside the home"
expect_flag 'holds 3 artifact-key composer(s)'
expect_flag 'expected 2'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a law that MOVED OUT of the home leaves the gate blind — not a pass ------------------
mk_clean_tree "$work/moved_law"
printf 'pub use super::keys::rootfs_pin_key;\npub fn rootfs_artifact_key(l: Option<&str>) -> String { match l { Some(l) => format!("rootfs-{l}"), None => "rootfs".into() } }\nfn ck(h: &str) -> String { format!("rootfs-{}", h) }\n' \
  > "$work/moved_law/vmcell/src/artifact/rootfs/mod.rs"
run_ban "$work/moved_law"
before=$fail
expect_rc 1 "law moved out of the sanctioned home"
expect_flag '0 pin-key composer(s)'
expect_flag 'this gate is now blind'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a home that moved or was renamed is a STALE exemption, not a pass --------------------
mk_clean_tree "$work/stale"
mv "$work/stale/vmcell/src/artifact/rootfs/mod.rs" "$work/stale/vmcell/src/artifact/rootfs/keys.rs"
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

if [[ $fail -ne 0 ]]; then
  echo "ban-rootfs-key-composers self-test FAILED"
  exit 1
fi
echo "ok: ban-rootfs-key-composers self-test passed"
