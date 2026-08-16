#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-registry-digest-check.sh (§10.5 F7 "one law, one
# predicate" for the registry digest FORMAT check, v33 delta 6c). Builds fixture trees mirroring the
# real module layout (the exemption is a path suffix, so the layout is load-bearing) and asserts
# every half of the scanner can fail:
#   * deleting the window scan lets a re-derived `sha256:` + 64-hex check pass — in either of the
#     two spellings that actually shipped (`!= 64 ||` and `== 64 &&`)                → reddens;
#   * deleting the exact-count check lets a SECOND check inside the sanctioned home pass, or a home
#     that lost its check (leaving the gate blind) pass                              → reddens;
#   * deleting the home-present check lets a renamed/moved home pass                 → reddens;
#   * deleting the non-vacuity check lets an empty tree report "ok"                  → reddens;
#   * the near misses stay un-flagged: a `strip_prefix("sha256:")` that COMPARES bytes with no
#     length test (`verify_handler_digest`, `cached_blob_matches` — banning those would delete the
#     verification the registry exists to enable), a bare `"sha256:"` literal, prose writing the
#     shape, and a `#[cfg(test)]` fixture that recomputes the law as its own assertion.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-registry-digest-check.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the sanctioned home with EXACTLY its one check, plus every legitimate
# `sha256:` spelling that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/artifact/rootfs"
  {
    printf 'pub(crate) fn reject_unpinned_digest(ns: &str, label: &str, digest: &str) -> Result<()> {\n'
    printf '    let hex = digest.strip_prefix("sha256:").unwrap_or_default();\n'
    printf "    if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {\n"
    printf '        return Ok(());\n'
    printf '    }\n'
    # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
    printf '    Err(Error::Artifact(format!("pins `{ns}.{label}.digest` must be sha256:<64 lowercase hex>")))\n'
    printf '}\n'
  } > "$root/artifact/registry.rs"
  # The two COMPARISON sites: same strip, no length test. Never flagged.
  {
    printf 'pub(crate) fn verify_handler_digest(label: &str, digest: &str, bytes: &[u8]) -> Result<()> {\n'
    printf '    let expected = digest.strip_prefix("sha256:").unwrap_or(digest);\n'
    printf '    let got = sha256_hex(bytes);\n'
    printf '    if got == expected { return Ok(()); }\n'
    # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
    printf '    Err(Error::Artifact(format!("handler `{label}` digest mismatch")))\n'
    printf '}\n'
    printf 'pub(crate) async fn cached_blob_matches(path: &Path, digest: &str) -> bool {\n'
    printf '    match tokio::fs::read(path).await {\n'
    printf '        Ok(bytes) => sha256_hex(&bytes) == digest.strip_prefix("sha256:").unwrap_or(digest),\n'
    printf '        Err(_) => false,\n'
    printf '    }\n}\n'
  } > "$root/artifact/handler.rs"
  # Prose writing the shape, a bare literal, and a unit-test fixture recomputing the law.
  {
    # shellcheck disable=SC2016  # literal Rust comment text (intended near-miss)
    printf '// checked through the one predicate: strip_prefix("sha256:") plus a 64-length test\n'
    printf 'fn pull(digest: &str) -> Result<()> {\n'
    printf '    if !digest.starts_with("sha256:") { return Err(tag_error()); }\n'
    printf '    Ok(())\n}\n'
    printf '#[cfg(test)]\n'
    printf 'mod tests {\n'
    printf '    fn is_pinned(d: &str) -> bool {\n'
    printf '        let hex = d.strip_prefix("sha256:").unwrap_or_default();\n'
    printf '        hex.len() == 64\n'
    printf '    }\n}\n'
  } > "$root/artifact/rootfs/mod.rs"
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

# --- Case 2: the regression this gate exists for — BOTH shipped duplicate spellings ---------------
# `artifact/mod.rs`'s inline `!= 64 ||` copy and `handler.rs`'s `== 64 &&` function, verbatim in
# shape. They were byte-equivalent and their MESSAGES were not, which is the whole defect.
mk_clean_tree "$work/dup"
{
  printf 'fn rootfs_entry(label: &str, digest: &str) -> Result<()> {\n'
  printf '    let hex = digest.strip_prefix("sha256:").unwrap_or_default();\n'
  printf '    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {\n'
  # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
  printf '        return Err(Error::Artifact(format!("pins `rootfs.{label}.digest` is malformed")));\n'
  printf '    }\n'
  printf '    Ok(())\n}\n'
} > "$work/dup/artifact/mod.rs"
{
  printf 'fn reject_unpinned_digest(label: &str, digest: &str) -> Result<()> {\n'
  printf '    let hex = digest.strip_prefix("sha256:").unwrap_or_default();\n'
  printf '    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) { return Ok(()); }\n'
  # shellcheck disable=SC2016  # literal Rust text, not shell expansion (intended)
  printf '    Err(Error::Artifact(format!("pins `handlers.{label}.digest` is malformed")))\n'
  printf '}\n'
} >> "$work/dup/artifact/handler.rs"
run_ban "$work/dup"
before=$fail
expect_rc 1 "both shipped duplicate spellings"
expect_flag 'A second spelling of the registry digest-format law'
expect_flag 'artifact/mod.rs:2'
expect_flag 'artifact/handler.rs'
expect_clean 'artifact/registry.rs'   # the home itself stays clean
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: near-miss precision — the comparison sites and the fixtures stay un-flagged ----------
mk_clean_tree "$work/near"
run_ban "$work/near"
before=$fail
expect_rc 0 "comparison sites, prose, bare literal and a cfg(test) fixture are not format checks"
expect_clean 'artifact/handler.rs'
expect_clean 'artifact/rootfs/mod.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a SECOND check inside the sanctioned home wears the home's exemption -----------------
mk_clean_tree "$work/extra"
{
  printf 'fn sneak(d: &str) -> bool {\n'
  printf '    let hex = d.strip_prefix("sha256:").unwrap_or_default();\n'
  printf '    hex.len() == 64\n}\n'
} >> "$work/extra/artifact/registry.rs"
run_ban "$work/extra"
before=$fail
expect_rc 1 "extra check inside the home"
expect_flag 'holds 2 digest-format check(s)'
expect_flag 'expected 1'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: the check GONE from the home leaves the gate blind — not a pass ----------------------
mk_clean_tree "$work/moved_law"
printf 'pub(crate) use super::digest::reject_unpinned_digest;\n' > "$work/moved_law/artifact/registry.rs"
run_ban "$work/moved_law"
before=$fail
expect_rc 1 "the predicate moved out of the sanctioned home"
expect_flag 'holds 0 digest-format check(s)'
expect_flag 'now blind'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a home that moved or was renamed is a STALE exemption, not a pass --------------------
mk_clean_tree "$work/stale"
mv "$work/stale/artifact/registry.rs" "$work/stale/artifact/digest.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "renamed sanctioned home"
expect_flag 'gate misconfigured'
expect_flag 'was not found'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: a subtree that excludes the home is a misconfiguration, not an "ok" ------------------
mkdir -p "$work/empty/net"
printf 'fn f() {}\n' > "$work/empty/net/mod.rs"
run_ban "$work/empty"
before=$fail
expect_rc 1 "subtree without the home"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

# --- Case 8: a tree with no Rust sources at all must NOT report "ok" (non-vacuity) ----------------
mkdir -p "$work/nosrc"
printf 'not rust\n' > "$work/nosrc/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources at all"
expect_flag 'vacuous'
[[ $fail -ne $before ]] && dump "case 8"

if [[ $fail -ne 0 ]]; then
  echo "ban-registry-digest-check self-test FAILED"
  exit 1
fi
echo "ok: ban-registry-digest-check self-test passed"
