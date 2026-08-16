#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-unpinned-path-literal.sh (§10.5 F7 "one law, one
# predicate" for the `unpinned_path` override key, v33 delta 6c). Builds fixture trees mirroring the
# real crate layout (the exemption is a path suffix, so the layout is load-bearing) and asserts every
# half of the scanner can fail:
#   * deleting the literal scan lets a second `"unpinned_path"` in a parser or a flattener pass → reddens;
#   * deleting the exact-count check lets a SECOND literal inside the sanctioned home pass, or a home
#     that lost the const (leaving the gate blind) pass                                        → reddens;
#   * deleting the home-present check lets a renamed/moved home pass                           → reddens;
#   * deleting the non-vacuity check lets a tree with no Rust sources report "ok"              → reddens;
#   * the near misses — comment/doc prose, the identifier, a `#[cfg(test)]` JSON fixture, and a
#     `tests/` fixture outside `src/` — must stay un-flagged, so the scanner is precise rather than
#     merely loud. Those fixtures are the assertions that would go red if the const changed; a gate
#     that flagged them would be weakened until it flagged nothing.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-unpinned-path-literal.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the sanctioned home with EXACTLY its one literal, consumers naming the const,
# and every legitimate spelling that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/artifact" "$root/vmcell/tests" "$root/vmcell-cli/src"
  {
    printf '/// The one override key. §10.5 leaves the reading open between an entry key\n'
    # shellcheck disable=SC2016  # literal Rust doc text naming the key (intended near-miss)
    printf '/// (`{"acme": {"unpinned_path": "…"}}`) and a reserved label.\n'
    printf 'pub const UNPINNED_PATH_KEY: &str = "unpinned_path";\n'
  } > "$root/vmcell/src/artifact/registry.rs"
  # A consumer that NAMES the const, plus a unit-test JSON fixture that spells it literally.
  {
    printf 'fn parse(obj: &Map) -> Result<()> {\n'
    printf '    let unpinned = obj.get(UNPINNED_PATH_KEY);\n'
    printf '    Ok(())\n}\n'
    # shellcheck disable=SC2016  # literal Rust comment text (intended near-miss)
    printf '// the entry key is spelled "unpinned_path" — never write it, name the const\n'
    printf '#[cfg(test)]\n'
    printf 'mod tests {\n'
    # shellcheck disable=SC2016  # literal Rust raw-string JSON fixture (intended near-miss)
    printf '    const FIXTURE: &str = r#"{"rootfs": {"acme": {"unpinned_path": "/tmp/x"}}}"#;\n'
    printf '}\n'
  } > "$root/vmcell/src/artifact/bundle.rs"
  # A dev target outside src/: fixtures there are the proof the const is right, never a copy of it.
  # shellcheck disable=SC2016  # literal Rust raw-string JSON fixture (intended near-miss)
  printf 'const OVERLAY: &str = r#"{"handlers": {"acme": {"unpinned_path": "/tmp/h"}}}"#;\n' \
    > "$root/vmcell/tests/rootfs_registry.rs"
  printf 'fn refuse() { let k = vmcell::artifact::registry::UNPINNED_PATH_KEY; }\n' \
    > "$root/vmcell-cli/src/main.rs"
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

# --- Case 2: the regression this gate exists for — the key re-spelled in production ---------------
# The dangerous direction is the LAST one: a `bundle` refusal scanning for a different spelling
# silently bundles an unpinned registration.
mk_clean_tree "$work/dup"
{
  printf 'fn rootfs_entry(obj: &Map) -> Result<()> {\n'
  printf '    let known = matches!(key, "image" | "digest" | "unpinned_path");\n'
  printf '    Ok(())\n}\n'
  printf 'fn flatten(label: &str) { out.insert(rootfs_pin_key(label, "unpinned_path"), v); }\n'
} > "$work/dup/vmcell/src/artifact/mod.rs"
printf 'fn refuse(k: &str) -> bool { k.ends_with("unpinned_path") }\n' \
  > "$work/dup/vmcell-cli/src/main.rs"
run_ban "$work/dup"
before=$fail
expect_rc 1 "the key re-spelled outside the home"
expect_flag 'A second spelling of the F7 dev-override entry key'
expect_flag 'vmcell/src/artifact/mod.rs:2'
expect_flag 'vmcell/src/artifact/mod.rs:5'
expect_flag 'vmcell-cli/src/main.rs'
expect_clean 'artifact/registry.rs'            # the home itself stays clean
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: near-miss precision — every legitimate spelling stays un-flagged ---------------------
mk_clean_tree "$work/near"
run_ban "$work/near"
before=$fail
expect_rc 0 "prose, the identifier, a cfg(test) fixture and a tests/ fixture are not copies"
expect_clean 'artifact/bundle.rs'
expect_clean 'vmcell/tests/'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a SECOND literal inside the sanctioned home wears the home's exemption ---------------
mk_clean_tree "$work/extra"
printf 'fn sneak() -> &'"'"'static str { "unpinned_path" }\n' >> "$work/extra/vmcell/src/artifact/registry.rs"
run_ban "$work/extra"
before=$fail
expect_rc 1 "extra literal inside the home"
# shellcheck disable=SC2016  # literal scanner output, not shell expansion (intended)
expect_flag 'holds 2 `unpinned_path` literal(s)'
expect_flag 'expected 1'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: the const GONE from the home leaves the gate blind — not a pass ----------------------
mk_clean_tree "$work/moved_law"
printf 'pub use super::keys::UNPINNED_PATH_KEY;\n' > "$work/moved_law/vmcell/src/artifact/registry.rs"
run_ban "$work/moved_law"
before=$fail
expect_rc 1 "the const moved out of the sanctioned home"
# shellcheck disable=SC2016  # literal scanner output, not shell expansion (intended)
expect_flag 'holds 0 `unpinned_path` literal(s)'
expect_flag 'now blind'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a home that moved or was renamed is a STALE exemption, not a pass --------------------
mk_clean_tree "$work/stale"
mv "$work/stale/vmcell/src/artifact/registry.rs" "$work/stale/vmcell/src/artifact/keys.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "renamed sanctioned home"
expect_flag 'gate misconfigured'
expect_flag 'was not found'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: a subtree that excludes the home is a misconfiguration, not an "ok" ------------------
mkdir -p "$work/empty/vmcell-daemon/src"
printf 'fn f() {}\n' > "$work/empty/vmcell-daemon/src/lib.rs"
run_ban "$work/empty"
before=$fail
expect_rc 1 "subtree without the home"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

# --- Case 8: a tree with no src/ sources at all must NOT report "ok" (non-vacuity) ----------------
mkdir -p "$work/nosrc/vmcell/tests"
printf 'fn f() {}\n' > "$work/nosrc/vmcell/tests/t.rs"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no production sources at all"
expect_flag 'vacuous'
[[ $fail -ne $before ]] && dump "case 8"

if [[ $fail -ne 0 ]]; then
  echo "ban-unpinned-path-literal self-test FAILED"
  exit 1
fi
echo "ok: ban-unpinned-path-literal self-test passed"
