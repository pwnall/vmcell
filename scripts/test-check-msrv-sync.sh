#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/check-msrv-sync.sh.
#
# The gate asserts ONE MSRV fact: `rust-toolchain.toml`'s pinned `[toolchain] channel` equals the
# declared `[workspace.package] rust-version`, and every other spelling of that number in the tree
# (a literal `rust-version` in an out-of-workspace manifest, a nested `rust-toolchain.toml`,
# `clippy.toml`'s `msrv`) equals it too. A gate whose self-test only proves the green path is theater
# (AGENTS.md rule 2), so every arm below is driven from a fixture tree the check is POINTED AT, and
# each is asserted to pass or fail:
#   * equal pair, with a member inheriting via `rust-version.workspace`      → must pass;
#   * unequal pair, both directions (the UNDERSTATED one is the named
#     `time 0.3.45` hazard)                                                 → must fail;
#   * a missing rust-toolchain.toml / a missing Cargo.toml                   → must fail;
#   * an absent `channel` key / an absent `rust-version` key                 → must fail;
#   * `rust-version` present but under the WRONG table — the exact input the
#     section-blind inline `sed` this replaces would have accepted            → must fail;
#   * a non-VERSION channel (`stable`), which makes the equality unstatable   → must fail;
#   * a SECOND literal declaration drifting low in an out-of-workspace crate
#     (the `fuzz/` and `examples/downstream-kernel/` shape — the copies the
#     two inline assertions never looked at)                                  → must fail;
#   * a nested `rust-toolchain.toml` pinning a different channel              → must fail;
#   * `clippy.toml` msrv drift                                               → must fail;
#   * `clippy.toml` absent, and present-without-`msrv` (clippy then falls
#     back to `rust-version`, which IS the one fact)                          → must pass.
#
# NOT reachable here (enumerated, not silently skipped — AGENTS.md rule 4): the gate's
# zero-manifest-scanned `gate misconfigured` arm. Once the root `Cargo.toml` existence check has
# passed, the scan always finds at least that manifest, so no fixture can drive the arm. It is kept in
# the gate as the belt-and-braces form the house style requires of every source-scanning check
# (docs/90 G4) and is proven only by inspection.
#
# Usage: test-check-msrv-sync.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

# ROOT is the repo whose scripts/ holds the check under test — the same optional argument every gate
# script here takes, so `just gates` and a hand run from any directory behave identically.
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
check="$root/scripts/check-msrv-sync.sh"
if [[ ! -x "$check" ]]; then
  echo "gate misconfigured: no executable check at: $check" >&2
  exit 1
fi
work="$(mktemp -d)"
# The fixture tree is residue too: cleaned on the panic path as well as the success path
# (AGENTS.md "Writing tests" — a leaked fixture reddens somebody else's suite as a product defect).
trap 'rm -rf "$work"' EXIT INT TERM

fail=0

# mk_tree <dir> <channel-line> <workspace-rust-version-line> — builds a minimal workspace: the pinned
# channel, the root manifest, and ONE member that inherits the fact the sanctioned way. Pass an empty
# string for either line to omit that key (the absent-key arms).
mk_tree() {
  local dir="$1" channel_line="$2" rv_line="$3"
  mkdir -p "$dir/crates/member/src"
  {
    printf '[toolchain]\n'
    [[ -n "$channel_line" ]] && printf '%s\n' "$channel_line"
    printf 'components = ["clippy", "rustfmt"]\n'
  } > "$dir/rust-toolchain.toml"
  {
    printf '[workspace]\nresolver = "2"\nmembers = ["crates/member"]\n\n'
    printf '[workspace.package]\nedition = "2024"\n'
    [[ -n "$rv_line" ]] && printf '%s\n' "$rv_line"
  } > "$dir/Cargo.toml"
  printf '[package]\nname = "member"\nversion = "0.1.0"\nrust-version.workspace = true\n' \
    > "$dir/crates/member/Cargo.toml"
}

# run <fixture-tree> — captures OUT/RC as globals (a plain call, not a `$(...)` capture, so the assignments
# survive: command substitution would run this in a subshell and take them with it).
run() {
  set +e
  OUT="$("$check" "$1" 2>&1)"
  RC=$?
  set -e
}

expect_pass() {  # expect_pass <label> <fixture-tree> [want-substring …]
  local label="$1" fixture="$2"; shift 2
  run "$fixture"
  if [[ "$RC" -ne 0 ]]; then
    echo "  FAIL [$label] must PASS, exited $RC:"; printf '%s\n' "$OUT" | sed 's/^/       /'; fail=1
    return
  fi
  local w
  for w in "$@"; do
    if ! grep -qF -- "$w" <<<"$OUT"; then
      echo "  FAIL [$label] passed but its verdict never says '$w':"; printf '%s\n' "$OUT" | sed 's/^/       /'
      fail=1
    fi
  done
  echo "  ok   [$label] passes"
}

expect_fail() {  # expect_fail <label> <fixture-tree> [want-substring …]
  local label="$1" fixture="$2"; shift 2
  run "$fixture"
  if [[ "$RC" -eq 0 ]]; then
    echo "  FAIL [$label] must FAIL, but it passed — the gate cannot go red here:"
    printf '%s\n' "$OUT" | sed 's/^/       /'; fail=1
    return
  fi
  local w
  for w in "$@"; do
    if ! grep -qF -- "$w" <<<"$OUT"; then
      echo "  FAIL [$label] reddened for the wrong reason (missing '$w'):"
      printf '%s\n' "$OUT" | sed 's/^/       /'; fail=1
    fi
  done
  echo "  ok   [$label] reddens"
}

echo "test-check-msrv-sync:"

# --- Green baseline. Without it every failing arm below proves nothing: a check that always fails is
# --- as useless as one that never does. The `inheriting via rust-version.workspace` figure is pinned
# --- so a future "simplification" that stops distinguishing the sanctioned non-copy from a literal
# --- (and therefore stops comparing the literals) reddens here.
mk_tree "$work/green" 'channel = "1.96.1"' 'rust-version = "1.96.1"'
expect_pass "equal pair" "$work/green" \
  'channel = 1.96.1' 'rust-version = 1.96.1' '1 inheriting via rust-version.workspace'

# --- Arm 1: drift, UNDERSTATED — the named hazard. The workspace is tested on 1.96.1 while consumers
# --- are told 1.85 works, so an MSRV-aware resolver hands them the older dependency versions the
# --- lockfile pins away from (the `time 0.3.45` class).
mk_tree "$work/understated" 'channel = "1.96.1"' 'rust-version = "1.85.0"'
expect_fail "understated MSRV" "$work/understated" 'MSRV drift' '1.85.0'

# --- Arm 1b: drift the OTHER way (declared floor above the pinned toolchain) must redden too — a
# --- one-sided comparison would let this through, and it refuses consumers that would work.
mk_tree "$work/overstated" 'channel = "1.90.0"' 'rust-version = "1.96.1"'
expect_fail "overstated MSRV" "$work/overstated" 'MSRV drift'

# --- Arm 2: the two halves of the one fact, each missing in turn.
mk_tree "$work/no-toolchain-file" 'channel = "1.96.1"' 'rust-version = "1.96.1"'
rm -f "$work/no-toolchain-file/rust-toolchain.toml"
expect_fail "no rust-toolchain.toml" "$work/no-toolchain-file" 'gate misconfigured'

mk_tree "$work/no-manifest" 'channel = "1.96.1"' 'rust-version = "1.96.1"'
rm -f "$work/no-manifest/Cargo.toml"
expect_fail "no root Cargo.toml" "$work/no-manifest" 'gate misconfigured'

# --- Arm 3: the files exist but the KEY is gone. An absent pin, or an absent declared floor, is the
# --- understatement at its widest — and the shape a permissive check reports as "nothing to compare,
# --- therefore fine".
mk_tree "$work/no-channel" '' 'rust-version = "1.96.1"'
expect_fail "no [toolchain] channel" "$work/no-channel" 'declares no'

mk_tree "$work/no-rustversion" 'channel = "1.96.1"' ''
expect_fail "no [workspace.package] rust-version" "$work/no-rustversion" 'declares no'

# --- Arm 4: SECTION AWARENESS. `rust-version` under `[package]` in the root manifest is not the
# --- workspace fact members inherit — nothing inherits it, so every member is still undeclared. The
# --- inline `sed` this gate replaces was section-blind and would have read this as a match, reporting
# --- a synced MSRV that no crate declares.
mk_tree "$work/wrong-table" 'channel = "1.96.1"' ''
printf '\n[package]\nname = "root-shim"\nrust-version = "1.96.1"\n' >> "$work/wrong-table/Cargo.toml"
expect_fail "rust-version under the wrong table" "$work/wrong-table" 'declares no'

# --- Arm 5: an unpinned channel. `stable` cannot be compared against a declared floor at all, so
# --- accepting it would leave this gate green while the pin it enforces does not exist.
mk_tree "$work/unpinned" 'channel = "stable"' 'rust-version = "1.96.1"'
expect_fail "non-version channel" "$work/unpinned" 'non-VERSION channel'

# --- Arm 6: THE COPY THE INLINE ASSERTIONS NEVER LOOKED AT. `fuzz/` and
# --- `examples/downstream-kernel/` are separate workspaces: they cannot write
# --- `rust-version.workspace = true`, so each spells the number literally. A literal that drifts low
# --- in the CONSUMER workspace is the understated-MSRV hazard reaching exactly the audience the
# --- contract exists for.
mk_tree "$work/second-literal" 'channel = "1.96.1"' 'rust-version = "1.96.1"'
mkdir -p "$work/second-literal/examples/downstream-kernel"
printf '[package]\nname = "downstream"\nversion = "0.1.0"\nrust-version = "1.80.0"\n' \
  > "$work/second-literal/examples/downstream-kernel/Cargo.toml"
expect_fail "out-of-workspace literal drifts low" "$work/second-literal" \
  'examples/downstream-kernel/Cargo.toml' '1.80.0'

# --- Arm 6b: the same literal, in AGREEMENT, must stay clean — otherwise arm 6 would be satisfied by
# --- a check that simply refuses every second manifest.
printf '[package]\nname = "downstream"\nversion = "0.1.0"\nrust-version = "1.96.1"\n' \
  > "$work/second-literal/examples/downstream-kernel/Cargo.toml"
expect_pass "out-of-workspace literal in agreement" "$work/second-literal" \
  '2 literal rust-version declaration(s)'

# --- Arm 7: a NESTED workspace pinning a different toolchain — the second half of the same drift, on
# --- the channel side. It means one of the two workspaces is built on a toolchain nobody tested.
mk_tree "$work/nested-channel" 'channel = "1.96.1"' 'rust-version = "1.96.1"'
mkdir -p "$work/nested-channel/fuzz"
printf '[package]\nname = "fuzz"\nversion = "0.1.0"\nrust-version = "1.96.1"\n' \
  > "$work/nested-channel/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-01-01"\n' > "$work/nested-channel/fuzz/rust-toolchain.toml"
expect_fail "nested rust-toolchain.toml disagrees" "$work/nested-channel" \
  'fuzz/rust-toolchain.toml' 'nightly-2026-01-01'

# --- Arm 8: clippy.toml. Its own comment claims a sync assertion keeps it in lockstep; the assertion
# --- this gate replaces never opened the file. Drift must redden…
mk_tree "$work/clippy-drift" 'channel = "1.96.1"' 'rust-version = "1.96.1"'
printf 'msrv = "1.88.0"\nallow-unwrap-in-tests = true\n' > "$work/clippy-drift/clippy.toml"
expect_fail "clippy.toml msrv drift" "$work/clippy-drift" 'clippy.toml' '1.88.0'

# --- …and the two legitimate shapes must stay green: no clippy.toml at all, and a clippy.toml that
# --- declares no `msrv` (clippy then falls back to the manifest's `rust-version`, which IS the one
# --- fact — flagging that would be flagging the correct configuration).
mk_tree "$work/clippy-absent" 'channel = "1.96.1"' 'rust-version = "1.96.1"'
expect_pass "no clippy.toml" "$work/clippy-absent" 'one MSRV fact'
printf 'allow-unwrap-in-tests = true\n' > "$work/clippy-absent/clippy.toml"
expect_pass "clippy.toml without msrv" "$work/clippy-absent" 'one MSRV fact'

# --- Arm 9: a missing ROOT is a misconfiguration, not a clean tree.
expect_fail "nonexistent root" "$work/no-such-root" 'gate misconfigured'

if [[ "$fail" -ne 0 ]]; then
  echo "test-check-msrv-sync: FAIL" >&2
  exit 1
fi
echo "test-check-msrv-sync: ok (all arms driven: equality both directions, both missing files, both"
echo "absent keys, the wrong-table read, an unpinned channel, a second literal + a nested channel +"
echo "clippy.toml drift, and the two legitimate clippy.toml shapes)"
