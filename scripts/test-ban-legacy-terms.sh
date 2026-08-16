#!/usr/bin/env bash
# Self-test for scripts/ban-legacy-terms.sh (design v14 §10.7 regression gate). Builds a fixture
# tree and asserts the scanner goes RED on each retired token — including the standalone capitalized
# `Imp` origin-harness name — and GREEN on clean code, on the English words
# `implementation`/`import`/`impl`, and on a per-line exemption.
# This is the "red on the inverse" guard: drop any banned pattern from the scanner and a fixture
# below stops being flagged; break comment-stripping and the prose fixture trips; break the
# exemption marker and the exempted fixture trips.
#
# It also drives the ROSTER, not just the patterns (docs/81 M13): the scanner used to gate its
# collector on `[[ -d "$d" ]]`, so the default roster's `justfile` — a regular file — was never
# opened, while the success line named it anyway. The regular-file / mixed-roster / empty-roster /
# missing-entry legs below are the red-on-inverse for that: restore the `-d` gate and the
# justfile-shaped fixture goes green, which fails this test.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-legacy-terms.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src"

# --- MUST be flagged (one isolated banned token per fixture) ------------------------------
printf 'struct TestVm {}\n'                                  > "$work/src/testvm.rs"
printf 'fn pick() { let _m = "rootless"; }\n'                > "$work/src/rootless.rs"
printf 'fn imp_testing_helper() {}\n'                        > "$work/src/under_testing.rs"
printf 'const P: &str = "Imp-testing project";\n'            > "$work/src/cap_testing.rs"
printf 'fn b() { let _ = "imp-guest-agent"; }\n'             > "$work/src/binname.rs"
printf 'fn k() { let _ = std::env::var("IMP_KERNEL"); }\n'   > "$work/src/envvar.rs"
printf 'fn t() { let _ = "imp-tap0"; }\n'                    > "$work/src/prefix.rs"
printf 'fn v() { let _ = imp_vmid(5); }\n'                   > "$work/src/ident.rs"
printf 'struct Imp;\nconst H: &str = "Imp'"'"'s cell";\n'   > "$work/src/cap_imp.rs"

# v33 delta 1 — the steward rename. ONE fixture per new scanner branch, so deleting any branch
# reddens exactly one fixture (the meta-rule: a gate whose self-test cannot fail is theater).
printf 'fn c() { let _ = "vmcell-guest-agent"; }\n'           > "$work/src/sw_crate.rs"
printf 'fn c() { let _ = vmcell_guest_agent::VERSION; }\n'    > "$work/src/sw_lib.rs"
printf 'struct AgentClient;\n'                                > "$work/src/sw_client.rs"
printf 'struct AgentPlacement;\n'                             > "$work/src/sw_placement.rs"
printf 'struct AgentOptions;\n'                               > "$work/src/sw_options.rs"
printf 'struct GuestAgentStage;\n'                            > "$work/src/sw_stage.rs"
printf 'fn e() -> Error { Error::Agent("x".into()) }\n'       > "$work/src/sw_error.rs"
printf 'const P: u32 = AGENT_VSOCK_PORT;\n'                   > "$work/src/sw_port.rs"
printf 'fn h() { let _ = guest_agent_src_hash(); }\n'         > "$work/src/sw_srchash.rs"
printf 'fn h() { let _ = guest_agent_closure_hash(); }\n'     > "$work/src/sw_closhash.rs"
printf 'const ID: &str = "boot.agent_ready";\n'               > "$work/src/sw_bootid.rs"
printf 'const ID: &str = "agent.exec_roundtrip";\n'           > "$work/src/sw_execid.rs"
printf 'fn f() { let _ = "--agent-musl"; }\n'                 > "$work/src/sw_flag.rs"
printf 'fn f() { let _ = agent_musl_path(); }\n'              > "$work/src/sw_musl.rs"

# --- MUST NOT be flagged ------------------------------------------------------------------
# The ordinary English words implementation/import/impl — never flagged, because `Imp`/`imp` is
# followed by a word character (so the standalone-`Imp` and `imp-`/`imp_` patterns can't match).
printf 'fn implementation_detail() {}\nfn importer() {}\nimpl Foo {}\nstruct Foo;\n' > "$work/src/origin.rs"
# Clean renamed code.
printf 'struct VmCell;\nfn spawn() { let _ = "vmcell-vm-spawn"; }\n'        > "$work/src/clean.rs"
# A genuinely-justified legacy mention carrying the per-line exemption marker.
printf 'const LEGACY: &str = "imp-testing"; // allow-legacy-term: fixture exercising the exemption\n' > "$work/src/exempt.rs"
# Prose-only mention in a comment — stripped before analysis, so not a false positive.
printf '// renamed away from the old rootless / imp-testing names to vmcell\nfn ok() {}\n' > "$work/src/prose.rs"

# v33 delta 1 — the KEPT words. "Agent" survives as the DOMAIN word, and a bare-word ban would
# redden the tree on its own charter. Each of these is live code (not a comment), so it is the
# scanner's PATTERNS being tested, not its comment-stripping.
printf 'const DOC: &str = "AGENTS.md";\n'                            > "$work/src/keep_agentsmd.rs"
printf 'const D: &str = "vmcell serves agentic execution";\n'        > "$work/src/keep_agentic.rs"
printf 'const F: &str = "AGENT-2 was the finding id";\n'             > "$work/src/keep_findingid.rs"
printf 'const K: &str = "kata agent-ctl speaks the same wire";\n'    > "$work/src/keep_agentctl.rs"
printf 'const H: &str = "User-Agent";\nconst P: &str = "Proxy-Agent";\nconst L: &str = "user-agent";\n' > "$work/src/keep_httphdr.rs"
# The exemption marker works for the new family too, not just the imp-* one.
printf 'const OLD: &str = "vmcell-guest-agent"; // allow-legacy-term: fixture exercising the steward-rename exemption\n' > "$work/src/keep_exempt_steward.rs"

set +e
out="$("$ban" "$work/src" 2>&1)"
rc=$?
set -e

fail=0
expect_flag() {
  if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi
}
expect_clean() {
  if grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi
}

if [[ $rc -ne 1 ]]; then echo "FAIL: scanner exit code = $rc, expected 1 (violations present)"; fail=1; fi
expect_flag testvm.rs
expect_flag rootless.rs
expect_flag under_testing.rs
expect_flag cap_testing.rs
expect_flag binname.rs
expect_flag envvar.rs
expect_flag prefix.rs
expect_flag ident.rs
expect_flag cap_imp.rs
# v33 delta 1: one assertion per new scanner branch.
expect_flag sw_crate.rs
expect_flag sw_lib.rs
expect_flag sw_client.rs
expect_flag sw_placement.rs
expect_flag sw_options.rs
expect_flag sw_stage.rs
expect_flag sw_error.rs
expect_flag sw_port.rs
expect_flag sw_srchash.rs
expect_flag sw_closhash.rs
expect_flag sw_bootid.rs
expect_flag sw_execid.rs
expect_flag sw_flag.rs
expect_flag sw_musl.rs
expect_clean origin.rs
expect_clean clean.rs
expect_clean exempt.rs
expect_clean prose.rs
# v33 delta 1: the kept words must stay green — a bare-word ban would redden the tree's own charter.
expect_clean keep_agentsmd.rs
expect_clean keep_agentic.rs
expect_clean keep_findingid.rs
expect_clean keep_agentctl.rs
expect_clean keep_httphdr.rs
expect_clean keep_exempt_steward.rs

# Cross-check: a fully-clean tree exits 0 with the "ok:" line.
mkdir -p "$work/clean"
printf 'struct VmCell;\nfn implementation_detail() {}\nfn spawn() { let _ = "vmcell"; }\n' > "$work/clean/a.rs"
set +e
clean_out="$("$ban" "$work/clean" 2>&1)"
clean_rc=$?
set -e
if [[ $clean_rc -ne 0 ]]; then echo "FAIL: clean tree exit code = $clean_rc, expected 0"; fail=1; fi
if ! grep -q '^ok:' <<<"$clean_out"; then echo "FAIL: clean tree missing 'ok:' line"; fail=1; fi

# --- The roster legs: a REGULAR FILE in the roster must actually be scanned ----------------
# docs/81 M13: the collector was `[[ -d "$d" ]] && find "$d" -type f -print0`, so the default
# roster's `justfile` — a regular file — was dropped, while the success line kept naming it. The
# fixture below is the review's own reproduction (a justfile-shaped file carrying `test-rootless:`
# and `echo imp-testing`); it exited 0 on the old collector. `justfile` has no extension, so it
# takes the `#`-stripping branch — the banned tokens are on live recipe lines, not in comments, so
# the fixture stays non-vacuous under that branch.
printf 'test-rootless:\n    echo imp-testing\n' > "$work/justfile"
set +e
jf_out="$("$ban" "$work/justfile" 2>&1)"
jf_rc=$?
set -e
if [[ $jf_rc -ne 1 ]]; then
  echo "FAIL [regular-file roster]: scanning a justfile-shaped file exited $jf_rc, expected 1."
  echo "  The collector is gating on directories again — a regular-file roster entry is being"
  echo "  dropped while the success line names it (docs/81 M13)."
  fail=1
fi
if ! grep -q 'justfile:1' <<<"$jf_out"; then echo "FAIL [regular-file roster]: 'test-rootless:' not flagged"; fail=1; fi
if ! grep -q 'justfile:2' <<<"$jf_out"; then echo "FAIL [regular-file roster]: 'echo imp-testing' not flagged"; fail=1; fi

# A mixed roster (directory + regular file) resolves both halves, and the success line reports the
# FILE COUNT — so a roster that silently resolves to nothing cannot print a reassuring message.
printf 'vmcell recipe:\n    echo vmcell\n' > "$work/clean-justfile"
set +e
mixed_out="$("$ban" "$work/clean" "$work/clean-justfile" 2>&1)"
mixed_rc=$?
set -e
if [[ $mixed_rc -ne 0 ]]; then
  echo "FAIL [mixed roster]: exit code = $mixed_rc, expected 0"; fail=1
fi
if ! grep -q 'scanned 2 files' <<<"$mixed_out"; then
  echo "FAIL [mixed roster]: expected 'scanned 2 files' (1 dir member + 1 regular file), got:"
  printf '  %s\n' "$mixed_out"
  fail=1
fi

# An empty roster is a caller bug, not an "ok" — exit 2, and NOT the "ok:" line (the L-HOST-1
# contracts-self-guard shape, same as check-lean-tree.sh's usage leg).
mkdir -p "$work/nothing"
set +e
empty_out="$("$ban" "$work/nothing" 2>&1)"
empty_rc=$?
set -e
if [[ $empty_rc -eq 0 ]]; then
  echo "FAIL [empty roster]: a roster resolving to 0 files exited 0 — it must fail loud."; fail=1
fi
if grep -q '^ok:' <<<"$empty_out"; then
  echo "FAIL [empty roster]: printed an 'ok:' line for a scan that opened nothing."; fail=1
fi

# A roster entry that does not exist is rejected, not skipped (every accepted input is honoured or
# rejected — a typo'd path must never read as a clean scan).
set +e
missing_out="$("$ban" "$work/no-such-path" 2>&1)"
missing_rc=$?
set -e
if [[ $missing_rc -eq 0 ]]; then
  echo "FAIL [missing roster entry]: a nonexistent path exited 0 instead of failing loud."; fail=1
fi
if grep -q '^ok:' <<<"$missing_out"; then
  echo "FAIL [missing roster entry]: printed an 'ok:' line for a path that does not exist."; fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo "---- scanner output (fixture tree) ----"; printf '%s\n' "$out"
  echo "---- scanner output (clean tree) ----"; printf '%s\n' "$clean_out"
  echo "---- scanner output (justfile fixture) ----"; printf '%s\n' "$jf_out"
  echo "---- scanner output (mixed roster) ----"; printf '%s\n' "$mixed_out"
  echo "---- scanner output (empty roster) ----"; printf '%s\n' "$empty_out"
  echo "---- scanner output (missing roster entry) ----"; printf '%s\n' "$missing_out"
  echo "ban-legacy-terms self-test FAILED"
  exit 1
fi
echo "ok: ban-legacy-terms self-test passed (incl. the 14 steward-rename branches, the kept domain
    words, the regular-file roster entry, the file count, and the empty/missing roster refusals)"
