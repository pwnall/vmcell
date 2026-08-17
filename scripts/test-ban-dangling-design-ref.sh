#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-dangling-design-ref.sh and the resolver it shares with
# scripts/check-docs-pointers.sh's section arm, scripts/design-headings.sh (docs/90 D2 — a
# `design §D` in a document the daemon SERVES to clients). Builds fixture repo roots — a docs/ tree with
# a design document, plus all five roster kinds: `crates/*/src`, `crates/*/tests`, `Cargo.toml`s, a
# `justfile`, and `scripts/` — and asserts every arm:
#   * deleting the section arm lets a `§99.9` and a lettered `§D` pass                     → this reddens;
#   * deleting the appendix arm lets an `Appendix Z` pass                                  → reddens;
#   * narrowing the roster back to `crates/*/src` lets a dangling reference in a `Cargo.toml`, a
#     `crates/*/tests` file, the `justfile` or a `scripts/` gate script pass — the blind spot that
#     held fifteen of them                                                                → reddens;
#   * pinning the design document by filename instead of discovering the NEWEST lets a reference that
#     only resolved in the retired version pass — the v31→v32→v33 break, twice over        → reddens;
#   * dropping the qualifier rules flags every deliberate `v15 §12.8` / `docs/78 §5` /
#     `design 62 §22` history citation, while a `design 77 §…` whose document does not exist, or a
#     bare `delta 5 §…` whose number is a DELTA and not a document, must still be checked → reddens;
#   * dropping the metavariable rule flags the `Appendix X` placeholder in correct prose   → reddens;
#   * dropping the `test-*.sh` class exclusion flags another gate's red-on-inverse fixtures, while
#     the same fixture text in a NON-self-test script must still be flagged                → reddens;
#   * dropping the per-line `allow-dangling-design-ref` marker flags the lines that QUOTE the D2
#     defect, while a marker that excuses nothing (every reference on its line resolves) or carries
#     no reason must not silence anything                                                  → reddens;
#   * dropping the vacuity arms lets a missing design document, a heading-less design document, a
#     source-less tree, a tests directory with no Rust in it, a `scripts/` holding only self-tests, a
#     reference-less tree, an all-skipped tree, an empty roster, or a missing resolver report
#     "ok"                                                                                → reddens.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-dangling-design-ref.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

# A design document with the shape the real one has: numbered `###` headings and lettered appendices.
mk_design() { # mk_design <path> <extra-heading…>
  local path="$1"; shift
  mkdir -p "$(dirname "$path")"
  {
    printf '# vmcell design\n\n## 4 Artifacts\n\n### 4.2 Rootfs\n\n## 12 Confinement\n\n'
    printf '### 12.4 Layer 3 — the setup broker\n\n## 13 Cross-cutting invariants\n\n'
    printf '### Appendix A\n\nThe load-bearing reversals.\n\n### Appendix B\n\nMore.\n'
    local h
    for h in "$@"; do printf '\n### %s Extra\n' "$h"; done
  } > "$path"
}

# The clean baseline: every reference form that must resolve or be skipped, in every roster kind, and
# none that must fail.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/crates/vmcell/src/net" "$root/crates/vmcell-daemon/src" \
    "$root/crates/vmcell/tests" "$root/scripts" "$root/docs/historical"
  mk_design "$root/docs/83-fixture-design-v33.md"
  # A retired document the DOCUMENT-NUMBER qualifier can name. Under docs/historical/ so it cannot be
  # mistaken for the current design by the resolver's `sort -V`.
  printf '# design v26, retired\n\n## 22. Sessions\n' \
    > "$root/docs/historical/62-fixture-design-v26.md"

  # KIND 1 — crate sources. Resolving, in the two places a reference actually lives: rustdoc and a
  # runtime string.
  {
    printf '/// The rootfs law (§4.2) and the jailer (design §12.4).\n'
    printf 'pub fn f() -> &%sstatic str { "the broker never parses network input (design §12.4)" }\n' "'"
    printf '// Cross-cutting: §13. Reversals: Appendix A.\n'
  } > "$root/crates/vmcell/src/net/tap.rs"
  # Skipped BY QUALIFIER: another design version's numbering, and a review document's own sections.
  {
    printf '// v15 §12.8: the blessed runner lives outside target/.\n'
    printf '// docs/78 §5 recorded this; docs/81 §9 added the sibling law.\n'
    printf '// v33 §4.2 is THIS design, so it is checked, not skipped.\n'
  } > "$root/crates/vmcell/src/history.rs"
  # Skipped as the METAVARIABLE: correct prose teaching the citation form (the daemon's real gate).
  printf 'const MSG: &str = "a lettered appendix is cited as \\"Appendix X\\", never as a section number";\n' \
    > "$root/crates/vmcell-daemon/src/openapi.rs"

  # KIND 2 — an integration suite. The real ones cite the battery roster and the law each leg guards.
  printf '// The confinement battery (§13) boots under the jail law (design §12.4).\n' \
    > "$root/crates/vmcell/tests/confinement.rs"

  # KIND 3 — the manifests. The contract ledger cites the design at every version edge, in all three
  # qualified forms plus the unqualified current one; and `delta 5 §4.2` is the shape the
  # document-NUMBER rule must NOT swallow (the bare number is a delta, and §4.2 is a real heading here).
  {
    printf '# THE CONTRACT LEDGER (design §4.2).\n'
    printf '# 0.6 -> 0.7: privileged-window hardening (design v24 §20).\n'
    printf '# 0.8 -> 0.9: persistent sessions (design 62 §22, the v26 pass).\n'
    printf '# 0.9 -> 0.10: delta 5 §4.2 — the bare number is a DELTA, not a document.\n'
    printf '[package]\nname = "vmcell"\nversion = "0.10.0"\n'
  } > "$root/crates/vmcell/Cargo.toml"
  printf '[workspace]\n# the workspace layout (§13)\nmembers = ["crates/vmcell"]\n' > "$root/Cargo.toml"

  # KIND 4 — the justfile: the recipe comments ARE the gate roster's documentation.
  printf '# lean-member invariants (v15 §12.8 #4 / §13):\ngates:\n    ./scripts/check-lean-tree.sh\n' \
    > "$root/justfile"

  # KIND 5 — a gate script stating the law it enforces, and (excluded) a self-test whose fixtures are
  # references that must NOT resolve.
  printf '# ONE predicate for the lean-member invariant (design §12.4).\n' \
    > "$root/scripts/check-lean-tree.sh"
  printf '# fixture: a §99.9 that must not resolve, and an Appendix Z.\n' \
    > "$root/scripts/test-check-lean-tree.sh"

  # The per-line marker: a line that QUOTES the D2 defect rather than pointing at it.
  printf '# docs/90 D2 served "design §D" (allow-dangling-design-ref: quoted defect) to clients.\n' \
    > "$root/scripts/check-docs-pointers.sh"
}

run_ban() { # run_ban <root> [script] -> sets $out/$rc
  local script="${2:-$ban}"
  set +e
  out="$("$script" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the clean tree MUST pass (the positive control) ---------------------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
before=$fail
expect_rc 0 "every reference resolves, is qualified, is marked, or is a self-test fixture"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
expect_clean 'history.rs'
expect_clean 'openapi.rs'
expect_clean 'test-check-lean-tree.sh'
expect_clean 'check-docs-pointers.sh'
# The verdict must state what it measured: a gate that checked 1 of 2000 references is a different
# claim from one that checked them all — and a gate whose roster lost a whole KIND still counts
# references, so each kind's file count is part of the claim too.
if ! grep -qE '[0-9]+ design reference\(s\)' <<<"$out"; then
  echo "FAIL: the verdict must state how many references it checked"; fail=1
fi
for kind in 'crate source' 'crate test' 'Cargo.toml' 'justfile' 'script'; do
  if ! grep -qE "[0-9]+ $kind" <<<"$out"; then
    echo "FAIL: the verdict must state the $kind file count"; fail=1
  fi
done
if ! grep -qE '[0-9]+ self-test file\(s\)' <<<"$out"; then
  echo "FAIL: the verdict must state how many self-test files were excluded"; fail=1
fi
if ! grep -qE '[0-9]+ reference\(s\) skipped as another' <<<"$out"; then
  echo "FAIL: the verdict must state how many were skipped as another document's numbering"; fail=1
fi
if ! grep -q 'metavariable' <<<"$out"; then
  echo "FAIL: the verdict must state the metavariable skips (a rule that starts swallowing real citations)"; fail=1
fi
if ! grep -q 'allow-dangling-design-ref. marker' <<<"$out"; then
  echo "FAIL: the verdict must state how many lines carry a marker"; fail=1
fi
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: a dangling section reference MUST be flagged -----------------------------------------
# Both shapes that shipped: a renumbered subsection in rustdoc, and D2's own lettered `§D` inside a
# string literal the daemon serves to clients.
mk_clean_tree "$work/bad"
printf '// a clone must never restore from the master (§12.12)\n' \
  > "$work/bad/crates/vmcell/src/zygote.rs"
printf 'const DESC: &str = "The vmcell daemon HTTP REST API (design §D).";\n' \
  > "$work/bad/crates/vmcell-daemon/src/served.rs"
# …and one that names THIS design version explicitly: the qualifier rule must not spare it.
printf '// v33 §99.9 is not a section of this design either\n' \
  > "$work/bad/crates/vmcell/src/wrong_version_ref.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "dangling section references"
expect_flag 'zygote.rs'
expect_flag '12.12'
expect_flag 'served.rs'
expect_flag 'wrong_version_ref.rs'
expect_clean 'history.rs'
expect_clean 'tap.rs'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 2b: THE BLIND SPOT — one dangling reference in each newly-scanned kind --------------------
# Every one of these kinds was unscanned by both pointer gates, and fifteen live dangling references
# were sitting in them: `design §20`/`§21` in the contract ledger, `§18.2`/`§12.8 #4`/`§12.23`/a
# lettered daemon-section id in the justfile, and `§12.8`/`§18.1`/`§12.23`/`§10.7` in three gate
# scripts' headers. Narrow the roster back to `crates/*/src` and this whole case goes green.
mk_clean_tree "$work/blindspot"
printf '# 0.7 -> 0.8: the OverlayStore seam (design §21).\n' >> "$work/blindspot/crates/vmcell/Cargo.toml"
printf '# the workspace members (§18.1)\n' >> "$work/blindspot/Cargo.toml"
printf '// the zygote fan-out battery (§12.12)\n' > "$work/blindspot/crates/vmcell/tests/zygote.rs"
printf '# vmcelld is not blessed on the dev hot path (§18.2)\n' >> "$work/blindspot/justfile"
printf '# ONE predicate for the broker lean boundary (design §12.23 / P2).\n' \
  > "$work/blindspot/scripts/check-broker-lean.sh"
run_ban "$work/blindspot"
before=$fail
expect_rc 1 "a dangling reference in each newly-scanned file kind"
expect_flag 'crates/vmcell/Cargo.toml'
expect_flag '18.1'
expect_flag 'tests/zygote.rs'
expect_flag 'justfile'
expect_flag 'check-broker-lean.sh'
[[ $fail -ne $before ]] && dump "case 2b"

# --- Case 3: a dangling APPENDIX reference is the same defect --------------------------------------
mk_clean_tree "$work/appendix"
printf '// the reversal is recorded in Appendix Z, cite it rather than re-arguing\n' \
  > "$work/appendix/crates/vmcell/src/reversal.rs"
run_ban "$work/appendix"
before=$fail
expect_rc 1 "a dangling appendix reference"
expect_flag 'reversal.rs'
expect_flag 'no such appendix'
# Appendix A (real) and the metavariable stay clean.
expect_clean 'tap.rs'
expect_clean 'openapi.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 3b: a ONE-FILE tree must still report a usable location -----------------------------------
# The appendix arm used to be a `grep -o` over the file list, and grep drops the filename when handed
# exactly one file — which turned the report into `1:Appendix Z`, the line number read as the path. The
# finding still fired, so no green was at risk; the location a reader has to act on was wrong. Both arms
# now run in one awk pass, where FILENAME is never inferred. A single-file tree is not hypothetical — a
# crate tree mid-reorg, or an explicitly narrowed root.
mkdir -p "$work/onefile/crates/vmcell/src"
mk_design "$work/onefile/docs/83-fixture-design-v33.md"
printf '// see Appendix Z, and the rootfs law §4.2\n' > "$work/onefile/crates/vmcell/src/lib.rs"
run_ban "$work/onefile"
before=$fail
expect_rc 1 "a dangling appendix in a single-file tree"
expect_flag 'crates/vmcell/src/lib.rs:1'
[[ $fail -ne $before ]] && dump "case 3b"

# --- Case 4: the design document is DISCOVERED, and the newest wins -------------------------------
# v31 → v32 → v33 each broke a gate that had pinned the filename. Here the RETIRED document declares
# §7.7 and the current one does not: a reference that resolves only in the old numbering must fail.
mk_clean_tree "$work/twodocs"
mk_design "$work/twodocs/docs/9-fixture-design-v9.md" "7.7"
printf '// the density lever is §7.7\n' > "$work/twodocs/crates/vmcell/src/density.rs"
run_ban "$work/twodocs"
before=$fail
expect_rc 1 "a reference that resolves only in the retired design version"
expect_flag 'density.rs'
expect_flag 'v33'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 4b: the DOCUMENT-NUMBER qualifier, both directions ---------------------------------------
# `design 62 §22` names document 62's numbering and is skipped (the baseline carries one and passes).
# The latitude is bounded twice over: the number must name a document that EXISTS, and the introducing
# word must be `design` — otherwise `delta 5 §22` would buy a free pass for any bare number at all.
mk_clean_tree "$work/badnumber"
printf '# 0.9 -> 0.10: sessions (design 77 §22) — no document 77 in the tree.\n' \
  >> "$work/badnumber/crates/vmcell/Cargo.toml"
run_ban "$work/badnumber"
before=$fail
expect_rc 1 "a document-number qualifier whose document does not exist"
expect_flag 'Cargo.toml'
expect_flag '22'
[[ $fail -ne $before ]] && dump "case 4b"

mk_clean_tree "$work/deltanumber"
printf '# delta 5 §22 — a DELTA number, not a document number.\n' \
  >> "$work/deltanumber/crates/vmcell/Cargo.toml"
run_ban "$work/deltanumber"
before=$fail
expect_rc 1 "a bare number that is a delta, not a document"
expect_flag 'Cargo.toml'
[[ $fail -ne $before ]] && dump "case 4c"

# --- Case 5: the self-test class exclusion, both directions ----------------------------------------
# A red-on-inverse self-test's fixtures are references that MUST NOT resolve, so scanning them would
# make this gate and those self-tests mutually unsatisfiable (the baseline's `test-check-lean-tree.sh`
# carries a `§99.9` and an `Appendix Z` and passes). The exclusion is a NAME rule, not a directory
# rule: the same text in a script that is not a self-test must still be flagged, or `scripts/` would be
# a blind spot behind a `test-` prefix.
mk_clean_tree "$work/selftest-name"
cp "$work/selftest-name/scripts/test-check-lean-tree.sh" "$work/selftest-name/scripts/fixtures.sh"
run_ban "$work/selftest-name"
before=$fail
expect_rc 1 "the same fixture text in a non-self-test script"
expect_flag 'fixtures.sh'
expect_clean 'test-check-lean-tree.sh'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: the per-line marker, all three directions ---------------------------------------------
# It excuses a quoted defect (the baseline's `check-docs-pointers.sh` line, which passes)…
# …it must NOT excuse a line whose references all resolve — that marker is standing by to absorb the
# next real break silently…
mk_clean_tree "$work/marker-vacuous"
printf '# the jail law (design §12.4) — allow-dangling-design-ref: nothing to excuse here.\n' \
  > "$work/marker-vacuous/scripts/check-jail.sh"
run_ban "$work/marker-vacuous"
before=$fail
expect_rc 1 "a marker whose line's references all resolve"
expect_flag 'check-jail.sh'
expect_flag 'excuses nothing'
[[ $fail -ne $before ]] && dump "case 6"

# …and a marker with NO reason is not a suppression at all (AGENTS.md bans reason-less suppressions),
# so the dangling reference on that line is still reported.
mk_clean_tree "$work/marker-no-reason"
printf '# the daemon REST surface (design §D) allow-dangling-design-ref:\n' \
  > "$work/marker-no-reason/scripts/check-rest.sh"
run_ban "$work/marker-no-reason"
before=$fail
expect_rc 1 "a marker with no reason"
expect_flag 'check-rest.sh'
[[ $fail -ne $before ]] && dump "case 6b"

# --- Case 7: the vacuity arms ---------------------------------------------------------------------
# G4, nine ways. Each is a tree where the gate could open nothing (or one KIND of nothing) and still
# print `ok:`.
check_misconfig() { # check_misconfig <label> <root> [flag] [script]
  local label="$1" path="$2" flag="${3:-gate misconfigured}" script="${4:-$ban}"
  run_ban "$path" "$script"
  if [[ $rc -ne 1 ]]; then echo "FAIL [$label]: exit code = $rc, expected 1"; fail=1; fi
  if ! grep -q "$flag" <<<"$out"; then
    echo "FAIL [$label]: expected '$flag', got:"; printf '%s\n' "$out"; fail=1
  fi
}

# 7a — no design document at all: nothing to resolve against.
mk_clean_tree "$work/nodesign"
rm "$work/nodesign/docs/83-fixture-design-v33.md"
check_misconfig "no design document" "$work/nodesign"

# 7b — a design document with no numbered headings: every reference would be reported dangling, or
# (with the comparison inverted) every one would pass.
mk_clean_tree "$work/noheadings"
printf '# vmcell design\n\nProse only, no numbered headings.\n' \
  > "$work/noheadings/docs/83-fixture-design-v33.md"
check_misconfig "design document with no numbered headings" "$work/noheadings"

# 7c — crates/ exists but holds no Rust: the first kind opens nothing.
mkdir -p "$work/nosrc/crates/vmcell/src"
mk_design "$work/nosrc/docs/83-fixture-design-v33.md"
printf 'not rust\n' > "$work/nosrc/crates/vmcell/src/README.md"
check_misconfig "no Rust sources" "$work/nosrc" "crates/\*/src"

# 7d — a tests directory with no Rust in it: the SECOND kind opens nothing while the first is healthy,
# which a merely-non-zero total cannot see. This is the arm that catches one glob of five dying.
mk_clean_tree "$work/notests"
rm "$work/notests/crates/vmcell/tests/confinement.rs"
printf 'fixtures, not rust\n' > "$work/notests/crates/vmcell/tests/README.md"
check_misconfig "a tests directory with no Rust" "$work/notests" "tests directory exists"

# 7e — a scripts/ directory holding ONLY self-tests: the fifth kind opens nothing, which would mean
# the gate scripts themselves went unscanned.
mk_clean_tree "$work/onlyselftests"
rm "$work/onlyselftests/scripts/check-lean-tree.sh" "$work/onlyselftests/scripts/check-docs-pointers.sh"
check_misconfig "scripts/ holding only self-tests" "$work/onlyselftests" "no non-self-test file"

# 7f — the whole roster empty: docs/ and nothing else.
mk_design "$work/emptyroster/docs/83-fixture-design-v33.md"
check_misconfig "an empty roster" "$work/emptyroster" "zero files"

# 7g — files that cite nothing: the extractor broke (this tree cites the design in nearly every law,
# so an empty extraction is never a clean tree).
mkdir -p "$work/norefs/crates/vmcell/src"
mk_design "$work/norefs/docs/83-fixture-design-v33.md"
printf 'pub fn f() -> u8 { 3 }\n' > "$work/norefs/crates/vmcell/src/lib.rs"
check_misconfig "no references found" "$work/norefs" "not one"

# 7h — every reference skipped as another document's numbering: the qualifier rule is meant to spare
# history citations, not to swallow the unqualified pointers that are the gate's whole subject.
mkdir -p "$work/allskipped/crates/vmcell/src"
mk_design "$work/allskipped/docs/83-fixture-design-v33.md"
printf '// v15 §12.8 and v30 §9.4 and docs/78 §5, all history\n' \
  > "$work/allskipped/crates/vmcell/src/lib.rs"
check_misconfig "every reference skipped" "$work/allskipped" "none was checked"

# 7i — the shared resolver is not reachable: the gate must refuse rather than fall back to a private
# copy of "find the newest design doc and list its headings", which is the duplication it exists
# without. The expected phrase is the RESOLVER-SPECIFIC one, not the generic "gate misconfigured":
# the ban carries a second guard for a resolver that runs but answers nothing (7a/7b's layer), and
# accepting either message here would leave this arm unfailable — removing the `-x` refusal would
# still pass on the other guard's wording.
mkdir -p "$work/noresolver"
cp "$ban" "$work/noresolver/ban-dangling-design-ref.sh"
chmod +x "$work/noresolver/ban-dangling-design-ref.sh"
check_misconfig "the shared design-headings resolver is missing" "$work/good" \
  "missing or not executable" "$work/noresolver/ban-dangling-design-ref.sh"

# 7j — a missing ROOT is a misconfiguration, not a clean tree.
check_misconfig "nonexistent root" "$work/no-such-root"

if [[ $fail -ne 0 ]]; then
  echo "ban-dangling-design-ref self-test FAILED"
  exit 1
fi
echo "ok: ban-dangling-design-ref self-test passed"
