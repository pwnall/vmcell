#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-id-claim-law-copies.sh (the cross-process id-claim law:
# where the registry is, and how owner liveness is decided). Builds fixture trees that mirror the
# real crate layout — the exemptions are path suffixes, so the layout is load-bearing — and asserts
# every arm of the scanner can FAIL:
#   * deleting the claim-directory arm lets a second `"/tmp/vmcell-vmid"` spelling pass  → reddens;
#   * deleting the liveness arm lets a second `/proc/{pid}` owner probe pass              → reddens;
#   * deleting the const check lets a directory literal hide in a function body of the law's own
#     home (the shape that keeps the writer and the reader in one file while they drift)  → reddens;
#   * deleting the stale-exemption check lets a moved/emptied home pass                   → reddens;
#   * restoring a permissive empty-scan arm lets a Rust-less tree report "ok"             → reddens.
# The precision legs matter as much: a rustdoc mention of the path, and a `/proc/{pid}/stat` READ of
# a process already known to exist, must never be flagged — a gate that cries wolf gets scoped down
# to nothing.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-id-claim-law-copies.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the law's home with exactly its two const literals and one liveness probe, the
# out-of-crate live assertion the roster exempts, plus the legitimate near-misses.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src" "$root/vmcell/tests" "$root/vmcell-daemon/src" "$root/vmcell-bench/src"
  {
    printf 'pub(crate) const SHARED_VMID_CLAIM_DIR: &str = "/tmp/vmcell-vmid";\n'
    printf 'pub(crate) const SHARED_SEGID_CLAIM_DIR: &str = "/tmp/vmcell-segid";\n'
    # shellcheck disable=SC2016  # the backticks are literal Rust doc text, not shell expansion (intended)
    printf '/// The lock file lives under `/tmp/vmcell-vmid`, and "/tmp/vmcell-segid" in prose.\n'
    printf 'fn owner_is_live(p: &Path) -> Result<bool> {\n'
    printf '    Ok(read(p)?.parse::<u32>().ok().is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists()))\n'
    printf '}\n'
  } > "$root/vmcell/src/orchestrator.rs"
  # Rostered: the live battery asserting the host registry from outside the crate.
  printf 'fn lock(segid: u32) -> PathBuf { Path::new("/tmp/vmcell-segid").join(format!("{segid}.lock")) }\n' \
    > "$root/vmcell/tests/segment.rs"
  # MUST NOT be flagged: reading a file UNDER /proc/<pid> asks about a process already known to
  # exist — a different question from whether it exists at all.
  printf 'fn rss(pid: u32) -> Option<u64> { read_to_string(format!("/proc/{pid}/status")).ok()?; None }\n' \
    > "$root/vmcell-bench/src/bench.rs"
  # MUST NOT be flagged: a doc comment naming the directory.
  # shellcheck disable=SC2016  # the backticks are literal Rust doc text, not shell expansion (intended)
  printf '//! Reservations live under `/tmp/vmcell-vmid` and are reclaimed on crash.\nfn f() {}\n' \
    > "$root/vmcell-daemon/src/sweep.rs"
}

run_ban() { set +e; out="$("$ban" "$1" 2>&1)"; rc=$?; set -e; }

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the sanctioned tree alone MUST pass (the positive control) ---------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
before=$fail
expect_rc 0 "law's home only"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: a second claim-directory spelling elsewhere MUST be flagged --------------------------
# This is the fail-OPEN drift: the sweep reads a directory nobody claims into, sees an empty
# registry, and reaps a live sibling's resources while logging a successful orphan reclaim.
mk_clean_tree "$work/dir"
printf 'fn dir() -> PathBuf { PathBuf::from("/tmp/vmcell-vmid") }\n' > "$work/dir/vmcell-daemon/src/claims.rs"
run_ban "$work/dir"
before=$fail
expect_rc 1 "second claim-directory literal"
expect_flag 'claims.rs'
expect_clean 'sweep.rs'      # the doc-comment mention stays clean
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: a second `/proc/{pid}` owner-liveness probe MUST be flagged --------------------------
mk_clean_tree "$work/probe"
printf 'fn alive(pid: u32) -> bool { Path::new(&format!("/proc/{pid}")).exists() }\n' \
  > "$work/probe/vmcell-daemon/src/live.rs"
run_ban "$work/probe"
before=$fail
expect_rc 1 "second owner-liveness probe"
expect_flag 'live.rs'
expect_flag 'owner_is_live'
expect_clean 'bench.rs'      # `/proc/{pid}/status` is a read, not an existence probe
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a directory literal inside the HOME that is not a const definition -------------------
# The shape a reviewer would wave through: still in orchestrator.rs, so "one file" — but no longer
# one FACT, which is what the allocators and the sweeps actually have to agree on.
mk_clean_tree "$work/inline"
# The COUNT is deliberately unchanged (still two literals): one const is replaced by an inline use,
# so the count arm sees nothing and only the const check can catch this. Without that care the case
# would pass on the wrong arm and the const check could be deleted unnoticed — measured.
python3 - "$work/inline/vmcell/src/orchestrator.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace(
    'pub(crate) const SHARED_SEGID_CLAIM_DIR: &str = "/tmp/vmcell-segid";',
    'fn segid_dir() -> PathBuf { PathBuf::from("/tmp/vmcell-segid") }',
)
open(p, "w").write(s)
PY
run_ban "$work/inline"
before=$fail
expect_rc 1 "non-const literal inside the law's home"
expect_flag "NOT one of the two"
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a home that no longer holds the law is a STALE exemption, not a pass -----------------
mk_clean_tree "$work/stale"
printf 'fn nothing() {}\n' > "$work/stale/vmcell/src/orchestrator.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "emptied home"
expect_flag 'gate misconfigured'
expect_flag 'claim-directory literal(s), expected 2'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a home that moved away is the same stale exemption -----------------------------------
mk_clean_tree "$work/moved"
rm "$work/moved/vmcell/src/orchestrator.rs"
run_ban "$work/moved"
before=$fail
expect_rc 1 "moved home"
expect_flag 'no such file'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: a rostered non-home entry that lost its subject is stale too --------------------------
# The out-of-crate live assertion is exempted BECAUSE it asserts the registry's lifecycle; an
# exemption that outlives that assertion is a widened blind spot.
mk_clean_tree "$work/testgone"
printf 'fn nothing() {}\n' > "$work/testgone/vmcell/tests/segment.rs"
run_ban "$work/testgone"
before=$fail
expect_rc 1 "emptied rostered test"
expect_flag 'gate misconfigured'
expect_flag 'tests/segment.rs'
[[ $fail -ne $before ]] && dump "case 7"

# --- Case 8: a tree with no Rust at all is a misconfiguration, not a pass --------------------------
mkdir -p "$work/nosrc/vmcell/src"
printf 'not rust\n' > "$work/nosrc/vmcell/src/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 8"

if [[ $fail -ne 0 ]]; then
  echo "ban-id-claim-law-copies self-test FAILED"
  exit 1
fi
echo "ok: ban-id-claim-law-copies self-test passed"
