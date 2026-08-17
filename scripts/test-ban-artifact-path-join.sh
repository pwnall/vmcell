#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-artifact-path-join.sh (rubric B12 / P3). Builds a fixture
# tree and asserts the scanner flags the inline `dir.join(client)` traversal form and leaves the
# sanctioned `resolve_artifact_path` home (name.rs) and the legitimate non-client joins alone.
# Deleting the join pattern from the scanner (its inverse) makes the MUST-flag fixtures go un-flagged
# and reddens this test.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-artifact-path-join.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src"

# --- MUST be flagged: a handler joining a client name onto the artifacts dir itself ---------------
printf 'fn upload(dir: &Path, name: &str) -> PathBuf { dir.join(name) }\n' > "$work/src/handler.rs"
# The struct-field form a real handler would write.
printf 'fn get(&self, name: &str) -> PathBuf { self.artifacts_dir.join(name) }\n' > "$work/src/store_field.rs"

# --- MUST NOT be flagged -------------------------------------------------------------------------
# The sanctioned validator home: the SAME construction, but resolve_artifact_path validated `name`
# to a single component first, and it lives in name.rs (skipped by basename).
printf 'pub fn resolve_artifact_path(dir: &Path, name: &str) -> Result<PathBuf> { Ok(dir.join(name)) }\n' > "$work/src/name.rs"
# A join onto a store accessor method (not a bare dir receiver) — goes through the store.
printf 'fn sub(&self) -> PathBuf { self.artifacts.dir().join(prefix) }\n' > "$work/src/accessor.rs"
# A fixed literal component and a computed expression are not raw client strings.
printf 'fn fixed(dir: &Path) -> PathBuf { dir.join("subdir") }\nfn comp(dir: &Path) -> PathBuf { dir.join(format!("{vmid}.lock")) }\n' > "$work/src/literal.rs"
# A doc comment mentioning the banned form must be stripped before matching (no false positive).
# shellcheck disable=SC2016  # the backticks are literal Rust source, not shell expansion (intended)
printf '//! no method constructs `dir.join(name)` itself; use resolve_artifact_path.\nfn f() {}\n' > "$work/src/comment.rs"

set +e
out="$("$ban" "$work/src" 2>&1)"
rc=$?
set -e

fail=0
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }

if [[ $rc -ne 1 ]]; then echo "FAIL: scanner exit code = $rc, expected 1 (violations present)"; fail=1; fi
expect_flag handler.rs
expect_flag store_field.rs
expect_clean name.rs
expect_clean accessor.rs
expect_clean literal.rs
expect_clean comment.rs

# --- The vacuous-scan legs: nothing to scan is a MISCONFIGURATION, not a clean daemon -------------
# G4: both arms used to exit 0 — an existing-but-Rust-less directory printed "ok: no Rust sources
# under …", and an explicitly-passed missing directory printed "ok: no daemon source directory …"
# (whose comment claimed this self-test relied on it; it never did — every fixture tree here exists).
# Either one turns a daemon-crate move (or a typo) into a green P3 gate that scanned zero bytes.
# Restoring either permissive arm reddens the matching leg.
check_misconfig() { # check_misconfig <label> <path>
  local label="$1" path="$2" o r
  set +e
  o="$("$ban" "$path" 2>&1)"
  r=$?
  set -e
  if [[ $r -ne 1 ]]; then echo "FAIL [$label]: exit code = $r, expected 1"; fail=1; fi
  if ! grep -q 'gate misconfigured' <<<"$o"; then
    echo "FAIL [$label]: expected 'gate misconfigured', got:"; printf '%s\n' "$o"; fail=1
  fi
}
mkdir -p "$work/nosrc"
printf 'not rust\n' > "$work/nosrc/README.md"
check_misconfig "directory with no Rust sources" "$work/nosrc"
check_misconfig "explicitly-passed missing directory" "$work/does-not-exist"

if [[ $fail -ne 0 ]]; then
  echo "---- scanner output ----"; printf '%s\n' "$out"
  echo "ban-artifact-path-join self-test FAILED"
  exit 1
fi
echo "ok: ban-artifact-path-join self-test passed"
