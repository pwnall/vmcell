#!/usr/bin/env bash
# Self-test for scripts/ban-global-state.sh (P31). Builds a fixture tree and asserts the
# scanner flags exactly the bypass cases the hardening targets and leaves the legitimate
# cases alone. This is the "red on the inverse" guard: the pre-P31 line-based scanner missed
# the multi-line `static` and the `use ... as` alias fixtures, so it fails this test; the
# comment-prose fixture fails if comment-stripping regresses; the exemption fixture fails if
# the per-line marker stops being honoured across a multi-line declaration.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-global-state.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src"

# --- MUST be flagged ---------------------------------------------------------------------
# Multi-line declaration: type on a continuation line (old line-based regex missed this).
printf 'static COUNTER:\n    AtomicU64 = AtomicU64::new(0);\n' > "$work/src/multiline_atomic.rs"
# `use Concrete as Alias` hides the type name; the initializer still names the ctor.
printf 'use std::sync::atomic::AtomicU64 as Counter;\nstatic C: Counter = AtomicU64::new(0);\n' > "$work/src/alias_ctor.rs"
# Bare aliased import of a near-exclusively-global type.
printf 'use std::sync::atomic::AtomicBool as Flag;\n' > "$work/src/alias_use.rs"

# --- MUST NOT be flagged -----------------------------------------------------------------
# Multi-line interior-mutable static, but justified with the per-line exemption marker.
printf 'static CACHE:\n    OnceLock<u32> = OnceLock::new(); // allow-global-state: fixture\n' > "$work/src/exempted.rs"
# Plain consts, including a string that mentions "Mutex" and a `'static` lifetime.
printf 'static MAX_RETRIES: usize = 10;\nstatic LABEL: &str = "uses a Mutex internally";\nfn f() -> &%cstatic str { "x" }\n' "'" > "$work/src/clean_const.rs"
# Prose comment containing a fake ctor — stripped before analysis, so not a false positive.
printf '// buggy: `static GLOBAL: Mutex<u32> = Mutex::new(0)` would leak.\nstatic OK: u32 = 5;\n' > "$work/src/comment_prose.rs"

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
expect_flag multiline_atomic.rs
expect_flag alias_ctor.rs
expect_flag alias_use.rs
expect_clean exempted.rs
expect_clean clean_const.rs
expect_clean comment_prose.rs

if [[ $fail -ne 0 ]]; then
  echo "---- scanner output ----"; printf '%s\n' "$out"
  echo "ban-global-state self-test FAILED"
  exit 1
fi
echo "ok: ban-global-state self-test passed"
