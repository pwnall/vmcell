#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-uncolored-cargo-parse.sh (AGENTS.md rule 2).
#
# The scanner has two ways to stop being a gate, and this test drives both:
#   * it stops FLAGGING — a parsed `cargo tree` without `--color never` slips through, which is the
#     defect class itself (three lean-member bans and one downstream fixture filter shipped dead);
#   * it starts flagging EVERYTHING — the false-positive arm. That is not cosmetic: the scanner's
#     own first draft flagged three of its own diagnostic strings, and a gate that cries wolf on its
#     own output is one suppression away from being deleted.
# The fixtures below therefore pair every violation shape with the near-miss that must stay silent.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-uncolored-cargo-parse.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
# expect_leg <name> <want_rc> <file...>
expect_leg() {
  local name="$1" want_rc="$2"
  shift 2
  local out rc
  set +e
  out=$("$ban" "$@" 2>&1)
  rc=$?
  set -e
  if [[ $rc -ne $want_rc ]]; then
    echo "FAIL [$name]: exit $rc, expected $want_rc"
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
  fi
}

# Every fixture is written through a QUOTED heredoc (`<<'EOF'`), not `printf`: the bodies are shell
# source containing `$(…)`, `"$work"` and backslash-continuations, and a quoted heredoc is the one
# form that takes them literally without a shellcheck SC2016 suppression per line.

# ---- VIOLATIONS: each must be flagged ----------------------------------------------------------
# The shipped shape: an `if cargo tree … | grep` ban (the three lean-member invariants).
cat > "$work/v-pipe.sh" <<'EOF'
if cargo tree --locked -e no-dev -p some-crate | grep -E "── tokio v"; then exit 1; fi
EOF
# Captured in a command substitution (check-vendored-vhost.sh's shape).
cat > "$work/v-capture.sh" <<'EOF'
tree=$(cargo tree --locked -e normal --all-features)
EOF
# Redirected to a fixture file (examples/downstream-kernel/ci-check.sh's shape — the live failure).
cat > "$work/v-redirect.sh" <<'EOF'
cargo tree --locked -e normal --all-features > "$work/real-tree.txt"
EOF
# Word-split in a `for` loop.
cat > "$work/v-forloop.sh" <<'EOF'
for p in $(cargo metadata --format-version 1 | jq -r '.packages[].name'); do echo "$p"; done
EOF
# A YAML `run:` block whose command is continued with a backslash — the ci.yml shape.
cat > "$work/v-continuation.yml" <<'EOF'
run: |
  if cargo tree --locked -e no-dev -p vmcell-guest-agent \
       | grep -E "── tokio v"; then exit 1; fi
EOF

for f in v-pipe.sh v-capture.sh v-redirect.sh v-forloop.sh v-continuation.yml; do
  expect_leg "flags: $f" 1 "$work/$f"
done

# ---- COMPLIANT + NEAR-MISSES: none may be flagged ----------------------------------------------
# The fix, in each of the two accepted spellings.
cat > "$work/ok-flag.sh" <<'EOF'
if cargo tree --color never --locked -e no-dev -p c | grep -E "── tokio v"; then exit 1; fi
EOF
cat > "$work/ok-equals.sh" <<'EOF'
tree=$(cargo tree --color=never --locked -e normal)
EOF
# Subcommands whose output nothing parses: colour there is for humans and must not be policed.
cat > "$work/ok-unparsed.sh" <<'EOF'
cargo build --locked
cargo clippy --all-targets -- -D warnings
cargo nextest run --locked
cargo fuzz run "$t" -- -max_total_time=300
EOF
# `cargo fuzz list` IS parsed (word-split into a loop in fuzz.yml) and must still NOT be flagged:
# cargo-fuzz is a third-party subcommand whose `List` accepts only `--fuzz-dir`, so the flag this
# scanner demands does not exist there and demanding it would break the workflow. A rule that cannot
# be satisfied is worse than no rule; this leg is what keeps it off the roster.
cat > "$work/ok-third-party.sh" <<'EOF'
for t in $(cargo fuzz list); do echo "$t"; done
EOF
# Prose and diagnostics that merely SPELL the invocation. All three of these were false positives in
# the scanner's first draft; they are the regression this leg pins.
cat > "$work/ok-prose.sh" <<'EOF'
# CI colours this; cargo then wraps tree glyphs in escapes.
echo "::error::cargo tree failed unexpectedly while probing $pkg" >&2
echo "the probe \`cargo tree -i axum\` found nothing" >&2
EOF
# The stub `cargo` shims the self-tests put on PATH dispatch on "$1" and never spell the invocation.
cat > "$work/ok-stub.sh" <<'EOF'
if [ "${1:-}" = "tree" ]; then cat "$FAKE_TREE"; exit 0; fi
EOF
# A COMPLIANT invocation whose `--color never` lives on a backslash-continuation line. A
# line-oriented scan flags this, which would force the rule to be written on one long line — so the
# scanner joins continuations, and this leg is what keeps that joining from being dropped.
cat > "$work/ok-continuation.sh" <<'EOF'
cargo tree \
  --color never \
  --locked -p foo > "$out"
EOF

for f in ok-flag.sh ok-equals.sh ok-unparsed.sh ok-third-party.sh ok-prose.sh ok-stub.sh ok-continuation.sh; do
  expect_leg "silent on: $f" 0 "$work/$f"
done

# ---- The scanner must not pass vacuously on its own roster --------------------------------------
# A file list that resolves to nothing would report "ok" for every future violation. Passing a
# non-existent path is the closest reachable shape; it must still exit 0 only because there is
# genuinely nothing to scan, and the count in the message must say so.
expect_leg "empty roster is honest" 0 "$work/does-not-exist.sh"

if [[ $fail -ne 0 ]]; then
  echo "ban-uncolored-cargo-parse self-test FAILED"
  exit 1
fi
echo "ok: ban-uncolored-cargo-parse self-test passed (5 violation shapes flagged, 6 compliant/near-miss shapes silent)"
