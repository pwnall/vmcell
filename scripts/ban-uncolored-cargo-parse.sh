#!/usr/bin/env bash
# Bans parsing cargo output that CI colourises (AGENTS.md rule 1: "every recurring defect class
# becomes a lint, a CI job, or a test that can go red").
#
# THE DEFECT CLASS. `.github/workflows/ci.yml` sets `CARGO_TERM_COLOR: always` at WORKFLOW level, so
# it is exported into every job and every `run:` block. `cargo tree` then dims the tree glyphs,
# emitting (ESC shown as \e):
#     \e[2m│\e[0m   \e[2m├──\e[0m tokio v1.49.0
# Two escape sequences bracket the glyph, and the reset `\e[0m` ends in a LOWERCASE `m` that sits
# between the `──` and the crate name. Every pattern anchored on that boundary silently stops
# matching. Two live instances, both shipped, both invisible to `just ci` (which does not export the
# variable — so local ≢ CI by construction, the shape AGENTS.md rule 3 exists to prevent):
#   * the three lean-member host-stack bans (`── (tokio|hyper|rtnetlink) v`) matched 0 lines in CI
#     where they match 28 locally — three security-adjacent gates passing while proving nothing;
#   * examples/downstream-kernel/ci-check.sh's `^[^a-z]*vhost` filter removed 0 of 3 lines, voiding
#     the fixture its "not applicable" leg asserts against and reddening the example-downstream job.
# `NO_COLOR=1` does NOT fix it — `CARGO_TERM_COLOR` outranks `NO_COLOR` (measured: still 0 matches).
# Only `--color never` on the invocation does, which is why this scanner keys on that flag
# specifically rather than on any general "colour is handled" heuristic.
#
# WHAT IT FLAGS: a `cargo <subcommand>` whose output this repo consumes — `tree`, `metadata`,
# `pkgid`, `locate-project` — appearing in a shell/YAML/justfile line without `--color never` (or
# `--color=never`). Comments are stripped first (`#` to end of line in all three languages), so the
# prose above is not itself a hit.
#
# WHAT IT DOES NOT FLAG: the stub `cargo` shims in the self-tests, which dispatch on `"$1" = "tree"`
# and never spell `cargo tree`; subcommands whose output nothing parses (`cargo build`,
# `cargo clippy`, `cargo nextest`) — their diagnostics are for humans and colour is wanted there;
# and third-party subcommands that have no `--color` to pass (see the roster note below).
#
# scripts/test-ban-uncolored-cargo-parse.sh is the red-on-inverse self-test.
#
# Usage: ban-uncolored-cargo-parse.sh [FILE ...]   (defaults to the repo's gate-bearing files)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

files=("$@")
if [[ ${#files[@]} -eq 0 ]]; then
  # The same roster `just ci` shellchecks, plus the workflows and the justfile itself — every place
  # in this repo where a cargo invocation's output is consumed by a gate.
  #
  # THE ONE EXCLUSION, and why it is not a hole: this scanner's own self-test writes deliberate
  # violation FIXTURES (heredocs containing bare `cargo tree …` lines) into a temp dir, so scanning
  # it would report the gate's own test data as violations — the cries-wolf failure mode that gets a
  # gate suppressed. It is named explicitly rather than matched by a `test-*` glob, because every
  # OTHER self-test in scripts/ is still scanned: `test-check-vendored-vhost.sh` and
  # `test-check-broker-lean.sh` build their fixtures as canned cargo OUTPUT, never as invocations,
  # so they carry no violation shape and a real one appearing in them must still be caught.
  files=()
  for f in "$root"/scripts/*.sh "$root"/examples/downstream-kernel/*.sh \
           "$root"/.github/workflows/*.yml "$root/scripts/git-pre-commit" "$root/justfile"; do
    [[ -f "$f" ]] || continue                                   # an unmatched glob stays literal
    [[ "$f" == */test-ban-uncolored-cargo-parse.sh ]] && continue
    files+=("$f")
  done
fi

# The subcommands whose stdout this repo parses AND which accept `--color`. Both halves matter: the
# roster is limited to cargo's own built-ins, because a rule that cannot be satisfied is worse than
# no rule. `cargo fuzz list` is the case in point — its output IS word-split into a loop in
# fuzz.yml, but cargo-fuzz is a third-party subcommand whose `List` struct carries only `--fuzz-dir`
# (checked in rust-fuzz/cargo-fuzz `src/options/list.rs`), so passing `--color never` would abort
# the loop on an unexpected argument and fuzz nothing. This scanner listed it in its first draft and
# then reddened `just ci` demanding an edit that would have broken the workflow. It is out, and
# fuzz.yml carries a target-count assertion instead — the empty-list hazard, gated where it is
# actually reachable.
#
# The match is anchored on COMMAND POSITION — start of line, whitespace, `(`, `|`, `&`, `;`, or a
# `$(` capture — and the subcommand must follow `cargo` immediately (past an optional `+toolchain`
# or global flag). Both halves are load-bearing against this scanner's own first draft, which
# flagged three of its own error strings: a looser `cargo .* tree` matched the prose "cargo then
# wraps tree glyphs", and an unanchored `cargo tree` matched `"::error::cargo tree failed…"` and the
# backticked `` `cargo tree -i axum` `` inside a diagnostic. A gate that cries wolf on its own
# messages gets suppressed, which is how a class gate stops being one.
parsed_re='(^|[[:space:]]|[|&;(]|[$]\()cargo([[:space:]]+[+-][^[:space:]]*)*[[:space:]]+(tree|metadata|pkgid|locate-project)\b'

# Normalise one file to `<first-line-number>:<logical line>`:
#   * comments stripped, so neither prose nor a rationale comment naming the invocation is a hit;
#   * backslash-continuations JOINED, reported against the line the command starts on. Joining is
#     not cosmetic — `cargo tree \` / `  --color never \` / `  -p foo` is a compliant invocation
#     whose flag lives on a later physical line, and a line-oriented scan would flag it. A gate that
#     forces its own rule to be written on one line is a gate people work around.
logical_lines() {
  awk '
    { sub(/(^|[[:space:]])#.*$/, "") }
    buf == "" { start = NR }
    { line = $0 }
    line ~ /\\$/ { sub(/\\$/, "", line); buf = buf line; next }
    { print start "\t" buf line; buf = "" }
    END { if (buf != "") print start "\t" buf }
  ' "$1"
}

hits=0
for f in "${files[@]}"; do
  [[ -f "$f" ]] || continue
  while IFS=$'\t' read -r lineno text; do
    [[ -z "$text" ]] && continue
    grep -qE -- '--color[= ]never' <<<"$text" && continue
    printf '%s:%s: cargo output is parsed without --color never\n' "${f#"$root"/}" "$lineno"
    printf '    %s\n' "$(sed -E 's/^[[:space:]]+//' <<<"$text")"
    hits=$((hits + 1))
  done < <(logical_lines "$f" | grep -E -- "$parsed_re" || true)
done

if [[ $hits -ne 0 ]]; then
  cat >&2 <<'MSG'

ban-uncolored-cargo-parse: the sites above parse cargo output that CI colourises.
  CI sets CARGO_TERM_COLOR=always at workflow level; cargo then wraps tree glyphs in
  \e[2m…\e[0m and every pattern anchored on the glyph/name boundary silently stops matching.
  Add `--color never` to the invocation (NO_COLOR does not override CARGO_TERM_COLOR), or
  route the check through the one predicate that already carries it:
      scripts/check-lean-tree.sh      — the lean-member host-stack ban
      scripts/check-broker-lean.sh    — the broker P2 web-stack exclusion
      scripts/check-vendored-vhost.sh — the vendored [patch.crates-io] assertion
MSG
  exit 1
fi
echo "ban-uncolored-cargo-parse: ok (${#files[@]} files; every parsed cargo invocation pins --color never)"
