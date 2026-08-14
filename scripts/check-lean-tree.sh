#!/usr/bin/env bash
# ONE predicate for the lean-member invariant (AGENTS.md "One law, one predicate"; design §12.8 #4
# and §18.1). A member that runs as guest PID 1 (`vmcell-guest-agent`), inside the privileged
# window (`vmcell-test-runner`), or is linked by BOTH the runner and the daemon
# (`vmcell-privilege`) must not link the host async stack — tokio, hyper, or rtnetlink.
#
# `--color never` is LOAD-BEARING, not tidiness. `.github/workflows/ci.yml` sets
# `CARGO_TERM_COLOR: always` at WORKFLOW level, so it applies to every job and every `run:` block.
# `cargo tree` then dims the tree glyphs, emitting (ESC shown as \e):
#     \e[2m│\e[0m   \e[2m├──\e[0m tokio v1.49.0
# The reset escape sits BETWEEN the `──` glyph and the crate name, so a `── tokio v` pattern matches
# nothing at all. Measured on this tree 2026-08-14 against `vmcell-daemon`, which genuinely links
# tokio and hyper: 28 matches uncoloured, 0 coloured, 28 coloured + `--color never`. The six
# hand-copied inline versions of this pipeline this script replaces (three in `ci.yml`, three in the
# `justfile`) were therefore DEAD in CI and alive locally — the local≢CI shape AGENTS.md rule 3
# exists to prevent, and a gate that cannot fail is theater (rule 2). `NO_COLOR=1` does NOT fix it:
# `CARGO_TERM_COLOR` outranks `NO_COLOR` (measured: still 0 matches). Only the flag does.
#
# `scripts/test-check-lean-tree.sh` is the red-on-inverse self-test: it exports
# `CARGO_TERM_COLOR=always` (the CI condition, not the dev one) and asserts this predicate REJECTS
# `vmcell-daemon`. Drop `--color never` below and that self-test reddens.
#
# Usage: check-lean-tree.sh <crate> [<crate> ...]
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: check-lean-tree.sh <crate> [<crate> ...]" >&2
  exit 1
fi

fail=0
for crate in "$@"; do
  # `-e no-dev`: dev-dependencies legitimately pull the host stack into the test build; the
  # invariant is about what the SHIPPED binary links. `--locked`: a stale lockfile fails loud with
  # cargo's own message rather than being silently re-resolved by a "check".
  tree=$(cargo tree --color never --locked -e no-dev -p "$crate")
  if hits=$(grep -E '── (tokio|hyper|rtnetlink) v' <<<"$tree"); then
    echo "::error::lean invariant violated — host stack leaked into $crate"
    printf '%s\n' "$hits" >&2
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "check-lean-tree: ok ($* link no tokio/hyper/rtnetlink)"
