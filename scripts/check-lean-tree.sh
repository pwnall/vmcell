#!/usr/bin/env bash
# ONE predicate for the lean-member invariant (AGENTS.md "One law, one predicate"; design §12.8 #4
# and §18.1). A governed member must not link the packages its row of the LEAN MATRIX below bans.
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
# `vmcell-daemon` under BOTH ban patterns. Drop `--color never` below and that self-test reddens.
#
# Usage:
#   check-lean-tree.sh --all                     check every row of the lean matrix (preferred)
#   check-lean-tree.sh <crate> [<crate> ...]     check named governed members (a name outside the
#                                                matrix is rejected; omitted rows are checked
#                                                anyway — see THE MATRIX IS THE LAW below)
#   check-lean-tree.sh --ban <alternation> <crate> [...]
#                                                ad-hoc / positive-control form: check <crate>
#                                                against an explicit ban pattern, matrix untouched
set -euo pipefail

# ── THE LEAN MATRIX ───────────────────────────────────────────────────────────────────────────
# One row per governed member: `<crate> <packages that must be ABSENT from its no-dev graph>`.
# TWO different absences, because "lean" means two different things in this workspace:
#
#   tokio|hyper|rtnetlink — the host ASYNC stack. A member that runs as guest PID 1
#                           (vmcell-steward), inside the privileged window
#                           (vmcell-test-runner), or is linked by BOTH the runner and the daemon
#                           (vmcell-privilege) must not link it.
#   axum|vmcell           — the daemon's SERVER stack. `vmcell-daemon-client` depends on
#                           `vmcell-daemon` with `default-features = false` so the wire DTOs are
#                           single-sourced without dragging the axum router and the `vmcell` host
#                           lib into every consumer (design §18.1; AGENTS.md "DTOs are
#                           single-sourced (client links `default-features = false`)"). That
#                           boundary had no gate at all — dropping the flag would have gone
#                           unnoticed (docs/81 m28).
#
#                           tokio and hyper are deliberately NOT banned on the client: `reqwest`
#                           links both legitimately, so reusing the host-async row there would have
#                           been a gate that can only ever be red. Different ban, SAME predicate —
#                           the alternative was a second copy of this pipeline, and every duplicate
#                           in this repo has diverged.
#
# The `── ` prefix in the compiled pattern is what makes `vmcell` an exact package match: the tree
# renders the client's one dependency as `└── vmcell-daemon v0.2.0`, which `── vmcell v` does not
# match, while a re-enabled `server` feature renders `── vmcell v0.13.0` and `── axum v0.8…`, which
# it does.
LEAN_MATRIX=(
  "vmcell-steward       tokio|hyper|rtnetlink"
  "vmcell-test-runner   tokio|hyper|rtnetlink"
  "vmcell-privilege     tokio|hyper|rtnetlink"
  "vmcell-daemon-client axum|vmcell"
)

# The ban pattern for a governed crate, or exit status 1 if it is not in the matrix.
matrix_ban_for() {
  local want="$1" row crate ban
  for row in "${LEAN_MATRIX[@]}"; do
    read -r crate ban <<<"$row"
    if [[ "$crate" == "$want" ]]; then
      printf '%s' "$ban"
      return 0
    fi
  done
  return 1
}

usage() {
  cat >&2 <<'USAGE'
usage: check-lean-tree.sh --all
       check-lean-tree.sh <crate> [<crate> ...]
       check-lean-tree.sh --ban <alternation> <crate> [<crate> ...]
USAGE
}

all=0
ban_override=""
crates=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) all=1; shift ;;
    --ban)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "::error::--ban requires a non-empty package alternation (e.g. --ban 'axum|vmcell')" >&2
        usage
        exit 1
      fi
      ban_override="$2"
      shift 2
      ;;
    -*)
      # Every accepted input is honoured or rejected: an unrecognised flag is a caller bug, never
      # a silently-ignored argument that turns the run into a vacuous pass.
      echo "::error::unknown flag: $1" >&2
      usage
      exit 1
      ;;
    *) crates+=("$1"); shift ;;
  esac
done

if (( all )) && [[ ${#crates[@]} -gt 0 ]]; then
  echo "::error::--all checks the whole matrix; it takes no crate names (got: ${crates[*]})" >&2
  exit 1
fi
if (( all )) && [[ -n "$ban_override" ]]; then
  echo "::error::--all uses each row's own ban pattern; --ban cannot be combined with it" >&2
  exit 1
fi
# An empty roster is a caller bug, not an in-band "nothing to check" sentinel (the L-HOST-1
# contracts-self-guard shape): a crate list that expands to nothing must fail loud rather than
# print a reassuring "ok".
if (( ! all )) && [[ ${#crates[@]} -eq 0 ]]; then
  usage
  exit 1
fi

# ── Selection ────────────────────────────────────────────────────────────────────────────────
# `selected` holds `<crate> <ban>` rows.
selected=()
if (( all )); then
  selected=("${LEAN_MATRIX[@]}")
elif [[ -n "$ban_override" ]]; then
  # Ad-hoc form: exactly what was asked for, and nothing else. This is the form the self-test's
  # positive controls use, so it must not drag the matrix in behind them.
  for crate in "${crates[@]}"; do
    selected+=("$crate $ban_override")
  done
else
  for crate in "${crates[@]}"; do
    if ban=$(matrix_ban_for "$crate"); then
      selected+=("$crate $ban")
    else
      echo "::error::$crate is not a governed member of the lean matrix in $0." >&2
      echo "  Add a row (with the packages that must be absent from its graph), or use" >&2
      echo "  \`--ban <alternation> $crate\` for an ad-hoc check." >&2
      exit 1
    fi
  done

  # THE MATRIX IS THE LAW, NOT THE CALL SITE. A caller that names a strict subset is a stale
  # roster — that is exactly how `vmcell-daemon-client`'s boundary went ungated while two call
  # sites confidently listed three crates (docs/81 m28). Checking only what was asked would make
  # this script's own table decorative, so the omitted rows are checked too, loudly, and the call
  # site is told to switch to `--all`.
  for row in "${LEAN_MATRIX[@]}"; do
    read -r mcrate mban <<<"$row"
    covered=0
    for crate in "${crates[@]}"; do
      if [[ "$crate" == "$mcrate" ]]; then covered=1; fi
    done
    if (( ! covered )); then
      selected+=("$mcrate $mban")
      echo "note: the caller's roster omits the governed member $mcrate — checking it anyway."
      echo "      Replace the crate list with \`--all\` so the matrix cannot go stale again."
    fi
  done
fi

# ── The predicate ────────────────────────────────────────────────────────────────────────────
fail=0
checked=()
for row in "${selected[@]}"; do
  read -r crate ban <<<"$row"
  # `-e no-dev`: dev-dependencies legitimately pull the host stack into the test build; the
  # invariant is about what the SHIPPED binary links. `--locked`: a stale lockfile fails loud with
  # cargo's own message rather than being silently re-resolved by a "check".
  tree=$(cargo tree --color never --locked -e no-dev -p "$crate")
  if hits=$(grep -E "── ($ban) v" <<<"$tree"); then
    echo "::error::lean invariant violated — $ban leaked into $crate"
    printf '%s\n' "$hits" >&2
    fail=1
  fi
  checked+=("$crate")
done

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "check-lean-tree: ok (${checked[*]} respect the lean matrix)"
