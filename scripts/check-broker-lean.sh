#!/usr/bin/env bash
# ONE predicate for the broker's lean boundary (design §12.23 / invariant P2; AGENTS.md "the broker,
# and the jailer"). The broker OWNS the engine, so tokio and rtnetlink are LEGITIMATE there — it
# does netns/tap/nft setup. Its boundary is the network-facing WEB SERVER: the HTTP surface that
# parses untrusted network input must never share the cap-holding process. That surface is
# `vmcell-daemon` + `axum`. `hyper` is deliberately NOT asserted absent — it enters legitimately
# through the egress proxy (hudsucker) and the HTTP clients (reqwest/oci-client).
#
# WHY THIS IS A SCRIPT AND NOT TWO INLINE `if` BLOCKS. The two copies it replaces (`ci.yml` and the
# `justfile`) both had the same defect: they tested only whether `cargo tree -i <pkg>` printed
# anything on stdout, with stderr sent to /dev/null.
#
#     $ cargo tree --locked -p vmcell-broker -e no-dev -i axum
#     error: package ID specification `axum` did not match any packages
#     $ echo $?
#     101
#
# The verdict "absent" and the verdict "cargo could not answer" are therefore indistinguishable: a
# rename, an ambiguous spec (`-i tokio` really does exit 101 with "specification `tokio` is
# ambiguous" in this workspace), a stale lockfile, or any other cargo failure all read as GREEN.
# That is a negative security gate with no way to fail — AGENTS.md rule 2's theater — guarding
# AGENTS.md's P2 posture rule. This script separates the three outcomes and carries the positive
# control AGENTS.md requires beside every negative security result.
#
# `--color never`: `ci.yml` sets `CARGO_TERM_COLOR: always` at workflow level; see
# scripts/check-lean-tree.sh for the full account of why parsing coloured cargo output is a defect
# class here. `scripts/ban-uncolored-cargo-parse.sh` is the gate that keeps it from recurring.
#
# Usage: check-broker-lean.sh
set -euo pipefail

# absent <pkg>: 0 = provably absent from the broker's graph, 1 = present, 2 = cargo could not answer.
# On "present" the offending tree is left in $reached for the caller to print.
#
# Note the `|| rc=$?` idiom rather than `set +e`/`set -e` around the call: a bare `set -e` inside a
# function re-enables errexit for the CALLER too, so a nonzero `return` would kill the script before
# the verdict could be classified — which silently turned the "present" and "cargo broke" arms into
# an immediate exit during this script's own bring-up. A condition context is the only form that
# both suppresses errexit and preserves the status.
reached=""
absent() {
  local pkg="$1" err rc=0
  err=$(mktemp)
  reached=""
  reached=$(cargo tree --color never --locked -p vmcell-broker -e no-dev -i "$pkg" 2>"$err") || rc=$?
  if [[ $rc -eq 0 ]]; then
    rm -f "$err"
    # cargo succeeded: a non-empty tree means the package really is reachable.
    [[ -n "$reached" ]] && return 1
    return 0
  fi
  # The one nonzero exit that means "absent" rather than "broken".
  if grep -q 'did not match any packages' "$err"; then
    rm -f "$err"
    return 0
  fi
  echo "::error::cargo tree failed unexpectedly while probing '$pkg' in vmcell-broker:" >&2
  cat "$err" >&2
  rm -f "$err"
  return 2
}

for pkg in vmcell-daemon axum; do
  rc=0
  absent "$pkg" || rc=$?
  case "$rc" in
    0) ;;
    1)
      echo "::error::vmcell-broker must not link $pkg (the network-input server stack must not share the cap-holder — P2)" >&2
      printf '%s\n' "$reached" >&2
      exit 1
      ;;
    *) exit 1 ;;
  esac
done

# POSITIVE CONTROL (AGENTS.md: "a negative security result needs a positive control (the allowed
# path reaches the same target)"). The two verdicts above are absences; this proves the probe that
# produced them can still find a crate that IS linked. `vmcell-daemon` links `axum` by definition —
# it is the web server — so an empty result here means the `-i` probe has stopped working and the
# absences above mean nothing.
if ! cargo tree --color never --locked -p vmcell-daemon -e no-dev -i axum | grep -q .; then
  echo "::error::positive control failed — \`cargo tree -i axum\` finds nothing even in vmcell-daemon," >&2
  echo "  which links axum by definition. The two exclusions above are therefore vacuous." >&2
  exit 1
fi

echo "check-broker-lean: ok (vmcell-broker links neither vmcell-daemon nor axum; the -i probe is live)"
