#!/usr/bin/env bash
# One law, one predicate: a root-disk wiring site must read BOTH `RootfsSource` laws
# (design §4.7, §13 Cross-cutting invariants).
#
# WHY THIS EXISTS. Until v33 delta 8 each of the four backends carried its own per-variant `match`
# deciding whether the root disk was attached writable, and **all four had drifted the same way**:
# every one of them attached a `RootfsSource::Block` root READ-WRITE while `build_kernel_cmdline`
# mounted it `ro` with `rootflags=noload`. So a guest could write straight through `/dev/vda` under
# a root filesystem the kernel believed was immutable — and a zygote fan-out hands N clones the same
# image file. Nothing caught it because four copies of a wrong answer agree with each other, and
# because `RootfsSource::Block` had never been booted by any test.
#
# The fix was structural — `RootfsSource::root_device_read_only()` owns the decision and every
# backend reads it — but the drift it replaces is NOT a compile error: a hand-written
# `readonly: false`, a dropped `readonly=on`, or a missing `ro=true` compiles perfectly. Hence this
# ban, which is the AGENTS.md shape for exactly that ("Where a law's drift is not a compile error it
# carries a grep-ban plus a red-on-inverse self-test").
#
# THE LAW, in two arms:
#
#   ARM 1 — PAIRING. A **root-disk wiring site** is a production source that names BOTH
#   `effective_image` (the "which file backs /dev/vda" law) and a device-writability token
#   (`readonly` / `is_read_only` / `ro=true`). Such a file decides both halves of the root disk's
#   attachment, so it must read `root_device_read_only` — a file that answers "which file" and talks
#   about read-onlyness while deciding writability some other way IS the defect, verbatim.
#
#   Both conditions are load-bearing. `effective_image` alone is not enough: `orchestrator.rs`'s
#   `resolve_cell_features` reads it to find the feature sidecar beside the file the guest mounts,
#   which is a legitimate use with nothing to do with attachment. A writability token alone is not
#   enough either: every backend also wires EXTRA disks, whose `readonly` is per-disk caller input
#   and rightly has no law.
#
#   ARM 2 — VACUITY. At least one file must match ARM 1's site test. Without this arm, renaming
#   either law would leave the scan hunting for a string that can never appear while still printing
#   "ok" — a green gate over an unscanned tree.
#
# The file that DEFINES the laws is exempt by detection, not by path: it is the one containing
# `pub fn root_device_read_only`, so moving the definition does not need an edit here.
#
# Usage: ban-root-disk-writability-literal.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

root="${1:-}"
if [[ -z "$root" ]]; then
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
if [[ ! -d "$root" ]]; then
  echo "gate misconfigured: no such root directory: $root" >&2
  exit 1
fi
root="$(cd "$root" && pwd)"

which_file_law="effective_image"
writability_law="root_device_read_only"
# The spellings the four backends give the root device's read-only flag, in argv-token and
# struct-field form. A site talking about disk writability at all names one of these.
writability_tokens='readonly|is_read_only|ro=true'

# Production sources only: `crates/*/src`. A test that constructs a `RootfsSource` and asserts one
# law at a time is asserting, not wiring.
mapfile -t sources < <(find "$root/crates" -type d -name src -prune -exec find {} -name '*.rs' -type f \; 2>/dev/null | sort)

wiring_sites=()
offenders=()
for file in "${sources[@]}"; do
  # A root-disk wiring site names BOTH halves of the attachment — see ARM 1.
  grep -q -- "$which_file_law" "$file" || continue
  grep -Eq -- "$writability_tokens" "$file" || continue
  wiring_sites+=("$file")
  # The definition site is exempt: it is where the laws are written, not a site that reads them.
  grep -q -- "pub fn $writability_law" "$file" && continue
  grep -q -- "$writability_law" "$file" && continue
  offenders+=("${file#"$root"/}")
done

if [[ ${#wiring_sites[@]} -eq 0 ]]; then
  echo "gate misconfigured: no production source under $root/crates names both \`$which_file_law\`" >&2
  echo "and a root-device writability token (${writability_tokens//|/, }). A law was renamed or" >&2
  echo "moved; update this scanner rather than letting it pass vacuously." >&2
  exit 1
fi

if [[ ${#offenders[@]} -ne 0 ]]; then
  echo "root-disk wiring reads only ONE of the two \`RootfsSource\` laws:" >&2
  for o in "${offenders[@]}"; do
    echo "  $o names \`$which_file_law\` but not \`$writability_law\`" >&2
  done
  cat >&2 <<'MSG'

A site that decides WHICH file backs /dev/vda must also decide whether it is attached writable, and
it must decide it through `RootfsSource::root_device_read_only()` — not with a hardcoded
`readonly: false` / a dropped `readonly=on` / a missing `ro=true`. All four backends once had their
own copy of that decision and all four had drifted to "writable" beneath a cmdline that mounts the
root `ro`, which is a write path with no reader and N zygote clones sharing one image (§4.7).
MSG
  exit 1
fi

echo "ok: ${#wiring_sites[@]} root-disk wiring site(s); each reads \`$writability_law\`"
