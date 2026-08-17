#!/usr/bin/env bash
# ONE MSRV FACT — and ONE place that asserts it. AGENTS.md ("Docs and dependencies" → Toolchain):
# "`rust-toolchain.toml` pins 1.96.1 and the declared `rust-version` **equals** it (one
# `[workspace.package]` fact, sync-asserted). An understated MSRV lets MSRV-aware resolvers
# re-resolve older consumers onto vulnerable dependency versions (the `time 0.3.45` class)."
#
# WHY THIS EXISTS. The assertion itself was written TWICE — an inline `sed` comparison in the
# justfile's `ci` recipe, and a `run:` block in `.github/workflows/ci.yml` whose own comment says
# "Mirrors the `just ci` assertion". Two copies of one law is the exact shape AGENTS.md rule 3 bans,
# and this repo has watched that shape drift three separate times in the CI/recipe direction alone
# (see `scripts/ban-ci-script-handcopy.sh`'s header). A mirrored assertion is worse than a mirrored
# roster: it can drift in STRICTNESS silently — one copy tightened to reject an unpinned channel, the
# other still accepting it — and whichever copy the reader happens to open tells them the law.
# Landing this script does not by itself remove those two inline copies; the change that adds it to
# the `gates` recipe deletes both, and after that the law has one home: this file.
#
# THE LAW, in three arms:
#
#   ARM 1 — THE NAMED PAIR. `rust-toolchain.toml`'s `[toolchain] channel` equals the root
#   `Cargo.toml`'s `[workspace.package] rust-version`. Both must be PRESENT (a missing key is a
#   silently-unpinned toolchain or a silently-undeclared MSRV, never a pass) and the channel must be
#   a pinned `x[.y[.z]]` version: `stable`/`nightly-…` cannot be compared to a declared floor at all,
#   so accepting one would make this gate green while the pin it exists to enforce does not exist.
#
#   ARM 2 — EVERY OTHER COPY OF THE SAME NUMBER. The workspace members inherit via
#   `rust-version.workspace = true` (the sanctioned non-copy — not compared, only counted), but some
#   manifests declare the number LITERALLY because they cannot inherit: the root manifest, plus every
#   SEPARATE workspace in the tree (today `fuzz/` and the out-of-tree `examples/downstream-kernel/`
#   consumer — the verdict line prints the live count rather than quoting one here, which is how doc
#   counts go stale). Each is an independent chance to understate the MSRV, and the two inline
#   assertions this replaces looked at exactly one of them. Any literal `rust-version` in a
#   non-vendored manifest, any additional
#   `rust-toolchain.toml` channel, and `clippy.toml`'s `msrv` must all equal the pinned channel.
#   `clippy.toml`'s own comment already CLAIMS to be "kept in lockstep … by the sync assertion in
#   `just ci` / ci.yml" — it was not; the assertion never read that file.
#
#   ARM 3 — NON-VACUITY. A scan that finds no manifests at all (a wrong ROOT, a moved crate tree)
#   is a gate MISCONFIGURATION and exits 1, never a reassuring `ok:` (docs/90 G4).
#
# Vendored third-party manifests (`vendor/**`) and build outputs (`**/target/**`) are excluded: their
# MSRV is not ours to hold in lockstep.
#
# Usage: check-msrv-sync.sh [ROOT]   (defaults to the repo root above this script)
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

toolchain_rel="rust-toolchain.toml"
manifest_rel="Cargo.toml"
toolchain="$root/$toolchain_rel"
manifest="$root/$manifest_rel"

for f in "$toolchain" "$manifest"; do
  if [[ ! -f "$f" ]]; then
    echo "gate misconfigured: expected file does not exist: $f" >&2
    echo "The MSRV is ONE fact spread over two files — the pinned channel and the declared floor." >&2
    echo "With either one absent there is nothing to hold in sync, which is not the same as agreeing." >&2
    exit 1
  fi
done

# Reads a value out of a TOML file, SECTION-AWARE: `toml_lookup <file> <section> <key>`, where
# <section> is the bracketed header with all whitespace removed (`[workspace.package]`) or the empty
# string for the top level (clippy.toml has no sections). Prints nothing when the key is absent in
# that section — a `rust-version` under some OTHER table is not the workspace fact, and the inline
# assertions this replaces would have accepted it (their `sed` was section-blind).
# Line comments are stripped before matching; no value here can legitimately contain a `#`.
toml_lookup() {
  local file="$1" section="$2" key="$3"
  awk -v want="$section" -v key="$key" '
    {
      line = $0
      sub(/[[:space:]]*#.*$/, "", line)
    }
    line ~ /^[[:space:]]*\[/ {
      cur = line
      gsub(/[[:space:]]/, "", cur)
      next
    }
    {
      if (cur != want) next
      if (line ~ ("^[[:space:]]*" key "[[:space:]]*=")) {
        sub("^[[:space:]]*" key "[[:space:]]*=[[:space:]]*", "", line)
        gsub(/^["'"'"']|["'"'"'][[:space:]]*$/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        print line
        exit
      }
    }
  ' "$file"
}

failed=0

channel="$(toml_lookup "$toolchain" "[toolchain]" "channel")"
declared="$(toml_lookup "$manifest" "[workspace.package]" "rust-version")"

if [[ -z "$channel" ]]; then
  echo "check-msrv-sync: FAIL — $toolchain_rel declares no \`[toolchain] channel\`."
  echo "  Without a pinned channel the toolchain is whatever rustup last installed, and the declared"
  echo "  MSRV has nothing to equal. Pin it (\`channel = \"x.y.z\"\`) rather than deleting the pin."
  failed=1
elif [[ ! "$channel" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
  echo "check-msrv-sync: FAIL — $toolchain_rel pins a non-VERSION channel: \`$channel\`."
  echo "  \`stable\`/\`beta\`/\`nightly-…\` cannot be compared against a declared \`rust-version\`, so this"
  echo "  gate would pass while the equality it exists to enforce is unstatable. Pin an explicit"
  echo "  x.y.z (the floor tracks the latest stable) instead."
  failed=1
fi

if [[ -z "$declared" ]]; then
  echo "check-msrv-sync: FAIL — $manifest_rel declares no \`[workspace.package] rust-version\`."
  echo "  An UNDECLARED MSRV is the understated-MSRV hazard at its widest: an MSRV-aware resolver is"
  echo "  free to hand a consumer the older, vulnerable dependency versions the lockfile pins away"
  echo "  from (the \`time 0.3.45\` class). Declare it, equal to the pinned channel."
  failed=1
fi

if [[ -n "$channel" && -n "$declared" && "$channel" != "$declared" ]]; then
  echo "check-msrv-sync: FAIL — MSRV drift: the pinned channel and the declared floor disagree."
  printf '  %-19s [toolchain] channel            = %s\n' "$toolchain_rel" "$channel"
  printf '  %-19s [workspace.package] rust-version = %s\n' "$manifest_rel" "$declared"
  echo ""
  echo "  These are one fact. An UNDERSTATED rust-version (declared lower than the toolchain that is"
  echo "  actually tested) lets MSRV-aware resolvers re-resolve older consumers onto dependency"
  echo "  versions this workspace never builds against — the \`time 0.3.45\` class. An overstated one"
  echo "  refuses consumers that would work. Move whichever is wrong; do not tolerate the gap."
  failed=1
fi

# --- ARM 2: every other declaration of the same number ---------------------------------------------
# Build outputs and vendored third-party trees are PRUNED, not filtered: a `-not -path` predicate
# still descends into `target/`, which on a built tree is tens of thousands of directories and turned
# this gate into a four-second stat storm. `examples/downstream-kernel` and `fuzz/` are deliberately IN
# scope — they are separate workspaces that spell the number literally, and a consumer understating the
# MSRV is the whole hazard.
prune_and_find() {  # prune_and_find <filename>
  find "$root" \
    \( -name target -o -name .git -o -path "$root/vendor" \) -prune -o \
    -type f -name "$1" -print0
}
mapfile -d '' -t manifests < <(prune_and_find 'Cargo.toml' | sort -z)
if [[ ${#manifests[@]} -eq 0 ]]; then
  echo "gate misconfigured: no Cargo.toml found under: $root"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
fi

inherited=0
literal=0
mismatches=""
for m in "${manifests[@]}"; do
  rel="${m#"$root"/}"
  # The sanctioned non-copy: the member inherits the one workspace fact. Counted, never compared.
  if grep -qE '^[[:space:]]*rust-version\.workspace[[:space:]]*=[[:space:]]*true' "$m"; then
    inherited=$((inherited + 1))
    continue
  fi
  # A literal declaration, in ANY table of that manifest: `[package]` for a crate,
  # `[workspace.package]` for a workspace root. Section-blind on purpose here — every literal spelling
  # of the number is a copy that can drift, wherever it sits.
  local_value="$(
    sed -nE 's/^[[:space:]]*rust-version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$m" | head -n1
  )"
  [[ -z "$local_value" ]] && continue
  literal=$((literal + 1))
  if [[ -n "$channel" && "$local_value" != "$channel" ]]; then
    mismatches+="  $rel: rust-version = $local_value (pinned channel is $channel)"$'\n'
  fi
done

# Any ADDITIONAL pinned channel (a nested workspace shipping its own rust-toolchain.toml) is the same
# fact again: a second pin that disagrees means one of the two workspaces is built on an untested
# toolchain, and neither inline assertion looked outside the repo root.
mapfile -d '' -t toolchains < <(prune_and_find 'rust-toolchain.toml' | sort -z)
extra_channels=0
for t in "${toolchains[@]}"; do
  [[ "$t" == "$toolchain" ]] && continue
  extra_channels=$((extra_channels + 1))
  rel="${t#"$root"/}"
  other="$(toml_lookup "$t" "[toolchain]" "channel")"
  if [[ -z "$other" ]]; then
    mismatches+="  $rel: declares no [toolchain] channel (an unpinned nested workspace)"$'\n'
  elif [[ -n "$channel" && "$other" != "$channel" ]]; then
    mismatches+="  $rel: channel = $other (repo-root channel is $channel)"$'\n'
  fi
done

# clippy.toml's `msrv` drives clippy's own version-gated lints. It is optional — with no `msrv`,
# clippy falls back to the manifest's `rust-version`, which IS the single fact — but when present it
# is a fourth spelling of the number, and its comment already claims a sync assertion covers it.
clippy_rel="clippy.toml"
clippy_msrv=""
if [[ -f "$root/$clippy_rel" ]]; then
  clippy_msrv="$(toml_lookup "$root/$clippy_rel" "" "msrv")"
  if [[ -n "$clippy_msrv" && -n "$channel" && "$clippy_msrv" != "$channel" ]]; then
    mismatches+="  $clippy_rel: msrv = $clippy_msrv (pinned channel is $channel)"$'\n'
  fi
fi

if [[ -n "${mismatches//[$'\n']/}" ]]; then
  echo "check-msrv-sync: FAIL — a second declaration of the MSRV disagrees with the pinned channel."
  echo "  Members inherit the one fact via \`rust-version.workspace = true\`; every LITERAL below is a"
  echo "  copy, and a copy that drifts LOW is the understated-MSRV hazard (the \`time 0.3.45\` class)"
  echo "  reaching consumers the workspace assertion never looked at:"
  printf '%s' "$mismatches"
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

summary="ok: one MSRV fact — $toolchain_rel [toolchain] channel = $channel == $manifest_rel [workspace.package] rust-version = $declared"
if [[ -n "$clippy_msrv" ]]; then
  summary+="; $clippy_rel msrv = $clippy_msrv"
fi
echo "$summary"
echo "(scanned ${#manifests[@]} manifest(s): $literal literal rust-version declaration(s) all equal to the"
echo "pinned channel, $inherited inheriting via rust-version.workspace; $extra_channels additional rust-toolchain.toml)"
