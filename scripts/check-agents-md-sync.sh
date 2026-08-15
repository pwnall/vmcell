#!/usr/bin/env bash
# `AGENTS.md` is the DEPLOYED copy of `docs/80-claude-agents-v7.md` — the source document says so in
# its own second line ("Deploy at the repository root as `AGENTS.md`"). Two files, one document.
#
# WHY THIS EXISTS. Two copies of one document is the same shape as two copies of one law, and it
# failed the same way. The docs/81 fix campaign rewrote AGENTS.md in seven hunks — the stale crate
# version, the `release` vs `debug` blessed runner, "three file capabilities" when
# `BLESSED_FILE_CAPS` has four, the new one-law-one-predicate roster, the `just gates` wiring — and
# touched the source document in exactly one. The result: the wave whose entire mandate was "counts
# and rosters quoted in docs are checked against the tree, never from memory" left every corrected
# number still wrong in the document AGENTS.md is deployed from. A reader who opened docs/80 got the
# pre-campaign answers.
#
# Nothing detected that. The two files were byte-identical at the commit before the campaign, so the
# invariant already existed — it was just unwritten, and an unwritten invariant is not a gate.
#
# THE LAW. The two paths are byte-identical. That is deliberately stricter than "the facts agree":
# a tolerance (ignore whitespace, ignore the header, diff only the rosters) is a second predicate
# that would itself drift, and the exact-equality form needs no maintenance as the document grows.
# If the two are ever meant to diverge, that is a real decision — make it here, in code, with the
# reason, rather than by letting an edit land in one of them.
set -euo pipefail

# Resolve from the script's own location so the check is path-independent: `just` runs it from the
# repo root, the self-test runs it against a throwaway fixture tree, and a downstream consumer could
# run it from anywhere.
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

deployed="$root/AGENTS.md"
source_doc=""

# Discover the source document rather than pinning its version-numbered filename: `docs/80-…-v7.md`
# becomes `-v8` at the next agents-doc reissue, exactly as the design doc went v31 -> v32 mid-
# campaign and broke two gates that had hardcoded ITS name. Pick the newest `claude-agents` doc that
# is not historical, the same "use the newest version you find" rule AGENTS.md states for the design.
while IFS= read -r candidate; do
    source_doc="$candidate"
done < <(find "$root/docs" -maxdepth 1 -name '*claude-agents*.md' -type f | sort)

if [[ -z "$source_doc" ]]; then
    echo "check-agents-md-sync: FAIL — no docs/*claude-agents*.md source document found under $root/docs" >&2
    echo "  (a roster that resolves to nothing must not print a reassuring message)" >&2
    exit 1
fi

if [[ ! -f "$deployed" ]]; then
    echo "check-agents-md-sync: FAIL — $deployed does not exist" >&2
    exit 1
fi

if ! cmp -s "$deployed" "$source_doc"; then
    echo "check-agents-md-sync: FAIL — AGENTS.md and its source document have drifted." >&2
    echo "  deployed: ${deployed#"$root"/}" >&2
    echo "  source  : ${source_doc#"$root"/}" >&2
    echo "" >&2
    echo "  AGENTS.md is the deployed copy of that document; they are two paths for one file." >&2
    echo "  Edit one, then copy it over the other:" >&2
    echo "      cp ${deployed#"$root"/} ${source_doc#"$root"/}     # if AGENTS.md is the newer" >&2
    echo "      cp ${source_doc#"$root"/} ${deployed#"$root"/}     # if the source doc is" >&2
    echo "" >&2
    echo "  Divergence so far:" >&2
    diff "$source_doc" "$deployed" | head -40 >&2
    exit 1
fi

echo "ok: AGENTS.md is byte-identical to ${source_doc#"$root"/} ($(wc -l <"$deployed") lines)"
