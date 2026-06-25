#!/usr/bin/env bash
# Enforces rubric B6 / design §12.5: IDs come from injected allocators, never module-global statics.
# Heuristic and line-based; shrink ALLOW_REGEX toward empty as the real allocators replace the globals.
set -euo pipefail

# The only file(s) currently permitted to hold the global allocator — adapt to your layout.
ALLOW_REGEX='src/vmm/mod\.rs|src/orchestrator\.rs'

violations="$(grep -rnE 'static[[:space:]]+mut[[:space:]]|static[[:space:]]+[A-Z0-9_]+[[:space:]]*:[[:space:]]*(std::sync::atomic::)?Atomic' src \
  | grep -vE "^($ALLOW_REGEX):" || true)"

if [[ -n "$violations" ]]; then
  echo "Forbidden module-global mutable state — use an injected allocator (rubric B6):"
  echo "$violations"
  exit 1
fi
echo "ok: no new global mutable ID/atomic state"
