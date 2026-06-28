#!/usr/bin/env bash
# Enforces rubric B6 / design §12.5: IDs and other shared state come from injected
# allocators/seams, never module-global mutable or interior-mutable statics.
#
# Heuristic and line-based. It flags module-scope statics of the dangerous kinds:
#   * `static mut`
#   * `static NAME: ...Atomic...`                                    (atomic counters/flags)
#   * `static NAME: ...OnceLock|OnceCell|Mutex|RwLock|Lazy|once_cell` (interior-mutable singletons)
#   * `lazy_static! { ... }`
#
# There are NO blanket whole-file exemptions. A genuinely-justified global must instead carry a
# per-line exemption marker on the same line:
#   static CA_CACHE: OnceLock<...> = OnceLock::new(); // allow-global-state: <reason>
# so every surviving global is justified in place and shows up in review.
set -euo pipefail

# Module-scope mutable / interior-mutable static declarations and singleton macros.
# The `[^=]*` keeps us on the declaration's type (before any `=` initializer), so plain
# `static FOO: &str = "..."` constants are not flagged.
PATTERN='static[[:space:]]+mut[[:space:]]|static[[:space:]]+[A-Za-z0-9_]+[[:space:]]*:[^=]*(Atomic|OnceLock|OnceCell|Mutex|RwLock|Lazy|once_cell)|lazy_static!'

violations="$(grep -rnE "$PATTERN" src \
  | grep -vF 'allow-global-state:' || true)"

if [[ -n "$violations" ]]; then
  echo "Forbidden module-global mutable/interior-mutable state — inject a seam (rubric B6),"
  echo "or add a trailing '// allow-global-state: <reason>' marker if the global is justified:"
  echo "$violations"
  exit 1
fi
echo "ok: no unjustified module-global mutable/singleton state"
