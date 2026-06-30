#!/usr/bin/env bash
# Enforces rubric B6 / design §12.5: IDs and other shared state come from injected
# allocators/seams, never module-global mutable or interior-mutable statics.
#
# Heuristic, but newline- and comment-aware (P31 hardening). It flags module-scope
# statics of the dangerous kinds:
#   * `static mut`
#   * `static NAME: ...Atomic...`                                    (atomic counters/flags)
#   * `static NAME: ...OnceLock|OnceCell|Mutex|RwLock|Lazy|once_cell` (interior-mutable singletons)
#   * `static NAME: Alias = Atomic*/OnceLock/... ::new(...)`          (type-name hidden via `use as`)
#   * `lazy_static! { ... }`
#   * `use ...::(Atomic*/OnceLock/OnceCell/Lazy) as Alias;`          (alias bypass of the type check)
# The declaration is accumulated across newlines up to its terminating `;`, so a
# multi-line `static\n  NAME: Atomic.. = ..;` can no longer slip past a line-based regex.
# Line comments are stripped before pattern-matching so prose like "the buggy `static
# OnceLock`" is never a false positive — but the exemption marker (a comment, below) is
# honoured first, before stripping.
#
# There are NO blanket whole-file exemptions. A genuinely-justified global must instead carry a
# per-line exemption marker on the same line as any line of its declaration:
#   static CA_CACHE: OnceLock<...> = OnceLock::new(); // allow-global-state: <reason>
# so every surviving global is justified in place and shows up in review.
#
# Usage: ban-global-state.sh [DIR ...]   (defaults to the shipped source trees: src benches)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(src benches)
fi

# Interior-mutable / atomic type stems that, at module scope, indicate shared mutable state.
KW='Atomic[A-Za-z0-9_]*|OnceLock|OnceCell|Mutex|RwLock|Lazy|once_cell'

violations=""
append() { if [[ -n "$1" ]]; then violations+="$1"$'\n'; fi; }

# Gather the .rs files once (NUL-safe).
mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
[[ ${#files[@]} -eq 0 ]] && { echo "ok: no Rust sources under: ${dirs[*]}"; exit 0; }

# Pass 1 — `static` declarations, accumulated across newlines, comment-stripped, exemption-aware.
for f in "${files[@]}"; do
  out="$(KW="$KW" awk -v FN="$f" '
    function flush() {
      collecting = 0
      if (exempt) { buf = ""; return }
      if (buf ~ /static[[:space:]]+mut[[:space:]]/) { print FN ":" startln ": " squeeze(buf); buf = ""; return }
      # interior-mutable type on the declared-type side (between `:` and `=`).
      if (buf ~ ("static[[:space:]]+[A-Za-z0-9_]+[[:space:]]*:[^=]*(" ENVIRON["KW"] ")")) { print FN ":" startln ": " squeeze(buf); buf = ""; return }
      # dangerous constructor on the initializer side: defeats `use ConcreteType as Alias`
      # type-name hiding (the alias dodges the type-side check, but the ctor call still names it).
      if (buf ~ ("(" ENVIRON["KW"] ")[[:space:]]*::[[:space:]]*(new|from|default|const_new)")) { print FN ":" startln ": " squeeze(buf); buf = ""; return }
      buf = ""
    }
    function squeeze(s) { gsub(/[[:space:]]+/, " ", s); gsub(/^ | $/, "", s); return s }
    {
      line = $0
      # Honour the exemption marker on ANY line of the declaration, before stripping comments.
      has_exempt = (line ~ /allow-global-state:/)
      code = line
      sub(/\/\/.*/, "", code)   # drop the line comment for pattern analysis
      if (!collecting && code ~ /(^|[^A-Za-z0-9_'"'"'])static[[:space:]]/) {
        collecting = 1; buf = ""; startln = NR; exempt = 0
      }
      if (collecting) {
        if (has_exempt) exempt = 1
        buf = buf " " code
        if (code ~ /;/) flush()
      }
    }
    END { if (collecting) flush() }
  ' "$f")"
  append "$out"
done

# Pass 2 — `lazy_static!` singleton macro (single token; line-based is sufficient).
append "$(grep -rnE 'lazy_static!' "${dirs[@]}" 2>/dev/null | grep -vF 'allow-global-state:' || true)"

# Pass 3 — `use ...::(Atomic*/OnceLock/OnceCell/Lazy) as Alias;` import aliasing. Aliasing one of
# these almost-exclusively-global types is the documented bypass of the type-side check; surface it.
# Mutex/RwLock are deliberately excluded here — they have legitimate struct-field uses under an alias.
append "$(grep -rnE 'use[[:space:]][^;]*\b(Atomic[A-Za-z0-9_]*|OnceLock|OnceCell|Lazy)\b[^;]*[[:space:]]+as[[:space:]]' "${dirs[@]}" 2>/dev/null | grep -vF 'allow-global-state:' || true)"

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "Forbidden module-global mutable/interior-mutable state — inject a seam (rubric B6),"
  echo "or add a trailing '// allow-global-state: <reason>' marker if the global is justified:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi
echo "ok: no unjustified module-global mutable/singleton state (scanned: ${dirs[*]})"
