#!/usr/bin/env bash
# Enforces design v14 §10.7: the crate-rename regression gate. After the imp-testing → vmcell
# rename, the legacy vocabulary must not creep back into non-historical code. This scanner flags
# the retired tokens so a stray re-introduction (a copy-pasted env var, an old binary name, the
# `rootless`/`TestVm` spellings, an `imp-*` internal prefix) fails CI instead of silently landing.
#
# Flagged tokens (everywhere in the roster — `crates/` + the `justfile` by default; any file kind,
# not just *.rs):
#   * `TestVm`                                         (renamed harness type → VmCell)
#   * `[Rr]ootless`                                    (renamed network/integration tier → unprivileged)
#   * `imp[_-]testing` / `Imp-testing`                 (old crate / project name → vmcell)
#   * `imp-guest-agent` / `imp-test-runner` / `imp-guest-tools`   (old binary names → vmcell-*)
#   * `IMP_KERNEL` / `IMP_ROOTFS` / `IMP_ARTIFACTS_DIR` / `IMP_CH_BIN`   (old env vars → VMCELL_*)
#   * `(^|[^A-Za-z0-9_])imp-`                          (the imp-vm-/imp-net-/imp-tap/imp-drop/imp-fc/
#                                                       imp-vsock/imp-serial/imp-smoltcp/imp-bench/...
#                                                       internal hyphen-prefix family → vmcell-*)
#   * `imp_(vmid|host_paths|netns)`                    (old internal identifiers)
#   * `Imp` / `Imp's`                                  (standalone capitalized origin-harness name →
#                                                       "a hypothetical agent-harness testing project")
#
# Deliberately NOT flagged: the ordinary English words `implementation` / `import` / `impl`. The
# standalone `Imp` pattern matches only the exact word `Imp` bounded by non-word characters, and the
# lowercase `imp` patterns require a trailing `-`/`_` (or the uppercase `IMP_` env form) — so
# `Implementation` / `Import` / `impl` (where `Imp`/`imp` is followed by a word character) never match.
# The capitalized standalone `Imp` origin-harness name is now flagged too: the project moved to the
# generic "hypothetical agent-harness testing project" phrasing, retiring the old §10.7-C exemption.
#
# Line comments are stripped before pattern-matching (`//` for Rust/C sources, `#` for non-.rs files
# like the justfile / shell / toml), so prose in a comment that mentions a banned word (e.g. a note
# about the old name) is not a false positive — but the exemption marker (below) is honoured first,
# before stripping.
#
# There are NO blanket whole-file exemptions. A genuinely-justified legacy mention must carry a
# per-line exemption marker on the same line:
#   let old = "imp-testing"; // allow-legacy-term: <reason>
# so every surviving legacy token is justified in place and shows up in review.
#
# Usage: ban-legacy-terms.sh [PATH ...]  (defaults to the crates/ member trees + the justfile)
# A PATH is a directory (every file under it is scanned) or a regular file (it is scanned). A PATH
# that does not exist, or a roster that resolves to zero files, is a caller bug and exits 2 — never
# a reassuring "ok" (docs/81 M13).
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: member source (lib + bins + tests + benches) lives under crates/; the build
  # orchestration lives in the justfile. Both are non-historical code the rename must hold in
  # (L-BIN-3). scripts/ and docs/ are deliberately NOT in the default scope: the ban/legacy gate
  # scripts and their self-tests legitimately embed the retired tokens (as detection patterns and
  # red-on-inverse fixtures), and docs/ carries the historical record of the rename itself — scanning
  # either would flag those legitimate mentions. Pass an explicit path to scan them ad hoc.
  dirs=(crates justfile)
fi

violations=""
append() { if [[ -n "$1" ]]; then violations+="$1"$'\n'; fi; }

# Resolve the roster to a FILE LIST (NUL-safe). Scan every file kind, not just *.rs — env vars and
# legacy names hide in shell/toml/markdown fixtures too.
#
# COLLECT FILES, DO NOT GATE ON DIRECTORIES. The previous collector was
# `[[ -d "$d" ]] && find "$d" -type f -print0`, so every regular-file roster entry was silently
# dropped — including the default roster's own `justfile`, which this gate has named in its success
# line since it was written while never opening a byte of it (docs/81 M13; a copy of the real
# justfile carrying `test-rootless:` + `echo imp-testing` still exited 0). A gate that reports
# scanning a target it never read is theater, so the roster is now resolved element by element and
# the success line reports the FILE COUNT: a roster that resolves to nothing cannot print a
# reassuring message, because it cannot print a count.
for p in "${dirs[@]}"; do
  [[ -e "$p" ]] && continue
  echo "ban-legacy-terms: roster entry does not exist: $p" >&2
  echo "  (a mistyped path must fail loud — it must not read as a clean scan)" >&2
  exit 2
done

files=()
mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    if [[ -d "$d" ]]; then
      find "$d" -type f -print0
    else
      printf '%s\0' "$d"
    fi
  done
)

# An empty resolution is a broken roster, never a clean tree: the only way to scan zero files is to
# have been pointed at nothing. Exit non-zero so it reads as the caller bug it is.
if [[ ${#files[@]} -eq 0 ]]; then
  echo "ban-legacy-terms: roster resolved to 0 files: ${dirs[*]}" >&2
  exit 2
fi

for f in "${files[@]}"; do
  # Skip binary files: -I makes grep report no match for binary, `.` matches any text line.
  grep -Iq . "$f" 2>/dev/null || continue
  out="$(awk -v FN="$f" '
    function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
    {
      line = $0
      # Honour the per-line exemption marker first (it lives in the comment), before stripping.
      if (line ~ /allow-legacy-term:/) next
      code = line
      sub(/\/\/.*/, "", code)   # drop the // line comment for pattern analysis (Rust/C sources)
      # Non-Rust members (justfile, shell, toml) comment with `#`; strip those too so a banned token
      # quoted in prose is not a false positive. Only for non-.rs files — Rust uses `#` for attributes
      # (`#[cfg…]`) and raw strings (`r#"…"#`), where `#`-stripping would corrupt the line (L-BIN-3).
      if (FN !~ /\.rs$/) sub(/#.*/, "", code)
      if (code ~ /TestVm/ \
       || code ~ /[Rr]ootless/ \
       || code ~ /imp[_-]testing/ \
       || code ~ /Imp-testing/ \
       || code ~ /imp-guest-agent|imp-test-runner|imp-guest-tools/ \
       || code ~ /IMP_KERNEL|IMP_ROOTFS|IMP_ARTIFACTS_DIR|IMP_CH_BIN/ \
       || code ~ /(^|[^A-Za-z0-9_])imp-/ \
       || code ~ /imp_(vmid|host_paths|netns)/ \
       || code ~ /(^|[^A-Za-z0-9_])Imp([^A-Za-z0-9_]|$)/) {
        print FN ":" NR ": " trim(line)
      }
    }
  ' "$f")"
  append "$out"
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "Forbidden legacy term(s) — the imp-testing → vmcell rename (design v14 §10.7) must hold."
  echo "Rename to the vmcell vocabulary, or add a trailing '// allow-legacy-term: <reason>' marker"
  echo "if the mention is genuinely justified (e.g. a historical reference in non-historical code):"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi
plural="s"
if [[ ${#files[@]} -eq 1 ]]; then plural=""; fi
echo "ok: no legacy imp-testing/rootless/TestVm/imp-*/Imp tokens (scanned ${#files[@]} file${plural} under: ${dirs[*]})"
