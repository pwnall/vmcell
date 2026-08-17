#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/check-docs-pointers.sh.
#
# The gate asserts that every `docs/…` pointer in the repo's prose resolves, and that every `§`/
# `Appendix X` reference in the root markdown files names a real heading of the current design
# document. A gate whose self-test only proves the green path is theater (AGENTS.md rule 2), so every
# arm below is driven from a fixture tree the check is POINTED AT:
#   * a live pointer, an arbitrary-digit pointer resolving to a differently-numbered
#     file, an explicit docs/historical/ pointer, a document-number citation of a
#     retired doc, a design `§` and an `Appendix` reference                        → must pass;
#   * a filename pointer at nothing at all                                          → must fail;
#   * THE REAL SHAPE: a live-looking filename whose document has been retired into
#     docs/historical/ — AGENTS.md's `docs/99-…-automated-quality-v9.md` after the
#     retirement, the break this gate is named for                                  → must fail;
#   * …and the SAME pointer inside the as-built ledger                              → must pass
#     (the scoped retirement fallback, proven in both directions);
#   * a NEW dangling pointer inside the ledger (in neither place)                    → must fail;
#   * a document-number citation whose number no document carries                    → must fail;
#   * a longer path that merely contains `docs/`
#     (`vendor/vhost/docs/vhost_architecture.drawio`)                                → must pass
#     (removing the start-of-token guard makes it dangle, reddening this leg);
#   * a `§` naming no section; an `Appendix Z`                                       → must fail;
#   * a bare `§6` in a file that numbers its OWN sections (README's shape)           → must pass,
#     while `design §99` in that same file                                           → must fail;
#   * `v15 §12.8` (another design version's numbering)                               → must pass,
#     while `v33 §99` (the CURRENT version, explicitly qualified)                     → must fail;
#   * the vacuity arms: no root markdown, no design document, a design document with
#     no numbered headings, zero pointers extracted, zero references extracted        → must fail;
#   * the roster arms, both directions: an exemption nobody names, an exemption that
#     now resolves, a ledger entry whose file is not there                            → must fail.
#
# The gate's `allowed`/`ledgers` rosters are hardcoded (they name real repo paths), so every fixture
# tree below reproduces them: the ledger file exists and carries both exempt pointers. That is the
# same fixture discipline test-ban-ci-script-handcopy.sh uses for its wrapper exemption.
#
# Usage: test-check-docs-pointers.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

# ROOT is the repo whose scripts/ holds the check under test — the same optional argument every gate
# script here takes, so `just gates` and a hand run from any directory behave identically.
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
check="$root/scripts/check-docs-pointers.sh"
if [[ ! -x "$check" ]]; then
  echo "gate misconfigured: no executable check at: $check" >&2
  exit 1
fi
work="$(mktemp -d)"
# The fixture tree is residue too: cleaned on the panic path as well as the success path
# (AGENTS.md "Writing tests" — a leaked fixture reddens somebody else's suite as a product defect).
trap 'rm -rf "$work"' EXIT INT TERM

fail=0

# mk_tree <dir> — a minimal but FAITHFUL tree: root markdown with no numbered sections (AGENTS.md's
# shape), a README that numbers its own (so the qualification rule is exercised), a design document
# with real headings, the as-built ledger carrying the two hardcoded exemptions, and one retired
# document under docs/historical/.
# Every fixture document is written through a QUOTED here-doc: the prose is markdown, a backticked
# pointer is one of the forms the extractor must handle, and a backtick inside a single-quoted string
# reads as command substitution to the linter (SC2016). A quoted here-doc is literal by construction,
# so the fixtures keep their real shape without a suppression at every line.
mk_tree() {
  local dir="$1"
  mkdir -p "$dir/docs/historical"
  cat > "$dir/AGENTS.md" <<'EOF'
# agents

Read `docs/implementation-notes.md` and `docs/99-fable-design-v99.md` (arbitrary digit).
The rubric is `docs/84-rubric-v7.md`; v32 is now `docs/historical/82-design-v32.md`.
The docs/45 refuted-lever table, and the docs/81 pass, are cited by number.
Design **section 13** is the reference `§13`, and **Appendix A** records the reversals.
EOF
  cat > "$dir/README.md" <<'EOF'
# readme

### 6. Privileged Test Runner

Blessing is described in §6 above; the daemon is design §11.
Why the stable path (v15 §12.8): capabilities strip on rewrite.
EOF
  cat > "$dir/docs/83-fable-design-v33.md" <<'EOF'
# design v33

## 11. The daemon

### 11.1 What it adds

## 13. Invariants

### Appendix A — reversals
EOF
  cat > "$dir/docs/84-rubric-v7.md" <<'EOF'
# rubric v7
EOF
  cat > "$dir/docs/implementation-notes.md" <<'EOF'
# implementation notes

The QEMU experiment write-up (`docs/qemu-follow-ups.md`) gated Task A.
Requests R1-R7 come from serial-nexus `docs/vmcell-requirements.md`.
EOF
  printf '# design v32, retired\n' > "$dir/docs/historical/82-design-v32.md"
  printf '# perf investigation 45, retired\n' > "$dir/docs/historical/45-perf-investigation.md"
  printf '# code review 81, retired\n' > "$dir/docs/historical/81-opus-code-review.md"
}

# run <fixture-tree> — captures OUT/RC as globals (a plain call, not a `$(...)` capture, so the assignments
# survive: command substitution would run this in a subshell and take them with it).
run() {
  set +e
  OUT="$("$check" "$1" 2>&1)"
  RC=$?
  set -e
}

expect_pass() {  # expect_pass <label> <fixture-tree> [want-substring …]
  local label="$1" fixture="$2"; shift 2
  run "$fixture"
  if [[ "$RC" -ne 0 ]]; then
    echo "  FAIL [$label] must PASS, exited $RC:"; printf '%s\n' "$OUT" | sed 's/^/       /'; fail=1
    return
  fi
  local w
  for w in "$@"; do
    if ! grep -qF -- "$w" <<<"$OUT"; then
      echo "  FAIL [$label] passed but its verdict never says '$w':"
      printf '%s\n' "$OUT" | sed 's/^/       /'; fail=1
    fi
  done
  echo "  ok   [$label] passes"
}

expect_fail() {  # expect_fail <label> <fixture-tree> [want-substring …]
  local label="$1" fixture="$2"; shift 2
  run "$fixture"
  if [[ "$RC" -eq 0 ]]; then
    echo "  FAIL [$label] must FAIL, but it passed — the gate cannot go red here:"
    printf '%s\n' "$OUT" | sed 's/^/       /'; fail=1
    return
  fi
  local w
  for w in "$@"; do
    if ! grep -qF -- "$w" <<<"$OUT"; then
      echo "  FAIL [$label] reddened for the wrong reason (missing '$w'):"
      printf '%s\n' "$OUT" | sed 's/^/       /'; fail=1
    fi
  done
  echo "  ok   [$label] reddens"
}

echo "test-check-docs-pointers:"

# --- Green baseline. Without it every failing arm below proves nothing. It carries one of EACH
# --- resolving form, so a resolver that loses any single convention reddens here rather than in a
# --- reviewer's afternoon: the live path, the arbitrary-digit glob (`-v99` finding `-v33`), the
# --- explicit historical path, and two document-number citations of retired documents.
mk_tree "$work/green"
expect_pass "every resolving form" "$work/green" 'all resolve' 'named exemption'

# --- Arm 1: a filename pointer at nothing at all.
mk_tree "$work/dangling"
cat >> "$work/dangling/AGENTS.md" <<'EOF'
See `docs/91-does-not-exist-v1.md` for the rationale.
EOF
expect_fail "filename pointer at nothing" "$work/dangling" 'docs/91-does-not-exist-v1.md'

# --- Arm 2: THE REAL SHAPE. AGENTS.md's "read before changing anything" list pointed at
# --- `docs/99-claude-fable-automated-quality-v9.md` — a live-looking path whose document had been
# --- retired into docs/historical/. Every agent is told to read that list first, and it sent them to a
# --- path with nothing at it. If this arm ever stops reddening, the gate has lost its reason to exist.
mk_tree "$work/retired-live-path"
cat >> "$work/retired-live-path/AGENTS.md" <<'EOF'
Read `docs/99-quality-v9.md` for the gate specifications.
EOF
printf '# quality v5, retired\n' > "$work/retired-live-path/docs/historical/85-quality-v5.md"
expect_fail "retired document named at its old LIVE path" "$work/retired-live-path" \
  'docs/99-quality-v9.md' 'docs/historical'

# --- Arm 2b: the OTHER direction of the same rule — the correction. Naming it `docs/historical/…`
# --- (what the fix actually did) must pass, or the gate would demand an impossible edit.
mk_tree "$work/retired-named"
printf '# quality v5, retired\n' > "$work/retired-named/docs/historical/85-quality-v5.md"
cat >> "$work/retired-named/AGENTS.md" <<'EOF'
Read `docs/historical/99-quality-v9.md` — **Retired**, there is no live copy.
EOF
expect_pass "retired document named under docs/historical/" "$work/retired-named" 'all resolve'

# --- Arm 2c: the ledger scope, both directions. The SAME live-looking retired path inside
# --- docs/implementation-notes.md passes (its dated entries name paths as they stood, and AGENTS.md
# --- forbids "fixing" them)…
mk_tree "$work/ledger-ok"
printf '# quality v5, retired\n' > "$work/ledger-ok/docs/historical/85-quality-v5.md"
cat >> "$work/ledger-ok/docs/implementation-notes.md" <<'EOF'
The v5 pass reconciled against `docs/85-quality-v5.md` (its path at the time).
EOF
expect_pass "retired path inside the as-built ledger" "$work/ledger-ok" 'as-built' 'all resolve'

# --- …while a NEW pointer in the ledger that exists in neither place still fails. The fallback is a
# --- scope, not an exemption from the check.
mk_tree "$work/ledger-dangling"
cat >> "$work/ledger-dangling/docs/implementation-notes.md" <<'EOF'
See `docs/93-never-existed.md` for the reconciliation.
EOF
expect_fail "new dangling pointer inside the ledger" "$work/ledger-dangling" 'docs/93-never-existed.md'

# --- Arm 3: a document-NUMBER citation whose number no document carries, live or historical. This is
# --- the lenient form, so it must still be able to fail — otherwise `docs/45` would be a free pass for
# --- any number at all.
mk_tree "$work/bad-number"
printf 'The docs/77 refuted-lever table settles it.\n' >> "$work/bad-number/AGENTS.md"
expect_fail "document number nothing carries" "$work/bad-number" 'docs/77'

# --- Arm 4: a LONGER path that merely contains `docs/` is a different file, elsewhere, and real. The
# --- vendored vhost drawing is the live instance. Deleting the start-of-token guard makes this dangle,
# --- so this leg is the guard's red-on-inverse.
mk_tree "$work/longer-path"
cat >> "$work/longer-path/AGENTS.md" <<'EOF'
The `vendor/vhost/docs/vhost_architecture.drawio` diagram was corrupted and reverted.
EOF
expect_pass "a longer path containing docs/ is not a pointer" "$work/longer-path" 'all resolve'

# --- Arm 5: the D2 class itself — a `§` naming a section the design does not have.
mk_tree "$work/bad-section"
printf 'The REST surface is described in §D.\n' >> "$work/bad-section/AGENTS.md"
expect_fail "section reference at a missing section" "$work/bad-section" \
  'no such section' 'AGENTS.md'

mk_tree "$work/bad-appendix"
printf 'The reversals live in Appendix Z.\n' >> "$work/bad-appendix/AGENTS.md"
expect_fail "appendix reference at a missing appendix" "$work/bad-appendix" 'no such appendix'

# --- Arm 6: the qualification rule, both directions. README numbers its OWN sections, so a bare `§6`
# --- there is a self-reference and must NOT be resolved against the design (the baseline already
# --- carries one). A `design §…` in that same file IS a design pointer and must redden when wrong —
# --- otherwise the rule that keeps README's self-references quiet would silence its design pointers too.
mk_tree "$work/qualified"
printf 'The daemon surface is design §99.\n' >> "$work/qualified/README.md"
expect_fail "qualified reference in a self-numbering file" "$work/qualified" 'no such section' 'README.md'

# --- Arm 7: version qualification. `v15 §12.8` names an OLDER design's numbering (the baseline carries
# --- one and passes). The CURRENT version, explicitly qualified, must be checked — a rule that skipped
# --- every `v<n> §` would silence exactly the references that name today's document.
mk_tree "$work/version-qualified"
printf 'Service mode is v33 §99.\n' >> "$work/version-qualified/AGENTS.md"
expect_fail "current-version-qualified reference" "$work/version-qualified" 'no such section'

# --- Arm 8: the vacuity arms. Each would otherwise report a reassuring "ok" over a scan of nothing
# --- (docs/90 G4): eight bans wore a green verdict on an empty tree until a review pass swept it.
mk_tree "$work/no-root-md"
rm -f "$work/no-root-md"/*.md
expect_fail "no root markdown" "$work/no-root-md" 'gate misconfigured'

mk_tree "$work/no-design"
rm -f "$work/no-design/docs/83-fable-design-v33.md"
expect_fail "no design document" "$work/no-design" 'gate misconfigured' 'design'

mk_tree "$work/design-no-headings"
printf '# design v33\n\nNo numbered headings at all.\n' > "$work/design-no-headings/docs/83-fable-design-v33.md"
expect_fail "design document with no numbered headings" "$work/design-no-headings" \
  'gate misconfigured' 'no numbered headings'

# Zero pointers extracted: built from scratch rather than from mk_tree, since mk_tree's whole point is
# to carry pointers. The ledger FILE still has to exist (its roster is checked before the scan runs) —
# it is simply empty of pointers, which is what makes the extractor arm the one that fires.
mkdir -p "$work/no-pointers/docs"
printf '# agents\n\nNo pointers here at all, just §13.\n' > "$work/no-pointers/AGENTS.md"
printf '# design v33\n\n## 13. Invariants\n' > "$work/no-pointers/docs/83-fable-design-v33.md"
printf '# implementation notes\n\nNo pointers here either.\n' \
  > "$work/no-pointers/docs/implementation-notes.md"
expect_fail "zero pointers extracted" "$work/no-pointers" 'gate misconfigured' 'not one'

# Zero section references extracted: same shape on the other arm.
mk_tree "$work/no-refs"
cat > "$work/no-refs/AGENTS.md" <<'EOF'
# agents

Read `docs/implementation-notes.md` and `docs/84-rubric-v7.md`.
EOF
printf '# readme\n\n### 6. Runner\n\nNothing cited.\n' > "$work/no-refs/README.md"
expect_fail "zero section references extracted" "$work/no-refs" 'gate misconfigured' 'reference'

# --- Arm 9: the rosters, both directions.
# An exemption nobody names any more is a widened blind spot.
mk_tree "$work/stale-exempt"
grep -v 'qemu-follow-ups' "$work/stale-exempt/docs/implementation-notes.md" \
  > "$work/stale-exempt/docs/impl.tmp"
mv "$work/stale-exempt/docs/impl.tmp" "$work/stale-exempt/docs/implementation-notes.md"
expect_fail "exemption nobody names" "$work/stale-exempt" 'gate misconfigured' 'qemu-follow-ups'

# An exemption that now RESOLVES is excusing nothing — and would hide the next break of that pointer.
mk_tree "$work/exempt-resolves"
printf '# the write-up, now committed\n' > "$work/exempt-resolves/docs/qemu-follow-ups.md"
expect_fail "exemption that now resolves" "$work/exempt-resolves" 'gate misconfigured' 'now RESOLVES'

# A ledger entry with no file behind it silently widens (or narrows) the retirement fallback.
mk_tree "$work/stale-ledger"
rm -f "$work/stale-ledger/docs/implementation-notes.md"
expect_fail "ledger entry with no file" "$work/stale-ledger" 'gate misconfigured' 'as-built ledger'

# --- Arm 10: a missing ROOT is a misconfiguration, not a clean tree.
expect_fail "nonexistent root" "$work/no-such-root" 'gate misconfigured'

if [[ "$fail" -ne 0 ]]; then
  echo "test-check-docs-pointers: FAIL" >&2
  exit 1
fi
echo "test-check-docs-pointers: ok (all arms driven: every resolving form, the retired-live-path break"
echo "and its correction, the ledger scope both ways, a bad document number, the longer-path guard, a"
echo "missing section and appendix, both qualification rules, five vacuity arms, and three roster arms)"
