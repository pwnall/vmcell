#!/usr/bin/env bash
# Keeps the vmid ceiling ONE law (AGENTS.md "One law, one predicate"; design §17, Networking).
#
# WHY THIS EXISTS. The `≈254`-VM-per-`/16` ceiling had SIX homes, and five of them spelled it as a
# bare literal: `ip_math`'s `% 254`, `VmidAllocator::allocate`'s `seeded_id_order(clock, 254)` and
# `reserve`'s `1..=254`, `CidAllocator`'s `3..=254`, `VmConfigBuilder::build`'s `vmid > 254`, and
# `naming`'s interface-name budget. Nothing tied them together, so the guest CID space had already
# drifted a notch BELOW the address map — 252 concurrent VMs against the map's 254 — which meant
# widening the map alone would have raised the concurrent-VM count by exactly zero. That is the
# defect class this gate exists to stop: not a wrong number, but two numbers that were supposed to
# be one.
#
# The primary fix is STRUCTURAL. Every home now reads `vmcell::net::MAX_VMID` (or
# `vmcell::vmm::MAX_GUEST_CID`, which is *derived* from it), so their drift is a compile error, and
# `net::tests::the_vmid_ceiling_is_one_law_with_five_other_homes` is the in-source roster that
# drives each home end to end. This scanner is that roster's COMPLEMENT, not a second copy of it:
# the roster proves the six known homes agree, and this proves no SEVENTH home was added by
# spelling the number inline — which no compiler and no roster can see.
#
# THE LAW. In production Rust text, outside the law's own home, neither the vmid ceiling nor the
# third-octet space may appear as a bare integer literal. Both numbers are read out of the home
# itself, so this gate follows the law when it moves instead of pinning a stale needle.
#
# What counts as production text, per the in-repo source-scan convention: `//` line comments
# stripped first (prose may cite the number), the file truncated at the first `#[cfg(test)]`, and
# `tests/`, `benches/`, `examples/` and `fuzz/` trees skipped entirely. A test that pins the ceiling
# fails LOUDLY the moment the ceiling moves — nine did in the widening that added this gate — so it
# needs no ban; a production literal is the one that disagrees in silence.
#
# NON-VACUITY. Three ways this scan could pass while proving nothing, each reported as a
# misconfiguration rather than an "ok":
#   * no Rust sources under the roster at all (a move, a reorg, an explicit-path typo);
#   * the law's home, its two consts, or its named delegate gone (a rename);
#   * not one production reference to `MAX_VMID` in the scanned trees (the law stopped being read).
#
# Usage: ban-inline-vmid-ceiling.sh [DIR ...]   (defaults to crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

# The law's home, relative to each scanned root. Named here so a rename is caught (below) rather
# than silently turning this gate into a scan with no exemption and no needle.
law_rel="vmcell/src/net/mod.rs"
# The in-source gate this one complements. If it is gone, the roster half of the law is gone and
# this scanner is no longer a complement — it is the only thing left, which is not what it was
# written to be.
delegate="the_vmid_ceiling_is_one_law_with_five_other_homes"

law_files=()
for d in "${dirs[@]}"; do
  [[ -f "$d/$law_rel" ]] && law_files+=("$d/$law_rel")
done
if [[ ${#law_files[@]} -eq 0 ]]; then
  echo "gate misconfigured: the vmid ceiling's home ($law_rel) is not under: ${dirs[*]}"
  echo "Without it this gate has no needle to read and no home to exempt. If net/mod.rs moved,"
  echo "update scripts/ban-inline-vmid-ceiling.sh — do not delete the scan."
  exit 1
fi

# Read the two numbers OUT OF the law, so the needle follows it.
law="${law_files[0]}"
max_vmid="$(sed -n 's/^pub const MAX_VMID: u32 = \([0-9_]*\);.*/\1/p' "$law" | tr -d _ | head -1)"
octet_space="$(sed -n 's/^const THIRD_OCTET_SPACE: u32 = \([0-9_]*\);.*/\1/p' "$law" | tr -d _ | head -1)"
if [[ -z "$max_vmid" || -z "$octet_space" ]]; then
  echo "gate misconfigured: could not read MAX_VMID / THIRD_OCTET_SPACE out of $law"
  echo "(got MAX_VMID='$max_vmid', THIRD_OCTET_SPACE='$octet_space'). One of them was renamed or"
  echo "reshaped; update this scanner's sed patterns — do not delete the scan."
  exit 1
fi
if ! grep -q "$delegate" "$law"; then
  echo "gate misconfigured: the in-source roster this gate complements ($delegate) is gone from $law"
  echo "This scanner only proves no NEW site spells the ceiling inline; the roster is what proves"
  echo "the known homes agree. Restore or rename-and-update it — do not delete the scan."
  exit 1
fi

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' \
      -not -path '*/tests/*' -not -path '*/benches/*' \
      -not -path '*/examples/*' -not -path '*/fuzz/*' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources
# is to have been pointed at the wrong place (docs/90 G4).
if [[ ${#files[@]} -eq 0 ]]; then
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
fi

violations=""
refs_seen=0

for f in "${files[@]}"; do
  # The law's own home is where both numbers legitimately live.
  skip=0
  for l in "${law_files[@]}"; do
    [[ "$f" == "$l" ]] && skip=1
  done

  result="$(awk -v FN="$f" -v SKIP="$skip" -v A="$max_vmid" -v B="$octet_space" '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      if (index(code, "#[cfg(test)]") > 0) { nextfile }
      if (SKIP == 1) next
      # Non-vacuity: production text OUTSIDE the law home that actually READS the law. The home
      # always names its own const, so counting it would make this arm unfalsifiable — the exact
      # "channel whose two ends default to the same value" shape (AGENTS.md rule 4). The
      # no-reference leg of the self-test is what keeps it honest.
      # (No apostrophes below: this awk program is single-quoted shell text.)
      if (code ~ /(^|[^0-9A-Za-z_])MAX_VMID([^0-9A-Za-z_]|$)/) refs++
      # A bare integer literal equal to either number. The leading class excludes a longer number
      # (`12549`), an identifier tail (`CID_254`) and a decimal tail (`1.254`); the trailing class
      # excludes a longer number and an identifier head.
      pat = "(^|[^0-9A-Za-z_.])(" A "|" B ")([^0-9A-Za-z_]|$)"
      if (code ~ pat) {
        gsub(/^[ \t]+|[ \t]+$/, "", code)
        print "LITERAL\t" FN ":" FNR "\t" code
      }
    }
    END { if (refs > 0) print "REFS\t" refs }
  ' "$f")"

  [[ -z "$result" ]] && continue
  while IFS=$'\t' read -r kind a b; do
    case "$kind" in
      REFS) refs_seen=$((refs_seen + a)) ;;
      LITERAL) violations+="  $a: $b"$'\n' ;;
    esac
  done <<<"$result"
done

if [[ $refs_seen -eq 0 ]]; then
  echo "gate misconfigured: no production reference to MAX_VMID outside its own home, under:"
  echo "${dirs[*]}"
  echo "Every home of the vmid ceiling is supposed to READ the law. If not one does, either the"
  echo "const was renamed or the scan is pointed at the wrong tree — a run that matches nothing"
  echo "reports 'ok' while proving nothing."
  exit 1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "The vmid ceiling ($max_vmid) or the third-octet space ($octet_space) is spelled as a bare"
  echo "literal in production text. Both are ONE law with one home: read \`vmcell::net::MAX_VMID\`"
  echo "(or \`vmcell::vmm::MAX_GUEST_CID\`, derived from it) instead. Six homes each carrying their"
  echo "own copy is what let the guest CID space drift a notch below the address map — 252"
  echo "concurrent VMs against a map that admitted 254 (design §17, Networking):"
  printf '%s' "$violations"
  echo "If this site legitimately needs the number for something else entirely, it needs its own"
  echo "named const with its own rationale — not this one's value."
  exit 1
fi

echo "ok: no inline vmid ceiling ($max_vmid) or third-octet space ($octet_space) in production"
echo "text; $refs_seen production reference(s) read the law (scanned: ${dirs[*]})"
