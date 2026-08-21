#!/usr/bin/env bash
# Keeps "what does a guest-kernel fault look like on the console" in ONE place
# (AGENTS.md "One law, one predicate"; design §5.4, The guest-kernel contract and the bootstrap seed).
#
# WHY THIS EXISTS. The host had TWO independent readers of a guest's serial console and the split had
# already started to cost: `vmcell::vmm::SerialLog::contains_panic` carried its own three panic
# literals inline, while `vmcell-artifact-validator`'s `classify` carried the §5.4 clause literals —
# and the validator's source records, in a comment, that it deliberately does NOT claim
# `Kernel panic` because the host owns that literal. That boundary is correct and is exactly the
# kind of agreement nothing enforces: a third site spelling `log.contains("Kernel panic")` compiles,
# passes review because it looks locally reasonable, and then diverges the first time a needle is
# added or corrected. Every duplicated law in this tree has diverged.
#
# THE LAW. In production Rust text, the console signatures live in
# `crates/vmcell/src/vmm/fault.rs` and nowhere else. A caller asks
# `vmcell::vmm::fault::classify_serial_fault` / `log_reports_panic`, or reads the needles out of
# `GuestFault::signatures()`; it never writes the literal itself.
#
# ITS NEEDLES ARE READ OUT OF THE LAW, NOT COPIED HERE. This script extracts them from the
# `*_SIGNATURES` consts of the owner file at run time, so a needle added there is banned elsewhere
# from that moment on, and this gate can never disagree with the code it guards. That also NAMES ITS
# DELEGATE: if the owner file or its consts are gone, this exits non-zero rather than silently
# guarding nothing.
#
# WHAT COUNTS AS PRODUCTION TEXT, per the in-repo source-scan convention
# (`ban-readiness-timeout-literal.sh`): only `*/src/**/*.rs` is scanned; `//` line comments are
# stripped first — a rustdoc line or a `//` note quoting a signature is prose, and prose cannot
# drift behavior — and each file is truncated at its first `#[cfg(test)]`. Both exclusions exist for
# the same reason: a canned kernel log is a test FIXTURE, which is the point of the tests rather
# than a second copy of the law. `crates/vmcell/tests/serial_fault.rs` (the real captured consoles)
# and the validator's in-`#[cfg(test)]` canned logs are exactly that, and a gate that forbade them
# would be demanding the classifier be tested on text that is not what kernels print.
#
# NON-VACUITY, three ways, and the third one is the subtle one. (1) The owner file must be found at
# all — that is the "names its delegate" arm: if the law moved, this stops rather than silently
# guarding nothing. (2) At least one needle must be extracted, because a scan with no needle matches
# nothing and would print a reassuring `ok:` (docs/90 G4). (3) At least one production source
# BESIDES the owner must be scanned — the owner is itself a `*/src/*` file, so a bare "zero files"
# test could never fire here and would be dead code wearing a guard's clothes; the reachable, honest
# condition is that the scan opened something it can actually flag. Each exits 1 with
# `gate misconfigured`.
#
# Usage: ban-inline-kernel-fault-signature.sh [DIR ...]   (defaults to crates/)
# The owner file is resolved as <FIRST DIR>/vmcell/src/vmm/fault.rs, so the self-test can point the
# whole gate at a fixture tree.
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

owner="${dirs[0]}/vmcell/src/vmm/fault.rs"
if [[ ! -f "$owner" ]]; then
  echo "gate misconfigured: the signature law is not at '$owner'."
  echo "This gate reads its needles OUT of that file's \`*_SIGNATURES\` consts. If"
  echo "\`vmcell::vmm::fault\` moved, point this script at its new home — do not delete the scan."
  exit 1
fi

# The needles, straight out of the law. Each const is `<NAME>_SIGNATURES: &[&str] = &[` … `];`.
# The extractor JOINS the file before matching, because rustfmt decides per-const whether the array
# fits on one line: at the time of writing `KASAN_SIGNATURES` and `PANIC_SIGNATURES` are collapsed
# onto a single line and the other two are one-literal-per-line. A line-at-a-time extractor silently
# lost every literal in a collapsed const and then ran off the end of the array picking up unrelated
# strings — a gate that reports `ok` while guarding a quarter of the law, which is exactly the
# vacuity class this repo keeps dying of. `//` comments are stripped first so prose that quotes the
# const's shape cannot open a bogus block.
mapfile -t needles < <(
  awk '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      joined = joined " " code
    }
    END {
      marker = "_SIGNATURES: &[&str] = &["
      rest = joined
      while ((at = index(rest, marker)) > 0) {
        rest = substr(rest, at + length(marker))
        end = index(rest, "];")
        block = (end > 0) ? substr(rest, 1, end - 1) : rest
        while (match(block, /"[^"]*"/)) {
          lit = substr(block, RSTART + 1, RLENGTH - 2)
          if (length(lit) > 0) print lit
          block = substr(block, RSTART + RLENGTH)
        }
        if (end > 0) rest = substr(rest, end + 2); else rest = ""
      }
    }
  ' "$owner"
)

if [[ ${#needles[@]} -eq 0 ]]; then
  echo "gate misconfigured: no \`*_SIGNATURES\` console needles found in '$owner'."
  echo "Either the consts were renamed/reshaped, or the law was deleted. A scan with no needle"
  echo "matches nothing and would print 'ok' while proving nothing."
  exit 1
fi

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -path '*/src/*' -print0
  done
)
violations=""
scanned=0
for f in "${files[@]}"; do
  # The law's own home is where the literals belong.
  [[ "$f" == "$owner" ]] && continue
  scanned=$((scanned + 1))

  hits="$(
    NEEDLES="$(printf '%s\n' "${needles[@]}")" awk -v FN="$f" '
      BEGIN {
        n = split(ENVIRON["NEEDLES"], arr, "\n")
        for (i = 1; i <= n; i++) if (length(arr[i]) > 0) needle[++cnt] = arr[i]
      }
      {
        code = $0
        sub(/\/\/.*/, "", code)                       # prose cannot drift behavior
        if (index(code, "#[cfg(test)]") > 0) { nextfile }  # fixtures are not a second law
        for (i = 1; i <= cnt; i++) {
          if (index(code, needle[i]) > 0) {
            printf "  %s:%d: %s\n", FN, NR, needle[i]
            break
          }
        }
      }
    ' "$f"
  )"
  [[ -n "$hits" ]] && violations+="$hits"$'\n'
done

# The reachable vacuity condition (see the header): the owner is itself a `*/src/*` file, so the
# roster is never literally empty — what CAN happen is that it holds nothing else, i.e. the scan
# opened only the one file it excludes and could not have flagged anything.
if [[ $scanned -eq 0 ]]; then
  echo "gate misconfigured: the only production source under '${dirs[*]}' is the law's own file."
  echo "The scan opened nothing it could flag, so an 'ok' here would prove nothing — every"
  echo "source-scanning gate dies this way (docs/90 G4). Point it at the crate trees."
  exit 1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A guest-kernel console signature is spelled inline. There is ONE recognizer:"
  echo "  vmcell::vmm::fault::classify_serial_fault  — which fault does this console prove?"
  echo "  vmcell::vmm::fault::log_reports_panic      — has the guest kernel stopped?"
  echo "  vmcell::vmm::fault::GuestFault::signatures — the needles themselves, if you need them."
  echo "Call one of those instead of re-spelling the literal (the boolean panic detector carried its"
  echo "own copy of three of these until E1 folded it in):"
  printf '%s' "$violations"
  exit 1
fi

echo "ok: ${#needles[@]} console signature(s) live only in $owner"
echo "(scanned $scanned production Rust source(s) beside it, under: ${dirs[*]})"
