#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-inline-kernel-fault-signature.sh (E1).
#
# A ban script that cannot go red is theater (AGENTS.md rule 2), and a source scan's characteristic
# failure is passing VACUOUSLY. Every arm is driven here:
#
#   * the clean tree — callers going through `classify_serial_fault` — passes        → an over-broad
#     scan reddens this;
#   * a re-spelled panic literal in another crate's `src` is flagged                 → deleting the
#     scan reddens;
#   * a re-spelled KASAN/oops/lockdep literal is flagged too, and the needle is
#     read OUT of the owner file, so a needle ADDED to the law is banned from that
#     moment on with no edit here                                                    → a scanner
#     carrying its own copy of the needles reddens this leg;
#   * a literal in a `//` comment, and one after `#[cfg(test)]`, are NOT flagged     → over-broad
#     matching reddens;
#   * a canned kernel log under `tests/` is NOT flagged                              → a roster that
#     forgot the `*/src/*` filter reddens (the fixtures the classifier is TESTED on are real kernel
#     text by necessity);
#   * an owner file that is gone is a misconfiguration, not "ok"                     → the
#     names-its-delegate arm;
#   * an owner file whose `*_SIGNATURES` consts are gone is a misconfiguration       → the
#     zero-needle arm: a scan with no needle matches nothing;
#   * a rustfmt-COLLAPSED const's literals are needles too, and an ordinary literal
#     outside every array is not                                                     → a
#     line-at-a-time extractor reddens this (it shipped in this gate's first cut and cost 4 of 15
#     needles while the verdict stayed green);
#   * a tree with nothing to scan is the same misconfiguration, in both its shapes  → the empty-tree
#     leg (docs/90 G4): nothing at all, and the law present with nothing beside it. Restoring a
#     permissive empty-scan arm reddens this.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-inline-kernel-fault-signature.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The owner file, in the shape the extractor reads: `*_SIGNATURES` consts, one literal per line.
mk_owner() {
  root="$1"
  mkdir -p "$root/vmcell/src/vmm"
  # BOTH layouts, deliberately: rustfmt collapses a short array onto ONE line and leaves a long
  # one at one literal per line, and the real owner file carries both shapes at once. A
  # line-at-a-time extractor silently drops every literal in a collapsed const — and then runs past
  # the array picking up unrelated strings — which is how the first cut of this gate guarded four of
  # its fifteen needles while printing "ok".
  {
    printf '/// Not a const: the marker "_SIGNATURES: &[&str] = &[" in prose must open nothing.\n'
    printf 'const KASAN_SIGNATURES: &[&str] = &["BUG: KASAN:"];\n'
    printf 'const OOPS_SIGNATURES: &[&str] = &[\n'
    printf '    "Oops: ",\n'
    printf '    "BUG: kernel NULL pointer dereference",\n'
    printf '];\n'
    printf 'const PANIC_SIGNATURES: &[&str] = &["Kernel panic", "panicked at"];\n'
    printf 'const LOCKDEP_SIGNATURES: &[&str] = &[\n'
    printf '    "possible circular locking dependency detected",\n'
    printf '];\n'
    printf '/// A DECOY: an ordinary literal outside every array must never become a needle.\n'
    printf 'const NO_CONSOLE_EVIDENCE: &str = "(no console text available)";\n'
    printf 'pub fn classify_serial_fault(log: &str) -> Option<SerialFault> { None }\n'
  } > "$root/vmcell/src/vmm/fault.rs"
}

# The clean baseline: the legitimate spellings the tree actually ships.
mk_clean_tree() {
  root="$1"
  mk_owner "$root"
  mkdir -p "$root/vmcell/src/steward" "$root/vmcell-artifact-validator/src" "$root/vmcell/tests"
  # A caller asks the law instead of re-spelling it.
  {
    printf 'fn expiry(serial: &dyn SerialLog) -> Error {\n'
    printf '    match serial.classify_fault() {\n'
    printf '        Some(f) => f.into_error(STEWARD_HANDSHAKE_OP),\n'
    printf '        None => Error::Timeout("Steward connection timed out".into()),\n'
    printf '    }\n}\n'
  } > "$root/vmcell/src/steward/mod.rs"
  # The validator: its clause literals are its own, its canned logs are under `#[cfg(test)]`, and
  # its PROSE mentions the host-owned literal — all three must stay clean.
  {
    printf '// The residual class deliberately does NOT claim "Kernel panic", which the host owns.\n'
    printf 'const ROOT_FS_MOUNT_SIGNATURES: &[&str] = &["No filesystem could mount root"];\n'
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    const NO_EROFS: &str = "[ 0.4] Kernel panic - not syncing: VFS: Unable to mount root fs";\n'
    printf '}\n'
  } > "$root/vmcell-artifact-validator/src/classify.rs"
  # The classifier's OWN gate: real captured kernel logs, necessarily verbatim, under tests/.
  {
    printf 'const OOPS_NULL_DEREF: &str = "[ 3.1] BUG: kernel NULL pointer dereference, address: 0";\n'
    printf 'const REAL_KERNEL_PANIC: &str = "[ 0.1] Kernel panic - not syncing: no init";\n'
  } > "$root/vmcell/tests/serial_fault.rs"
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q -- "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q -- "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the clean tree MUST pass (the positive control) --------------------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
expect_rc 0 "callers going through the law"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
expect_clean 'classify.rs'
expect_clean 'tests/serial_fault.rs'
[[ $fail -ne 0 ]] && dump "case 1"

# --- Case 2: the exact regression — the panic literals re-spelled in production ------------------
mk_clean_tree "$work/bad"
mkdir -p "$work/bad/vmcell-daemon/src"
{
  printf 'fn wedged(log: &str) -> bool {\n'
  printf '    log.contains("Kernel panic") || log.contains("panicked at")\n'
  printf '}\n'
} > "$work/bad/vmcell-daemon/src/health.rs"
# …and the classes the boolean detector never covered, which is the whole point of the law.
mkdir -p "$work/bad/vmcell-bench/src"
{
  printf 'fn instrumented(log: &str) -> bool {\n'
  printf '    log.contains("BUG: KASAN:")\n'
  printf '        || log.contains("possible circular locking dependency detected")\n'
  printf '}\n'
} > "$work/bad/vmcell-bench/src/lib.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "inline console signatures"
expect_flag 'vmcell-daemon/src/health.rs'
expect_flag 'vmcell-bench/src/lib.rs'
expect_flag 'Kernel panic'
expect_flag 'BUG: KASAN:'
expect_clean 'classify.rs'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: the needles come from the LAW, not from this script ----------------------------------
# Add a needle to the owner file only. A scanner carrying its own copy stays green here.
mk_clean_tree "$work/newneedle"
python3 - "$work/newneedle/vmcell/src/vmm/fault.rs" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace('&["BUG: KASAN:"]', '&["BUG: KASAN:", "BUG: KFENCE:"]', 1)
open(p, 'w').write(s)
PY
mkdir -p "$work/newneedle/vmcell-cli/src"
printf 'fn f(log: &str) -> bool { log.contains("BUG: KFENCE:") }\n' > "$work/newneedle/vmcell-cli/src/main.rs"
run_ban "$work/newneedle"
before=$fail
expect_rc 1 "a needle added to the law is banned elsewhere from that moment on"
expect_flag 'BUG: KFENCE:'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: prose and test text are NOT production text -----------------------------------------
mk_clean_tree "$work/prose"
mkdir -p "$work/prose/vmcell-qemu/src"
{
  printf '/// Panic capture works at every level: the host matches the Kernel panic marker.\n'
  printf 'pub fn note() {}\n'
  printf '#[cfg(test)]\nmod tests {\n'
  printf '    const CANNED: &str = "[ 0.1] Oops: 0000 [#1] PREEMPT SMP";\n'
  printf '}\n'
} > "$work/prose/vmcell-qemu/src/lib.rs"
run_ban "$work/prose"
before=$fail
expect_rc 0 "a rustdoc mention and a canned log under #[cfg(test)]"
expect_clean 'vmcell-qemu/src/lib.rs'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: the owner file is GONE — names its delegate ------------------------------------------
mk_clean_tree "$work/noowner"
rm -f "$work/noowner/vmcell/src/vmm/fault.rs"
run_ban "$work/noowner"
before=$fail
expect_rc 1 "the law's home is missing"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: the owner file exists but carries NO signature consts --------------------------------
# A scan with zero needles matches nothing and would otherwise print a reassuring "ok".
mk_clean_tree "$work/noneedles"
printf 'pub fn classify_serial_fault(_log: &str) -> Option<SerialFault> { None }\n' \
  > "$work/noneedles/vmcell/src/vmm/fault.rs"
run_ban "$work/noneedles"
before=$fail
expect_rc 1 "the law carries no needles"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 6b: a COLLAPSED const's literals are needles too, and a decoy literal is not -----------
# The regression that shipped in this gate's first cut. `KASAN_SIGNATURES` and `PANIC_SIGNATURES` are
# one-liners in the fixture (as rustfmt writes them), so a line-at-a-time extractor loses all three
# of their literals; the same bug then leaves the block "open" and turns the file's ordinary strings
# into needles. Both halves are asserted here.
mk_clean_tree "$work/collapsed"
mkdir -p "$work/collapsed/vmcell-broker/src"
{
  printf 'fn a(log: &str) -> bool { log.contains("BUG: KASAN:") }\n'
  printf 'fn b(log: &str) -> bool { log.contains("panicked at") }\n'
} > "$work/collapsed/vmcell-broker/src/lib.rs"
# The decoy: the SAME literal the owner file holds outside every array. Legitimate everywhere.
mkdir -p "$work/collapsed/vmcell-daemon-client/src"
printf 'const MISSING: &str = "(no console text available)";\n' \
  > "$work/collapsed/vmcell-daemon-client/src/lib.rs"
run_ban "$work/collapsed"
before=$fail
expect_rc 1 "literals from a collapsed const"
expect_flag 'BUG: KASAN:'
expect_flag 'panicked at'
expect_clean 'vmcell-daemon-client'
[[ $fail -ne $before ]] && dump "case 6b"

# --- Case 7: a tree with nothing to scan is a misconfiguration, not "ok" --------------------------
# docs/90 G4: eight bans wore a green verdict on an empty tree. Two shapes, because the owner file is
# itself a `*/src/*` source and so the roster is never literally empty here.
#   7a — nothing at all: the "names its delegate" arm answers first.
mkdir -p "$work/emptytree"
run_ban "$work/emptytree"
before=$fail
expect_rc 1 "an empty tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7a"

#   7b — the law is there and NOTHING ELSE is: the scan opened only the file it excludes, so it could
#   not have flagged anything. Restoring a permissive `ok` on this shape reddens this leg.
mk_owner "$work/onlyowner"
run_ban "$work/onlyowner"
before=$fail
expect_rc 1 "only the law itself, nothing to scan"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7b"

if [[ $fail -ne 0 ]]; then
  echo "ban-inline-kernel-fault-signature self-test FAILED"
  exit 1
fi
echo "ok: ban-inline-kernel-fault-signature self-test passed"
