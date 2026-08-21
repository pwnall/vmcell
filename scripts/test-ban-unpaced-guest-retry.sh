#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-unpaced-guest-retry.sh (design §3.5).
#
# A ban script that cannot go red is theater (AGENTS.md rule 2), and a source scan's characteristic
# failure is passing VACUOUSLY. Every arm is driven here:
#
#   * the exact regression — `sleep(Duration::from_millis(200))` back at the restart call site —
#     is flagged                                                        → deleting the pattern reddens;
#   * a bare number (`sleep(200)`) is flagged too                       → a `Duration::`-only needle reddens;
#   * a rustfmt-wrapped literal sleep is still seen whole               → a line-at-a-time scan reddens;
#   * `sleep(delay)` / `sleep(pause)` are NOT flagged                   → an over-broad grep reddens;
#   * a literal in a comment, or under `#[cfg(test)]`, is NOT flagged   → over-broad matching reddens;
#   * a tree whose production text sleeps nowhere is a misconfiguration → the pacing-deleted arm reddens;
#   * a tree with no `fn retry_backoff(` is the same                    → the missing-delegate arm reddens;
#   * a tree with no Rust sources at all is the same                    → restoring a permissive
#     empty-scan arm reddens this leg (docs/90 G4).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-unpaced-guest-retry.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the spellings the guest-tools binary actually ships.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell-guest-tools/src"
  {
    printf 'const MINI_INIT_RESTART_BACKOFF_BASE: Duration = Duration::from_millis(250);\n'
    printf 'fn retry_backoff(base: Duration, ceiling: Duration, consecutive: u32) -> Duration {\n'
    printf '    let doublings = consecutive.saturating_sub(1).min(u32::BITS - 1);\n'
    printf '    base.saturating_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX)).min(ceiling)\n}\n'
    # The restart loop: BOTH arms take their pause from the predicate.
    printf '// The pre-fix arm slept a literal Duration::from_millis(200) right here.\n'
    printf 'fn mini_init_forever(p: &str) -> i32 {\n'
    printf '    loop {\n'
    printf '        match mini_init_restart_after(started.elapsed(), consecutive_failures) {\n'
    printf '            MiniInitRestart::After { delay, consecutive } => {\n'
    printf '                consecutive_failures = consecutive;\n'
    printf '                std::thread::sleep(delay);\n'
    printf '            }\n'
    printf '            MiniInitRestart::CapTripped => return mini_init_power_off(WHY),\n'
    printf '        }\n'
    printf '    }\n}\n'
    # The accept loops: the same shape, a different pair of constants.
    printf 'fn serve_vsock(port: u32) -> i32 {\n'
    printf '    let (pause, log) = accept_error_pacing(consecutive_errors);\n'
    printf '    std::thread::sleep(pause);\n'
    printf '    0\n}\n'
    # A unit test may sleep whatever keeps it fast.
    printf '#[cfg(test)]\nmod tests {\n'
    printf '    fn t() { std::thread::sleep(Duration::from_millis(5)); }\n'
    printf '}\n'
  } > "$root/vmcell-guest-tools/src/main.rs"
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1/vmcell-guest-tools" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the clean tree MUST pass (the positive control) --------------------------------------
# It also proves the two NOT-flagged spellings: `sleep(delay)` / `sleep(pause)`, the literal inside
# the `//` comment, and the one under `#[cfg(test)]`.
mk_clean_tree "$work/good"
run_ban "$work/good"
expect_rc 0 "every pause comes from the pacing law"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
[[ $fail -ne 0 ]] && dump "case 1"

# --- Case 2: the exact regression, and its bare-number twin ---------------------------------------
mk_clean_tree "$work/bad"
mkdir -p "$work/bad/vmcell-guest-tools/src"
{
  printf 'fn spawn_arm() {\n'
  printf '    eprintln!("mini-init: could not start {program}: {e}");\n'
  printf '    std::thread::sleep(Duration::from_millis(200));\n'
  printf '    std::thread::sleep(200);\n'
  # rustfmt-wrapped: a line-at-a-time scan would miss this one.
  printf '    std::thread::sleep(\n'
  printf '        Duration::from_secs(1),\n'
  printf '    );\n'
  printf '}\n'
} > "$work/bad/vmcell-guest-tools/src/restart.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "a pause built at the call site"
expect_flag 'restart.rs'
expect_flag 'from_millis(200)'
expect_flag 'from_secs(1)'
# The legitimate file stays clean.
expect_clean 'main.rs'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: production text that sleeps nowhere is a misconfiguration, not a pass -----------------
# This is the arm that catches the pacing being DELETED rather than re-spelled: a restart loop with
# no sleep at all is the original defect, and a scan hunting for literals would report "ok".
mkdir -p "$work/nosleep/vmcell-guest-tools/src"
{
  printf 'fn retry_backoff(b: Duration, c: Duration, n: u32) -> Duration { b }\n'
  printf 'fn mini_init_forever() { loop { let _ = spawn(); } }\n'
  printf '#[cfg(test)]\nmod tests { fn t() { std::thread::sleep(Duration::from_millis(5)); } }\n'
} > "$work/nosleep/vmcell-guest-tools/src/main.rs"
run_ban "$work/nosleep"
before=$fail
expect_rc 1 "no sleep in production text"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: the delegate is gone → misconfigured -------------------------------------------------
# The scan holds the CALL SITES; the curve is held by the unit tests over `retry_backoff`. If that
# law is renamed or deleted, this scan must say so rather than keep guarding call sites of nothing.
mkdir -p "$work/nodelegate/vmcell-guest-tools/src"
{
  printf 'fn mini_init_forever() { loop { std::thread::sleep(delay); } }\n'
} > "$work/nodelegate/vmcell-guest-tools/src/main.rs"
run_ban "$work/nodelegate"
before=$fail
expect_rc 1 "the delegate law is absent"
expect_flag 'retry_backoff'
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a tree with no Rust at all is the same misconfiguration ------------------------------
# G4: a permissive empty-scan arm would print "ok" having opened no file, short-circuiting cases 3
# and 4. Restoring that arm reddens this leg.
mkdir -p "$work/nosrc/vmcell-guest-tools/src"
printf 'not rust\n' > "$work/nosrc/vmcell-guest-tools/src/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 5"

if [[ $fail -ne 0 ]]; then
  echo "ban-unpaced-guest-retry self-test FAILED"
  exit 1
fi
echo "ok: ban-unpaced-guest-retry self-test passed"
