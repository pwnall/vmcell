#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-agent-ip-shellout.sh (AGENT-4 / TEST-5).
# Builds a fixture tree and asserts the scanner flags exactly the `ip` shell-out cases and
# leaves the legitimate cases alone: deleting the `"ip"` / `/ip` patterns from the scanner
# (its inverse) makes the MUST-flag fixtures go un-flagged and reddens this test.
# The multi-word shell-string fixtures below cover the OTHER half of the scanner (M-BIN-3's
# `"ip ` / `"…/ip ` branches) for the same reason PRIV-4 added the bare-Mutex/OnceLock fixtures to
# test-ban-global-state.sh: until they existed every MUST-flag case was a bare `"ip"` argv literal,
# so deleting both multi-word branches from the scanner left every expectation intact — half a gate
# that could not fail.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-agent-ip-shellout.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src"

# --- MUST be flagged: real `ip` shell-outs -----------------------------------------------
printf 'fn boot() { let mut c = std::process::Command::new("ip"); c.arg("link"); }\n' > "$work/src/spawn_ip.rs"
printf 'fn restore() { cmd.args(["ip", "addr", "flush"]); }\n' > "$work/src/arg_ip.rs"
printf 'fn boot() { std::process::Command::new("/sbin/ip"); }\n' > "$work/src/path_ip.rs"
# The multi-word shell-string forms (M-BIN-3). Neither contains `"ip"` nor a quoted path ENDING in
# `/ip`, so each is flagged only by its own scanner branch — delete `"ip ` and sh_cmd_ip.rs goes
# un-flagged; delete `"[^"]*\/ip ` and sh_cmd_slash_ip.rs does.
printf 'fn boot() { Command::new("sh").arg("-c").arg("ip link set eth0 up"); }\n' > "$work/src/sh_cmd_ip.rs"
printf 'fn boot() { Command::new("sh").arg("-c").arg("/sbin/ip addr add 10.0.0.2/30 dev eth0"); }\n' > "$work/src/sh_cmd_slash_ip.rs"

# --- MUST NOT be flagged: legitimate steward code + false-positive guards -------------------
# The steward's real, legitimate dynamic exec of a host-supplied argv[0].
printf 'fn exec(req: &Req) { let mut c = Command::new(&req.argv[0]); }\n' > "$work/src/dynamic_argv.rs"
# A comment mentioning "ip" must be stripped before analysis (no false positive).
printf '// the steward never runs "ip"; the kernel ip= cmdline configures eth0.\nfn f() {}\n' > "$work/src/comment_ip.rs"
# Substrings that merely contain the letters ip must not trip the exact-literal match.
printf 'fn f() { let _ = ["skip", "gossip", "zip"]; let _ = "recipient"; }\n' > "$work/src/substrings.rs"
# A different binary is fine.
printf 'fn f() { std::process::Command::new("curl"); }\n' > "$work/src/other_bin.rs"

set +e
out="$("$ban" "$work/src" 2>&1)"
rc=$?
set -e

fail=0
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }

if [[ $rc -ne 1 ]]; then echo "FAIL: scanner exit code = $rc, expected 1 (violations present)"; fail=1; fi
expect_flag spawn_ip.rs
expect_flag arg_ip.rs
expect_flag path_ip.rs
expect_flag sh_cmd_ip.rs
expect_flag sh_cmd_slash_ip.rs
expect_clean dynamic_argv.rs
expect_clean comment_ip.rs
expect_clean substrings.rs
expect_clean other_bin.rs

# --- The vacuous-scan legs: nothing to scan is a MISCONFIGURATION, not a clean steward ------------
# G4: both arms used to exit 0 — an existing-but-Rust-less directory printed "ok: no Rust sources
# under …", and an explicitly-passed missing directory printed "ok: no steward source directory …".
# Either one turns a steward rename/move (or a typo) into a green gate that scanned zero bytes.
# Restoring either permissive arm reddens the matching leg.
check_misconfig() { # check_misconfig <label> <path>
  local label="$1" path="$2" o r
  set +e
  o="$("$ban" "$path" 2>&1)"
  r=$?
  set -e
  if [[ $r -ne 1 ]]; then echo "FAIL [$label]: exit code = $r, expected 1"; fail=1; fi
  if ! grep -q 'gate misconfigured' <<<"$o"; then
    echo "FAIL [$label]: expected 'gate misconfigured', got:"; printf '%s\n' "$o"; fail=1
  fi
}
mkdir -p "$work/nosrc"
printf 'not rust\n' > "$work/nosrc/README.md"
check_misconfig "directory with no Rust sources" "$work/nosrc"
check_misconfig "explicitly-passed missing directory" "$work/does-not-exist"

if [[ $fail -ne 0 ]]; then
  echo "---- scanner output ----"; printf '%s\n' "$out"
  echo "ban-agent-ip-shellout self-test FAILED"
  exit 1
fi
echo "ok: ban-agent-ip-shellout self-test passed"
