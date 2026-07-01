#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-agent-ip-shellout.sh (AGENT-4 / TEST-5).
# Builds a fixture tree and asserts the scanner flags exactly the `ip` shell-out cases and
# leaves the legitimate cases alone: deleting the `"ip"` / `/ip` patterns from the scanner
# (its inverse) makes the MUST-flag fixtures go un-flagged and reddens this test.
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

# --- MUST NOT be flagged: legitimate agent code + false-positive guards -------------------
# The agent's real, legitimate dynamic exec of a host-supplied argv[0].
printf 'fn exec(req: &Req) { let mut c = Command::new(&req.argv[0]); }\n' > "$work/src/dynamic_argv.rs"
# A comment mentioning "ip" must be stripped before analysis (no false positive).
printf '// the agent never runs "ip"; the kernel ip= cmdline configures eth0.\nfn f() {}\n' > "$work/src/comment_ip.rs"
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
expect_clean dynamic_argv.rs
expect_clean comment_ip.rs
expect_clean substrings.rs
expect_clean other_bin.rs

if [[ $fail -ne 0 ]]; then
  echo "---- scanner output ----"; printf '%s\n' "$out"
  echo "ban-agent-ip-shellout self-test FAILED"
  exit 1
fi
echo "ok: ban-agent-ip-shellout self-test passed"
