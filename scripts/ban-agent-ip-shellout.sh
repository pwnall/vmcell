#!/usr/bin/env bash
# Enforces the zero-netlink / zero-`ip`-in-PID-1 invariant (design §4.3, §9.2; AGENTS.md
# "Zero-netlink in PID 1") as a POSITIVE structural gate.
#
# The guest agent (`vmcell-guest-agent`) configures the network purely via the kernel `ip=`
# cmdline — it runs NO `ip link/addr/route`, in-process OR by shelling out. The existing
# lean-tree `cargo tree` ban catches a regression that pulls in a netlink CRATE, but a
# regression that simply SHELLS OUT to the distro `ip` binary (adding no dependency) at
# boot/restore would pass every other gate (AGENT-4 / TEST-5). This scanner closes that hole:
# it fails if any agent source spawns / references the `ip` binary.
#
# What it flags (line comments stripped first, so prose mentioning `"ip"` is not a false
# positive):
#   * the exact string literal `"ip"`            (e.g. `Command::new("ip")`, `.arg("ip")`,
#                                                  `vec!["ip"]` — the argv token that runs ip)
#   * a quoted path ending in `/ip`              (e.g. `Command::new("/sbin/ip")`)
# It deliberately does NOT match a dynamic exec of a host-supplied argv (the agent's legitimate
# `Command::new(&req.argv[0])`), nor substrings like `"skip"`/`"gossip"`/`"zip"`.
#
# NOTE ON SCOPE: this bans `ip` ONLY inside the guest AGENT. `vmcell-guest-tools` legitimately
# *implements* `ip` (the erofs helper, §5.3), so it is out of scope by construction.
#
# Usage: ban-agent-ip-shellout.sh [DIR]   (defaults to crates/vmcell-guest-agent/src)
set -euo pipefail

dir="${1:-crates/vmcell-guest-agent/src}"
if [[ ! -d "$dir" ]]; then
  echo "ok: no agent source directory at $dir (nothing to scan)"
  exit 0
fi

mapfile -d '' -t files < <(find "$dir" -type f -name '*.rs' -print0)
[[ ${#files[@]} -eq 0 ]] && { echo "ok: no Rust sources under $dir"; exit 0; }

violations=""
for f in "${files[@]}"; do
  out="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)                 # drop the line comment before matching
      # exact `"ip"` argv literal, or a quoted path ending in `/ip`.
      if (code ~ /"ip"/ || code ~ /"[^"]*\/ip"/) {
        print FN ":" FNR ": " $0
      }
    }
  ' "$f")"
  [[ -n "$out" ]] && violations+="$out"$'\n'
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "Forbidden \`ip\` invocation in the guest agent — the agent must do ZERO ip/netlink"
  echo "(kernel \`ip=\` cmdline configures eth0; design §4.3/§9.2). Remove the shell-out:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi
echo "ok: guest agent invokes no \`ip\` binary (scanned: $dir)"
