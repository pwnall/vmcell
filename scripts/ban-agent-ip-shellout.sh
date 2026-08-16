#!/usr/bin/env bash
# Enforces the zero-netlink / zero-`ip`-in-PID-1 invariant (design §4.3, §9.2; AGENTS.md
# "Zero-netlink in PID 1") as a POSITIVE structural gate.
#
# The steward (`vmcell-steward`) configures the network purely via the kernel `ip=`
# cmdline — it runs NO `ip link/addr/route`, in-process OR by shelling out. The existing
# lean-tree `cargo tree` ban catches a regression that pulls in a netlink CRATE, but a
# regression that simply SHELLS OUT to the distro `ip` binary (adding no dependency) at
# boot/restore would pass every other gate (AGENT-4 / TEST-5). This scanner closes that hole:
# it fails if any steward source spawns / references the `ip` binary.
#
# What it flags (line comments stripped first, so prose mentioning `"ip"` is not a false
# positive):
#   * the exact string literal `"ip"`            (e.g. `Command::new("ip")`, `.arg("ip")`,
#                                                  `vec!["ip"]` — the argv token that runs ip)
#   * a quoted path ending in `/ip`              (e.g. `Command::new("/sbin/ip")`)
#   * a quoted shell string starting with `ip `  (e.g. `.arg("ip link set eth0 up")`,
#                                                  `sh -c "ip link set eth0 up"` — the multi-word form)
#   * a quoted shell string starting with `/…/ip ` + args (e.g. `"/sbin/ip link set eth0 up"`)
# It deliberately does NOT match a dynamic exec of a host-supplied argv (the steward's legitimate
# `Command::new(&req.argv[0])`), nor substrings like `"skip"`/`"gossip"`/`"zip"` — the `ip` token must
# sit right after the opening quote or its path, so none of those spellings can match.
#
# NOTE ON SCOPE: this bans `ip` ONLY inside the guest STEWARD. `vmcell-guest-tools` legitimately
# *implements* `ip` (the erofs helper, §5.3), so it is out of scope by construction.
#
# Usage: ban-agent-ip-shellout.sh [DIR]   (defaults to crates/vmcell-steward/src)
set -euo pipefail

dir="${1:-crates/vmcell-steward/src}"
if [[ ! -d "$dir" ]]; then
  # M-BIN-4: a MISSING default directory is a gate MISCONFIGURATION (a rename/move silently retired
  # the gate), not a clean pass — fail loud. Only stay tolerant when the caller EXPLICITLY supplied a
  # path (that is caller error, not a retired gate).
  if [[ $# -eq 0 ]]; then
    echo "gate misconfigured: expected the default steward source at $dir but it is missing"
    exit 1
  fi
  echo "ok: no steward source directory at $dir (nothing to scan)"
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
      # Flag, in order:
      #   * the exact `"ip"` argv literal            (Command::new("ip"), .arg("ip"), vec!["ip"])
      #   * a quoted path ending in `/ip`            (Command::new("/sbin/ip"))
      #   * a quoted string whose first token is ip  (sh -c "ip link set eth0 up")
      #   * a quoted string starting with a `/…/ip ` path + args ("/sbin/ip link set …")
      # The last two close the multi-word shell-string hole (M-BIN-3). They require the `ip` token to
      # sit immediately after the opening quote (or right after its path + a space), so `"skip "`,
      # `"gossip "`, `"unzip …"` still do NOT match — the no-false-positive contract above is kept.
      if (code ~ /"ip"/ || code ~ /"[^"]*\/ip"/ || code ~ /"ip / || code ~ /"[^"]*\/ip /) {
        print FN ":" FNR ": " $0
      }
    }
  ' "$f")"
  [[ -n "$out" ]] && violations+="$out"$'\n'
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "Forbidden \`ip\` invocation in the steward — the steward must do ZERO ip/netlink"
  echo "(kernel \`ip=\` cmdline configures eth0; design §4.3/§9.2). Remove the shell-out:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi
echo "ok: steward invokes no \`ip\` binary (scanned: $dir)"
