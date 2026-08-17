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
# A DIR that is missing, or that holds zero Rust sources, is a caller bug and exits 1 — never a
# reassuring "ok" (docs/90 G4).
set -euo pipefail

dir="${1:-crates/vmcell-steward/src}"
# M-BIN-4: a MISSING scan directory is a gate MISCONFIGURATION (a rename/move silently retired the
# gate), not a clean pass — fail loud, whether the path came from the default or from the caller. The
# former explicit-path tolerance (`ok: no steward source directory …`, exit 0) made a typo'd or
# reorganized path read as a clean steward (docs/90 G4).
if [[ ! -d "$dir" ]]; then
  echo "gate misconfigured: no such directory to scan: $dir"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
fi

mapfile -d '' -t files < <(find "$dir" -type f -name '*.rs' -print0)
# Same law for a directory that exists but holds no Rust: zero files scanned is a pointer bug, not a
# steward that shells out to nothing.
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: $dir"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

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
