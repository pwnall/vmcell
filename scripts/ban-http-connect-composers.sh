#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the SYNTHESIZED HTTP `CONNECT` REQUEST LINE —
# the one place a guest-chosen authority is spliced into an HTTP request — across every host crate.
#
# THE LAW. §6.4's transparent intake recovers a redirected connection's destination from bytes the
# GUEST chose (the ClientHello's SNI, or the `Host` header) and then composes
# `CONNECT <authority> HTTP/1.1` to hand the connection to hudsucker's explicit-proxy intake. That
# authority crosses an HTTP boundary, so exactly one function may compose that line, and it composes
# it only after `transparent::validate_authority_host` has refused a `\r\n` (request smuggling), a
# space, a `/`, an empty host or a port outside 1–65535. A second composer somewhere else would not
# be a style problem: it is the request-smuggling hole re-opened, and no compiler sees it, because
# `format!` accepts any string.
#
# WHY THIS IS NOT THE VSOCK `CONNECT`. `vmcell::steward`'s control plane writes `CONNECT <port>\n` —
# the AF_VSOCK bridge prologue, a different protocol with its own one-law home. The needle here is
# therefore an HTTP request line specifically: `"CONNECT ` AND `HTTP/1.` on the same line. Matching a
# bare `CONNECT` would flag that unrelated law's call sites and teach the reader to ignore this gate.
#
# THE LAW, in four arms:
#
#   ARM 1 — ONE COMPOSER. In production code under a scanned crate's `src`, an HTTP `CONNECT`
#   request line may be composed only in the law's own file. Anywhere else, compose it there — or, if
#   the site genuinely is a client naming its own destination rather than a proxy relaying a peer's,
#   add it to the exemption roster below WITH its reason, the way this file does for the in-guest
#   curl shim.
#
#   ARM 2 — THE LAW STILL VALIDATES. The law's file must still define `validate_authority_host` and
#   still call it. A composer that stopped validating is the defect this gate is about, sitting in
#   the one file this gate does not scan for composers.
#
#   ARM 3 — THE EXEMPTION CANNOT OUTLIVE WHAT IT EXCUSES. An exempted file that no longer composes a
#   CONNECT line is a widened blind spot, not a pass: it is reported as a misconfiguration so the
#   roster shrinks with the code (ban-ci-script-handcopy.sh's ARM 3, ban-inline-setns.sh's moved
#   sanctioned site).
#
#   ARM 4 — NON-VACUITY. Zero Rust sources scanned is a caller bug and exits 1 — the only way to open
#   nothing is to have been pointed at nothing (docs/90 G4). Zero composers found anywhere is the
#   same class one step in: the law's own site must be visible to this scan, or the needle has rotted
#   and the gate is matching nothing forever.
#
# WHAT IS DELIBERATELY NOT FLAGGED: line comments and rustdoc (this file's own law is described in
# prose in three modules, and prose is not a call site), and everything from a file's `mod tests {`
# onward (a test that composes a CONNECT by hand is the JUDGE of the law — `classify`'s HTTP-intake
# fixtures feed exactly that literal).
#
# Usage: ban-http-connect-composers.sh [DIR ...]   (defaults to the workspace member trees under crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source lives under crates/. `examples/downstream-kernel/` is a separate
  # workspace and is scanned only when named explicitly.
  dirs=(crates)
fi

# The law's home and the predicate that guards it, by path suffix (the self-test's fixture trees
# mirror the real layout, so a suffix is the portable anchor — ban-inline-netns-path.sh's shape).
law_suffix="/vmcell/src/proxy/transparent.rs"
law_predicate="validate_authority_host"

# Sites that compose an HTTP CONNECT line and are NOT the law, by path suffix, each with its reason:
exempt_suffixes=(
  # `crates/vmcell-guest-tools/src/main.rs` — the IN-GUEST curl shim's `probe_connect`. It is the
  # client end, not the proxy end: its authority comes from its own argv (the test's command line),
  # never from a peer's bytes, and it links none of the host front-end. It exists to re-issue a
  # CONNECT manually so a blocked domain's 403 is observable in-guest, which is a different job from
  # relaying a destination somebody else chose.
  "/vmcell-guest-tools/src/main.rs"
)

mapfile -d '' -t all_files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# --- ARM 4a: an empty scan is a MISCONFIGURATION, never a clean tree -------------------------------
if [[ ${#all_files[@]} -eq 0 ]]; then
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
fi

# --- ARM 2: the law is still there, and still validates --------------------------------------------
law_file=""
for f in "${all_files[@]}"; do
  if [[ "$f" == *"$law_suffix" ]]; then law_file="$f"; break; fi
done
if [[ -z "$law_file" ]]; then
  echo "gate misconfigured: the transparent-intake law ($law_suffix) was not found under: ${dirs[*]}"
  echo "This gate exempts exactly that file from the composer ban because it is the one composer."
  echo "With the law gone, the exemption points at nothing — update the suffix in"
  echo "scripts/ban-http-connect-composers.sh to the law's new home."
  exit 1
fi
if ! grep -q "fn $law_predicate" "$law_file"; then
  echo "gate misconfigured: $law_file no longer defines \`fn $law_predicate\`."
  echo "That predicate is WHY the one composer is allowed to splice a guest-chosen authority into a"
  echo "request line. Without it the exempted file is exactly the defect this gate bans elsewhere."
  exit 1
fi
# A CALL, not the declaration: `grep "$law_predicate("` matches `fn validate_authority_host(a: …)`
# too, which would make this arm unfailable — the self-test's "defined but never called" leg found
# exactly that and is why the `fn` line is excluded here.
if ! grep -n "$law_predicate(" "$law_file" | grep -qv "fn $law_predicate("; then
  echo "gate misconfigured: $law_file defines \`$law_predicate\` but never calls it."
  echo "An unvalidated authority reaching \`CONNECT <authority> HTTP/1.1\` is request smuggling from"
  echo "any guest that can name an SNI or a Host header."
  exit 1
fi

# The needle: an HTTP request line, not the vsock prologue. Both halves must be on the line.
# "Production" is everything before the file's unit-test module.
scan() { # scan <file>
  awk -v FN="$1" '
    index($0, "mod tests {") { exit }
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose is not a call site)
      if (index(code, "\"CONNECT ") > 0 && index(code, "HTTP/1.") > 0) { print FN ":" FNR ": " $0 }
    }
  ' "$1"
}

scanned=0
declare -A crates_scanned=()
composers=0
violations=""
declare -A exempt_hit=()
for f in "${all_files[@]}"; do
  # Library/binary sources only. Integration tests under crates/*/tests/ are the law's judges.
  [[ "$f" == *"/src/"* ]] || continue
  scanned=$((scanned + 1))
  owner="${f%%/src/*}"
  crates_scanned["${owner##*/}"]=1

  hit="$(scan "$f")"
  [[ -z "${hit//[$'\n']/}" ]] && continue
  composers=$((composers + 1))

  if [[ "$f" == *"$law_suffix" ]]; then
    continue
  fi
  sanctioned=0
  for ex in "${exempt_suffixes[@]}"; do
    if [[ "$f" == *"$ex" ]]; then
      exempt_hit["$ex"]=1
      sanctioned=1
      break
    fi
  done
  [[ $sanctioned -eq 1 ]] && continue
  violations+="$hit"$'\n'
done

# --- ARM 4b: the law's own site must be visible, or the needle has rotted --------------------------
if [[ $composers -eq 0 ]]; then
  echo "gate misconfigured: no HTTP CONNECT request-line composer was found ANYWHERE under"
  echo "${dirs[*]}, including the law's own file ($law_file)."
  echo "The needle (a line holding both \`\"CONNECT \` and \`HTTP/1.\`) no longer matches the code it"
  echo "was written for, so this scan would report 'ok' forever regardless of what lands."
  exit 1
fi

# --- ARM 3: a stale exemption is a widened blind spot ----------------------------------------------
for ex in "${exempt_suffixes[@]}"; do
  if [[ -z "${exempt_hit[$ex]:-}" ]]; then
    echo "gate misconfigured: the exempted site *$ex no longer composes an HTTP CONNECT line."
    echo "The exemption now excuses nothing while still hiding that file from this scan. Delete it"
    echo "from exempt_suffixes in scripts/ban-http-connect-composers.sh."
    exit 1
  fi
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "An HTTP \`CONNECT\` request line is composed outside its one law. A guest-chosen authority"
  echo "(an SNI, a Host header) spliced into a request line without"
  echo "\`vmcell::proxy::transparent::$law_predicate\` is request smuggling — a CR/LF in the"
  echo "authority injects whatever headers the guest likes. Compose it in $law_suffix, or add this"
  echo "site to exempt_suffixes WITH its reason (see the in-guest curl shim's entry):"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi

echo "ok: every HTTP CONNECT request line is composed in the one law ($law_suffix, guarded by"
echo "$law_predicate) or in ${#exempt_suffixes[@]} rostered exemption(s) that still compose one —"
echo "scanned $scanned file(s) across ${#crates_scanned[@]} crate(s) under ${dirs[*]}, $composers composer site(s) found"
