#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the Cloud Hypervisor binary resolver — design
# §10.4's `VMCELL_CH_BIN` contract entry — as a POSITIVE structural gate.
#
# THE LAW. `vmcell::artifact::ch_binary_path()` is the designated home: `$VMCELL_CH_BIN`, else bare
# `cloud-hypervisor` on `PATH`. It is `pub` precisely so out-of-crate artifact builders and harnesses
# read the SAME variable, and its own rustdoc exists because that drift had already shipped once — the
# snapshot stage read `CLOUD_HYPERVISOR_PATH` while the builder read `VMCELL_CH_BIN`, so overriding
# one left the other on the default.
#
# WHY THIS EXISTS. docs/90 A2 found a THIRD byte-identical copy of that resolver in `vmcell-cli`, the
# one every VM-lifecycle verb (`run`, `create`, `snapshot`, `stats`) went through — and design §17's
# open-consolidation register, whose job is to inventory exactly this, named only two of the three.
# The CLI copy is closed, and its own file carries an in-source call-site gate
# (`the_cli_resolves_the_ch_binary_through_the_one_library_law`) that scans its production half. That
# gate can only ever see `vmcell-cli/src/main.rs`: `include_str!("main.rs")` is its whole universe.
# This scanner is the class, repo-wide — the copy that matters next is the one in whichever crate has
# no such gate. It also cannot be satisfied by a parity assertion: `ch_bin() == ch_binary_path()`
# CANNOT FAIL, because with the variable unset both spellings answer `cloud-hypervisor`, and
# `set_var` is banned here (`disallowed-methods`, process-global besides). So the law is scanned.
#
# WHAT IT FLAGS: the QUOTED variable name (`"VMCELL_CH_BIN"`) anywhere under `crates/`, line comments
# stripped first — so prose naming `$VMCELL_CH_BIN` (the resolver's own rustdoc, the CLI's delegation
# note, the snapshot stage's "SAME env var" comment) is never a false positive. Reading the variable
# is what a resolver DOES; naming it in a string is the only way to read it.
#
# SCOPE, stated rather than implied: the CH variable is the one with a designated home. `VMCELL_FC_BIN`
# / `_QEMU_BIN` / `_CROSVM_BIN` have no `vmcell`-side law to route through (there is no
# `fc_binary_path`), so banning their spellings would name no home to send the reader to. When one is
# added, this gate grows an arm — it does not get a sibling script.
#
# THE ROSTER below is the whole list of files that may name the variable, by path suffix, each with an
# EXACT count and the reason it is there. Exact counts in both directions, the shape
# ban-kernel-key-composers.sh uses: a reader ADDED inside a rostered file is a second resolver wearing
# a roster entry's exemption, and a count that dropped to zero means the entry is stale — the gate's
# blind spot without the site it was granted for. A test fixture is a legitimate reason to name the
# variable AND the likeliest hiding place for a real second reader, which is why the counts are pinned
# per file instead of the test halves being excluded wholesale.
#
# Usage: ban-ch-binary-resolver-copies.sh [DIR ...]   (defaults to the workspace member trees under crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source (lib + bins + tests + benches) lives under crates/.
  # `examples/downstream-kernel/` is a SEPARATE workspace (the out-of-tree consumer gate) and its
  # `ci-check.sh` drives the variable from the SHELL, not from Rust — out of this scan by construction.
  dirs=(crates)
fi

# The env var whose reads are being counted, and the one function allowed to read it.
env_var="VMCELL_CH_BIN"
law="vmcell::artifact::ch_binary_path"
# The home, by path suffix, plus the definition it must still contain (a home that no longer defines
# the resolver is a moved law, not a pass).
home_suffix="/vmcell/src/artifact/mod.rs"
home_defines="fn ch_binary_path"
home_count=1

# Every OTHER file that may name the variable: path suffix, exact count, reason. A2 names the first
# three as deliberately different and to be kept; the fourth is the CLI's own call-site gate, which
# has to name what it forbids in order to scan for it.
exempt_suffix=(
  # Flag-then-env PRECEDENCE: `--ch-bin` wins, else the variable, else the default. That is a
  # different law (an operator flag the library has no business knowing about), not a copy of this one.
  "/vmcelld/src/main.rs"
  # The daemon integration suite's PATH-SEARCHING variant: it must find a REAL binary to boot VMs
  # with, so it walks PATH itself and skips a non-executable hit — behavior the library resolver
  # deliberately does not have (it returns a bare name and lets `exec` fail).
  "/vmcelld/tests/integration.rs"
  # `bench-vm`'s `(backend, env var, default)` table: the generalised form over all four backends,
  # asserted for parity with the validator getters, plus the injected-lookup test that pins
  # "override wins, else the documented default" without mutating the process environment.
  "/vmcell-bench/src/bin/bench-vm.rs"
  # The CLI's OWN call-site gate: `the_cli_resolves_the_ch_binary_through_the_one_library_law` scans
  # its production half for this variable name, so the needle appears in its test half. Removing this
  # entry does not make the CLI cleaner — it deletes the gate that closed A2.
  "/vmcell-cli/src/main.rs"
)
exempt_count=(1 1 2 1)

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources is
# to have been pointed at the wrong place (a move/reorg, or an explicit-path typo).
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

# `index()`, not a regex: the needle is a quoted identifier and belongs in no pattern.
needle="\"$env_var\""
scan() { # scan <file> -> the matching lines, prefixed file:line
  awk -v FN="$1" -v NEEDLE="$needle" '
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose is not a read)
      if (index(code, NEEDLE) > 0) { print FN ":" FNR ": " $0 }
    }
  ' "$1"
}
count() { if [[ -z "${1//[$'\n']/}" ]]; then echo 0; else printf '%s\n' "$1" | grep -c ''; fi }

home_seen=0
home_found=0
home_hits=""
seen=()
found=()
hits=()
for _ in "${exempt_suffix[@]}"; do seen+=(0); found+=(0); hits+=(""); done
violations=""

for f in "${files[@]}"; do
  hit="$(scan "$f")"
  n="$(count "$hit")"
  if [[ "$f" == *"$home_suffix" ]]; then
    home_seen=1
    home_found="$n"
    home_hits="$hit"
    if ! grep -q "$home_defines" "$f"; then
      echo "gate misconfigured: $home_suffix no longer defines \`$home_defines\`."
      echo "The one resolver moved or was renamed, so this gate is counting reads against a home that"
      echo "does not hold the law. Point \`home_suffix\` in scripts/ban-ch-binary-resolver-copies.sh at"
      echo "the law's new file in the same change that moves it."
      exit 1
    fi
    continue
  fi
  idx=-1
  for i in "${!exempt_suffix[@]}"; do
    if [[ "$f" == *"${exempt_suffix[i]}" ]]; then idx=$i; break; fi
  done
  if [[ $idx -ge 0 ]]; then
    seen[idx]=1
    found[idx]="$n"
    hits[idx]="$hit"
    continue
  fi
  [[ $n -gt 0 ]] && violations+="$hit"$'\n'
done

failed=0

# --- The home: present, and read EXACTLY as often as the law says ----------------------------------
if [[ $home_seen -eq 0 ]]; then
  echo "gate misconfigured: the sanctioned home $home_suffix was not found under: ${dirs[*]}"
  echo "The law moved or the file was renamed — update the roster in"
  echo "scripts/ban-ch-binary-resolver-copies.sh. An exemption that matches nothing is a retired gate,"
  echo "not a pass."
  exit 1
fi
if [[ "$home_found" -ne "$home_count" ]]; then
  echo "The sanctioned home $home_suffix reads \`$env_var\` $home_found time(s) (expected $home_count)."
  echo "A read ADDED here is a second resolver inside the law's own file; a read GONE means the law no"
  echo "longer resolves the variable at all and every consumer silently fell back to the default."
  printf '%s' "${home_hits:-}" | grep -vE '^[[:space:]]*$' || true
  failed=1
fi

# --- The roster: every entry still present, still reading it exactly as declared -------------------
for i in "${!exempt_suffix[@]}"; do
  if [[ ${seen[$i]} -eq 0 ]]; then
    echo "gate misconfigured: ${exempt_suffix[$i]} is on the roster of files that may name"
    echo "\`$env_var\` but no such file was scanned under: ${dirs[*]}. An entry that matches nothing is a"
    echo "widened blind spot, not a pass — drop it, or point it at the file's new path."
    failed=1
  elif [[ "${found[$i]}" -ne "${exempt_count[$i]}" ]]; then
    echo "${exempt_suffix[$i]} names \`$env_var\` ${found[$i]} time(s) (roster says ${exempt_count[$i]})."
    echo "An extra read is a second resolver wearing this entry's exemption; a missing one means the"
    echo "reason the entry was granted is gone. Fix the code, or update the count in"
    echo "scripts/ban-ch-binary-resolver-copies.sh deliberately — never delete the scan."
    printf '%s' "${hits[$i]:-}" | grep -vE '^[[:space:]]*$' || true
    failed=1
  fi
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A copy of the Cloud Hypervisor binary resolver: this file reads \`$env_var\` itself instead of"
  echo "calling \`$law()\` (AGENTS.md \"One law, one predicate\"; docs/90 A2, which found the third such"
  echo "copy). A resolver that drifts from the law does not fail to compile — it boots a different"
  echo "binary than \`\$$env_var\` names, or silently ignores the override entirely:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  echo "If the caller genuinely needs different behavior (an operator flag that outranks the variable,"
  echo "a PATH search), say so on the roster in scripts/ban-ch-binary-resolver-copies.sh with its"
  echo "count and its reason — the ${#exempt_suffix[@]} entries that are there each earned it."
  failed=1
fi

if [[ $failed -ne 0 ]]; then exit 1; fi

echo "ok: \`$env_var\` is read only by $law in $home_suffix"
echo "($home_count read), plus the ${#exempt_suffix[@]} rostered file(s) at their declared counts;"
echo "every other site under ${dirs[*]} calls the one resolver (${#files[@]} file(s) scanned)"
