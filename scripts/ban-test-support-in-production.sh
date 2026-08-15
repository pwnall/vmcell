#!/usr/bin/env bash
# Keeps `vmcell`'s `test-support` fixtures out of PRODUCTION code (docs/81 §9, AGENTS.md
# "Fail loud" / rule 1).
#
# WHY THIS EXISTS. `vmcell::metrics::FakeCgroupFs` used to be `#[cfg(test)]`-only, which made it
# invisible downstream — so `vmcell-firecracker`, `vmcell-qemu`, `vmcell-crosvm` and
# `vmcell-artifact-validator` each hand-rolled a `TestCgroupFs` copy of it. The fix exposes it (and
# `vmcell::vmm::VmmProcessGroup::already_reaped_for_test`, which fabricates the "leader already
# reaped" state the M-VMM-1 gates need) behind a `test-support` feature that each backend takes as a
# DEV-dependency.
#
# That is safe for a plain `cargo build -p <backend>` — dev-dependencies are not resolved, the
# feature is off, and a production reference is a compile error. It is NOT safe under
# `cargo clippy --all-targets` / `cargo test`, where cargo's feature unification builds ONE `vmcell`
# with the union of normal- and dev-dependency features: the fixtures become visible to the lib
# target too, and a production path that reached for one would compile clean in exactly the builds
# CI runs. A test double wired into a shipped code path is the failure this closes — `FakeCgroupFs`
# reports invented cgroup counters (`mem_peak_mib: 42`) and enforces nothing, so a VM built over it
# would report limits it does not have.
#
# THE LAW. No production Rust text under the scanned trees may name a `test-support` fixture. What
# counts as production text, per the in-repo source-scan convention (`virtiofs_pacing_gate`):
#   * only files under a `src/` directory — `tests/`, `benches/` and `examples/` are cargo dev
#     targets and may use the fixtures freely;
#   * `//` line comments stripped first, so prose naming a fixture is never a false positive;
#   * truncated at the first `#[cfg(test)]`, so a unit-test module may use them freely. (Note
#     `#[cfg(not(test))]` does not contain that literal and so does not truncate.)
#
# THE SANCTIONED SITES are the DEFINITIONS, matched by path suffix. Each must (a) still name its
# symbol and (b) still carry a `feature = "test-support"` cfg gate — so an exemption whose
# definition moved, or whose gate was dropped (making the fixture unconditionally public), is
# reported as a stale exemption rather than silently widening the ban's blind spot.
#
# NON-VACUITY. Each banned symbol must appear SOMEWHERE outside production text in the scanned
# trees. A symbol that is used nowhere means the roster is stale — the scan would then be looking
# for something that cannot appear, the way every source-scanning gate dies.
#
# Usage: ban-test-support-in-production.sh [DIR ...]   (defaults to crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

# The fixtures `vmcell`'s `test-support` feature exposes. Grown when the feature grows.
banned=(
  "FakeCgroupFs"
  "already_reaped_for_test"
)

# Where each fixture is DEFINED (path suffix), and therefore legitimately named in production text
# behind its own `feature = "test-support"` gate.
sanctioned=(
  "/vmcell/src/metrics.rs"
  "/vmcell/src/vmm/mod.rs"
)
seen=()
named=()
gated=()
for _ in "${sanctioned[@]}"; do seen+=(0); named+=(0); gated+=(0); done

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
[[ ${#files[@]} -eq 0 ]] && { echo "ok: no Rust sources under: ${dirs[*]}"; exit 0; }

# `production_text FILE` — comments stripped, truncated at the first `#[cfg(test)]`.
production_text() {
  awk '
    {
      code = $0
      sub(/\/\/.*/, "", code)
      if (index(code, "#[cfg(test)]") > 0) { exit }
      print FNR "\t" code
    }
  ' "$1"
}

violations=""
misconfig=""
# Whether each banned symbol was seen anywhere outside production text (the non-vacuity check).
used_in_dev=()
for _ in "${banned[@]}"; do used_in_dev+=(0); done

for f in "${files[@]}"; do
  # Cargo dev targets: `tests/`, `benches/`, `examples/` are never production.
  if [[ "$f" != */src/* ]]; then
    for i in "${!banned[@]}"; do
      grep -q -- "${banned[i]}" "$f" && used_in_dev[i]=1
    done
    continue
  fi

  prod="$(production_text "$f")"
  for i in "${!banned[@]}"; do
    # Anything named outside production text counts toward non-vacuity.
    if grep -q -- "${banned[i]}" "$f"; then
      if ! grep -q -- "${banned[i]}" <<<"$prod"; then used_in_dev[i]=1; fi
    fi
  done

  idx=-1
  for i in "${!sanctioned[@]}"; do
    if [[ "$f" == *"${sanctioned[i]}" ]]; then idx=$i; seen[i]=1; break; fi
  done

  hits=""
  for sym in "${banned[@]}"; do
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      hits+="$f:${line%%$'\t'*}: ${line#*$'\t'}"$'\n'
    done < <(grep -- "$sym" <<<"$prod" || true)
  done

  if [[ $idx -ge 0 ]]; then
    # A sanctioned definition site: it must still NAME its symbol, and still be GATED.
    [[ -n "${hits//[$'\n']/}" ]] && named[idx]=1
    grep -q 'feature = "test-support"' "$f" && gated[idx]=1
    continue
  fi
  [[ -n "${hits//[$'\n']/}" ]] && violations+="$hits"
done

for i in "${!sanctioned[@]}"; do
  if [[ ${seen[$i]} -eq 0 ]]; then
    misconfig+="  ${sanctioned[$i]}: no such file under: ${dirs[*]}"$'\n'
  elif [[ ${named[$i]} -eq 0 ]]; then
    misconfig+="  ${sanctioned[$i]}: exempted but defines no test-support fixture"$'\n'
  elif [[ ${gated[$i]} -eq 0 ]]; then
    misconfig+="  ${sanctioned[$i]}: defines a fixture with NO \`feature = \"test-support\"\` gate"$'\n'
  fi
done
for i in "${!banned[@]}"; do
  if [[ ${used_in_dev[$i]} -eq 0 ]]; then
    misconfig+="  ${banned[$i]}: named nowhere outside production text — the roster is stale"$'\n'
  fi
done

if [[ -n "${misconfig//[$'\n']/}" ]]; then
  echo "gate misconfigured: the test-support roster no longer describes the tree."
  echo "Update scripts/ban-test-support-in-production.sh — an exemption or a banned symbol that"
  echo "matches nothing is a retired gate, not a pass:"
  printf '%s' "$misconfig"
  exit 1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "A \`vmcell/test-support\` fixture is named in PRODUCTION code. These are test doubles —"
  echo "\`FakeCgroupFs\` reports invented counters and enforces nothing — and cargo's feature"
  echo "unification makes them visible to lib targets under \`--all-targets\`, so this compiles"
  echo "clean in exactly the builds CI runs (docs/81 §9). Move the use into a \`#[cfg(test)]\`"
  echo "module, a \`tests/\` target, or take a real seam:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi

echo "ok: no test-support fixture is named in production code, and both definition sites are"
echo "present and feature-gated (scanned: ${dirs[*]})"
