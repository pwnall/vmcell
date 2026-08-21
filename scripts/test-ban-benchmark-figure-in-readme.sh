#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-benchmark-figure-in-readme.sh.
#
# A ban that cannot go red is theater (AGENTS.md rule 2), and a prose scanner's characteristic
# failures are the two opposite ones: passing vacuously, and flagging ordinary writing. Both are
# driven here, arm by arm:
#
#   * a README that points instead of quoting passes                      → an over-broad pattern reddens;
#   * a version pin, a file mode, a port, a distro release and a memory
#     size in a config example all stay clean OUTSIDE the section         → the same, on the shapes
#                                                                           this README really carries;
#   * a time in ms, a fractional second, a throughput rate and a
#     percentile bound to a value are flagged anywhere                    → deleting an ARM 1
#                                                                           alternative reddens;
#   * the SAME size token is clean outside the section and flagged
#     inside it                                                           → collapsing the two arms
#                                                                           reddens, in whichever
#                                                                           direction it collapsed;
#   * a report line pasted into a fenced code block is still flagged      → excluding code fences
#                                                                           reddens (the likeliest
#                                                                           way the defect lands);
#   * a marked line excuses its figure, and a marker excusing nothing
#     is a misconfiguration                                               → both marker directions;
#   * no benchmark heading, two benchmark headings, an empty section
#     body, and no README at all are each a misconfiguration, never
#     a green `ok:`                                                       → the vacuity arms (docs/90 G4).
#
# The canary arm (the ban's own proof of life, since a clean README yields zero hits) needs no leg
# of its own: it runs ahead of every scan, so a broken extractor reddens every case below.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-benchmark-figure-in-readme.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline, built out of the shapes the real README carries: pinned versions, an install
# mode, a port, a distro release, a memory size in a config example — and a benchmark section that
# names what produces the numbers instead of quoting them.
# shellcheck disable=SC2016  # every backtick below is literal markdown, not shell expansion (intended)
mk_readme() { # mk_readme <root> [extra lines appended INSIDE the benchmark section]
  local root="$1"; shift
  mkdir -p "$root"
  {
    printf '# vmcell\n\n'
    printf '## Development\n\n'
    printf '### 2. Cargo-installed subprocess binaries\n\n'
    printf 'Cloud Hypervisor v53.0 is the pinned release; Firecracker is v1.16.1 and QEMU 10.2.1.\n'
    printf 'sudo install -m 0755 /tmp/cloud-hypervisor /usr/local/bin/cloud-hypervisor\n'
    printf 'The steward port used to be mirrored as two host/guest 5000s.\n'
    printf 'A cell built with `.mem_mib(512)` gets 512 MiB of guest RAM on a 30 GiB host.\n'
    printf 'Validated on Ubuntu 26.04.\n\n'
    printf '### 10. Benchmarks\n\n'
    printf 'No figure is quoted here: `docs/benchmark-results.md` is canonical, `scripts/perf-matrix.sh`\n'
    printf 'produces the matrix, and `just test-bench` proves the wiring. A run reports p50/p95/p99\n'
    printf 'over the sample, per backend, per mode (see `VALID_MODES`).\n'
    for line in "$@"; do printf '%s\n' "$line"; done
  } > "$root/README.md"
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()      { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; dump "$2"; fi; }
expect_out()     { if ! grep -qF "$1" <<<"$out"; then echo "FAIL: $2: expected output to contain '$1'"; fail=1; dump "$2"; fi; }
expect_not_out() { if   grep -qF "$1" <<<"$out"; then echo "FAIL: $2: output must NOT contain '$1'"; fail=1; dump "$2"; fi; }
dump()           { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the positive control — pointers, not numbers ------------------------------------------
mk_readme "$work/clean"
run_ban "$work/clean"
expect_rc 0 "clean README"
expect_out "ok: README.md quotes no benchmark figure" "clean README"

# --- Case 2: ARM 1, outside the section — the four performance shapes ------------------------------
for probe in \
  "Cold boot is 305 ms on this substrate." \
  "The exec round trip is 0.7 ms p50." \
  "Teardown settles in 1.5 s." \
  "The NAT moves 940 MB/s guest to host." \
  "Restore is p95 = 62 on Firecracker."
do
  mk_readme "$work/arm1"
  # Appended OUTSIDE the benchmark section: rewrite the file with the probe in the earlier section.
  sed -i "s|Validated on Ubuntu 26.04.|Validated on Ubuntu 26.04. $probe|" "$work/arm1/README.md"
  run_ban "$work/arm1"
  expect_rc 1 "ARM 1: $probe"
  expect_out "[any-section]" "ARM 1: $probe"
done

# --- Case 3: the two arms are genuinely different --------------------------------------------------
# A size token is ordinary prose outside the section (a config example) and a figure inside it.
mk_readme "$work/size-outside"
sed -i "s|Validated on Ubuntu 26.04.|Validated on Ubuntu 26.04. The rootfs image is 79 MB.|" \
  "$work/size-outside/README.md"
run_ban "$work/size-outside"
expect_rc 0 "a size outside the benchmark section is ordinary prose"
expect_not_out "[any-section]" "size outside the section"

mk_readme "$work/size-inside" "An OCI rootfs is 79 MB and KSM merges 84% across eight guests."
run_ban "$work/size-inside"
expect_rc 1 "a size INSIDE the benchmark section is a figure"
expect_out "[benchmark-section]" "size inside the section"

# --- Case 4: a pasted report block inside a code fence is still scanned ---------------------------
mk_readme "$work/fenced" '```' 'Cold Boot: p50=305 p95=322' '```'
run_ban "$work/fenced"
expect_rc 1 "a report pasted into a fenced block"
expect_out "README.md:" "fenced report"

# --- Case 5: the escape hatch, both directions ----------------------------------------------------
# shellcheck disable=SC2016  # literal markdown backticks (intended)
mk_readme "$work/marked" 'The `--timeout 30s` flag value <!-- allow-benchmark-figure: a CLI default, not a measurement -->'
run_ban "$work/marked"
expect_rc 0 "a marked line excuses its unit-bearing number"
expect_out "1 marked exemption(s)" "marked line"

mk_readme "$work/stale-marker" 'Nothing measurable here <!-- allow-benchmark-figure: stale -->'
run_ban "$work/stale-marker"
expect_rc 1 "a marker that excuses nothing is a widened blind spot"
expect_out "gate misconfigured" "stale marker"

# --- Case 6: the vacuity arms ---------------------------------------------------------------------
mk_readme "$work/noheading"
sed -i 's|### 10. Benchmarks|### 10. Measurements|' "$work/noheading/README.md"
run_ban "$work/noheading"
expect_rc 1 "no benchmark heading"
expect_out "gate misconfigured" "no benchmark heading"

mk_readme "$work/twoheadings" '' '### 11. More Benchmarks' '' 'Also pointers only.'
run_ban "$work/twoheadings"
expect_rc 1 "two benchmark headings leave the strict arm no single home"
expect_out "gate misconfigured" "two benchmark headings"

mkdir -p "$work/emptysection"
printf '# vmcell\n\n## Benchmarks\n' > "$work/emptysection/README.md"
run_ban "$work/emptysection"
expect_rc 1 "an empty section body"
expect_out "gate misconfigured" "empty section body"

mkdir -p "$work/noreadme"
run_ban "$work/noreadme"
expect_rc 1 "no README at all"
expect_out "gate misconfigured" "no README"

if [[ $fail -ne 0 ]]; then
  echo "ban-benchmark-figure-in-readme self-test FAILED"
  exit 1
fi
echo "ok: ban-benchmark-figure-in-readme self-test passed"
