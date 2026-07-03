#!/usr/bin/env bash
# Establish the current-code performance baseline. Runs the cold/restore latency
# suites for CH + FC and the CH phase-budget breakdown, teeing full output to a
# log and printing only the summary lines. Serial-log/VMM warn noise is dropped.
set -uo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${1:-/tmp/perf-baseline.log}"
: > "$LOG"

# Grep pattern for the meaningful summary lines (drops CH serial-log + trace noise).
KEEP='Cold Boot|Warm Restore|PHASE-BUDGET|^  (create|connect|exec|teardown)|TOTAL|VSOCK-RTT|round-trip|cpufreq:|Capabilities:|=== |^Running benchmarks|^kernel:'

FAILED=0
run() {
  echo "### $*" | tee -a "$LOG"
  # M-BIN-1: bench-vm now exits non-zero on zero post-warmup samples / missing
  # artifacts. Do NOT `|| true` the whole pipeline (that swallowed the failure) —
  # `grep` returning 1 on "no summary matched" is tolerated by inspecting
  # PIPESTATUS[0] (the benchmark's own exit), not the pipeline tail.
  "$WS/scripts/run-bench.sh" "$@" 2>&1 | tee -a "$LOG" | grep -E "$KEEP"
  local bench_rc=${PIPESTATUS[0]}
  echo | tee -a "$LOG"
  if [ "$bench_rc" -ne 0 ]; then
    echo "!!! benchmark FAILED (exit $bench_rc): $*" | tee -a "$LOG"
    FAILED=1
  fi
}

echo "== PERF BASELINE @ $(date -Is) ==" | tee -a "$LOG"
run --backend cloud-hypervisor --mode latency     --iterations 20 --warmup 3
run --backend cloud-hypervisor --mode phase-budget --iterations 12 --warmup 3
run --backend cloud-hypervisor --mode vsock-rtt    --iterations 200
run --backend firecracker      --mode latency      --iterations 20 --warmup 3
if [ "$FAILED" -ne 0 ]; then
  echo "== FAILED @ $(date -Is): one or more benchmarks errored (full log: $LOG) ==" | tee -a "$LOG"
  exit 1
fi
echo "== DONE @ $(date -Is) (full log: $LOG) ==" | tee -a "$LOG"
