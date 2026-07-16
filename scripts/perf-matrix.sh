#!/usr/bin/env bash
# Full performance matrix: every applicable metric on every backend. Superset of
# perf-baseline.sh (which is CH-latency/phase/vsock + FC-latency only). Backends
# self-skip modes they cannot serve (QEMU has no snapshot -> suspend-size skips,
# latency/phase-budget emit COLD only). Same substrate/method as perf-baseline.sh:
# freq-pinned via the blessed runner under a delegated cgroup scope, warm-cache.
#
# Usage: scripts/perf-matrix.sh [logfile]
# Assumes: `just bless` installed the runner at .vmcell-bin/release/ and
#          target/release/bench-vm was built with `--features firecracker,qemu`.
set -uo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${1:-/tmp/perf-matrix.log}"
: > "$LOG"

# Summary lines worth keeping (drops CH serial-log + VMM deprecation noise).
KEEP='Cold Boot|Warm Restore|PHASE-BUDGET|^  (create|connect|exec|teardown|destroy|list)|TOTAL|VSOCK-RTT|round-trip|SUSPEND-SIZE|snapshot bytes|memory file =|memory-file share|host RssShmem total|host RssAnon total|marginal host|KSM pages_sharing|guest MemTotal|guest pid1|density|no snapshot support|cpufreq:|Capabilities:|=== |^Running benchmarks|^kernel:|No successful runs|NET-START|NET-EGRESS|fan-out|agent-ready across|CoW support|master ready|DAEMON-API|NOT freq-pinned|does not rotate|no unprivileged|single-clone|skipping'

FAILED=0
run() {
  echo "### $*" | tee -a "$LOG"
  "$WS/scripts/run-bench.sh" "$@" 2>&1 | tee -a "$LOG" | grep -E "$KEEP"
  local rc=${PIPESTATUS[0]}
  echo | tee -a "$LOG"
  if [ "$rc" -ne 0 ]; then
    echo "!!! benchmark FAILED (exit $rc): $*" | tee -a "$LOG"
    FAILED=1
  fi
}

echo "== PERF MATRIX @ $(date -Is) ==" | tee -a "$LOG"
for BE in cloud-hypervisor firecracker qemu; do
  echo "==================== BACKEND: $BE ====================" | tee -a "$LOG"
  run --backend "$BE" --mode latency      --iterations 20 --warmup 3
  run --backend "$BE" --mode phase-budget --iterations 12 --warmup 3
  run --backend "$BE" --mode vsock-rtt    --iterations 200
  run --backend "$BE" --mode suspend-size --mem-mib 256
  run --backend "$BE" --mode footprint    --count 8
  # Follow-up probes for the paths the single-VM/no-network/library-direct modes above
  # structurally cannot reach (docs/benchmark-results.md coverage caveat). net-egress
  # self-skips on FC (no unprivileged vhost-user-net); zygote degrades to the single-clone
  # control on FC (no host-path rotation).
  run --backend "$BE" --mode net-egress   --iterations 10 --warmup 3
  run --backend "$BE" --mode zygote       --count 8 --iterations 5 --warmup 2
done
# KSM-dedup density lever is CH-only (needs mergeable=on + shared=off).
echo "==================== CH KSM-mergeable footprint ====================" | tee -a "$LOG"
run --backend cloud-hypervisor --mode footprint --count 8 --ksm-mergeable

# Daemon-API probe: the vmcelld HTTP + broker-bridge overhead over the raw VMM op — a
# standalone script (spins up its own daemon), CH-only. Reuses the release runner like
# run-bench.sh. Not freq-pinned (read the `list` bridge floor + deltas, not absolutes).
echo "==================== DAEMON-API probe (vmcelld HTTP + broker, CH) ====================" | tee -a "$LOG"
echo "### scripts/perf-daemon.sh 20 3" | tee -a "$LOG"
"$WS/scripts/perf-daemon.sh" 20 3 2>&1 | tee -a "$LOG" | grep -E "$KEEP"
drc=${PIPESTATUS[0]}
echo | tee -a "$LOG"
if [ "$drc" -ne 0 ]; then
  echo "!!! DAEMON-API probe FAILED (exit $drc)" | tee -a "$LOG"
  FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "== FAILED @ $(date -Is): one or more benchmarks errored (full log: $LOG) ==" | tee -a "$LOG"
  exit 1
fi
echo "== DONE @ $(date -Is) (full log: $LOG) ==" | tee -a "$LOG"
