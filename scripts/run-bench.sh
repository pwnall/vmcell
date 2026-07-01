#!/usr/bin/env bash
# Run ONE bench-vm invocation under the delegated cgroup scope + capability runner.
# Reused by the baseline and the perf experiments so every run shares identical
# substrate (freq-pin via CAP_DAC_OVERRIDE, delegated memory/cpu controllers).
#
# Usage: scripts/run-bench.sh <bench-vm args...>
#   e.g. scripts/run-bench.sh --backend cloud-hypervisor --mode latency --iterations 20 --warmup 3
#
# Assumes: `just bless` has installed the blessed runner at .vmcell-bin/release/,
# and `target/release/bench-vm` is freshly built (the caller rebuilds when needed).
set -euo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$WS/.vmcell-bin/release/vmcell-test-runner"
BENCH="$WS/target/release/bench-vm"
exec systemd-run --user --scope -q --collect -p Delegate=yes \
  "$WS/scripts/with-delegated-scope.sh" "$RUNNER" "$BENCH" "$@"
