#!/usr/bin/env bash
# Full performance matrix: every applicable metric on every backend. Backends self-skip
# modes they cannot serve (QEMU has no snapshot -> suspend-size skips, latency/phase-budget
# emit COLD only). Substrate/method: freq-pinned via the blessed runner under a delegated
# cgroup scope, warm-cache. Every mode — including daemon-api — is a `bench-vm` mode run
# through run-bench.sh; there is no separate probe script.
#
# Usage: scripts/perf-matrix.sh [logfile]
# Assumes: `just bless` installed the runner at .vmcell-bin/release/ and
#          target/release/bench-vm was built via `cargo build --release -p vmcell-bench`
#          (its default features enable all FOUR backends: cloud-hypervisor + firecracker + qemu +
#          crosvm). crosvm needs a `crosvm` binary on PATH ($VMCELL_CROSVM_BIN or /usr/local/bin).
set -uo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${1:-/tmp/perf-matrix.log}"
: > "$LOG"

# Summary lines worth keeping (drops CH serial-log + VMM deprecation noise).
KEEP='Cold Boot|Warm Restore|PHASE-BUDGET|^  (create|connect|exec|teardown|destroy|list|restore)|TOTAL|VSOCK-RTT|round-trip|SUSPEND-SIZE|snapshot bytes|memory file =|memory-file share|host RssShmem total|host RssAnon total|marginal host|KSM pages_sharing|guest MemTotal|guest pid1|density|no snapshot support|cpufreq:|Capabilities:|=== |^Running benchmarks|^kernel:|No successful runs|NET-START|NET-EGRESS|fan-out|agent-ready across|CoW support|master ready|DAEMON-API|NOT freq-pinned|does not rotate|no unprivileged|single-clone|skipping|session-|CAP_NET_ADMIN'

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
# crosvm capabilities (§2.5): snapshot_restore=true (latency-restore/suspend-size/phase-restore run),
# restore_rotates_host_paths=false (zygote degrades to the single-clone control, like FC),
# unprivileged_vhost_user_net=false (net-egress plain/tls self-skip, like FC). net-egress privileged
# rides tap+netns+nft under the runner's CAP_NET_ADMIN.
for BE in cloud-hypervisor firecracker qemu crosvm; do
  echo "==================== BACKEND: $BE ====================" | tee -a "$LOG"
  run --backend "$BE" --mode latency      --iterations 20 --warmup 3
  run --backend "$BE" --mode phase-budget --iterations 12 --warmup 3
  run --backend "$BE" --mode vsock-rtt    --iterations 200
  run --backend "$BE" --mode suspend-size --mem-mib 256
  run --backend "$BE" --mode footprint    --count 8
  # Follow-up probes for the paths the single-VM/no-network/library-direct modes above
  # structurally cannot reach (docs/benchmark-results.md coverage caveat). net-egress
  # `plain`/`tls` self-skip on FC (no unprivileged vhost-user-net); zygote degrades to the
  # single-clone control on FC (no host-path rotation); net-egress `privileged` and session
  # run on all three (session needs no cap; privileged self-skips without CAP_NET_ADMIN,
  # which the blessed runner provides here).
  run --backend "$BE" --mode net-egress   --iterations 10 --warmup 3
  run --backend "$BE" --mode net-egress   --net-mode tls        --iterations 10 --warmup 3
  run --backend "$BE" --mode net-egress   --net-mode privileged --iterations 10 --warmup 3
  run --backend "$BE" --mode zygote       --count 8 --iterations 5 --warmup 2
  run --backend "$BE" --mode session      --iterations 30 --warmup 3
done
# KSM-dedup density lever is CH-only (needs mergeable=on + shared=off).
echo "==================== CH KSM-mergeable footprint ====================" | tee -a "$LOG"
run --backend cloud-hypervisor --mode footprint --count 8 --ksm-mergeable

# Daemon-API probe: the vmcelld HTTP + broker-bridge overhead over the raw VMM op. A
# bench-vm mode (was scripts/perf-daemon.sh) — it spawns its own vmcelld, which inherits the
# runner's ambient caps, drives create/restore/exec/list/destroy over HTTP, and reports
# through the shared `pcts`. CH-only (the daemon backend is CH); freq-pinned like every mode.
echo "==================== DAEMON-API probe (vmcelld HTTP + broker, CH) ====================" | tee -a "$LOG"
run --backend cloud-hypervisor --mode daemon-api --iterations 20 --warmup 3

if [ "$FAILED" -ne 0 ]; then
  echo "== FAILED @ $(date -Is): one or more benchmarks errored (full log: $LOG) ==" | tee -a "$LOG"
  exit 1
fi
echo "== DONE @ $(date -Is) (full log: $LOG) ==" | tee -a "$LOG"
