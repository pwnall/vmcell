#!/usr/bin/env bash
# Daemon-API latency probe: the overhead the `vmcelld` HTTP daemon + broker bridge
# adds over the raw VMM op. Complements the library-direct `bench-vm` matrix, which
# never exercises the daemon (coverage gap noted in docs/benchmark-results.md).
#
# Measures four operations with `curl -w %{time_total}` (the daemon-side request
# latency, excluding curl process startup):
#   create  = POST /v1/vms   -> full cold-boot-to-agent-ready THROUGH the HTTP+broker
#   exec    = POST /v1/vms/{id}/exec  -> HTTP + broker bridge + in-guest vsock exec
#   list    = GET  /v1/vms   -> pure HTTP + broker bridge, NO VMM work (the bridge floor)
#   destroy = DELETE /v1/vms/{id}  -> teardown THROUGH the daemon
#
# create/destroy are timed as a create->destroy lifecycle loop; list/exec are timed
# on ONE steady VM (isolating the per-op bridge cost from VM churn).
#
# NOT freq-pinned (unlike bench-vm): the daemon runs as a plain backgrounded process,
# so read the RELATIVE bridge overhead (esp. `list`, a few ms of pure HTTP+bridge),
# not the absolute create latency (which is boot-bound and turbo-sensitive). Compare
# daemon `exec` vs bench-vm `vsock-rtt`, and daemon `create` vs bench-vm CH cold, to
# read the bridge delta.
#
# Usage: scripts/perf-daemon.sh [iterations] [warmup]
# Assumes: `just bless` installed the release runner at .vmcell-bin/release/, and
#          target/release/vmcelld exists (cargo build --locked --release -p vmcelld),
#          and target/vmcell-artifacts/{vmlinux,rootfs.erofs} are built.
set -uo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ITERS="${1:-10}"
WARMUP="${2:-3}"

RUNNER="$WS/.vmcell-bin/release/vmcell-test-runner"
VMCELLD="$WS/target/release/vmcelld"
ART_SRC="$WS/target/vmcell-artifacts"

# Fail loud on missing prerequisites (M-BIN-1 spirit: a probe that measured nothing
# must exit non-zero, not print a skip and return 0).
for f in "$RUNNER" "$VMCELLD" "$ART_SRC/vmlinux" "$ART_SRC/rootfs.erofs"; do
  if [ ! -e "$f" ]; then
    echo "=== DAEMON-API: prerequisite missing: $f ==="
    echo "  build: just bless ; cargo build --locked --release -p vmcelld ; (artifacts via just test-privileged)"
    exit 1
  fi
done
if ! command -v cloud-hypervisor >/dev/null 2>&1; then
  echo "=== DAEMON-API: cloud-hypervisor not on PATH; skipping ==="
  exit 1
fi

# Ephemeral, private artifact store seeded with the two prebuilt artifacts (the store
# is create-only; readers tolerate a missing .sha256 sidecar).
ART_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vmcell-daemon-bench.XXXXXX")"
cp "$ART_SRC/vmlinux" "$ART_SRC/rootfs.erofs" "$ART_DIR/"

# Free ephemeral port so a stale daemon / parallel run does not collide.
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
BASE="http://127.0.0.1:$PORT"

DAEMON_PID=""
cleanup() {
  # Graceful: SIGTERM drives run_http_parent's shutdown_signal -> engine.shutdown_all()
  # (tears down every VM + the broker); SIGKILL is the backstop. Always runs (trap EXIT)
  # so a mid-probe abort still reaps the broker + any live cloud-hypervisor VMs.
  if [ -n "$DAEMON_PID" ]; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$DAEMON_PID" 2>/dev/null && kill -KILL "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  rm -rf "$ART_DIR"
}
trap cleanup EXIT

echo "=== DAEMON-API (vmcelld HTTP + broker bridge; port=$PORT n=$ITERS warmup=$WARMUP) ==="
echo "  NOT freq-pinned — read the bridge overhead (list) and deltas, not absolute create."

# Launch the daemon through the blessed runner (execs into vmcelld, so $! IS the
# daemon PID). Real broker split (no --no-setup-broker) so the bridge is measured.
"$RUNNER" "$VMCELLD" \
  --artifacts-dir "$ART_DIR" \
  --bind "127.0.0.1:$PORT" \
  --allow-unauthenticated \
  --ch-bin "$(command -v cloud-hypervisor)" \
  --resource-prefix vmcd >/dev/null 2>&1 &
DAEMON_PID=$!

# Readiness poll (20s budget, matching the integration harness).
healthy=0
for _ in $(seq 1 80); do
  if curl -sf "$BASE/healthz" >/dev/null 2>&1; then healthy=1; break; fi
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "  daemon exited before healthz"; exit 1; }
  sleep 0.25
done
[ "$healthy" -eq 1 ] || { echo "  daemon not healthy in 20s"; exit 1; }

CREATE_BODY='{"kernel":"vmlinux","rootfs":"rootfs.erofs"}'

# Times one curl call in ms (curl's own %{time_total}, seconds->ms). Prints the ms and
# writes the response body to $2 so callers can parse an id without a second request.
timed_curl() { # $1=ms_out_var (unused; echoes ms) ; args after -- are curl args ; body->stdout via fd
  :
}

# create one VM, echo "<ms> <id>"
create_vm() {
  local out ms id
  out="$(curl -s -w '\n%{time_total}' -X POST "$BASE/v1/vms" \
        -H 'content-type: application/json' -d "$CREATE_BODY" 2>/dev/null)"
  ms="$(printf '%s\n' "$out" | tail -n1)"
  id="$(printf '%s\n' "$out" | sed '$d' | python3 -c 'import sys,json;print(json.load(sys.stdin)["vm"]["id"])' 2>/dev/null)"
  printf '%s %s\n' "$ms" "$id"
}
# echo ms for a DELETE of $1
destroy_vm() { curl -s -o /dev/null -w '%{time_total}' -X DELETE "$BASE/v1/vms/$1" 2>/dev/null; }
# echo ms for a GET /v1/vms
list_vms() { curl -s -o /dev/null -w '%{time_total}' "$BASE/v1/vms" 2>/dev/null; }
# echo ms for an exec of /bin/true in $1
exec_vm() { curl -s -o /dev/null -w '%{time_total}' -X POST "$BASE/v1/vms/$1/exec" \
            -H 'content-type: application/json' -d '{"argv":["/bin/true"]}' 2>/dev/null; }

# Percentiles via nearest-rank (ceil(n*q)-1, clamped) — matches bench-vm's `pcts`
# (NOT the broken floor(n*q) estimator, AGENTS.md). Input: whitespace-separated
# seconds-floats on stdin; output: "p50=.. p95=.. p99=.. max=.. (ms)".
# NOTE: pass the program via `-c` (NOT `python3 - <<HEREDOC`): with a `-` program the
# heredoc becomes python's stdin, so `sys.stdin.read()` gets EOF and every sample set
# reads empty. With `-c`, stdin stays the piped `printf` data.
pctl() {
  python3 -c '
import sys, math
label = sys.argv[1]
xs = sorted(float(x)*1000.0 for x in sys.stdin.read().split())
if not xs:
    print(f"  {label}: No successful samples"); sys.exit(0)
n = len(xs); last = n-1
idx = lambda q: min(max(math.ceil(n*q)-1, 0), last)
p50, p95, p99, mx = xs[idx(.5)], xs[idx(.95)], xs[idx(.99)], xs[last]
print(f"  {label:8s}: count={n} p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms max={mx:.1f}ms")
' "$1"
}

# --- Lifecycle loop: create -> destroy, timing each (with warmup) ---
create_ms=""; destroy_ms=""
total=$((ITERS + WARMUP))
for i in $(seq 1 "$total"); do
  read -r cms cid < <(create_vm)
  if [ -z "$cid" ] || [ "$cid" = "None" ]; then
    echo "  create iteration $i failed (no id returned)"; exit 1
  fi
  dms="$(destroy_vm "$cid")"
  if [ "$i" -gt "$WARMUP" ]; then
    create_ms+="$cms "; destroy_ms+="$dms "
  fi
done

# --- Steady-op loop: one VM, time N list + N exec (isolates per-op bridge cost) ---
read -r _wms sid < <(create_vm)
if [ -z "$sid" ] || [ "$sid" = "None" ]; then echo "  steady VM create failed"; exit 1; fi
list_ms=""; exec_ms=""
for _ in $(seq 1 "$WARMUP"); do list_vms >/dev/null; exec_vm "$sid" >/dev/null; done
for _ in $(seq 1 "$ITERS"); do
  list_ms+="$(list_vms) "
  exec_ms+="$(exec_vm "$sid") "
done
destroy_vm "$sid" >/dev/null

printf '%s' "$create_ms"  | pctl create
printf '%s' "$exec_ms"    | pctl exec
printf '%s' "$list_ms"    | pctl list
printf '%s' "$destroy_ms" | pctl destroy
echo "=== DAEMON-API done ==="
