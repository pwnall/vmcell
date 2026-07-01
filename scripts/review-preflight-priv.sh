#!/usr/bin/env bash
# Preflight gate for a *privileged-aware* code review (Review 37+).
#
# A privileged-aware review runs the host-facing integration suites
# (`just test-privileged` / `just test-unprivileged`) so findings on the VMM lifecycle,
# snapshot/restore, cgroup limits, netns/tap, and the egress proxy are
# *empirically validated* rather than static-only. Those suites need: a usable
# /dev/kvm, the capability runner blessed with +ep (NOT +p — a +p blessing
# leaves the caps un-raised and every privileged test dies early, which reads as
# skip==pass), the VM artifacts built, and a delegatable cgroup-v2 domain scope.
#
# This script is the HARD GATE: it exits 0 and prints `PREFLIGHT: READY` only
# when the privileged suites can actually run; otherwise it exits non-zero and
# prints `PREFLIGHT: NOT READY` plus the exact remediation. The review
# orchestration must BLOCK on a non-zero exit and ask the maintainer to run the
# printed command (usually `just bless`) — it must NOT silently fall back to a
# static-only review, because that produces a less accurate result while looking
# complete.
#
# Usage: scripts/review-preflight-priv.sh
# Honors: VMCELL_ARTIFACTS_DIR, VMCELL_KERNEL, VMCELL_ROOTFS (same resolution as the lib).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# v15 §12.8: the blessed runner is installed to the stable ./.vmcell-bin/ path (outside target/,
# so cargo's churn never strips its caps), which is also what `just test-privileged` points the
# nextest target-runner at.
RUNNER_DEBUG=".vmcell-bin/debug/vmcell-test-runner"
RUNNER_RELEASE=".vmcell-bin/release/vmcell-test-runner"
ART_DIR="${VMCELL_ARTIFACTS_DIR:-target/vmcell-artifacts}"
KERNEL="${VMCELL_KERNEL:-$ART_DIR/vmlinux}"
ROOTFS="${VMCELL_ROOTFS:-$ART_DIR/rootfs.erofs}"
NEEDED_CAPS=(cap_net_admin cap_sys_admin cap_dac_override)

problems=()
note() { printf '  %s\n' "$1"; }

echo "== vmcell privileged-review preflight =="

# 1) KVM ---------------------------------------------------------------------
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  note "KVM        : OK (/dev/kvm readable+writable)"
else
  note "KVM        : MISSING or not accessible (/dev/kvm)"
  problems+=("No usable /dev/kvm. Privileged review needs a KVM-capable host with /dev/kvm rw (kvm group or an ACL grant). This is not something \`just bless\` can fix.")
fi

# 2) Capability runner blessed with +ep -------------------------------------
check_runner() {
  local path="$1" caps
  if [ ! -x "$path" ]; then
    note "runner     : $path NOT BUILT"
    problems+=("Capability runner $path is not built. Run \`just bless\` (it builds AND setcaps both debug and release runners via -p vmcell-test-runner).")
    return
  fi
  caps="$(getcap "$path" 2>/dev/null)"
  local ok=1 c
  for c in "${NEEDED_CAPS[@]}"; do
    case "$caps" in *"$c"*) ;; *) ok=0 ;; esac
  done
  # Effective bit: getcap renders the file-effective flag as `=ep` / `+ep`.
  case "$caps" in *ep*) ;; *) ok=0 ;; esac
  if [ "$ok" = 1 ]; then
    note "runner     : OK ($path : ${caps#* })"
  else
    note "runner     : NOT BLESSED ($path : ${caps:-<no caps>})"
    problems+=("Capability runner $path lacks cap_net_admin,cap_sys_admin,cap_dac_override with the effective bit (+ep). Caps strip on every rebuild. Run \`just bless\`. (A +p-only blessing is NOT enough — the runner checks the EFFECTIVE set.)")
  fi
}
check_runner "$RUNNER_DEBUG"     # the one `just test-privileged` uses

# 3) Artifacts built ---------------------------------------------------------
art_ok=1
[ -s "$KERNEL" ] || { art_ok=0; }
[ -s "$ROOTFS" ] || { art_ok=0; }
if [ "$art_ok" = 1 ]; then
  note "artifacts  : OK (kernel=$KERNEL, rootfs=$ROOTFS)"
else
  note "artifacts  : MISSING (kernel=$KERNEL exists=$([ -s "$KERNEL" ] && echo y || echo n); rootfs=$ROOTFS exists=$([ -s "$ROOTFS" ] && echo y || echo n))"
  problems+=("VM artifacts missing. Build them: \`cargo run --bin vmcell -- build\` (writes to $ART_DIR), or point VMCELL_KERNEL/VMCELL_ROOTFS at existing images.")
fi

# 4) Delegatable cgroup-v2 domain scope -------------------------------------
if command -v systemd-run >/dev/null 2>&1; then
  root_ctl="$(cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true)"
  if echo "$root_ctl" | grep -qw memory && echo "$root_ctl" | grep -qw cpu; then
    note "cgroup     : OK (systemd-run present; root delegates [$root_ctl]) — run suites under: systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged"
  else
    note "cgroup     : WARN (root subtree_control=[$root_ctl]) — memory/cpu may not delegate; metrics_limits limit assertions could be unrunnable"
    problems+=("Root cgroup does not delegate memory+cpu; the metrics_limits limit/OOM assertions need a delegated domain scope. Run the suites under \`systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh ...\`.")
  fi
else
  note "cgroup     : WARN (systemd-run not found) — cannot create a delegated --user scope for metrics_limits"
fi

echo
if [ "${#problems[@]}" -eq 0 ]; then
  echo "PREFLIGHT: READY — privileged suites can run."
  exit 0
fi
echo "PREFLIGHT: NOT READY"
for p in "${problems[@]}"; do echo "  - $p"; done
echo
echo "Most common fix: run \`just bless\` (re-bless the capability runner; caps strip on every rebuild)."
exit 1
