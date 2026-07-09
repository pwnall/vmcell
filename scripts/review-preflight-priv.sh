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
# This script is the HARD GATE, with a machine-keyable three-way verdict (exit code + sentinel line)
# so the review orchestration acts on the *kind* of not-ready instead of parsing prose:
#   exit 0  `PREFLIGHT: READY`            — the privileged suites can actually run; run them now.
#   exit 2  `PREFLIGHT: BLOCKED-ON-BLESS` — the ONLY failures are bless-remediable (runner missing /
#                                          caps stripped / stale stamp). BLOCK and ask the maintainer
#                                          for one `just bless`, then rerun. This is NOT a licence to
#                                          downgrade to static-only — the host is capable.
#   exit 1  `PREFLIGHT: NOT READY`        — a genuinely absent facility remains (no /dev/kvm, no
#                                          artifacts, no cgroup delegation) that `just bless` cannot
#                                          fix; only then is a STATIC-ONLY review (runtime claims
#                                          marked unverified) legitimate.
# The review orchestration must BLOCK on any non-zero exit — it must NOT silently fall back to a
# static-only review, because that produces a less accurate result while looking complete. The
# exit-2 split exists because agents kept reading a bless-fixable NOT-READY as a genuinely-missing
# facility and downgrading themselves — the exact reflex AGENTS.md rule 5 removes.
#
# Usage: scripts/review-preflight-priv.sh
# Honors (each defaults to the real host path; overridable ONLY so the red-on-inverse self-test,
# test-review-preflight-priv.sh, can drive each probe through a fixture. This probe reports whether
# the suites can run for the reviewer themselves — it is NOT a security boundary, so an overridden
# probe grants no privilege; the blessed runner's file caps + 0700 mode are the real boundary (PRIV-1)):
#   VMCELL_ARTIFACTS_DIR, VMCELL_KERNEL, VMCELL_ROOTFS   VM artifacts (same resolution as the lib)
#   VMCELL_BIN_DIR                                       capability-runner install dir (.vmcell-bin)
#   VMCELL_KVM_DEV                                       the KVM char device (/dev/kvm)
#   VMCELL_CGROUP_SUBTREE_CONTROL                        the cgroup-v2 root delegation state file
#   VMCELL_SYSTEMD_RUN                                   the scope-launcher probed for cgroup delegation (systemd-run)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1   # setup failure ⇒ generic not-ready (exit 2 is reserved for BLOCKED-ON-BLESS)

# v15 §12.8: the blessed runner is installed to the stable ./.vmcell-bin/ path (outside target/,
# so cargo's churn never strips its caps), which is also what `just test-privileged` points the
# nextest target-runner at.
BIN_DIR="${VMCELL_BIN_DIR:-.vmcell-bin}"
RUNNER_DEBUG="$BIN_DIR/debug/vmcell-test-runner"
RUNNER_RELEASE="$BIN_DIR/release/vmcell-test-runner"
ART_DIR="${VMCELL_ARTIFACTS_DIR:-target/vmcell-artifacts}"
KERNEL="${VMCELL_KERNEL:-$ART_DIR/vmlinux}"
ROOTFS="${VMCELL_ROOTFS:-$ART_DIR/rootfs.erofs}"
KVM_DEV="${VMCELL_KVM_DEV:-/dev/kvm}"
SUBTREE_CTL="${VMCELL_CGROUP_SUBTREE_CONTROL:-/sys/fs/cgroup/cgroup.subtree_control}"
SYSTEMD_RUN_BIN="${VMCELL_SYSTEMD_RUN:-systemd-run}"
NEEDED_CAPS=(cap_net_admin cap_sys_admin cap_dac_override)

# Failures split into two buckets so the verdict tells a maintainer's one-sudo `just bless` fix
# (runner missing / caps stripped / stale stamp) apart from a genuinely absent facility (no KVM, no
# artifacts, no cgroup delegation). An agent must ask for the bless instead of downgrading a
# privileged-aware review to static-only — the exact reflex this split removes (AGENTS.md rule 5).
env_problems=()     # environmental: NOT fixable by `just bless`  ⇒ exit 1, genuinely static-only
bless_problems=()   # bless-remediable: runner build/caps/stamp   ⇒ exit 2, BLOCKED-ON-BLESS
note() { printf '  %s\n' "$1"; }

echo "== vmcell privileged-review preflight =="

# 1) KVM ------------------------------------------------------------ (environmental)
if [ -e "$KVM_DEV" ] && [ -r "$KVM_DEV" ] && [ -w "$KVM_DEV" ]; then
  note "KVM        : OK ($KVM_DEV readable+writable)"
else
  note "KVM        : MISSING or not accessible ($KVM_DEV)"
  env_problems+=("No usable $KVM_DEV. Privileged review needs a KVM-capable host with $KVM_DEV rw (kvm group or an ACL grant). This is not something \`just bless\` can fix.")
fi

# 2) Capability runner blessed with +ep ------------------------- (bless-remediable)
check_runner() {
  local path="$1" caps
  if [ ! -x "$path" ]; then
    note "runner     : $path NOT BUILT"
    bless_problems+=("Capability runner $path is not built. Run \`just bless\` (it builds AND setcaps both debug and release runners via -p vmcell-test-runner).")
    return
  fi
  caps="$(getcap "$path" 2>/dev/null)"
  local ok=1 c
  for c in "${NEEDED_CAPS[@]}"; do
    case "$caps" in *"$c"*) ;; *) ok=0 ;; esac
  done
  # Effective bit: getcap renders the file-effective flag as a distinct field `=ep` / `+ep`.
  # Match that field, NOT a bare `ep` substring — the getcap line also prints the file PATH, so a
  # path component containing `ep` (…/deps/…, a username with `ep`) would spuriously satisfy `*ep*`
  # even on a `+p`-only (un-raised) runner, reading as skip==pass (L-BIN-2).
  case "$caps" in *=ep*|*+ep*) ;; *) ok=0 ;; esac
  if [ "$ok" = 1 ]; then
    note "runner     : OK ($path : ${caps#* })"
  else
    note "runner     : NOT BLESSED ($path : ${caps:-<no caps>})"
    bless_problems+=("Capability runner $path lacks cap_net_admin,cap_sys_admin,cap_dac_override with the effective bit (+ep). Caps strip on every rebuild. Run \`just bless\`. (A +p-only blessing is NOT enough — the runner checks the EFFECTIVE set.)")
  fi
}
check_runner "$RUNNER_DEBUG"     # the one `just test-privileged` uses
# The release runner is optional for `just test-privileged` (which wraps with the DEBUG build), but
# `just bless` blesses both. If a release runner IS present, verify it too so a half-blessed install
# (a release copy that lost its caps) is visible instead of silently un-checked — RUNNER_RELEASE was
# previously defined but never used (L-BIN-2). A missing release build is fine and is not flagged.
if [ -x "$RUNNER_RELEASE" ]; then
  check_runner "$RUNNER_RELEASE"
fi

# 3) Artifacts built ----------------------------------------------- (environmental)
art_ok=1
[ -s "$KERNEL" ] || { art_ok=0; }
[ -s "$ROOTFS" ] || { art_ok=0; }
if [ "$art_ok" = 1 ]; then
  note "artifacts  : OK (kernel=$KERNEL, rootfs=$ROOTFS)"
else
  note "artifacts  : MISSING (kernel=$KERNEL exists=$([ -s "$KERNEL" ] && echo y || echo n); rootfs=$ROOTFS exists=$([ -s "$ROOTFS" ] && echo y || echo n))"
  env_problems+=("VM artifacts missing. Build them: \`cargo run -p vmcell-cli --bin vmcell -- build\` (writes to $ART_DIR), or point VMCELL_KERNEL/VMCELL_ROOTFS at existing images.")
fi

# 4) Delegatable cgroup-v2 domain scope ---------------------------- (environmental)
# Delegation is an environmental facility in BOTH failing forms — a present-but-non-delegating root,
# and no systemd-run at all (the --user scope cannot be created). Neither is fixable by `just bless`,
# so both feed env_problems: leaving the no-systemd arm bucket-less would let an unblessed runner on a
# systemd-less host read as BLOCKED-ON-BLESS, telling a maintainer to bless a host whose metrics_limits
# suite still cannot run (env must dominate). A KVM CI runner / dev host has systemd-run, so it stays OK.
if command -v "$SYSTEMD_RUN_BIN" >/dev/null 2>&1; then
  root_ctl="$(cat "$SUBTREE_CTL" 2>/dev/null || true)"
  if echo "$root_ctl" | grep -qw memory && echo "$root_ctl" | grep -qw cpu; then
    note "cgroup     : OK (systemd-run present; root delegates [$root_ctl]) — run suites under: systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged"
  else
    note "cgroup     : WARN (root subtree_control=[$root_ctl]) — memory/cpu may not delegate; metrics_limits limit assertions could be unrunnable"
    env_problems+=("Root cgroup does not delegate memory+cpu; the metrics_limits limit/OOM assertions need a delegated domain scope. Run the suites under \`systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh ...\`.")
  fi
else
  note "cgroup     : MISSING (systemd-run not found) — cannot create the delegated --user scope for metrics_limits"
  env_problems+=("systemd-run not found, so the delegated cgroup-v2 --user scope the metrics_limits limit/OOM assertions need cannot be created. Environmental — not something \`just bless\` provides; install systemd/a user manager or run on a host that has one.")
fi

echo
# Three-way verdict, machine-keyable (exit code + sentinel line) so the review orchestration can act
# without parsing prose (see AGENTS.md "probe, don't presume"):
#   exit 0  PREFLIGHT: READY            — run both operating-mode suites now.
#   exit 2  PREFLIGHT: BLOCKED-ON-BLESS — bless-remediable ONLY: ask the maintainer for one `just bless`,
#                                         then rerun. NOT license to downgrade to static-only.
#   exit 1  PREFLIGHT: NOT READY        — a genuinely absent facility remains: this run is static-only.
# ENVIRONMENTAL dominates: if any facility is truly missing, `just bless` cannot help, so the verdict is
# exit 1 even when the runner is ALSO unblessed (both are listed, but the run is static-only regardless).
if [ "${#env_problems[@]}" -eq 0 ] && [ "${#bless_problems[@]}" -eq 0 ]; then
  echo "PREFLIGHT: READY — privileged suites can run."
  exit 0
fi
if [ "${#env_problems[@]}" -gt 0 ]; then
  echo "PREFLIGHT: NOT READY — a genuinely absent facility remains (not fixable by \`just bless\`):"
  for p in "${env_problems[@]}"; do echo "  - $p"; done
  for p in "${bless_problems[@]}"; do echo "  - (also, but not the blocker) $p"; done
  echo
  echo "Fix the items above, or label this run STATIC-ONLY and mark every runtime claim unverified."
  exit 1
fi
# Only bless-remediable failures remain — one maintainer `just bless` (single sudo) unblocks the suites.
echo "PREFLIGHT: BLOCKED-ON-BLESS — ask the maintainer to run \`just bless\`, then rerun preflight and the suites:"
for p in "${bless_problems[@]}"; do echo "  - $p"; done
echo
echo "This is NOT a static-only downgrade: the host is capable; the capability runner just needs (re-)blessing."
exit 2
