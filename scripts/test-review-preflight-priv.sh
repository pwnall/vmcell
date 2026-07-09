#!/usr/bin/env bash
# Self-test for scripts/review-preflight-priv.sh — the "red on the inverse" guard for its three-way
# readiness verdict (the bless-only sentinel). The defect this guards: an agent read a bless-fixable
# failure (the capability runner not blessed) as a genuinely-missing facility and downgraded a
# privileged-aware review to static-only. The fix is the classifier that separates ENVIRONMENTAL
# failures (exit 1, `PREFLIGHT: NOT READY` — genuinely static-only) from BLESS-REMEDIABLE ones
# (exit 2, `PREFLIGHT: BLOCKED-ON-BLESS` — ask for `just bless`, do NOT downgrade). If the classifier
# ever routes a bless-only failure to exit 1, or an environmental failure to exit 2, this test reddens.
#
# The probe reads the real host, so the fixtures drive it through the documented test seams that each
# default to the real path: VMCELL_KVM_DEV, VMCELL_BIN_DIR (runner location), VMCELL_KERNEL/ROOTFS
# (artifacts), VMCELL_CGROUP_SUBTREE_CONTROL (root delegation state), VMCELL_SYSTEMD_RUN (the scope
# launcher probed for cgroup delegation). A rw regular file satisfies the KVM `-e -r -w` probe, a
# non-empty file satisfies the artifact `-s` probe, a file containing "memory cpu" satisfies the cgroup
# delegation grep, and a `command -v`-findable name satisfies the systemd-run presence probe — so every
# facility is fakeable host-independently (this test runs in `just ci` / the ubuntu-latest lint job,
# with no KVM, no caps, and whether or not the host actually has systemd-run).
#
# NOT reachable here (enumerated, not silently skipped — AGENTS.md rule 4): the READY (exit 0) verdict
# needs a *blessed* runner, and setting file caps needs CAP_SETFCAP (sudo). So READY is validated only
# by the real preflight on a KVM host. This self-test covers the two FAILURE classifications, which are
# the regression surface the exit-2 sentinel exists to protect.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pf="$here/review-preflight-priv.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Shared "good" fixtures: a rw KVM stand-in, non-empty artifacts, a delegating cgroup control file,
# and an EMPTY bin dir so the capability runner is always "NOT BUILT" — the bless-remediable failure
# both cases share (the runner path under it never exists, so check_runner returns before any getcap).
kvm_ok="$work/kvm"             ; : > "$kvm_ok"               # regular rw file ⇒ -e -r -w all true
kern_ok="$work/vmlinux"        ; printf 'x' > "$kern_ok"     # non-empty ⇒ -s true
root_ok="$work/rootfs.erofs"   ; printf 'x' > "$root_ok"
cg_ok="$work/subtree_control"  ; printf 'cpuset cpu io memory pids\n' > "$cg_ok"
bindir_empty="$work/bin-empty" ; mkdir -p "$bindir_empty"
kvm_missing="$work/no-such-kvm"                              # absent ⇒ KVM probe fails (environmental)
systemd_present="true"                                       # a builtin `command -v` always finds; the
                                                            #   probe only tests existence, never execs it
systemd_absent="$work/no-systemd-run"                       # absent ⇒ cgroup delegation cannot be established

# run_pf <kvm-dev-path> <systemd-run-path> — runs the probe with the fixture env, capturing OUT/RC as
# globals (a plain call, NOT a `$(...)` capture, so the globals survive: command substitution would run
# it in a subshell and the assignments would die with it).
run_pf() {
  set +e
  OUT="$(
    VMCELL_KVM_DEV="$1" \
    VMCELL_SYSTEMD_RUN="$2" \
    VMCELL_BIN_DIR="$bindir_empty" \
    VMCELL_KERNEL="$kern_ok" VMCELL_ROOTFS="$root_ok" \
    VMCELL_CGROUP_SUBTREE_CONTROL="$cg_ok" \
    bash "$pf" 2>&1
  )"
  RC=$?
  set -e
}

fail=0
# check <label> <want_rc> <want_substr> <forbid_substr> — asserts against the globals OUT/RC.
check() {
  local label="$1" want_rc="$2" want="$3" forbid="$4"
  if [[ "$RC" != "$want_rc" ]]; then echo "FAIL[$label]: exit=$RC, expected $want_rc"; fail=1; fi
  if ! grep -q "$want" <<<"$OUT"; then echo "FAIL[$label]: output missing sentinel '$want'"; fail=1; fi
  if grep -q "$forbid" <<<"$OUT"; then echo "FAIL[$label]: output must NOT contain '$forbid'"; fail=1; fi
}

# 1) BLESS-ONLY: KVM + artifacts + cgroup (systemd-run present, delegating) all satisfied, only the
#    runner is missing ⇒ exit 2 BLOCKED-ON-BLESS. It must NOT read as the genuinely-static-only exit-1
#    `NOT READY` verdict — that misclassification is precisely the downgrade-to-static-only reflex the
#    sentinel removes.
run_pf "$kvm_ok" "$systemd_present"
check "bless-only" 2 "BLOCKED-ON-BLESS" "NOT READY"

# 2) ENVIRONMENTAL (missing KVM): a genuinely absent facility ⇒ exit 1 `NOT READY`. The runner is ALSO
#    missing here, so this pins the ENVIRONMENTAL-DOMINATES ordering: a real facility gap must win over
#    a bless-fixable one, never be masked as BLOCKED-ON-BLESS (which would tell a reviewer to bless a
#    host that can never run the suites).
run_pf "$kvm_missing" "$systemd_present"
check "environmental(kvm)" 1 "NOT READY" "BLOCKED-ON-BLESS"

# 3) ENVIRONMENTAL (no systemd-run) — the misroute guard. With KVM + artifacts OK but systemd-run
#    absent, the delegated cgroup scope cannot be established; that is environmental, so even though the
#    ONLY OTHER failure is the bless-remediable runner, env must dominate ⇒ exit 1 `NOT READY`, never
#    exit 2 BLOCKED-ON-BLESS. (A bless-only classification here would tell a maintainer to `just bless` a
#    host whose cgroup-dependent metrics_limits suite still cannot run — the bug this case pins closed.)
run_pf "$kvm_ok" "$systemd_absent"
check "environmental(no-systemd)" 1 "NOT READY" "BLOCKED-ON-BLESS"

if (( fail )); then
  echo "---- last probe output ----"; printf '%s\n' "$OUT"
  echo "review-preflight-priv self-test FAILED"
  exit 1
fi
echo "ok: review-preflight-priv self-test passed (bless-only ⇒ exit 2 BLOCKED-ON-BLESS; environmental ⇒ exit 1 NOT READY)"
