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
#                                          caps stripped / blessing STALE, i.e. blessed from older
#                                          sources). BLOCK and ask the maintainer for one
#                                          `just bless`, then rerun. This is NOT a licence to
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
# Usage: scripts/review-preflight-priv.sh [--check-runner <runner-path>]
#   --check-runner runs ONLY the blessed-runner probe against <runner-path> and exits
#   0 (blessed) / 2 (bless-remediable). It is the ONE home of that predicate: `just bless`'s
#   idempotence skip calls it instead of restating the caps check.
# Honors (each defaults to the real host path; overridable ONLY so the red-on-inverse self-test,
# test-review-preflight-priv.sh, can drive each probe through a fixture. This probe reports whether
# the suites can run for the reviewer themselves — it is NOT a security boundary, so an overridden
# probe grants no privilege; the blessed runner's file caps + 0700 mode are the real boundary (PRIV-1)):
#   VMCELL_ARTIFACTS_DIR, VMCELL_KERNEL, VMCELL_ROOTFS   VM artifacts (same resolution as the lib)
#   VMCELL_BIN_DIR                                       capability-runner install dir (.vmcell-bin)
#   VMCELL_RUNNER_SRC_PATHS                              colon-separated staleness roots (the runner's
#                                                        in-tree source closure; see BLESS_SRC_PATHS)
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
NEEDED_CAPS=(cap_net_admin cap_sys_admin cap_dac_override cap_setpcap)

# G9 staleness roots: the runner binary's whole IN-TREE source closure. `vmcell-test-runner` is
# deliberately dependency-thin — `vmcell-privilege` plus rustix, and nothing from the vmcell lib —
# so "was this blessed copy built from the tree under review?" is answered by three paths: the two
# crates' `src/` trees and `Cargo.lock` (which moves whenever an external dep in that closure does).
# Colon-separated (no path here contains a colon). A root that does not exist is skipped, so the
# roster cannot make the probe fail on a partial checkout.
BLESS_SRC_PATHS_DEFAULT="crates/vmcell-test-runner/src:crates/vmcell-privilege/src:Cargo.lock"
IFS=: read -r -a BLESS_SRC_PATHS <<<"${VMCELL_RUNNER_SRC_PATHS:-$BLESS_SRC_PATHS_DEFAULT}"

# Failures split into two buckets so the verdict tells a maintainer's one-sudo `just bless` fix
# (runner missing / caps stripped / stale stamp) apart from a genuinely absent facility (no KVM, no
# artifacts, no cgroup delegation). An agent must ask for the bless instead of downgrading a
# privileged-aware review to static-only — the exact reflex this split removes (AGENTS.md rule 5).
env_problems=()     # environmental: NOT fixable by `just bless`  ⇒ exit 1, genuinely static-only
bless_problems=()   # bless-remediable: runner build/caps/stamp   ⇒ exit 2, BLOCKED-ON-BLESS
note() { printf '  %s\n' "$1"; }

# The capability-runner probe (bless-remediable). Defined before the banner so
# `--check-runner` can dispatch to it without running any unrelated probe.
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
    # Name the caps from NEEDED_CAPS, never a hand-written list: the set grew a transient
    # `cap_setpcap` (vmcell_privilege::BLESSED_FILE_CAPS) and a restated list would have kept
    # printing the old three — telling the operator the runner lacks caps it already has.
    local needed_list; needed_list="$(IFS=,; echo "${NEEDED_CAPS[*]}")"
    bless_problems+=("Capability runner $path lacks one of $needed_list with the effective bit (+ep). Caps strip on every rebuild. Run \`just bless\`. (A +p-only blessing is NOT enough — the runner checks the EFFECTIVE set.)")
  fi
}

# The blessing-FRESHNESS probe (bless-remediable) — G9. `check_runner` above answers "does this copy
# still carry the caps?"; it says nothing about WHICH BUILD carries them, and a blessed copy older
# than the sources was measured shipping a whole privileged review: preflight printed READY while the
# blessed runner predated a rewrite of the privilege transition, so every privileged run — including
# `the_bounding_set_is_shrunk_to_exactly_the_delivered_caps`, the live gate on the runner's OWN
# posture — certified a binary nobody was reviewing. Static review cannot see it and AGENTS rule 5
# sends the reviewer through this probe, so the probe has to be the thing that can tell.
#
# It must answer WITHOUT cargo: a review session runs this while other work holds the cargo lock, and
# `cargo build -p vmcell-test-runner` here would both block and (worse) rewrite target/. So the two
# cargo-free signals `just bless` leaves behind are used instead:
#   1. the content-hash stamp `<dir>/.blessed` the recipe writes next to the stable copy, keyed on the
#      built runner's sha256. The stable copy is a byte copy of that build (setcap only sets an xattr,
#      `mv` within the directory preserves content), so stamp != sha256(stable copy) means the copy was
#      replaced out of band. A MISSING stamp is stale by definition: unstamped provenance is no
#      provenance, and only `just bless` ever writes one.
#   2. mtime: any source in BLESS_SRC_PATHS newer than the stable copy means the tree moved after the
#      blessing. `find -newer` compares full mtime precision, so no timestamp arithmetic is needed.
# Signal 2 is a proxy, and deliberately conservative in the safe direction (it can call a
# touched-but-unchanged tree stale; it cannot call a genuinely stale blessing current) — the failure
# mode of a false STALE is one `just bless`, the failure mode of a false CURRENT is a whole review
# certifying the wrong binary.
#
# NOT wired into `check_runner`/`--check-runner`: that predicate is also `just bless`'s idempotence
# skip, and bless answers this same question STRICTLY BETTER — it hashes the binary it just built,
# which is ground truth rather than a proxy. Folding the mtime proxy in would make the recipe re-sudo
# on an mtime-only bump its own hash check knows is a no-op. Two questions, two probes; the caps
# question keeps its one home.
check_blessing_fresh() {
  local path="$1" stamp stamped rest actual newer p
  local reasons=()
  stamp="$(dirname "$path")/.blessed"
  if [ ! -x "$path" ]; then
    # Not built at all — `check_runner` has already filed that as the bless-remediable problem, and a
    # second entry saying the absent file is also stale would just dilute the remediation message.
    note "blessing   : n/a ($path not built — see the runner line above)"
    return
  fi
  if [ ! -f "$stamp" ]; then
    reasons+=("no content-hash stamp at $stamp (only \`just bless\` writes one, so this copy's provenance is unknown)")
  else
    read -r stamped rest < "$stamp" || stamped=""
    actual="$(sha256sum "$path" | cut -d' ' -f1)"
    if [ "$stamped" != "$actual" ]; then
      reasons+=("$path (sha256 ${actual:0:12}…) does not match its $stamp stamp (${stamped:0:12}…): the copy was replaced out of band")
    fi
  fi
  for p in "${BLESS_SRC_PATHS[@]}"; do
    [ -e "$p" ] || continue
    # Fail LOUD when the comparison itself cannot run: a suppressed `find` error (unreadable root,
    # no findutils) yields an empty result, which would read as "nothing newer" — a silent CURRENT,
    # the exact false-green class this probe exists to remove. `-quit` stops at the first hit, so
    # this stats no more of the tree than it must.
    if ! newer="$(find "$p" -newer "$path" -print -quit)"; then
      reasons+=("could not compare mtimes under $p (find failed), so freshness is unknown")
      continue
    fi
    [ -n "$newer" ] && reasons+=("$newer is newer than the blessed copy")
  done
  if [ "${#reasons[@]}" -eq 0 ]; then
    note "blessing   : CURRENT ($path matches $stamp; no source under ${BLESS_SRC_PATHS[*]} is newer)"
    return
  fi
  note "blessing   : STALE ($path)"
  local r
  for r in "${reasons[@]}"; do note "             - $r"; done
  local joined; joined="$(printf '%s; ' "${reasons[@]}")"
  bless_problems+=("Blessed capability runner $path is STALE: ${joined%; }. Ask the maintainer to run \`just bless\` (one sudo) and rerun this preflight BEFORE the suites: nextest wraps every privileged test in this exact binary, so running them now would certify an older runner than the tree under review — including the gate on the runner's own capability posture, which asserts about whichever binary happens to be blessed.")
}

# ONE LAW, ONE PREDICATE: `just bless`'s idempotence skip asks the same question this probe does —
# "does the stable copy still carry all three caps with the EFFECTIVE bit?" — and a second copy of
# it had already diverged once on strictness (the `*ep*` substring the L-BIN-2 note above describes).
# `--check-runner <path>` exposes exactly `check_runner` so the recipe calls THIS function instead
# of restating it: exit 0 = blessed, 2 = bless-remediable, matching the whole-preflight verdict
# codes. It prints the same one-line note, so a caller can surface it verbatim.
if [ "${1:-}" = "--check-runner" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 --check-runner <runner-path>" >&2; exit 1; }
  check_runner "$2"
  [ ${#bless_problems[@]} -eq 0 ] && exit 0
  exit 2
fi

echo "== vmcell privileged-review preflight =="

# 1) KVM ------------------------------------------------------------ (environmental)
if [ -e "$KVM_DEV" ] && [ -r "$KVM_DEV" ] && [ -w "$KVM_DEV" ]; then
  note "KVM        : OK ($KVM_DEV readable+writable)"
else
  note "KVM        : MISSING or not accessible ($KVM_DEV)"
  env_problems+=("No usable $KVM_DEV. Privileged review needs a KVM-capable host with $KVM_DEV rw (kvm group or an ACL grant). This is not something \`just bless\` can fix.")
fi

# 2) Capability runner blessed with +ep ------------------------- (bless-remediable)
check_runner "$RUNNER_DEBUG"     # the one `just test-privileged` uses
# The release runner is optional for `just test-privileged` (which wraps with the DEBUG build), but
# `just bless` blesses both. If a release runner IS present, verify it too so a half-blessed install
# (a release copy that lost its caps) is visible instead of silently un-checked — RUNNER_RELEASE was
# previously defined but never used (L-BIN-2). A missing release build is fine and is not flagged.
if [ -x "$RUNNER_RELEASE" ]; then
  check_runner "$RUNNER_RELEASE"
fi

# 2b) The blessing is the CURRENT build --------------------------- (bless-remediable)
# Same shape as the caps probe above, and for the same reason: `just bless` blesses both copies, so a
# stale one is visible rather than silently un-checked. Blessed caps on a binary two commits old is
# the G9 defect — the suites run, and certify the wrong build.
check_blessing_fresh "$RUNNER_DEBUG"
if [ -x "$RUNNER_RELEASE" ]; then
  check_blessing_fresh "$RUNNER_RELEASE"
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
