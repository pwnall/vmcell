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
# It also guards the G9 BLESSING-FRESHNESS verdict: a blessed runner built from OLDER sources than the
# tree under review still passes the caps probe, and preflight printed READY while every privileged
# test ran through a binary two commits stale. The freshness legs below pin all four decisions —
# stamp-matches + sources-older ⇒ READY, and missing stamp / mismatched stamp / newer source ⇒
# BLOCKED-ON-BLESS — so deleting the check (or neutering it to "always current") reddens here.
#
# Those legs need a runner that reads as BLESSED, and setting real file caps needs CAP_SETFCAP (sudo),
# which this test does not have. The seam used instead is PATH: the probe asks the `getcap` on PATH, so
# a fixture `getcap` shim (printing exactly the four-cap `=ep` line a blessed runner yields) is
# prepended for those legs only. That is a FIXTURE, not a privilege bypass — this whole script is a
# readiness probe, never a security boundary (the runner's real file caps + 0700 mode are, PRIV-1), and
# the caps-classification legs 1-3 keep using the real `getcap` via an empty bin dir.
#
# NOT reachable here (enumerated, not silently skipped — AGENTS.md rule 4): (a) a READY verdict against
# a genuinely cap-carrying runner on a real KVM host — only the real preflight proves that, and the
# freshness legs prove only the *classification*, since the shim decides the caps answer; (b) the
# freshness probe's "find failed, freshness unknown" reason, whose only cheap trigger is an unreadable
# staleness root — a fixture that stops failing when the suite runs as root (some CI containers do),
# and a gate that cannot fail under root is worse than an enumerated gap.
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

# --- G9 blessing-freshness fixtures -------------------------------------------------------------
# `getcap` shim: renders the blessed line (path + the four caps with the effective bit) for whatever
# path it is handed, so the caps probe answers OK and the ONLY remaining verdict input is freshness.
shimdir="$work/shim"; mkdir -p "$shimdir"
cat > "$shimdir/getcap" <<'SHIM'
#!/usr/bin/env bash
printf '%s cap_dac_override,cap_setpcap,cap_net_admin,cap_sys_admin=ep\n' "${1:-}"
SHIM
chmod +x "$shimdir/getcap"

# Every mtime below is set EXPLICITLY (`touch -d`), never inherited from creation order, so the
# newer/older relation the probe reads is a property of the fixture and not of how fast this ran.
# A directory's own mtime bumps when a file is created in it, so each src dir is touched LAST.
mk_bindir() {  # mk_bindir <dir> <stamp-mode: match|missing|mismatch>
  local dir="$1" mode="$2" runner="$1/debug/vmcell-test-runner"
  mkdir -p "$dir/debug"
  printf 'runner-fixture' > "$runner"; chmod 0700 "$runner"
  case "$mode" in
    match)    sha256sum "$runner" | cut -d' ' -f1 > "$dir/debug/.blessed" ;;
    mismatch) printf '%064d\n' 0 > "$dir/debug/.blessed" ;;   # a well-formed hash of something else
    missing)  ;;                                              # `just bless` never ran here
  esac
  touch -d '2021-01-01 00:00:00' "$runner"
}
bindir_fresh="$work/bin-fresh"       ; mk_bindir "$bindir_fresh" match
bindir_nostamp="$work/bin-nostamp"   ; mk_bindir "$bindir_nostamp" missing
bindir_badstamp="$work/bin-badstamp" ; mk_bindir "$bindir_badstamp" mismatch

mk_src() {  # mk_src <dir> <mtime> — a stand-in for crates/<crate>/src
  mkdir -p "$1"; printf 'fn main() {}' > "$1/main.rs"
  touch -d "$2" "$1/main.rs" "$1"
}
mk_src "$work/src-old" '2020-01-01 00:00:00'   # older than the blessing ⇒ blessing is current
mk_src "$work/src-new" '2022-01-01 00:00:00'   # newer than the blessing ⇒ blessing is stale
: > "$work/lock-old"; touch -d '2020-01-01 00:00:00' "$work/lock-old"
: > "$work/lock-new"; touch -d '2022-01-01 00:00:00' "$work/lock-new"
srcs_old="$work/src-old:$work/lock-old"        # the whole closure predates the blessing
srcs_newsrc="$work/src-new:$work/lock-old"     # a crate source moved after the blessing
srcs_newlock="$work/src-old:$work/lock-new"    # only Cargo.lock moved (a dep bump)

# run_pf_with <kvm-dev> <systemd-run> <bin-dir> <src-paths> <path-prefix> — runs the probe with the
# fixture env, capturing OUT/RC as globals (a plain call, NOT a `$(...)` capture, so the globals
# survive: command substitution would run it in a subshell and the assignments would die with it).
run_pf_with() {
  set +e
  OUT="$(
    PATH="${5:+$5:}$PATH" \
    VMCELL_KVM_DEV="$1" \
    VMCELL_SYSTEMD_RUN="$2" \
    VMCELL_BIN_DIR="$3" \
    VMCELL_RUNNER_SRC_PATHS="$4" \
    VMCELL_KERNEL="$kern_ok" VMCELL_ROOTFS="$root_ok" \
    VMCELL_CGROUP_SUBTREE_CONTROL="$cg_ok" \
    bash "$pf" 2>&1
  )"
  RC=$?
  set -e
}

# run_pf <kvm-dev-path> <systemd-run-path> — the caps-classification legs: empty bin dir (runner NOT
# BUILT), real `getcap` on PATH, and a fixture source closure so these legs never stat the live tree.
run_pf() { run_pf_with "$1" "$2" "$bindir_empty" "$srcs_old" ""; }

# run_pf_bless <bin-dir> <src-paths> — the freshness legs: every environmental facility satisfied and
# the shimmed `getcap`, so the verdict turns ONLY on the blessing-freshness decision.
run_pf_bless() { run_pf_with "$kvm_ok" "$systemd_present" "$1" "$2" "$shimdir"; }

fail=0
# check <label> <want_rc> <want_substr> <forbid_substr> — asserts against the globals OUT/RC.
check() {
  local label="$1" want_rc="$2" want="$3" forbid="$4"
  if [[ "$RC" != "$want_rc" ]]; then echo "FAIL[$label]: exit=$RC, expected $want_rc"; fail=1; fi
  if ! grep -q "$want" <<<"$OUT"; then echo "FAIL[$label]: output missing sentinel '$want'"; fail=1; fi
  if grep -q "$forbid" <<<"$OUT"; then echo "FAIL[$label]: output must NOT contain '$forbid'"; fail=1; fi
}
# also_want / also_forbid <label> <substr> — extra assertions on the SAME captured OUT. The freshness
# legs need them to stay non-vacuous: an exit-2 verdict alone would also be produced by a runner that
# merely lost its caps, so each stale leg additionally pins that the reason printed is the STALE one
# and that the caps probe is NOT what failed.
also_want() {
  if ! grep -q "$2" <<<"$OUT"; then echo "FAIL[$1]: output missing '$2'"; fail=1; fi
}
also_forbid() {
  if grep -q "$2" <<<"$OUT"; then echo "FAIL[$1]: output must NOT contain '$2'"; fail=1; fi
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

# 4) FRESH BLESSING (G9 positive control): stamp matches the stable copy and the whole source closure
#    predates it ⇒ exit 0 READY. This is the leg that keeps the freshness check honest in the other
#    direction: a check that reports STALE unconditionally (or one keyed on the wrong comparison
#    direction) would block every review, and it reddens HERE rather than on a maintainer's afternoon.
run_pf_bless "$bindir_fresh" "$srcs_old"
check "fresh-blessing" 0 "PREFLIGHT: READY" "BLOCKED-ON-BLESS"
also_want "fresh-blessing" "blessing   : CURRENT"
also_forbid "fresh-blessing" "STALE"

# 5) NO STAMP: the copy exists and carries the caps, but `just bless` never stamped it — provenance
#    unknown, which is stale by definition (the measured G9 shape is a caps-OK copy nobody can date).
run_pf_bless "$bindir_nostamp" "$srcs_old"
check "no-stamp" 2 "BLOCKED-ON-BLESS" "PREFLIGHT: READY"
also_want "no-stamp" "blessing   : STALE"
also_want "no-stamp" "no content-hash stamp"
also_forbid "no-stamp" "NOT BLESSED"          # the exit 2 is attributable to freshness, not caps

# 6) STAMP MISMATCH: the stable copy's content differs from what the stamp records — it was replaced
#    out of band (a hand `cp` over the blessed path, a restore from backup), so the blessing certifies
#    a build nobody can identify.
run_pf_bless "$bindir_badstamp" "$srcs_old"
check "stamp-mismatch" 2 "BLOCKED-ON-BLESS" "PREFLIGHT: READY"
also_want "stamp-mismatch" "does not match its"
also_forbid "stamp-mismatch" "NOT BLESSED"

# 7) SOURCE NEWER (the measured G9 case): stamp matches, caps are fine, but a runner-closure source
#    file moved after the blessing — exactly the state in which preflight printed READY and 228
#    privileged tests certified a pre-rewrite binary.
run_pf_bless "$bindir_fresh" "$srcs_newsrc"
check "source-newer" 2 "BLOCKED-ON-BLESS" "PREFLIGHT: READY"
also_want "source-newer" "is newer than the blessed copy"
also_want "source-newer" "just bless"
also_forbid "source-newer" "NOT BLESSED"

# 8) LOCKFILE NEWER: the closure is not just the two `src/` trees — a dep bump moves `Cargo.lock` and
#    changes the runner binary, with no in-tree source edit to notice. Pinned separately so a roster
#    that quietly drops the lockfile entry reddens.
run_pf_bless "$bindir_fresh" "$srcs_newlock"
check "lockfile-newer" 2 "BLOCKED-ON-BLESS" "PREFLIGHT: READY"
also_want "lockfile-newer" "lock-new is newer than the blessed copy"

# 9) BUCKET ORDERING: a stale blessing is bless-remediable, so it must NOT be able to mask a genuinely
#    absent facility. With KVM missing AND the blessing stale, environmental still dominates ⇒ exit 1.
run_pf_with "$kvm_missing" "$systemd_present" "$bindir_fresh" "$srcs_newsrc" "$shimdir"
check "stale+no-kvm" 1 "NOT READY" "PREFLIGHT: READY"
also_want "stale+no-kvm" "(also, but not the blocker)"

if (( fail )); then
  echo "---- last probe output ----"; printf '%s\n' "$OUT"
  echo "review-preflight-priv self-test FAILED"
  exit 1
fi
echo "ok: review-preflight-priv self-test passed (bless-only ⇒ exit 2 BLOCKED-ON-BLESS; environmental ⇒ exit 1 NOT READY; blessing freshness: current ⇒ READY, missing/mismatched stamp or newer source ⇒ BLOCKED-ON-BLESS)"
