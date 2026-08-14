#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/check-broker-lean.sh (AGENTS.md rule 2).
#
# The predicate under test reads exactly one thing — this workspace's `cargo tree` resolution — so
# the test drives it with canned trees through a stub `cargo` on PATH, the same shape
# scripts/test-check-vendored-vhost.sh uses. That keeps every leg hermetic (no registry, no network,
# no fixture workspace) and lets the THREE-WAY verdict be exercised, which is the whole point: the
# inline copies this script replaced could only ever say "green", because they read stdout alone and
# discarded the stderr that distinguishes "absent" from "cargo could not answer".
#
#   absent + control live      -> exit 0   the shipping state
#   axum PRESENT in the broker -> exit 1   the actual P2 violation
#   cargo BROKEN (ambiguous spec, stale lock, rename) -> exit 1, NOT a silent pass. This is the leg
#                                 that fails against the old inline `2>/dev/null | grep -q .` form.
#   positive control EMPTY     -> exit 1   the probe stopped working, so the absences prove nothing
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check-broker-lean.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

# Stub `cargo`: `-p <pkg> … -i <spec>` is answered from $work/<pkg>.<spec>{,.err,.rc} so each leg
# can script every arm independently. A missing trio means "absent, exit 0".
cat > "$work/bin/cargo" <<'STUB'
#!/usr/bin/env bash
[ "${1:-}" = "tree" ] || { echo "stub cargo: unexpected subcommand ${1:-}" >&2; exit 127; }
pkg=""; spec=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p) pkg="$2"; shift 2 ;;
    -i) spec="$2"; shift 2 ;;
    *) shift ;;
  esac
done
base="$FIXTURES/$pkg.$spec"
[ -f "$base.err" ] && cat "$base.err" >&2
[ -f "$base" ] && cat "$base"
exit "$(cat "$base.rc" 2>/dev/null || echo 0)"
STUB
chmod +x "$work/bin/cargo"

fail=0
run_leg() {
  local name="$1" want_rc="$2" want_text="$3" dir="$4"
  local out rc
  set +e
  out=$(FIXTURES="$dir" PATH="$work/bin:$PATH" "$check" 2>&1)
  rc=$?
  set -e
  if [[ $rc -ne $want_rc ]]; then
    echo "FAIL [$name]: exit $rc, expected $want_rc"
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
  elif ! grep -q "$want_text" <<<"$out"; then
    echo "FAIL [$name]: output missing '$want_text'"
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
  fi
}

# The clean shipping shape: both probes absent (cargo exits 101 with its own absent message, exactly
# as it really does here), and the positive control finds axum in vmcell-daemon.
mk_clean() {
  local d="$1"
  mkdir -p "$d"
  cat > "$d/vmcell-broker.vmcell-daemon.err" <<'EOF'
error: package ID specification `vmcell-daemon` did not match any packages
EOF
  echo 101 > "$d/vmcell-broker.vmcell-daemon.rc"
  cat > "$d/vmcell-broker.axum.err" <<'EOF'
error: package ID specification `axum` did not match any packages
EOF
  echo 101 > "$d/vmcell-broker.axum.rc"
  cat > "$d/vmcell-daemon.axum" <<'EOF'
axum v0.8.7
└── vmcell-daemon v0.13.0 (/w/crates/vmcell-daemon)
EOF
}

mk_clean "$work/clean"
run_leg "clean (absent + live control)" 0 "check-broker-lean: ok" "$work/clean"

# THE VIOLATION: axum really is reachable from the broker.
mk_clean "$work/violation"
rm -f "$work/violation/vmcell-broker.axum.err" "$work/violation/vmcell-broker.axum.rc"
cat > "$work/violation/vmcell-broker.axum" <<'EOF'
axum v0.8.7
└── vmcell-broker v0.13.0 (/w/crates/vmcell-broker)
EOF
run_leg "axum present in the broker" 1 "must not link axum" "$work/violation"

# THE LEG THE OLD INLINE FORM COULD NOT FAIL: cargo answers neither yes nor no. The real trigger in
# this workspace is `-i tokio` -> "specification `tokio` is ambiguous"; a rename or a stale lockfile
# produces the same class. Discarding stderr turned every one of these into a green "absent".
mk_clean "$work/broken"
cat > "$work/broken/vmcell-broker.axum.err" <<'EOF'
error: package ID specification `axum` is ambiguous
EOF
echo 101 > "$work/broken/vmcell-broker.axum.rc"
run_leg "cargo cannot answer (ambiguous spec)" 1 "failed unexpectedly" "$work/broken"

# THE CONTROL'S OWN INVERSE: the probe stops finding axum even where it is linked, so the two
# absences above stop meaning anything. Without this leg the positive control is decoration.
mk_clean "$work/deadprobe"
: > "$work/deadprobe/vmcell-daemon.axum"
run_leg "positive control empty" 1 "positive control failed" "$work/deadprobe"

if [[ $fail -ne 0 ]]; then
  echo "check-broker-lean self-test FAILED"
  exit 1
fi
echo "ok: check-broker-lean self-test passed (clean, violation-red, cargo-broken-red, dead-control-red)"
