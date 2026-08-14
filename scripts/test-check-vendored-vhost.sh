#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/check-vendored-vhost.sh (design v30 §10.4 / M-VEND-3, the
# v30 delta-2 gate). The predicate under test reads ONE thing — this workspace's own `cargo tree`
# resolution — so the test drives it with canned trees through a stub `cargo` on PATH. That keeps
# every leg hermetic (no registry, no network, no fixture workspace to resolve) and lets the
# three-way verdict be exercised in full:
#
#   patched (path form)  -> exit 0   the positive control
#   patched (git form)   -> exit 0   the git-dep consumer's sanctioned replication shape
#   REGISTRY             -> exit 1   the actual dropped-patch trap
#   absent from graph    -> exit 0   not applicable (a workspace with no QEMU-unpriv feature set):
#                                    reporting a hard failure the consumer is told to ignore is
#                                    exactly what the three-way split avoids
#   OFF-FAMILY vhost     -> exit 0   the same not-applicable verdict when the only vhost in the graph
#                                    is an unrelated one OUTSIDE the pinned minor family (vmcell's
#                                    own lockfile carries a registry 0.15.0 beside the patched
#                                    0.16.0, so mixed-version graphs are real, not hypothetical)
#
# Deleting the registry branch from the script (its inverse) makes legs 3 and 5 go green and reddens
# this test; widening the not-applicable branch to swallow a present-but-unpatched crate reddens
# leg 5, which is the one leg where the two crates disagree; un-anchoring presence back to any
# `<crate> v…` (dropping the pinned-family read) reddens leg 6.
#
# The version anchor itself is read from the vendored crates beside the script under test, so these
# fixtures name the SAME versions the repo pins — a pin bump that forgot this file fails loudly here
# rather than degrading the gate to a permanent "not applicable".
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check-vendored-vhost.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

# Stub `cargo`: prints the canned tree named by $FAKE_TREE for `cargo tree …`, so the script under
# test resolves nothing and touches no lockfile.
cat > "$work/bin/cargo" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = "tree" ]; then cat "$FAKE_TREE"; exit 0; fi
echo "stub cargo: unexpected subcommand ${1:-}" >&2; exit 127
STUB
chmod +x "$work/bin/cargo"

cat > "$work/patched-path.txt" <<'EOF'
vmcell v0.12.0 (/home/dev/vmcell/crates/vmcell)
├── vhost v0.16.0 (/home/dev/vmcell/vendor/vhost)
└── vhost-user-backend v0.22.0 (/home/dev/vmcell/vendor/vhost-user-backend)
EOF

cat > "$work/patched-git.txt" <<'EOF'
consumer v0.1.0 (/home/dev/consumer)
├── vhost v0.16.0 (https://github.com/example/vmcell?tag=v0.13.0#deadbeef)
└── vhost-user-backend v0.22.0 (https://github.com/example/vmcell?tag=v0.13.0#deadbeef)
EOF

cat > "$work/registry.txt" <<'EOF'
consumer v0.1.0 (/home/dev/consumer)
├── vhost v0.16.0
└── vhost-user-backend v0.22.0
EOF

cat > "$work/absent.txt" <<'EOF'
consumer v0.1.0 (/home/dev/consumer)
└── vmcell v0.13.0
    └── serde v1.0.0
EOF

# Only ONE of the two crates keeps the patch: the half-dropped shape a copied-but-stale stanza
# produces. Must fail, and must name the unpatched crate.
cat > "$work/half.txt" <<'EOF'
consumer v0.1.0 (/home/dev/consumer)
├── vhost v0.16.0
└── vhost-user-backend v0.22.0 (/home/dev/consumer/vendor/vhost-user-backend)
EOF

# The consumer whose only `vhost` is an unrelated registry one OUTSIDE the pinned minor family
# (0.15.x here, reached through fuse-backend-rs — the exact shape vmcell's own lockfile has). It
# links none of the patched sources, so BOTH crates must read as not applicable; an any-version
# presence match instead reports the dropped-patch failure the consumer is then told to ignore.
cat > "$work/off-family.txt" <<'EOF'
consumer v0.1.0 (/home/dev/consumer)
└── fuse-backend-rs v0.12.0
    └── vhost v0.15.0
EOF

fail=0
run_leg() {
    local name="$1" tree="$2" want_rc="$3" want_text="$4"
    local out rc
    set +e
    out="$(FAKE_TREE="$work/$tree" PATH="$work/bin:$PATH" "$check" 2>&1)"
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

run_leg "patched/path form (positive control)" patched-path.txt 0 "check-vendored-vhost: ok"
run_leg "patched/git form (git-dep consumer)"  patched-git.txt  0 "check-vendored-vhost: ok"
run_leg "REGISTRY (the dropped-patch trap)"    registry.txt     1 "resolves from the REGISTRY"
run_leg "absent (not applicable)"              absent.txt       0 "check not applicable"
run_leg "half-patched (vhost dropped)"         half.txt         1 "vhost resolves from the REGISTRY"
run_leg "off-family vhost (not applicable)"    off-family.txt   0 "vhost v0.16.x not in this workspace's graph"

# The anchor's own misconfiguration branch: a copy of the script with no vendor/ trees beside it has
# no pin to anchor on, and an unanchored check is precisely the any-version shape this rewrite
# removed — so it must fail loud rather than fall back to a green. Without this leg the fail-loud
# branch is unexecuted code.
mkdir -p "$work/copied"
cp "$check" "$work/copied/check-vendored-vhost.sh"
set +e
out="$(FAKE_TREE="$work/patched-path.txt" PATH="$work/bin:$PATH" "$work/copied/check-vendored-vhost.sh" 2>&1)"
rc=$?
set -e
if [[ $rc -ne 1 ]] || ! grep -q "cannot read the pinned version" <<<"$out"; then
    echo "FAIL [no vendor trees beside the script]: exit $rc, expected 1 with 'cannot read the pinned version'"
    printf '  ---- output ----\n%s\n' "$out"
    fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo "check-vendored-vhost self-test FAILED"
  exit 1
fi
echo "ok: check-vendored-vhost self-test passed (patched path/git, registry-red, not-applicable incl. off-family, half-patched-red, unanchored-red)"
