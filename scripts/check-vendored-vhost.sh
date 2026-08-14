#!/usr/bin/env bash
# Asserts the vendored vhost patch is live IN THE CURRENT WORKSPACE (vmcell's own, or a git-dep
# consumer's that replicated the [patch.crates-io] stanza — design v30 §10.4 says when that is
# load-bearing: QEMU + NetConfig::Unprivileged only). Path-independent: greps this workspace's own
# resolution. `cargo tree` only — resolves, never compiles. --locked ONLY: a stale/absent lockfile
# fails loud with cargo's own message (the repo's --locked policy; an unlocked fallback would
# silently re-resolve and could rewrite the consumer's Cargo.lock as a side effect of a "check").
# Two sanctioned replication shapes pass (both resolve the patched sources):
#   path form  — copy the stanza AND the vendor/vhost* trees to your workspace root
#                (cargo tree prints "… (/…/vendor/vhost…)")
#   git form   — a [patch.crates-io] entry pointing at the vmcell git repo
#                (cargo tree prints "… (https://… or git+…vmcell…)")
# A crate absent from the graph — or present only in a version OUTSIDE the pinned minor family —
# means this workspace never links the vhost vmcell patches (no QEMU-unpriv feature set, or an
# unrelated vhost pulled in by some other dependency): the check is not applicable and exits 0,
# saying so. Exit 1 is reserved for the pinned family being present-but-unpatched, the actual
# dropped-patch trap. Matching presence on any `vhost v…` at all was an accept-then-reject: vmcell's
# own lockfile carries a registry `vhost 0.15.0` beside the patched 0.16.0, so a consumer whose ONLY
# vhost is such an unrelated one got a hard "the patch is dropped" it is then told to ignore.
#
# ONE LAW (M-VEND-3): this script is the single vendored-patch predicate. `just ci` CALLS it rather
# than carrying its own inline `cargo tree | grep` copies — the two copies it replaced had already
# diverged on pattern strictness, the duplication-hides-divergence trap. The pinned VERSION is read
# the same way, from the vendored crate beside this script rather than baked into it: a hard-coded
# spec would silently turn a pin bump (`=0.16.0` → `=0.17.0`, vendor tree bumped with it) into a
# permanent "not applicable" green — the drift is the failure mode the anchor exists to catch, so
# the anchor may not be a second copy of the version. That makes this script script-relative (the
# vendor trees ship beside it); a consumer runs it out of the vmcell checkout it consumes, with its
# OWN workspace as cwd, exactly as examples/downstream-kernel/ci-check.sh does.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The ONE version source: the vendored crate's own `[package] version`. It is what
# `[patch.crates-io]` resolves to, so it cannot disagree with the `=`-pin (cargo would report
# "Patch was not used" instead of applying it).
pinned_version() {
    local manifest="$1" ver
    ver=$(awk -F'"' '/^\[/ { inpkg = ($0 ~ /^\[package\]/) }
                     inpkg && /^version *=/ { print $2; exit }' "$manifest" 2>/dev/null || true)
    printf '%s' "$ver"
}

tree=$(cargo tree --locked -e normal --all-features)
fail=0
for spec in "vhost vendor/vhost" "vhost-user-backend vendor/vhost-user-backend"; do
    crate=${spec%% *}; dirpat=$(cut -d' ' -f2 <<<"$spec")
    ver=$(pinned_version "$here/../$dirpat/Cargo.toml")
    if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        # Gate misconfiguration, not a pass: no pin means no anchor, and an unanchored check is the
        # any-version accept-then-reject this rewrite removed. Fail loud (the M-BIN-4 precedent).
        echo "check-vendored-vhost: cannot read the pinned version from $here/../$dirpat/Cargo.toml" >&2
        echo "  Run this script from the vmcell checkout you consume (its vendor/ trees are the pin" >&2
        echo "  source); copying the script alone leaves it with nothing to anchor on." >&2
        exit 1
    fi
    family="${ver%.*}"                       # the pinned MINOR family: 0.16.0 -> 0.16
    # Presence is anchored on that family, so an unrelated `vhost v0.15.x` elsewhere in the graph
    # reads as not-applicable rather than as a dropped patch.
    if ! grep -qE "\b${crate} v${family//./\\.}\." <<<"$tree"; then
        echo "check-vendored-vhost: ${crate} v${family}.x not in this workspace's graph — check not applicable"
        echo "  (enable the QEMU-unprivileged feature set to make it meaningful)"
        continue
    fi
    # the \) after the dir keeps `vendor/vhost` from also matching `vendor/vhost-user-backend`
    if ! grep -qE "\b${crate} v${ver//./\\.} \((.*${dirpat//./\\.}\)|https?://|git\+)" <<<"$tree"; then
        echo "check-vendored-vhost: ${crate} resolves from the REGISTRY — the carried" >&2
        echo "  SET_VRING_ENABLE patch is dropped in this workspace. Replicate vmcell's" >&2
        echo "  [patch.crates-io] stanza at YOUR workspace root (path form needs the vendor/" >&2
        echo "  trees copied too; the git form needs only the stanza — design v30 §10.4)." >&2
        fail=1
    fi
done
if [ "$fail" -eq 0 ]; then echo "check-vendored-vhost: ok"; fi
exit "$fail"
