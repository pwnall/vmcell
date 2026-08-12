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
# A crate ABSENT from the graph entirely means this workspace never links vhost (no QEMU-unpriv
# feature set) — the check is not applicable and exits 0, saying so; exit 1 is reserved for
# present-but-unpatched, the actual dropped-patch trap.
#
# ONE LAW (M-VEND-3): this script is the single vendored-patch predicate. `just ci` CALLS it rather
# than carrying its own inline `cargo tree | grep` copies — the two copies it replaced had already
# diverged on pattern strictness, the duplication-hides-divergence trap. The `=`-pins in the root
# `Cargo.toml` remain the version source the two `spec` strings below must track.
set -euo pipefail

tree=$(cargo tree --locked -e normal --all-features)
fail=0
for spec in "vhost v0.16.0 vendor/vhost" "vhost-user-backend v0.22.0 vendor/vhost-user-backend"; do
    crate=${spec%% *}; ver=$(cut -d' ' -f2 <<<"$spec"); dirpat=$(cut -d' ' -f3 <<<"$spec")
    if ! grep -qE "\b${crate} v" <<<"$tree"; then
        echo "check-vendored-vhost: ${crate} not in this workspace's graph — check not applicable"
        echo "  (enable the QEMU-unprivileged feature set to make it meaningful)"
        continue
    fi
    # the \) after the dir keeps `vendor/vhost` from also matching `vendor/vhost-user-backend`
    if ! grep -qE "\b${crate} ${ver//./\\.} \((.*${dirpat//./\\.}\)|https?://|git\+)" <<<"$tree"; then
        echo "check-vendored-vhost: ${crate} resolves from the REGISTRY — the carried" >&2
        echo "  SET_VRING_ENABLE patch is dropped in this workspace. Replicate vmcell's" >&2
        echo "  [patch.crates-io] stanza at YOUR workspace root (path form needs the vendor/" >&2
        echo "  trees copied too; the git form needs only the stanza — design v30 §10.4)." >&2
        fail=1
    fi
done
if [ "$fail" -eq 0 ]; then echo "check-vendored-vhost: ok"; fi
exit "$fail"
