#!/usr/bin/env bash
# Run a command inside a cgroup-v2 *domain* scope with the memory+cpu (+pids+io)
# controllers delegated to child cgroups, so the orchestrator can create per-VM
# cgroups with enforceable limits (required by `metrics_limits`).
#
# Intended to be invoked under a delegated systemd scope, e.g.:
#   systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged
#
# The cgroup-v2 "no internal processes" rule means a cgroup may either hold
# processes or enable controllers for its children, not both. So we move this
# shell into a `supervisor/` leaf and enable the controllers on the (now
# process-free) scope's subtree_control. The orchestrator strips the
# `/supervisor` suffix when computing the per-VM cgroup path, placing VM cgroups
# as siblings of `supervisor/` where the delegated controllers apply.
set -euo pipefail

cg_rel=$(awk -F: '/^0::/{print $3}' /proc/self/cgroup)
cg_base="/sys/fs/cgroup${cg_rel}"

if [ -d "$cg_base" ]; then
  mkdir -p "$cg_base/supervisor"
  # Move ourselves (and thus the test processes we spawn) into the leaf first;
  # writing subtree_control while the scope still holds a process fails EBUSY.
  if ! echo $$ >"$cg_base/supervisor/cgroup.procs" 2>/dev/null; then
    echo "with-delegated-scope: WARN could not move into supervisor leaf ($cg_base/supervisor)" >&2
  fi
  for c in memory cpu pids io; do
    if grep -qw "$c" "$cg_base/cgroup.controllers" 2>/dev/null; then
      if ! echo "+$c" >"$cg_base/cgroup.subtree_control" 2>/dev/null; then
        echo "with-delegated-scope: WARN could not delegate controller '$c'" >&2
      fi
    else
      echo "with-delegated-scope: WARN controller '$c' not available in this scope" >&2
    fi
  done
  echo "with-delegated-scope: scope=$cg_base subtree_control=[$(cat "$cg_base/cgroup.subtree_control" 2>/dev/null)]" >&2
else
  echo "with-delegated-scope: WARN cgroup base $cg_base not found; running without delegation" >&2
fi

exec "$@"
