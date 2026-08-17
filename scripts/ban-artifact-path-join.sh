#!/usr/bin/env bash
# Enforces rubric B12 / invariant P3 (AGENTS.md "Security checks anchor on trusted data … never a
# client-supplied path, never inline `dir.join(client)`") as a POSITIVE structural gate.
#
# The ONLY code that turns a client-supplied artifact name into a filesystem path is
# `resolve_artifact_path` (crates/vmcell-daemon/src/name.rs), which validates the name is a single
# safe path component FIRST. A daemon handler that builds `<artifacts_dir>.join(<client name>)`
# itself is a path-traversal hole (`../../etc/shadow`), so that inline form is banned everywhere in
# the daemon crate EXCEPT the one sanctioned validator.
#
# What it flags (line comments stripped first, so the `dir.join(name)` inside a doc comment is not a
# false positive): an inline join onto a directory-typed receiver named `dir`/`path`/`artifacts_dir`/
# `base` whose argument is a BARE identifier — the client-name variable —
#     dir.join(name)      artifacts_dir.join(client)      self.artifacts_dir.join(name)
# It deliberately does NOT flag:
#   * the sanctioned `resolve_artifact_path` home (name.rs, skipped by basename);
#   * a join onto a method call — `store.dir().join(prefix)` (goes through the store accessor, not a
#     bare dir receiver);
#   * a join of a string literal or a computed expression — `dir.join("subdir")`,
#     `dir.join(format!(...))`, `base.join(crate::naming::…())` — none is a raw client string.
#
# SCOPE: the daemon crate ONLY. Client artifact names arrive over the daemon's HTTP surface; the
# `vmcell` orchestrator/artifact pipeline joins internal (non-client) names and is out of scope by
# construction — widening the scan there would flag legitimate internal joins the rubric never meant.
#
# Usage: ban-artifact-path-join.sh [DIR]   (defaults to crates/vmcell-daemon/src)
# A DIR that is missing, or that holds zero Rust sources, is a caller bug and exits 1 — never a
# reassuring "ok" (docs/90 G4).
set -euo pipefail

dir="${1:-crates/vmcell-daemon/src}"
# A MISSING scan directory is a gate MISCONFIGURATION (a rename/move silently retired the gate), not a
# clean pass — fail loud, whether the path came from the default or from the caller. The former
# explicit-path tolerance (`ok: no daemon source directory …`, exit 0) claimed the self-test relied on
# it; it does not — every fixture tree it scans exists (docs/90 G4).
if [[ ! -d "$dir" ]]; then
  echo "gate misconfigured: no such directory to scan: $dir"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
fi

mapfile -d '' -t files < <(find "$dir" -type f -name '*.rs' -print0)
# Same law for a directory that exists but holds no Rust: zero files scanned is a pointer bug, not a
# clean daemon crate.
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: $dir"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

violations=""
for f in "${files[@]}"; do
  # name.rs is the sanctioned home of resolve_artifact_path — every `dir.join(name)` there is the one
  # validated construction. Skip it by basename (the scan is already scoped to the daemon src, so this
  # is the only name.rs).
  [[ "$(basename "$f")" == "name.rs" ]] && continue
  out="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose is not a violation)
      # A dir-typed receiver `.join(<bare identifier>)`: the exact inline-traversal form. The receiver
      # must be one of dir/path/artifacts_dir/base preceded by a non-word char (so a longer name like
      # `some_dir` is not matched, but `self.artifacts_dir` is), and the argument a bare ident closed
      # by `)` — so a method-call receiver (`dir().join`), a string literal, or a computed expression
      # (`format!(...)`, `crate::naming::…()`) never matches.
      if (code ~ /(^|[^A-Za-z0-9_])(dir|path|artifacts_dir|base)\.join\([a-z_][A-Za-z0-9_]*\)/) {
        print FN ":" FNR ": " $0
      }
    }
  ' "$f")"
  [[ -n "$out" ]] && violations+="$out"$'\n'
done

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "artifact-path ban: a client-string path join outside resolve_artifact_path (rubric B12/P3)."
  echo "Route the client name through vmcell_daemon::name::resolve_artifact_path (it validates the"
  echo "name is a single safe component) instead of joining it directly:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  exit 1
fi
echo "ok: no inline client-string path join outside resolve_artifact_path (scanned: $dir)"
