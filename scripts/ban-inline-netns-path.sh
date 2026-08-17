#!/usr/bin/env bash
# Enforces "one law, one predicate" (AGENTS.md) for the NETNS LAYOUT — the `/var/run/netns/<name>`
# bind-mount path — across every crate the law's own in-source gate structurally cannot see.
#
# THE LAW. `crates/vmcell/src/net/tap.rs` holds `NETNS_DIR` and composes from it in exactly two
# places (`netns_dir()` for a `read_dir` root, `netns_path(name)` for one namespace). Its rustdoc
# claimed the layout was spelled "in exactly one place" while four other production sites composed it
# inline — the §6.4 proxy's namespace entry, `build_vmm_cmd`'s pre-fork C string and the orphan
# scanner's two `read_dir`s — and the claim aged into fiction because nothing could see it age. All
# four are closed and `tap.rs`'s `netns_layout_gate` module now pins the roster in both directions.
#
# WHY A SECOND GATE IS NOT A SECOND COPY OF THE LAW. That in-source gate walks
# `env!("CARGO_MANIFEST_DIR")/src`, so its whole verdict is about `crates/vmcell/src` — and
# `netns_path`/`netns_dir` are `pub(crate)`, so no other crate CAN route through them. A netns path
# needed in `vmcell-daemon`, `vmcell-broker`, `vmcelld` or a backend crate therefore has nowhere to
# come from except a fresh inline literal, and not one line of the existing gate would move. This
# scanner is exactly that complement: it scans every OTHER crate's `src` and DELEGATES
# `crates/vmcell/src` to `netns_layout_gate` rather than re-counting its roster here. Nothing in this
# file spells the layout either — the needle is read out of `NETNS_DIR` itself, so a change to the
# law cannot leave a stale copy of it behind in this gate.
#
# THE LAW, in four arms:
#
#   ARM 1 — THE LAYOUT LITERAL. A string literal starting with `NETNS_DIR`'s value, in production
#   code under a scanned crate's `src`, is a second spelling of the layout. Whatever shape the call
#   site needs (a `PathBuf`, a `read_dir` root, a NUL-terminated string for a post-fork `open`) it
#   composes from the law; if the law is not reachable from that crate, the fix is to widen the law's
#   visibility (or move the work into `vmcell`), never to re-type the path.
#
#   ARM 2 — THE ALIAS. `/var/run` is conventionally a symlink to `/run` (`hostcaps::netns_reachable`
#   probes either), so `"/run/netns/…"` names the SAME directory while matching no scan anchored on
#   the law's own text. It is the same class as F3's reserved-cmdline aliases: an emitted-literal scan
#   structurally cannot discover an alias, so the alias is banned explicitly. It is DERIVED from the
#   law (`${NETNS_DIR#/var}`), not typed, so it follows the law if the law ever moves.
#
#   ARM 3 — THE DELEGATION IS REAL. `crates/vmcell/src` is skipped because `netns_layout_gate` owns
#   it. If the law's file, its `NETNS_DIR` const, or that gate module is gone, this gate is skipping a
#   whole crate that nothing else checks — a misconfiguration, never a pass.
#
#   ARM 4 — NON-VACUITY. Zero Rust sources scanned, or zero sources outside the delegated crate, is a
#   caller bug and exits 1: a complement gate whose complement is empty measures nothing (docs/90 G4).
#
# WHAT IS DELIBERATELY NOT FLAGGED:
#   * line comments and rustdoc — `vmcell-privilege`'s `CAP_DAC_OVERRIDE` rationale names the path in
#     prose, and prose is not a call site (comments are stripped before matching);
#   * a file's unit-test module (everything from `mod tests {`), matching `netns_layout_gate`'s own
#     definition of "production": a test that recomputes the layout independently is the JUDGE of the
#     law, not a violation of it;
#   * `crates/*/tests/` integration tests, for the same reason and by scope — `tests/segment.rs`,
#     `tests/lifecycle.rs` and `vmcelld/tests/integration.rs` each recompute the path to assert that
#     residue is GONE, which is the assertion the law exists to make possible.
#
# Usage: ban-inline-netns-path.sh [DIR ...]   (defaults to the workspace member trees under crates/)
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  # v15 workspace: all member source lives under crates/. `examples/downstream-kernel/` is a separate
  # workspace (the out-of-tree consumer gate) and is scanned only when named explicitly.
  dirs=(crates)
fi

# The law's home and the in-source gate that owns it, by path suffix (the fixture trees the self-test
# builds mirror the real layout, so a suffix is the portable anchor — the shape ban-inline-setns.sh
# uses for its sanctioned sites).
law_suffix="/vmcell/src/net/tap.rs"
law_gate_module="mod netns_layout_gate"
# Every file under this crate's src is the in-source gate's scope, not this one's.
delegated_infix="/vmcell/src/"

mapfile -d '' -t all_files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources is
# to have been pointed at the wrong place (a move/reorg, or an explicit-path typo).
[[ ${#all_files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

# --- ARM 3: the delegated scope must still have its owner ------------------------------------------
law_file=""
for f in "${all_files[@]}"; do
  if [[ "$f" == *"$law_suffix" ]]; then law_file="$f"; break; fi
done
if [[ -z "$law_file" ]]; then
  echo "gate misconfigured: the netns-layout law ($law_suffix) was not found under: ${dirs[*]}"
  echo "This gate reads its needle OUT of that file's \`NETNS_DIR\` and skips that crate's src because"
  echo "\`netns_layout_gate\` covers it. With the law gone there is no needle and no owner for the"
  echo "skipped scope — update the suffix in scripts/ban-inline-netns-path.sh to the law's new home."
  exit 1
fi
# Composed from the law itself, so this gate's own text is never what it counts.
layout="$(sed -nE 's/^[[:space:]]*const NETNS_DIR: &str = "([^"]+)".*/\1/p' "$law_file" | head -n 1)"
if [[ -z "$layout" ]]; then
  echo "gate misconfigured: $law_file defines no \`const NETNS_DIR: &str = \"…\"\`."
  echo "The needle is read from the law rather than typed here, so an unreadable law leaves this scan"
  echo "matching the empty string — i.e. flagging everything or nothing, never the law."
  exit 1
fi
if ! grep -q "$law_gate_module" "$law_file"; then
  echo "gate misconfigured: $law_file no longer contains \`$law_gate_module\`."
  echo "That module is why this gate skips ${delegated_infix#/}* — it pins the law's call-site roster"
  echo "inside the owning crate, in both directions. Without it, skipping that crate leaves the law's"
  echo "own home unchecked by anything. Restore the in-source gate, or widen this scan to cover it."
  exit 1
fi

# ARM 2's alias, DERIVED from the law: `/var/run` is conventionally a symlink to `/run`, so a literal
# spelled without the `/var` names the same directory. When the law does not start with `/var` there
# is no alias to derive and the arm reports itself inactive rather than silently checking nothing.
alias_layout="${layout#/var}"
[[ "$alias_layout" == "$layout" ]] && alias_layout=""

# The needles include the OPENING QUOTE, so only a literal that *starts* with the layout counts — the
# same anchor `netns_layout_gate` uses, which is what keeps a prose mention out of the count.
needle="\"$layout"
alias_needle=""
[[ -n "$alias_layout" ]] && alias_needle="\"$alias_layout"

# `index()`, not a regex: the needle is a path full of `/` and `.` and belongs in no pattern.
# "Production" is everything before the file's unit-test module, matching netns_layout_gate.
scan() { # scan <file> <needle>
  awk -v FN="$1" -v NEEDLE="$2" '
    index($0, "mod tests {") { exit }
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (prose is not a call site)
      if (index(code, NEEDLE) > 0) { print FN ":" FNR ": " $0 }
    }
  ' "$1"
}

scanned=0
declare -A crates_scanned=()
violations=""
alias_violations=""
for f in "${all_files[@]}"; do
  # Library/binary sources only. Integration tests under crates/*/tests/ are the law's judges.
  [[ "$f" == *"/src/"* ]] || continue
  # The delegated scope: crates/vmcell/src belongs to net/tap.rs's netns_layout_gate.
  [[ "$f" == *"$delegated_infix"* ]] && continue
  scanned=$((scanned + 1))
  # The crate name is the path component before `/src/`, for the verdict's breadth figure.
  owner="${f%%/src/*}"
  crates_scanned["${owner##*/}"]=1

  hit="$(scan "$f" "$needle")"
  [[ -n "${hit//[$'\n']/}" ]] && violations+="$hit"$'\n'
  if [[ -n "$alias_needle" ]]; then
    ahit="$(scan "$f" "$alias_needle")"
    [[ -n "${ahit//[$'\n']/}" ]] && alias_violations+="$ahit"$'\n'
  fi
done

# --- ARM 4: a complement gate whose complement is empty measures nothing ---------------------------
if [[ $scanned -eq 0 ]]; then
  echo "gate misconfigured: every Rust source under ${dirs[*]} is either outside a crate's src/ or"
  echo "inside the delegated ${delegated_infix#/} scope, so this scan opened nothing of its own."
  echo "Its whole job is the COMPLEMENT of net/tap.rs's netns_layout_gate; with an empty complement it"
  echo "would report 'ok' having checked no crate at all."
  exit 1
fi

failed=0
if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "The netns layout ($layout) is spelled inline outside its one law. Compose it from"
  echo "\`vmcell::net::tap::netns_path\` / \`netns_dir\` (AGENTS.md \"One law, one predicate\"; the law's"
  echo "own rustdoc claimed one spelling while four sites had their own). If the law is not reachable"
  echo "from this crate, widen the law — do not re-type the path:"
  printf '%s\n' "$violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ -n "${alias_violations//[$'\n']/}" ]]; then
  echo "The netns layout spelled through its ALIAS ($alias_layout): \`/var/run\` is conventionally a"
  echo "symlink to \`/run\`, so this names the same directory while matching no scan anchored on the"
  echo "law's own text — the alias class AGENTS.md's F3 rule names. Compose from"
  echo "\`vmcell::net::tap::netns_path\` / \`netns_dir\` instead:"
  printf '%s\n' "$alias_violations" | grep -vE '^[[:space:]]*$'
  failed=1
fi
if [[ $failed -ne 0 ]]; then exit 1; fi

alias_note="or its alias ($alias_layout)"
[[ -z "$alias_layout" ]] && alias_note="(no alias to derive: the law does not start with /var)"
echo "ok: no production site spells the netns layout ($layout) $alias_note inline —"
echo "scanned $scanned file(s) across ${#crates_scanned[@]} crate(s) under ${dirs[*]}, with"
echo "${delegated_infix#/} delegated to net/tap.rs's netns_layout_gate (which pins the law's own"
echo "roster both ways)"
