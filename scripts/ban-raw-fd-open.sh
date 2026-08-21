#!/usr/bin/env bash
# Enforces the O_CLOEXEC law on the fd-opening sites in `crates/vmcell/src/net_sys.rs`
# (AGENTS.md "Helper daemons and the broker child: spawn with `PR_SET_PDEATHSIG` + `CLOEXEC`").
#
# THE LAW. `net_sys::create_tap_in_current_netns` opens `/dev/net/tun` through
# `std::fs::OpenOptions`, which sets `O_CLOEXEC` unconditionally. C's `open(2)` does not. That
# difference is load-bearing, not hygiene: `vmcelld` fork/execs VMMs and forks the broker
# CONCURRENTLY with this call, and a leaked `/dev/net/tun` fd is an *attached tap queue* — the VMM's
# own `TUNSETIFF` on the same tap then fails `EBUSY`, which is verbatim the "Open tap device failed:
# Device or resource busy" that `create_persistent_tap_in_ns`'s persist-then-drop dance exists to
# prevent. The behavior is byte-identical to the `tun-tap` crate this replaced (its open was Rust's
# too); what CHANGED is that the open is now in vmcell's own source, so it is now possible to
# "tidy" it into a raw `libc::open` beside the `libc::ioctl` next to it and regress it invisibly.
#
# WHY A GREP GATE. The drift is not a compile error — `libc::open` compiles fine and the tap still
# comes up — and it is not observable from a test either: the failure needs a concurrent fork/exec
# to race the open, and `create_tap_in_current_netns` is `pub(crate)`, so there is no live leg that
# could hold the property. AGENTS.md's rule for exactly this shape is a grep-ban plus a
# red-on-inverse self-test.
#
# WHAT IT FLAGS (line comments stripped first, so the rustdoc above the law — which names
# `libc::open` as the thing not to write — is never a false positive): a call-shaped `open`,
# `open64`, `openat` or `openat2` reached through `libc::`/`nix::`, in any scanned file. It
# deliberately does NOT flag `OpenOptions::new().open(..)` or `File::open(..)`, which are the
# CLOEXEC-setting spellings this law prescribes: the pattern requires the `libc::`/`nix::` path
# qualifier, so a method call on a Rust type never matches.
#
# SCOPE, AND WHY IT IS A COMPLEMENT RATHER THAN A SECOND COPY. `net_sys.rs` is the only module in
# `crates/vmcell` that may write `unsafe` at all on the net path (`net/mod.rs` is
# `#![forbid(unsafe_code)]` and covers `net::tap`), so a raw open *elsewhere* in `net/` is already a
# compile error and this gate would be restating it. The scan therefore covers the whole of
# `crates/` — a raw open in another crate is not this law's business and is not flagged, because the
# pattern is anchored on the sanctioned file's own roster below.
#
# Usage: ban-raw-fd-open.sh [DIR ...]   (defaults to the workspace member trees under crates/)
# A roster that resolves to zero Rust sources is a caller bug and exits 1 — never a reassuring "ok"
# (docs/90 G4).
set -euo pipefail

dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
  dirs=(crates)
fi

# The file the law lives in. It must be present and must still hold the `OpenOptions` open, or the
# ban is guarding a site that moved — reported as a misconfiguration, never a pass.
LAW_FILE="/vmcell/src/net_sys.rs"
LAW_NEEDLE="OpenOptions"

mapfile -d '' -t files < <(
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && find "$d" -type f -name '*.rs' -print0
  done
)
# An empty scan is a MISCONFIGURATION, never a clean tree: the only way to match zero Rust sources is
# to have been pointed at the wrong place (a move/reorg, or an explicit-path typo).
[[ ${#files[@]} -eq 0 ]] && {
  echo "gate misconfigured: no Rust sources under: ${dirs[*]}"
  echo "The scan would be vacuous — every source-scanning gate dies this way."
  exit 1
}

law_seen=0
law_has_openoptions=0
violations=""

for f in "${files[@]}"; do
  if [[ "$f" == *"$LAW_FILE" ]]; then
    law_seen=1
    # Comments stripped: the rustdoc names `OpenOptions` in prose too, and a gate that accepted the
    # prose as the site would stay green over a file whose code no longer opens anything.
    if awk '{ code = $0; sub(/\/\/.*/, "", code); if (code ~ /OpenOptions/) found = 1 }
            END { exit found ? 0 : 1 }' "$f"; then
      law_has_openoptions=1
    fi
  fi
  # Only the sanctioned file is held to this law; see SCOPE above.
  [[ "$f" == *"$LAW_FILE" ]] || continue
  hit="$(awk -v FN="$f" '
    {
      code = $0
      sub(/\/\/.*/, "", code)   # drop the line comment before matching (the rustdoc names libc::open)
      if (code ~ /(libc|nix[A-Za-z0-9_:]*)::[[:space:]]*open(at2?|64)?[[:space:]]*\(/) {
        print FN ":" FNR ": " $0
      }
    }
  ' "$f")"
  [[ -n "${hit//[$'\n']/}" ]] && violations+="$hit"$'\n'
done

if [[ $law_seen -eq 0 ]]; then
  echo "gate misconfigured: ${LAW_FILE} not found under: ${dirs[*]}"
  echo "This ban is anchored on that file; if it moved, move the anchor with it."
  exit 1
fi
if [[ $law_has_openoptions -eq 0 ]]; then
  echo "gate misconfigured: ${LAW_FILE} no longer contains \`${LAW_NEEDLE}\`"
  echo "The law this ban enforces is that the fd open there goes through OpenOptions (O_CLOEXEC)."
  echo "Either the open moved — move this anchor — or it was replaced, which is the defect itself."
  exit 1
fi

if [[ -n "${violations//[$'\n']/}" ]]; then
  echo "raw fd-open syscall in the module that must set O_CLOEXEC:"
  printf '%s' "$violations"
  echo
  echo "Use std::fs::OpenOptions/File::open, which set O_CLOEXEC unconditionally. A raw libc::open"
  echo "does not, and vmcelld fork/execs VMMs concurrently with this call: a leaked /dev/net/tun fd"
  echo "is an attached tap queue, so the VMM's own TUNSETIFF fails EBUSY."
  exit 1
fi

echo "ok: ${LAW_FILE#/} opens its fds through ${LAW_NEEDLE} (O_CLOEXEC); no raw libc/nix open"
echo "    (scanned: ${dirs[*]}, $(printf '%s\n' "${files[@]}" | grep -c '') Rust file(s))"
