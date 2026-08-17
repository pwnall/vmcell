#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-inline-setns.sh (review S2 / delta 8 "one law, one
# predicate"). Builds fixture trees that mirror the real crate layout (the exemptions are path
# suffixes, so the layout is load-bearing) and asserts all four halves of the scanner:
#   * deleting the `setns(` pattern leaves the inline-call fixtures un-flagged  → this test reddens;
#   * deleting the >1-call check lets a SECOND call inside a sanctioned file pass → reddens;
#   * deleting the stale-exemption check lets a moved/emptied sanctioned site pass → reddens;
#   * deleting the netns_rs arm lets a `NetNs::run`/`enter` (a setns reached through the dependency,
#     review m14) pass → reddens, while `rt.enter()` in a non-netns_rs file must stay un-flagged;
#   * restoring the permissive empty-scan arm lets a Rust-less tree report "ok" → reddens (docs/90 G4).
# The last two exist for the reason PRIV-4 added the bare-Mutex/OnceLock fixtures to
# test-ban-global-state.sh: without them the exempt-file half of the gate could not fail at all.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-inline-setns.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline every fixture starts from: both sanctioned sites with exactly one raw call, plus
# the legitimate non-call spellings that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/vmm" "$root/vmcell/src/net" "$root/vmcell-broker/src"
  # Sanctioned site 1 — the one home (net_sys::setns_net), with the SAFETY prose that must be
  # comment-stripped before matching.
  {
    # shellcheck disable=SC2016  # the backticks are literal Rust comment text, not shell expansion (intended)
    printf '// SAFETY: `setns(2)` on `fd`, borrowed from a live `File` for the call.\n'
    printf 'pub(crate) fn setns_net(fd: RawFd) -> io::Result<()> {\n'
    printf '    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };\n'
    printf '    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }\n}\n'
  } > "$root/vmcell/src/net_sys.rs"
  # Sanctioned site 2 — build_vmm_cmd's pre_exec (async-signal-safe between fork and execve).
  {
    printf 'fn pre_exec() -> std::io::Result<()> {\n'
    printf '    if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 { return Err(e); }\n'
    printf '    Ok(())\n}\n'
  } > "$root/vmcell/src/vmm/mod.rs"
  # MUST NOT be flagged: the sanctioned wrapper call (a longer identifier).
  printf 'fn dial() { crate::net_sys::setns_net(ns.as_raw_fd()).map_err(|e| e)?; }\n' \
    > "$root/vmcell/src/net/segment.rs"
  # MUST NOT be flagged: the seccomp allow-list names the syscall, it does not call it; and an
  # error string mentioning setns has no call parenthesis.
  {
    printf 'const ALLOW: &[(&str, i64)] = &[("setns", libc::SYS_setns)];\n'
    printf 'fn f() { let _ = enter_netns(&file, "Failed to setns"); }\n'
  } > "$root/vmcell/src/vmm/jail.rs"
  # MUST NOT be flagged: a doc comment writing the syscall in call form.
  # shellcheck disable=SC2016  # the backticks are literal Rust doc text, not shell expansion (intended)
  printf '//! `setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN` in the owning user namespace.\nfn f() {}\n' \
    > "$root/vmcell-broker/src/lib.rs"
  # MUST NOT be flagged by the netns_rs arm: the crate's non-thread-moving API (get/new/remove) in
  # the one file that legitimately uses it, next to the dedicated-thread helper every move goes
  # through — plus a `run_in_tokio(`/`run_with_rtnetlink(` call whose name merely BEGINS with `run`.
  {
    printf 'fn del(netns: &str) -> Result<()> {\n'
    printf '    let ns = netns_rs::NetNs::get(netns)?;\n'
    printf '    ns.remove()?;\n'
    printf '    in_netns(netns, || run_in_tokio(|| async { Ok(()) }))\n}\n'
  } > "$root/vmcell/src/net/tap.rs"
  # MUST NOT be flagged: `rt.enter()` in a file that has nothing to do with netns_rs (the arm is
  # scoped to files whose code names the crate, so a runtime guard is not a false positive).
  printf 'fn t() { let rt = Runtime::new().unwrap(); let _g = rt.enter(); }\n' \
    > "$root/vmcell/src/net/smoltcp.rs"
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: a new inline call outside the sanctioned sites MUST be flagged ------------------------
mk_clean_tree "$work/bad"
mkdir -p "$work/bad/vmcell/src/proxy" "$work/bad/vmcell-daemon/src"
# The exact S2 regression: a third `unsafe { libc::setns }` with its own hand-written SAFETY proof.
printf 'fn enter() {\n    // SAFETY: setns on a netns fd.\n    if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 { return Err(e); }\n}\n' \
  > "$work/bad/vmcell/src/proxy/mod.rs"
# The same law broken through a different crate's spelling (no `libc::` prefix, no `unsafe` on the line).
printf 'fn enter(fd: RawFd) { nix::sched::setns(fd, CloneFlags::CLONE_NEWNET)?; }\n' \
  > "$work/bad/vmcell-daemon/src/bridge.rs"
run_ban "$work/bad"
expect_rc 1 "inline call outside the sanctioned sites"
expect_flag 'proxy/mod.rs'
expect_flag 'bridge.rs'
expect_clean 'net_sys.rs'
expect_clean 'vmm/mod.rs'
expect_clean 'segment.rs'
expect_clean 'jail.rs'
expect_clean 'lib.rs'
expect_clean 'tap.rs'
expect_clean 'smoltcp.rs'
[[ $fail -ne 0 ]] && dump "case 1"

# --- Case 2: the sanctioned tree alone MUST pass (the positive control) ---------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
before=$fail
expect_rc 0 "sanctioned sites only"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the sanctioned tree"; fail=1; fi
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: a SECOND call inside a sanctioned file is a new site wearing an old exemption --------
mk_clean_tree "$work/extra"
printf 'fn other() { unsafe { libc::setns(fd2, libc::CLONE_NEWNET) }; }\n' >> "$work/extra/vmcell/src/vmm/mod.rs"
run_ban "$work/extra"
before=$fail
expect_rc 1 "second call inside a sanctioned file"
expect_flag 'vmm/mod.rs'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a sanctioned site that no longer calls setns is a STALE exemption, not a pass --------
mk_clean_tree "$work/stale"
printf 'pub(crate) fn setns_net(fd: RawFd) -> io::Result<()> { unimplemented!() }\n' \
  > "$work/stale/vmcell/src/net_sys.rs"
run_ban "$work/stale"
before=$fail
expect_rc 1 "emptied sanctioned site"
expect_flag 'exempted but calls no setns'
expect_flag '/vmcell/src/net_sys.rs'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: a sanctioned site that moved away is the same stale exemption ------------------------
mk_clean_tree "$work/moved"
rm "$work/moved/vmcell/src/net_sys.rs"
run_ban "$work/moved"
before=$fail
expect_rc 1 "moved sanctioned site"
expect_flag 'no such file'
[[ $fail -ne $before ]] && dump "case 5"

# --- Case 6: a `setns` reached through netns_rs is the same law broken (review m14) --------------
# `NetNs::run`/`run_in`/`enter` move the CALLING thread — invisible to the raw-`setns(` arm, which
# is exactly how seven pooled-tokio-worker namespace moves survived this gate. Both spellings must
# be flagged, in a file the raw arm reports as clean.
mk_clean_tree "$work/dep"
mkdir -p "$work/dep/vmcell-daemon/src"
{
  printf 'fn setup(netns: &str) {\n'
  printf '    let ns = netns_rs::NetNs::get(netns).unwrap();\n'
  printf '    let _ = ns.run(move |_| do_netlink_work());\n'
  printf '}\n'
} > "$work/dep/vmcell/src/net/route.rs"
{
  printf 'use netns_rs::NetNs;\n'
  printf 'fn enter_it(name: &str) { NetNs::run_in(name, |_| ()).unwrap(); }\n'
  printf 'fn enter_direct(ns: &NetNs) { ns.enter().unwrap(); }\n'
} > "$work/dep/vmcell-daemon/src/netns_helper.rs"
run_ban "$work/dep"
before=$fail
expect_rc 1 "netns_rs thread-moving call outside in_netns"
expect_flag 'route.rs'
expect_flag 'netns_helper.rs'
expect_flag 'net::tap::in_netns'
# The clean tree's legitimate netns_rs usage (get/remove) and the unrelated `rt.enter()` stay clean.
expect_clean 'tap.rs'
expect_clean 'smoltcp.rs'
[[ $fail -ne $before ]] && dump "case 6"

# --- Case 7: a tree with no Rust at all is a misconfiguration, not a pass -------------------------
# G4: this arm used to print "ok: no Rust sources under: …" and exit 0 BEFORE the stale-exemption
# report below could run, so a moved crate tree (or a typo'd explicit path) reported success having
# opened no file. Restoring that arm reddens this case.
mkdir -p "$work/nosrc/vmcell/src"
printf 'not rust\n' > "$work/nosrc/vmcell/src/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 7"

if [[ $fail -ne 0 ]]; then
  echo "ban-inline-setns self-test FAILED"
  exit 1
fi
echo "ok: ban-inline-setns self-test passed"
