#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-inline-netns-path.sh (AGENTS.md "One law, one predicate",
# the netns-layout law `vmcell::net::tap::NETNS_DIR`). Builds fixture trees that mirror the real crate
# layout — the law's home and the delegated scope are path suffixes, so the layout is load-bearing —
# and asserts every arm of the scanner:
#   * deleting the layout arm lets an inline `"/var/run/netns/…"` in another crate pass  → this reddens;
#   * deleting the ALIAS arm lets `"/run/netns/…"` (the same directory through the `/var` symlink)
#     pass, which is the shape no scan anchored on the law's own text can see → reddens;
#   * dropping the delegation checks lets the gate skip crates/vmcell/src with no in-source gate left
#     owning it (law file gone, `NETNS_DIR` gone, `netns_layout_gate` gone) → reddens;
#   * restoring a permissive empty-scan arm lets a Rust-less tree, or a tree that is ONLY the
#     delegated crate, report "ok" → reddens (docs/90 G4: a complement gate with an empty complement).
# The must-stay-clean fixtures are the reason the flagged ones mean anything: prose naming the path, a
# unit-test module recomputing it (the law's judge), an integration test under tests/, and the
# delegated crate's own two sanctioned compositions.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-inline-netns-path.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline every fixture starts from: the law's home with its const and its in-source gate,
# plus the legitimate spellings elsewhere that must never be flagged.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/vmcell/src/net" "$root/vmcell/tests" \
           "$root/vmcell-daemon/src" "$root/vmcell-privilege/src" \
           "$root/vmcell-broker/src" "$root/vmcelld/src" "$root/vmcelld/tests"
  # THE LAW's home: the const this gate reads its needle out of, the two sanctioned compositions, and
  # the in-source gate module that owns this crate's src (so the delegation has an owner).
  {
    printf 'const NETNS_DIR: &str = "/var/run/netns";\n'
    printf 'pub(crate) fn netns_dir() -> &%sstatic std::path::Path { std::path::Path::new(NETNS_DIR) }\n' "'"
    printf 'pub(crate) fn netns_path(name: &str) -> std::path::PathBuf { netns_dir().join(name) }\n'
    printf '#[cfg(test)]\nmod netns_layout_gate {\n    const ROSTER: &[(&str, usize)] = &[("net/tap.rs", 1)];\n}\n'
  } > "$root/vmcell/src/net/tap.rs"
  # The delegated crate's OTHER files: a second composition here is netns_layout_gate's finding, not
  # this gate's — it must stay clean here even though the literal is present.
  printf 'fn enter(netns: &str) { let p = std::path::Path::new("/var/run/netns").join(netns); }\n' \
    > "$root/vmcell/src/delegated_holdout.rs"
  # MUST NOT be flagged: another crate composing through the law by NAME.
  printf 'fn setup(netns: &str) { let p = vmcell::net::tap::netns_path(netns); }\n' \
    > "$root/vmcell-daemon/src/bridge.rs"
  # MUST NOT be flagged: prose. vmcell-privilege's real rustdoc names the path as the bind-mount
  # target CAP_DAC_OVERRIDE is needed for.
  # shellcheck disable=SC2016  # the backticks are literal Rust doc text, not shell expansion (intended)
  printf '/// - `CAP_DAC_OVERRIDE` — the `netns_rs` bind-mount target under `/var/run/netns`\npub const CAPS: u8 = 3;\n' \
    > "$root/vmcell-privilege/src/lib.rs"
  # MUST NOT be flagged: a unit-test module recomputing the layout independently — the law's JUDGE
  # (this is exactly what tap.rs's own tests and vmcelld's residue checks do).
  {
    printf 'fn teardown(netns: &str) { vmcell::net::tap::delete_netns(netns); }\n'
    printf 'mod tests {\n'
    printf '    #[test]\n    fn residue_is_gone() {\n'
    printf '        assert!(!std::path::Path::new("/var/run/netns").join("vmcell-1").exists());\n'
    printf '    }\n}\n'
  } > "$root/vmcell-broker/src/lib.rs"
  # MUST NOT be flagged: an integration test under tests/ (out of scope by the same reasoning).
  printf 'fn netns_exists(name: &str) -> bool { Path::new("/var/run/netns").join(name).exists() }\n' \
    > "$root/vmcelld/tests/integration.rs"
  printf 'fn netns_exists(name: &str) -> bool { Path::new("/var/run/netns").join(name).exists() }\n' \
    > "$root/vmcell/tests/lifecycle.rs"
  # A plain non-violating source in a crate that must be counted as scanned.
  printf 'fn main() { println!("vmcelld"); }\n' > "$root/vmcelld/src/main.rs"
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

# --- Case 1: the clean tree MUST pass (the positive control) ---------------------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
before=$fail
expect_rc 0 "clean tree"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
# The verdict must name the breadth it actually reached: a complement gate that scanned one file is
# not the same claim as one that scanned every other crate.
if ! grep -qE 'scanned [0-9]+ file\(s\) across [0-9]+ crate\(s\)' <<<"$out"; then
  echo "FAIL: the verdict must state how much it scanned"; fail=1
fi
[[ $fail -ne $before ]] && dump "case 1"

# --- Case 2: an inline layout literal in another crate's src MUST be flagged ------------------------
# The exact shape the closed holdouts had, in a crate the in-source gate cannot see.
mk_clean_tree "$work/bad"
printf 'fn sweep() { for e in std::fs::read_dir("/var/run/netns").unwrap() { drop(e); } }\n' \
  > "$work/bad/vmcell-daemon/src/sweep.rs"
printf 'fn open_ns(n: &str) { let p = format!("/var/run/netns/{n}"); let _ = std::fs::File::open(p); }\n' \
  > "$work/bad/vmcelld/src/spawn.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "inline layout literal outside the delegated crate"
expect_flag 'sweep.rs'
expect_flag 'spawn.rs'
expect_flag 'netns_path'
# Everything legitimate stays clean, including the delegated crate's own holdout.
expect_clean 'delegated_holdout.rs'
expect_clean 'bridge.rs'
expect_clean 'vmcell-privilege'
expect_clean 'vmcell-broker'
expect_clean 'integration.rs'
expect_clean 'lifecycle.rs'
[[ $fail -ne $before ]] && dump "case 2"

# --- Case 3: the ALIAS spelling is the same law broken ---------------------------------------------
# `/var/run` is conventionally a symlink to `/run` (hostcaps probes either), so this reaches the same
# directory while matching nothing anchored on the law's text. Deleting the alias arm reddens here.
mk_clean_tree "$work/alias"
printf 'fn open_ns(n: &str) { let _ = std::fs::File::open(format!("/run/netns/{n}")); }\n' \
  > "$work/alias/vmcell-broker/src/spawn.rs"
run_ban "$work/alias"
before=$fail
expect_rc 1 "the /run/netns alias"
expect_flag 'spawn.rs'
expect_flag 'ALIAS'
[[ $fail -ne $before ]] && dump "case 3"

# --- Case 4: a `/run` literal that is NOT the netns layout must stay clean --------------------------
# hostcaps' reachability probe reads `/run` and `/var/run` as directories; neither is a netns path,
# and flagging them would make the alias arm a false-positive generator instead of a gate.
mk_clean_tree "$work/runprobe"
printf 'fn reachable() -> bool { std::path::Path::new("/run").is_dir() || std::path::Path::new("/var/run").is_dir() }\n' \
  > "$work/runprobe/vmcell-daemon/src/probe.rs"
run_ban "$work/runprobe"
before=$fail
expect_rc 0 "a bare /run reachability probe"
expect_clean 'probe.rs'
[[ $fail -ne $before ]] && dump "case 4"

# --- Case 5: the delegation must have an owner (three ways it can go stale) ------------------------
# The gate skips crates/vmcell/src BECAUSE netns_layout_gate covers it. Each of these leaves that
# scope owned by nothing, which is worse than a violation: a whole crate silently unchecked.
mk_clean_tree "$work/nolaw"
rm "$work/nolaw/vmcell/src/net/tap.rs"
run_ban "$work/nolaw"
before=$fail
expect_rc 1 "the law's file moved away"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 5a"

mk_clean_tree "$work/noconst"
printf 'pub(crate) fn netns_path(name: &str) -> std::path::PathBuf { somewhere(name) }\n#[cfg(test)]\nmod netns_layout_gate {}\n' \
  > "$work/noconst/vmcell/src/net/tap.rs"
run_ban "$work/noconst"
before=$fail
expect_rc 1 "NETNS_DIR gone, so the needle would be empty"
expect_flag 'gate misconfigured'
expect_flag 'NETNS_DIR'
[[ $fail -ne $before ]] && dump "case 5b"

mk_clean_tree "$work/nogate"
printf 'const NETNS_DIR: &str = "/var/run/netns";\npub(crate) fn netns_path(n: &str) -> std::path::PathBuf { std::path::Path::new(NETNS_DIR).join(n) }\n' \
  > "$work/nogate/vmcell/src/net/tap.rs"
run_ban "$work/nogate"
before=$fail
expect_rc 1 "the in-source gate that owns the delegated scope is gone"
expect_flag 'gate misconfigured'
expect_flag 'netns_layout_gate'
[[ $fail -ne $before ]] && dump "case 5c"

# --- Case 6: the vacuous-scan legs ----------------------------------------------------------------
# G4: a source-scanning gate that opens nothing must never print `ok:`. For a COMPLEMENT gate there
# are two ways to open nothing, and the second is the interesting one: a tree that is only the
# delegated crate scans zero files of its own while every delegation check still passes.
mkdir -p "$work/nosrc/vmcell-daemon/src"
printf 'not rust\n' > "$work/nosrc/vmcell-daemon/src/README.md"
run_ban "$work/nosrc"
before=$fail
expect_rc 1 "no Rust sources in the scanned tree"
expect_flag 'gate misconfigured'
[[ $fail -ne $before ]] && dump "case 6a"

mkdir -p "$work/onlylaw/vmcell/src/net"
cp "$work/good/vmcell/src/net/tap.rs" "$work/onlylaw/vmcell/src/net/tap.rs"
cp "$work/good/vmcell/src/delegated_holdout.rs" "$work/onlylaw/vmcell/src/delegated_holdout.rs"
run_ban "$work/onlylaw"
before=$fail
expect_rc 1 "the complement is empty (only the delegated crate present)"
expect_flag 'gate misconfigured'
expect_flag 'COMPLEMENT'
[[ $fail -ne $before ]] && dump "case 6b"

if [[ $fail -ne 0 ]]; then
  echo "ban-inline-netns-path self-test FAILED"
  exit 1
fi
echo "ok: ban-inline-netns-path self-test passed"
