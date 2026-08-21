#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-raw-fd-open.sh (AGENTS.md rule 2: "Write the red-on-inverse
# first; a gate whose self-test cannot fail is theater").
#
# Drives the REAL script against fixture trees mirroring the crate layout — never a restatement of
# its logic — so a change to the scanner's pattern is caught here rather than by review.
#
# Cases:
#   1 clean fixture (OpenOptions, no raw open)                       -> exit 0, ok:
#   2 libc::open beside the ioctl                                    -> exit 1, names the violation
#   3 libc::open64 / nix::fcntl::open / openat / openat2             -> exit 1 (every spelling)
#   4 libc::open in a COMMENT, and OpenOptions/File::open in code     -> exit 0 (no false positive)
#   5 the anchored file is gone (renamed/moved)                      -> exit 1, gate misconfigured
#   6 the anchored file lost its OpenOptions open                    -> exit 1, gate misconfigured
#   7 a raw open in ANOTHER crate                                    -> exit 0 (out of this law's scope)
#   8 empty tree                                                     -> exit 1, gate misconfigured
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-raw-fd-open.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
out=""
rc=0

run_ban() { set +e; out="$("$ban" "$1" 2>&1)"; rc=$?; set -e; }
expect_rc() {
  if [[ $rc -ne $1 ]]; then
    echo "FAIL [$2]: expected exit $1, got $rc"
    printf '%s\n' "$out" | sed 's/^/       /'
    fail=1
  fi
}
expect_flag() {
  if ! grep -q -- "$1" <<<"$out"; then
    echo "FAIL [$2]: output did not mention '$1'"
    printf '%s\n' "$out" | sed 's/^/       /'
    fail=1
  fi
}

# A fixture tree whose net_sys.rs body is $2, under root $1.
make_tree() {
  local root="$1" body="$2"
  mkdir -p "$root/vmcell/src"
  printf '%s\n' "$body" > "$root/vmcell/src/net_sys.rs"
  mkdir -p "$root/vmcell/src/net"
  echo 'pub fn unrelated() {}' > "$root/vmcell/src/net/tap.rs"
}

# --- Case 1: clean -------------------------------------------------------------------------------
t="$work/c1"
make_tree "$t" 'fn open_tun() {
    let tun = std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun").unwrap();
    let _ = unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, p) };
}'
run_ban "$t"
expect_rc 0 "case 1 clean"
expect_flag "ok:" "case 1 clean"

# --- Case 2: libc::open --------------------------------------------------------------------------
t="$work/c2"
make_tree "$t" 'fn open_tun() {
    let _opts = std::fs::OpenOptions::new();
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
}'
run_ban "$t"
expect_rc 1 "case 2 libc::open"
expect_flag "raw fd-open syscall" "case 2 libc::open"
expect_flag "EBUSY" "case 2 libc::open"

# --- Case 3: every other raw spelling ------------------------------------------------------------
for spelling in 'libc::open64(p, f)' 'nix::fcntl::open(p, f, m)' 'libc::openat(d, p, f)' 'libc::openat2(d, p, f, s)'; do
  t="$work/c3"
  rm -rf "$t"
  make_tree "$t" "fn open_tun() {
    let _opts = std::fs::OpenOptions::new();
    let fd = unsafe { $spelling };
}"
  run_ban "$t"
  expect_rc 1 "case 3 $spelling"
  expect_flag "raw fd-open syscall" "case 3 $spelling"
done

# --- Case 4: comments and the prescribed spellings are not violations ----------------------------
t="$work/c4"
make_tree "$t" '/// A raw libc::open here would reintroduce the leak. Never write libc::open(..).
fn open_tun() {
    // libc::open(path, libc::O_RDWR) is what NOT to do.
    let a = std::fs::OpenOptions::new().read(true).open("/dev/net/tun").unwrap();
    let b = std::fs::File::open("/dev/net/tun").unwrap();
}'
run_ban "$t"
expect_rc 0 "case 4 comments + prescribed spellings"
expect_flag "ok:" "case 4 comments + prescribed spellings"

# --- Case 5: the anchored file moved -------------------------------------------------------------
t="$work/c5"
mkdir -p "$t/vmcell/src"
echo 'fn elsewhere() {}' > "$t/vmcell/src/other.rs"
run_ban "$t"
expect_rc 1 "case 5 anchor missing"
expect_flag "gate misconfigured" "case 5 anchor missing"
expect_flag "not found under" "case 5 anchor missing"

# --- Case 6: the anchored file lost its OpenOptions open -----------------------------------------
t="$work/c6"
make_tree "$t" 'fn no_open_here() {
    let _ = unsafe { libc::ioctl(fd, libc::TUNSETPERSIST, 1) };
}'
run_ban "$t"
expect_rc 1 "case 6 anchor lost its open"
expect_flag "gate misconfigured" "case 6 anchor lost its open"
expect_flag "no longer contains" "case 6 anchor lost its open"

# --- Case 7: another crate is out of scope -------------------------------------------------------
t="$work/c7"
make_tree "$t" 'fn open_tun() {
    let tun = std::fs::OpenOptions::new().read(true).open("/dev/net/tun").unwrap();
}'
mkdir -p "$t/vmcell-steward/src"
echo 'fn f() { let fd = unsafe { libc::open(p, 0) }; }' > "$t/vmcell-steward/src/netif.rs"
run_ban "$t"
expect_rc 0 "case 7 other crate out of scope"
expect_flag "ok:" "case 7 other crate out of scope"

# --- Case 8: empty tree is a misconfiguration, never a pass (docs/90 G4) --------------------------
t="$work/c8"
mkdir -p "$t"
run_ban "$t"
expect_rc 1 "case 8 empty tree"
expect_flag "gate misconfigured" "case 8 empty tree"
expect_flag "vacuous" "case 8 empty tree"

if [[ $fail -ne 0 ]]; then
  echo "ban-raw-fd-open self-test FAILED"
  exit 1
fi
echo "ok: ban-raw-fd-open self-test passed (7 violation/misconfiguration shapes flagged, 3 compliant"
echo "    shapes silent, incl. the empty-tree and moved/hollowed-anchor refusals — docs/90 G4)"
