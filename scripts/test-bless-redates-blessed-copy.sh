#!/usr/bin/env bash
# Red-on-inverse self-test for the `bless` recipe's ANTI-WEDGE: `just bless` must leave the stable
# blessed copy dated no earlier than the moment it established that copy IS the current build.
#
# WHY THIS EXISTS. docs/90 G9 gave `scripts/review-preflight-priv.sh` a cargo-free way to answer "is
# the blessed runner the build under review?" — a content-hash `.blessed` stamp plus a `find -newer`
# mtime proxy over the runner's source closure (crates/vmcell-test-runner/src,
# crates/vmcell-privilege/src, Cargo.lock). The proxy is deliberately conservative: it may call a
# touched-but-unchanged tree STALE, because a false CURRENT certifies the wrong binary for a whole
# privileged review while a false STALE costs one `just bless`.
#
# That trade only holds if `just bless` can actually CLEAR a false STALE. It could not. The recipe's
# idempotence skip fires when the freshly built runner's sha256 equals the stamp — the AUTHORITATIVE
# answer, strictly better than the proxy — and it then replaced nothing, so the stable copy kept its
# old mtime and the preflight kept reporting STALE. A comment-only edit, or a bare directory-mtime bump
# from a temp file (which cargo does not even rebuild for), was enough to pin the documented reviewer
# path at BLOCKED-ON-BLESS permanently: preflight says "ask the maintainer to run `just bless`", the
# maintainer runs it, the verdict does not move. AGENTS.md "probe, don't presume" routes every
# privileged review through that probe, so a wedged probe is a review that cannot start.
#
# The fix — `redate_for_freshness_proxy` at BOTH exits where the hash is known to match — landed in the
# justfile with no gate. AGENTS.md rule 1: a fix for a defect a human found lands WITH its gate. This
# is that gate, and it has no partner ban script: the law is behavioural, not textual, so it is proven
# by RUNNING the real recipe against the real preflight.
#
# HOW IT IS EXERCISED, and why nothing is restated. A self-test that re-implemented the recipe's logic
# would gate its own copy (the hand-copy class, AGENTS.md rule 3). Instead each leg builds a throwaway
# fixture repo, copies the REAL justfile and the REAL scripts/review-preflight-priv.sh into it, and
# runs `just bless` there with `cargo`/`getcap`/`sudo`/`cp` stubbed on PATH. The detector is the real
# preflight's own freshness verdict. The inverse legs delete ONE named line from the fixture's copy of
# the justfile — never from the repo's — and require the wedge to come back.
#
# The stub `cargo` mimics the hazardous case: a REBUILD WHOSE OUTPUT IS BYTE-IDENTICAL (the comment-only
# edit), so only mtimes move and the recipe's hash check takes the skip path. The stub `sudo` REFUSES
# on the skip legs, which is how those legs prove no setcap was reached; the re-bless legs get a
# pretending stub. Nothing here elevates: this whole path is a readiness probe, not a security boundary
# (the runner's real file caps + 0700 mode are, PRIV-1).
#
# GUARANTEES: no cargo, no sudo, no KVM, and the repo's own ./.vmcell-bin is never touched — asserted
# at the end, not assumed. The fixture tree is cleaned on the panic path as well as the success path.
#
# Usage: test-bless-redates-blessed-copy.sh [ROOT]   (defaults to the repo root above this script)
set -euo pipefail

root="${1:-}"
if [[ -z "$root" ]]; then
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
if [[ ! -d "$root" ]]; then
  echo "gate misconfigured: no such root directory: $root" >&2
  exit 1
fi
root="$(cd "$root" && pwd)"

justfile="$root/justfile"
preflight="$root/scripts/review-preflight-priv.sh"
for f in "$justfile" "$preflight"; do
  if [[ ! -f "$f" ]]; then
    echo "gate misconfigured: expected file does not exist: $f" >&2
    echo "This gate runs the REAL recipe against the REAL preflight; with either missing there is" >&2
    echo "nothing to exercise and a green verdict would mean nothing." >&2
    exit 1
  fi
done
if ! command -v just >/dev/null 2>&1; then
  echo "gate misconfigured: \`just\` is not on PATH, so the \`bless\` recipe cannot be run at all." >&2
  echo "This gate is invoked BY the \`gates\` recipe, so a missing \`just\` means the caller is not the" >&2
  echo "recipe — install just (CI: taiki-e/install-action) rather than skipping the check." >&2
  exit 1
fi
if ! just --justfile "$justfile" --working-directory "$root" --show bless >/dev/null 2>&1; then
  echo "gate misconfigured: the justfile at $justfile has no \`bless\` recipe." >&2
  echo "That recipe is the subject of this gate — the blessed runner's one install path." >&2
  exit 1
fi

# The two re-dating call sites, by the exact text the inverse legs delete. Named here (not inlined at
# the legs) so a rename of the helper produces ONE clear failure instead of two silent no-op deletions:
# a `grep -v` that removes nothing leaves the fixture identical to the green one, and the leg would then
# fail with a confusing "expected STALE, got CURRENT".
# shellcheck disable=SC2016  # literal justfile TEXT to grep for, not shell expansion (intended)
redate_skip_site='redate_for_freshness_proxy "$stable" "$stamp"'
# shellcheck disable=SC2016  # same: the `$tmp` is the recipe's own variable name, matched verbatim
redate_rebless_site='redate_for_freshness_proxy "$tmp"'

# THE REPO'S OWN BLESSED RUNNER IS OFF LIMITS. Its state is fingerprinted here and re-checked at the
# end: this gate runs in `just ci` on a developer's box, where that binary carries live capabilities and
# a review may be mid-flight. A gate that re-dated it would corrupt the very signal it defends.
fingerprint_real_bindir() {
  local p out=""
  for p in "$root/.vmcell-bin/debug/vmcell-test-runner" "$root/.vmcell-bin/debug/.blessed" \
           "$root/.vmcell-bin/release/vmcell-test-runner" "$root/.vmcell-bin/release/.blessed"; do
    if [[ -e "$p" ]]; then
      out+="$p $(stat -c '%a %s %Y' "$p")"$'\n'
    else
      out+="$p ABSENT"$'\n'
    fi
  done
  printf '%s' "$out"
}
real_before="$(fingerprint_real_bindir)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

# Every mtime is set EXPLICITLY, never inherited from creation order, so the newer/older relation the
# preflight reads is a property of the fixture and not of how fast this ran.
blessed_at='2026-08-10 00:00:00'   # when the (fixture) blessing happened
edited_at='2026-08-12 00:00:00'    # a source edited AFTER it — the wedge's premise

# --- PATH stubs -----------------------------------------------------------------------------------
stubs="$work/stubs"; mkdir -p "$stubs"
# A rebuild whose output is BYTE-IDENTICAL to the blessed copy: only mtimes move, so the recipe's
# sha256 comparison takes the idempotence skip. That is the exact input the wedge needed.
cat > "$stubs/cargo" <<'STUB'
#!/usr/bin/env bash
mkdir -p target/debug target/release
printf 'RUNNER-CONTENT-C\n' > target/debug/vmcell-test-runner
printf 'RUNNER-CONTENT-C\n' > target/release/vmcell-test-runner
chmod 0755 target/debug/vmcell-test-runner target/release/vmcell-test-runner
echo "[stub cargo] $*"
STUB
# The fixture's stable copy "carries" the four blessed caps with the effective bit, so the preflight's
# `check_runner` (which the recipe also calls, via --check-runner) reads it as blessed and the ONLY
# remaining verdict input is freshness.
cat > "$stubs/getcap" <<'STUB'
#!/usr/bin/env bash
printf '%s cap_dac_override,cap_setpcap,cap_net_admin,cap_sys_admin=ep\n' "${1:-}"
STUB
# Reaching sudo on a skip leg would mean the idempotence skip did NOT happen. Fail loud instead of
# elevating anything.
cat > "$stubs/sudo" <<'STUB'
#!/usr/bin/env bash
echo "[stub sudo] REFUSED: this leg must never reach sudo/setcap (args: $*)" >&2
exit 1
STUB
chmod +x "$stubs"/cargo "$stubs"/getcap "$stubs"/sudo

# The re-bless legs need setcap to "succeed" (still without elevating anything) AND a `cp` that
# PRESERVES timestamps: plain `cp` already dates the staged copy, so only under a timestamp-preserving
# `cp` is the second re-dating call site's effect observable. That makes this leg the pin that keeps the
# site from being deleted as "redundant" — a later `cp -p` (or a `cp` implementation that preserves)
# would silently re-open the wedge on the re-bless path.
stubs_rebless="$work/stubs-rebless"; mkdir -p "$stubs_rebless"
cp "$stubs/getcap" "$stubs_rebless/getcap"
cat > "$stubs_rebless/sudo" <<'STUB'
#!/usr/bin/env bash
echo "[stub sudo] pretending: $*"
STUB
cat > "$stubs_rebless/cp" <<'STUB'
#!/usr/bin/env bash
exec /bin/cp -p "$@"
STUB
cat > "$stubs_rebless/cargo" <<STUB
#!/usr/bin/env bash
mkdir -p target/debug target/release
printf 'RUNNER-CONTENT-C\n' > target/debug/vmcell-test-runner
printf 'RUNNER-CONTENT-C\n' > target/release/vmcell-test-runner
chmod 0755 target/debug/vmcell-test-runner target/release/vmcell-test-runner
touch -d '$blessed_at' target/debug/vmcell-test-runner target/release/vmcell-test-runner
echo "[stub cargo] built runner dated $blessed_at (\$*)"
STUB
chmod +x "$stubs_rebless"/*

fail=0

# mk_repo <dest> [stamp-mode] — a throwaway repo carrying the REAL justfile and the REAL preflight.
# stamp-mode: `match` (default — the stable copy is this build, so bless takes the skip path) or
# `mismatch` (forces the re-bless path).
mk_repo() {
  local dest="$1" stamp_mode="${2:-match}" d
  rm -rf "$dest"
  mkdir -p "$dest/scripts" "$dest/crates/vmcell-test-runner/src" "$dest/crates/vmcell-privilege/src" \
           "$dest/.vmcell-bin/debug" "$dest/.vmcell-bin/release" "$dest/target/debug" \
           "$dest/target/release" "$dest/artifacts"
  cp "$justfile" "$dest/justfile"
  cp "$preflight" "$dest/scripts/review-preflight-priv.sh"
  printf 'fn main() {}\n' > "$dest/crates/vmcell-test-runner/src/main.rs"
  printf '// the privilege transition\n' > "$dest/crates/vmcell-privilege/src/lib.rs"
  printf '# lockfile\n' > "$dest/Cargo.lock"
  printf 'vmlinux\n' > "$dest/artifacts/vmlinux"
  printf 'rootfs\n' > "$dest/artifacts/rootfs.erofs"
  printf 'cpuset cpu io memory pids\n' > "$dest/subtree_control"
  # A genuinely correct blessing: the stable copies are byte-identical to what the stub build produces,
  # 0700, stamped with that content's sha256, and dated at the (older) blessing time.
  for d in debug release; do
    printf 'RUNNER-CONTENT-C\n' > "$dest/.vmcell-bin/$d/vmcell-test-runner"
    chmod 0700 "$dest/.vmcell-bin/$d/vmcell-test-runner"
    if [[ "$stamp_mode" == "mismatch" ]]; then
      printf '%064d\n' 0 > "$dest/.vmcell-bin/$d/.blessed"    # a well-formed hash of something else
    else
      sha256sum "$dest/.vmcell-bin/$d/vmcell-test-runner" | cut -d' ' -f1 > "$dest/.vmcell-bin/$d/.blessed"
    fi
    touch -d "$blessed_at" "$dest/.vmcell-bin/$d/vmcell-test-runner" "$dest/.vmcell-bin/$d/.blessed"
  done
  # THE WEDGE'S PREMISE: a source edited after the blessing, whose rebuild is byte-identical.
  touch -d "$edited_at" "$dest/crates/vmcell-privilege/src/lib.rs"
}

# drop_line <dest> <literal> — deletes one named line from the FIXTURE's justfile (never the
# repo's) and fails loud if it matched nothing: a no-op deletion would silently turn an inverse leg
# into a duplicate of the green one.
drop_line() {
  local dest="$1" literal="$2"
  if ! grep -qF -- "$literal" "$dest/justfile"; then
    note_fail "cannot construct the inverse: the \`bless\` recipe contains no line matching '$literal'."
    note_fail "  Either the anti-wedge re-dating was removed (in which case the green legs above are"
    note_fail "  already red) or the helper was renamed — update this gate's redate_skip_site /"
    note_fail "  redate_rebless_site pattern to the new spelling."
    leg_end
    return 1
  fi
  grep -vF -- "$literal" "$dest/justfile" > "$dest/justfile.tmp"
  mv "$dest/justfile.tmp" "$dest/justfile"
}

# run_bless <dest> <stubdir> — runs the REAL recipe in the fixture, capturing BLESS_OUT/BLESS_RC.
run_bless() {
  set +e
  BLESS_OUT="$(cd "$1" && PATH="$2:$PATH" just bless 2>&1)"
  BLESS_RC=$?
  set -e
}

# run_preflight <dest> — runs the REAL preflight in the fixture through its documented seams,
# capturing PF_OUT/PF_RC. /dev/null is a rw character device, so it satisfies the KVM `-e -r -w` probe;
# `true` is `command -v`-findable, which is all the systemd-run probe tests.
run_preflight() {
  set +e
  PF_OUT="$(
    cd "$1" && PATH="$stubs:$PATH" \
      VMCELL_KVM_DEV=/dev/null \
      VMCELL_ARTIFACTS_DIR="$1/artifacts" \
      VMCELL_CGROUP_SUBTREE_CONTROL="$1/subtree_control" \
      VMCELL_SYSTEMD_RUN=true \
      ./scripts/review-preflight-priv.sh 2>&1
  )"
  PF_RC=$?
  set -e
}

# --- Leg-scoped assertions. Each leg opens with `leg <label>` and closes with `leg_end [suffix]`,
# which prints ONE verdict line and, only when that leg failed, its captured outputs ONCE. The
# alternative (each assertion dumping the capture it read) printed the whole preflight transcript four
# times over for a single broken leg, which buries the one line that matters. `leg_end` also reports
# per-leg, so an early failure does not silence every later leg's verdict.
leg_msgs=()
leg_label=""
# Opening a leg also CLEARS the captures, so a failure dump can only ever show output this leg
# actually produced — a stale capture from three legs back is worse than none.
leg() { leg_label="$1"; leg_msgs=(); BLESS_OUT=""; PF_OUT=""; }
# want / forbid take the captured output BY VALUE, never by variable name: an indirection would hide
# from the linter (and from a reader) which capture each assertion is really reading.
want() {  # want <what> <captured-output> <substring>
  if ! grep -qF -- "$3" <<<"$2"; then leg_msgs+=("$1 is missing '$3'"); fi
}
forbid() {  # forbid <what> <captured-output> <substring>
  if grep -qF -- "$3" <<<"$2"; then leg_msgs+=("$1 must NOT contain '$3'"); fi
}
want_rc() {  # want_rc <what> <actual> <expected>
  if [[ "$2" != "$3" ]]; then leg_msgs+=("$1 exit=$2, expected $3"); fi
}
note_fail() { leg_msgs+=("$1"); }   # a non-substring assertion (mode, stamp, fingerprint)
leg_end() {  # leg_end [suffix]
  if [[ ${#leg_msgs[@]} -eq 0 ]]; then
    echo "  ok   [$leg_label]${1:+ $1}"
    return
  fi
  local m
  for m in "${leg_msgs[@]}"; do echo "  FAIL [$leg_label] $m"; done
  [[ -n "${BLESS_OUT:-}" ]] && { echo "       ---- bless output ----"; printf '%s\n' "$BLESS_OUT" | sed 's/^/       /'; }
  [[ -n "${PF_OUT:-}" ]] && { echo "       ---- preflight output ----"; printf '%s\n' "$PF_OUT" | sed 's/^/       /'; }
  fail=1
}

echo "test-bless-redates-blessed-copy:"

# --- LEG 1: THE PROPERTY. A correct blessing plus a post-bless source edit reads STALE (the proxy is
# --- doing its job); `just bless` takes the idempotence skip — no cp, no sudo — and the verdict CLEARS.
# --- That last step is the whole fix: before it, this bless moved nothing and the STALE was permanent.
leg "skip path clears the stale verdict"
mk_repo "$work/skip"
run_preflight "$work/skip"
want_rc "pre-bless preflight" "$PF_RC" 2
want "the preflight output" "$PF_OUT" "blessing   : STALE"
want "the preflight output" "$PF_OUT" "is newer than the blessed copy"
run_bless "$work/skip" "$stubs"
want_rc "bless" "$BLESS_RC" 0
want "the bless output" "$BLESS_OUT" "already blessed"          # the idempotence skip, not a re-bless
forbid "the bless output" "$BLESS_OUT" "REFUSED"                # …so the refusing sudo stub was never reached
forbid "the bless output" "$BLESS_OUT" "(re)blessed"
run_preflight "$work/skip"
want_rc "post-bless preflight" "$PF_RC" 0
want "the preflight output" "$PF_OUT" "blessing   : CURRENT"
want "the preflight output" "$PF_OUT" "PREFLIGHT: READY"
forbid "the preflight output" "$PF_OUT" "STALE"
# `touch` moves timestamps ONLY: the 0700 mode (PRIV-1) and the stamp's content must survive it.
if [[ "$(stat -c %a "$work/skip/.vmcell-bin/debug/vmcell-test-runner")" != "700" ]]; then
  note_fail "the re-dated stable copy lost its 0700 owner-only mode"
fi
if [[ "$(cat "$work/skip/.vmcell-bin/debug/.blessed")" \
      != "$(sha256sum "$work/skip/.vmcell-bin/debug/vmcell-test-runner" | cut -d' ' -f1)" ]]; then
  note_fail "the stamp no longer matches the stable copy after the re-date"
fi
leg_end

# --- LEG 2: THE INVERSE of leg 1. Delete the skip path's re-dating line and the wedge returns: the
# --- same bless reports "already blessed" and the preflight still says BLOCKED-ON-BLESS. This is the
# --- leg that makes leg 1 non-vacuous.
leg "inverse: skip path without the re-date stays wedged"
mk_repo "$work/skip-inverse"
if drop_line "$work/skip-inverse" "$redate_skip_site"; then
  run_bless "$work/skip-inverse" "$stubs"
  want_rc "bless" "$BLESS_RC" 0
  want "the bless output" "$BLESS_OUT" "already blessed"
  run_preflight "$work/skip-inverse"
  want_rc "post-bless preflight" "$PF_RC" 2
  want "the preflight output" "$PF_OUT" "blessing   : STALE"
  forbid "the preflight output" "$PF_OUT" "PREFLIGHT: READY"
  leg_end "(the wedge reproduces without the fix)"
fi

# --- LEG 3: THE SECOND CALL SITE. On the re-bless path the hash is known to match by construction (the
# --- staged file IS the built runner), so the same rule applies. Under a timestamp-PRESERVING `cp` and
# --- a built runner dated at the old blessing, only the explicit re-date makes the fresh blessing read
# --- CURRENT.
leg "re-bless path dates the copy it just blessed"
mk_repo "$work/rebless" mismatch
run_bless "$work/rebless" "$stubs_rebless"
want_rc "bless" "$BLESS_RC" 0
want "the bless output" "$BLESS_OUT" "(re)blessed"              # the re-bless path, not the skip
run_preflight "$work/rebless"
want_rc "post-bless preflight" "$PF_RC" 0
want "the preflight output" "$PF_OUT" "blessing   : CURRENT"
leg_end

# --- LEG 4: THE INVERSE of leg 3.
leg "inverse: re-bless path without the re-date reads stale"
mk_repo "$work/rebless-inverse" mismatch
if drop_line "$work/rebless-inverse" "$redate_rebless_site"; then
  run_bless "$work/rebless-inverse" "$stubs_rebless"
  want_rc "bless" "$BLESS_RC" 0
  want "the bless output" "$BLESS_OUT" "(re)blessed"
  run_preflight "$work/rebless-inverse"
  want_rc "post-bless preflight" "$PF_RC" 2
  want "the preflight output" "$PF_OUT" "blessing   : STALE"
  leg_end "(the site is load-bearing, not redundant)"
fi

# --- LEG 5: THE PROBE KEEPS ITS TEETH, mtime half. Re-dating must not be a way to silence the proxy: a
# --- source edited AFTER the bless has to read STALE again. Without this leg the fix could be
# --- "implemented" by touching the sources, or by deleting the proxy, and legs 1/3 would still pass.
leg "a source edited after the bless re-reddens"
touch "$work/skip/crates/vmcell-test-runner/src/main.rs"
run_preflight "$work/skip"
want_rc "preflight" "$PF_RC" 2
want "the preflight output" "$PF_OUT" "blessing   : STALE"
want "the preflight output" "$PF_OUT" "crates/vmcell-test-runner/src/main.rs is newer than the blessed copy"
leg_end

# --- LEG 6: THE PROBE KEEPS ITS TEETH, content half. The re-date must not paper over a stable copy
# --- replaced out of band (a hand `cp` over the blessed path, a restore from backup): the content-hash
# --- stamp still has to disagree.
leg "a stable copy replaced out of band stays stale"
mk_repo "$work/tampered"
printf 'RUNNER-CONTENT-TAMPERED\n' > "$work/tampered/.vmcell-bin/debug/vmcell-test-runner"
chmod 0700 "$work/tampered/.vmcell-bin/debug/vmcell-test-runner"
run_preflight "$work/tampered"
want_rc "preflight" "$PF_RC" 2
want "the preflight output" "$PF_OUT" "does not match its"
leg_end

# --- The repo's own blessed runner must be exactly as it was.
leg "the repo's own .vmcell-bin is byte- and timestamp-identical"
real_after="$(fingerprint_real_bindir)"
if [[ "$real_before" != "$real_after" ]]; then
  note_fail "this gate touched the repo's own .vmcell-bin — it must only ever exercise fixtures:"
  while IFS= read -r d; do note_fail "  $d"; done < <(
    diff <(printf '%s' "$real_before") <(printf '%s' "$real_after")
  )
fi
leg_end

if [[ $fail -ne 0 ]]; then
  echo "test-bless-redates-blessed-copy: FAIL" >&2
  exit 1
fi
echo "test-bless-redates-blessed-copy: ok (both re-dating call sites proven load-bearing against the"
echo "real recipe and the real preflight; the freshness proxy keeps its mtime and content teeth; no"
echo "cargo, no sudo, no KVM, and ./.vmcell-bin untouched)"
