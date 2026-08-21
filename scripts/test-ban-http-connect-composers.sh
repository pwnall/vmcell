#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-http-connect-composers.sh (AGENTS.md rule 2: "a gate whose
# self-test cannot fail is theater").
#
# Every arm is driven against a THROWAWAY FIXTURE TREE mirroring the real layout — never against the
# checkout — so the gate is proven able to go red without anyone having to break the repository, and
# the fixtures own their cleanup on the panic path (a `trap`, not a happy-path `rm`).
#
# The arms, one per way this gate could quietly stop working:
#   1. CLEAN — the law plus its rostered exemption: `ok`, exit 0. Without this the "red" arms below
#      prove only that the script can exit 1.
#   2. VIOLATION — a second crate composing an HTTP CONNECT line: exit 1, naming the file.
#   3. NOT THE VSOCK CONNECT — a crate writing `CONNECT <port>\n` (the AF_VSOCK bridge prologue, a
#      different law): still `ok`. A gate that flagged that would be teaching its readers to ignore
#      it.
#   4. PROSE AND TESTS — a composer inside a `//` comment and one below `mod tests {`: still `ok`.
#   5. EMPTY TREE — zero Rust sources: `gate misconfigured`, exit 1. The arm that keeps this gate
#      from wearing a green verdict on a tree it never opened (docs/90 G4).
#   6. LAW GONE — the law's file missing: `gate misconfigured`, exit 1.
#   7. LAW STOPPED VALIDATING — the law's file without `fn validate_authority_host`, and with it
#      defined but never called: `gate misconfigured`, exit 1 (both legs). This is the defect the
#      whole gate exists for, sitting in the one file the composer ban exempts.
#   8. NEEDLE ROTTED — a tree where nothing composes a CONNECT line at all: `gate misconfigured`,
#      exit 1, rather than a vacuous `ok`.
#   9. STALE EXEMPTION — the rostered exemption present but no longer composing: `gate
#      misconfigured`, exit 1, so the roster shrinks with the code.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="$here/ban-http-connect-composers.sh"
[[ -x "$gate" ]] || { echo "self-test misconfigured: $gate is not executable"; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

law_body() { # law_body <validator-decl> <validator-call>
  cat <<EOF
//! Fixture standing in for the transparent intake.
pub(crate) $1 {
    Ok(())
}

async fn synthesize_connect(authority: &str) -> std::io::Result<()> {
    $2
    let request = format!("CONNECT {authority} HTTP/1.1\\r\\nHost: {authority}\\r\\n\\r\\n");
    let _ = request;
    Ok(())
}

#[cfg(test)]
mod tests {
    // A test fixture composing the same line by hand is the JUDGE of the law, not a violation.
    const HELLO: &[u8] = b"CONNECT example.com:443 HTTP/1.1\\r\\n";
}
EOF
}

make_tree() { # make_tree <dir> [--no-law|--law-unvalidated|--law-uncalled] [--no-exempt-composer]
  local root="$1"; shift
  local law_mode="full" exempt_mode="composes"
  for arg in "$@"; do
    case "$arg" in
      --no-law) law_mode="absent" ;;
      --law-unvalidated) law_mode="unvalidated" ;;
      --law-uncalled) law_mode="uncalled" ;;
      --no-exempt-composer) exempt_mode="silent" ;;
    esac
  done

  mkdir -p "$root/crates/vmcell/src/proxy" "$root/crates/vmcell-guest-tools/src"
  case "$law_mode" in
    full)
      law_body "fn validate_authority_host(a: &str) -> Result<(), ()>" \
               "validate_authority_host(authority).map_err(|()| std::io::Error::other(\"bad\"))?;" \
        > "$root/crates/vmcell/src/proxy/transparent.rs" ;;
    unvalidated)
      law_body "fn something_else(a: &str) -> Result<(), ()>" "" \
        > "$root/crates/vmcell/src/proxy/transparent.rs" ;;
    uncalled)
      law_body "fn validate_authority_host(a: &str) -> Result<(), ()>" "" \
        > "$root/crates/vmcell/src/proxy/transparent.rs" ;;
    absent) : ;;
  esac

  if [[ "$exempt_mode" == "composes" ]]; then
    cat > "$root/crates/vmcell-guest-tools/src/main.rs" <<'EOF'
// The in-guest curl shim: a CLIENT naming its own destination from argv.
fn probe_connect(host: &str, port: u16) {
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    let _ = req;
}
EOF
  else
    cat > "$root/crates/vmcell-guest-tools/src/main.rs" <<'EOF'
// The shim no longer speaks CONNECT at all.
fn main() {}
EOF
  fi
}

expect_ok() { # expect_ok <label> <dir>
  local out
  if ! out="$("$gate" "$2/crates" 2>&1)"; then
    echo "FAIL [$1]: expected exit 0, got failure:"; echo "$out"; exit 1
  fi
  case "$out" in
    ok:*) ;;
    *) echo "FAIL [$1]: expected an 'ok:' verdict, got:"; echo "$out"; exit 1 ;;
  esac
  echo "PASS [$1]"
}

expect_red() { # expect_red <label> <dir> <needle>
  local out rc=0
  out="$("$gate" "$2/crates" 2>&1)" || rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "FAIL [$1]: expected a non-zero exit, got 0:"; echo "$out"; exit 1
  fi
  if [[ "$out" != *"$3"* ]]; then
    echo "FAIL [$1]: expected output to mention '$3', got:"; echo "$out"; exit 1
  fi
  echo "PASS [$1]"
}

# --- 1. CLEAN -------------------------------------------------------------------------------------
clean="$tmp/clean"; make_tree "$clean"
expect_ok "clean tree" "$clean"

# --- 2. VIOLATION ---------------------------------------------------------------------------------
bad="$tmp/violation"; make_tree "$bad"
mkdir -p "$bad/crates/vmcell-daemon/src"
cat > "$bad/crates/vmcell-daemon/src/relay.rs" <<'EOF'
fn relay(sni: &str) -> String {
    format!("CONNECT {sni}:443 HTTP/1.1\r\n\r\n")
}
EOF
expect_red "a second composer is banned" "$bad" "relay.rs"

# --- 3. THE VSOCK CONNECT IS A DIFFERENT LAW ------------------------------------------------------
vsock="$tmp/vsock"; make_tree "$vsock"
mkdir -p "$vsock/crates/vmcell/src/steward"
cat > "$vsock/crates/vmcell/src/steward/mod.rs" <<'EOF'
fn prologue(port: u16) -> String {
    format!("CONNECT {port}\n")
}
EOF
expect_ok "the vsock CONNECT prologue is not flagged" "$vsock"

# --- 4. PROSE AND TESTS ---------------------------------------------------------------------------
prose="$tmp/prose"; make_tree "$prose"
mkdir -p "$prose/crates/vmcell-broker/src"
cat > "$prose/crates/vmcell-broker/src/lib.rs" <<'EOF'
// The intake writes "CONNECT host:443 HTTP/1.1" upstream — described, never composed here.
fn nothing() {}

#[cfg(test)]
mod tests {
    const WIRE: &str = "CONNECT example.com:443 HTTP/1.1\r\n";
}
EOF
expect_ok "prose and unit tests are not call sites" "$prose"

# --- 5. EMPTY TREE (the arm that proves the zero-file scan is not a green 'ok') --------------------
empty="$tmp/empty"; mkdir -p "$empty/crates"
expect_red "an empty tree is a misconfiguration" "$empty" "gate misconfigured"

# --- 6. LAW GONE ----------------------------------------------------------------------------------
nolaw="$tmp/nolaw"; make_tree "$nolaw" --no-law
expect_red "a missing law is a misconfiguration" "$nolaw" "was not found"

# --- 7. LAW STOPPED VALIDATING (both legs) --------------------------------------------------------
unval="$tmp/unvalidated"; make_tree "$unval" --law-unvalidated
expect_red "a law with no validator is a misconfiguration" "$unval" "no longer defines"
uncalled="$tmp/uncalled"; make_tree "$uncalled" --law-uncalled
expect_red "a validator that is never called is a misconfiguration" "$uncalled" "never calls it"

# --- 8. NEEDLE ROTTED -----------------------------------------------------------------------------
norot="$tmp/norot"; mkdir -p "$norot/crates/vmcell/src/proxy"
cat > "$norot/crates/vmcell/src/proxy/transparent.rs" <<'EOF'
pub(crate) fn validate_authority_host(a: &str) -> Result<(), ()> { let _ = a; Ok(()) }
fn caller() { let _ = validate_authority_host("a"); }
EOF
expect_red "a needle that matches nothing at all is a misconfiguration" "$norot" "no longer matches"

# --- 9. STALE EXEMPTION ---------------------------------------------------------------------------
stale="$tmp/stale"; make_tree "$stale" --no-exempt-composer
expect_red "an exemption that excuses nothing is a misconfiguration" "$stale" "no longer composes"

echo "ok: ban-http-connect-composers.sh goes red on every inverse and green on every control"
