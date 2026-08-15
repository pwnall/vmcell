//! Bearer API-key authentication (design §11.6, Authentication — a bearer API key / invariant §13, Cross-cutting invariants).
//!
//! A pre-shared **opaque** API key presented as an HTTP Bearer token (`Authorization: Bearer <key>`,
//! the RFC 6750 transport) — NOT a full OAuth authorization-server flow (the daemon is a local,
//! single-tenant control plane; the bearer *transport* is the idiomatic part to adopt). The key is
//! compared in **constant time** against a stored SHA-256 (so neither a timing side-channel nor the
//! length leaks the secret), loaded from a **perms-checked file** (never a CLI arg / env / log line).

use crate::error::DaemonError;
use sha2::{Digest, Sha256};
use std::path::Path;
use subtle::ConstantTimeEq;

/// A stored API key — held as its SHA-256, never the raw secret, so a memory dump does not reveal it
/// and every comparison is over a fixed 32-byte digest (no length leak).
#[derive(Clone)]
pub struct ApiKey {
    digest: [u8; 32],
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the digest — a `Debug` in a log line is a partial-secret leak.
        f.write_str("ApiKey(<redacted>)")
    }
}

impl ApiKey {
    /// Builds a key from its raw secret bytes (hashing immediately; the raw key is not retained).
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            digest: sha256(secret),
        }
    }

    /// Constant-time check that `presented` matches this key.
    ///
    /// Both sides are hashed to 32 bytes and compared with `subtle::ConstantTimeEq`, so the compare
    /// is data-independent in time and never short-circuits on a length or first-byte mismatch — the
    /// AGENTS.md "match normalized input, ship with a positive control" discipline for a secret.
    #[must_use]
    pub fn verify(&self, presented: &[u8]) -> bool {
        let got = sha256(presented);
        bool::from(got.ct_eq(&self.digest))
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// The daemon's authentication policy.
#[derive(Clone, Debug)]
pub enum AuthPolicy {
    /// Every non-open route requires the bearer key.
    Key(ApiKey),
    /// Auth disabled — only reachable via the explicit `--allow-unauthenticated` dev flag, logged
    /// loudly at every request (design §11.6, Authentication — a bearer API key). The per-request
    /// warn lives in the HTTP auth layer, driven by [`AuthDecision::UnauthenticatedBypass`].
    Unauthenticated,
}

/// How a request was allowed through — the value the HTTP auth layer logs on.
///
/// [`authorize`] stays **pure** (no I/O, no logging, unit-testable against its inverses), so the
/// "logged loudly at every request" half of the `--allow-unauthenticated` contract (design §11.6,
/// Authentication — a bearer API key) travels back to the layer as data rather than as a side
/// effect the predicate performs itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthDecision {
    /// The request presented the correct bearer key.
    Authenticated,
    /// Auth was **bypassed** by the `--allow-unauthenticated` dev flag. The caller must warn, on
    /// every request — a one-time start-up warn scrolls out of a long-running daemon's log.
    UnauthenticatedBypass,
}

/// Extracts the bearer token from an `Authorization` header value, if it is a well-formed
/// `Bearer <token>` with a non-empty token. Case-insensitive on the scheme per RFC 7235.
#[must_use]
pub fn extract_bearer(header: Option<&str>) -> Option<&str> {
    let value = header?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

/// The PURE authorization decision (no I/O), unit-tested against its inverses.
///
/// - `Unauthenticated` policy ⇒ `Ok(AuthDecision::UnauthenticatedBypass)` (the dev bypass, which
///   the layer warns on per request).
/// - absent / malformed / empty bearer ⇒ `Unauthorized` (401, with a `WWW-Authenticate` challenge).
/// - present but wrong ⇒ `Forbidden` (403).
/// - present and correct ⇒ `Ok(AuthDecision::Authenticated)` (the positive control).
///
/// # Errors
/// Returns [`DaemonError::Unauthorized`] or [`DaemonError::Forbidden`] as above.
pub fn authorize(
    policy: &AuthPolicy,
    auth_header: Option<&str>,
) -> Result<AuthDecision, DaemonError> {
    let key = match policy {
        // The bypass is reported, never silently swallowed: the caller owns the loud per-request
        // warn design §11.6 promises (finding `allow-unauthenticated-not-logged-per-request`).
        AuthPolicy::Unauthenticated => return Ok(AuthDecision::UnauthenticatedBypass),
        AuthPolicy::Key(k) => k,
    };
    let Some(token) = extract_bearer(auth_header) else {
        return Err(DaemonError::Unauthorized(
            "missing or malformed `Authorization: Bearer <key>` header".to_string(),
        ));
    };
    if key.verify(token.as_bytes()) {
        Ok(AuthDecision::Authenticated)
    } else {
        Err(DaemonError::Forbidden("invalid API key".to_string()))
    }
}

/// Loads an API key from a file, refusing a **group- or other-readable** file (design §11.6, Authentication — a bearer API key / §13, Cross-cutting invariants):
/// a control-plane secret must not be world-readable. Trailing whitespace/newline is trimmed so an
/// `echo "$key" > keyfile` works.
///
/// # Errors
/// Returns [`DaemonError::BadRequest`] if the file is missing, unreadable, empty, or has permissive
/// (group/other-readable) permissions.
pub fn load_api_key_file(path: &Path) -> Result<ApiKey, DaemonError> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path)
        .map_err(|e| DaemonError::BadRequest(format!("cannot stat API key file {path:?}: {e}")))?;
    // Refuse if any group/other permission bit is set (0o077). Owner-only (0o600/0o400) is required.
    if meta.mode() & 0o077 != 0 {
        return Err(DaemonError::BadRequest(format!(
            "API key file {path:?} is group/other-accessible (mode {:o}); \
             run `chmod 600 {}` — a control-plane secret must be owner-only",
            meta.mode() & 0o777,
            path.display()
        )));
    }
    let raw = std::fs::read(path)
        .map_err(|e| DaemonError::BadRequest(format!("cannot read API key file {path:?}: {e}")))?;
    let trimmed = trim_key(&raw);
    if trimmed.is_empty() {
        return Err(DaemonError::BadRequest(format!(
            "API key file {path:?} is empty"
        )));
    }
    Ok(ApiKey::from_secret(trimmed))
}

/// Trims trailing ASCII whitespace (space, tab, CR, LF) so a keyfile written with a trailing newline
/// matches the header value the client sends. Index-free (via `rposition`/`get`) to satisfy the
/// crate-wide `indexing_slicing` deny.
fn trim_key(raw: &[u8]) -> &[u8] {
    let end = raw
        .iter()
        .rposition(|&b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |i| i + 1);
    raw.get(..end).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bearer_parses_scheme_case_insensitively() {
        assert_eq!(extract_bearer(Some("Bearer abc")), Some("abc"));
        assert_eq!(extract_bearer(Some("bearer abc")), Some("abc"));
        assert_eq!(extract_bearer(Some("BEARER  abc ")), Some("abc"));
        assert_eq!(extract_bearer(Some("Basic abc")), None);
        assert_eq!(extract_bearer(Some("Bearer ")), None);
        assert_eq!(extract_bearer(Some("abc")), None);
        assert_eq!(extract_bearer(None), None);
    }

    // Positive control + the two failure modes (design §11.6, Authentication — a bearer API key): correct → Ok, wrong → Forbidden,
    // absent → Unauthorized. RED on the inverse (an `authorize` that accepts a wrong key, or
    // conflates absent with wrong).
    #[test]
    fn authorize_accepts_correct_rejects_wrong_and_absent() {
        let policy = AuthPolicy::Key(ApiKey::from_secret(b"s3cret-key"));
        assert_eq!(
            authorize(&policy, Some("Bearer s3cret-key")).expect("positive control"),
            AuthDecision::Authenticated,
            "a real key authenticates — the layer must NOT warn on it"
        );

        let wrong = authorize(&policy, Some("Bearer nope")).expect_err("wrong key");
        assert!(matches!(wrong, DaemonError::Forbidden(_)), "wrong => 403");

        let absent = authorize(&policy, None).expect_err("absent");
        assert!(
            matches!(absent, DaemonError::Unauthorized(_)),
            "absent => 401"
        );

        let malformed = authorize(&policy, Some("Basic s3cret-key")).expect_err("malformed");
        assert!(
            matches!(malformed, DaemonError::Unauthorized(_)),
            "malformed => 401"
        );
    }

    // The dev bypass allows everything AND reports itself as a bypass, so the HTTP layer can warn
    // loudly on every request (design §11.6, Authentication — a bearer API key). RED on the inverse
    // (an `authorize` that returns a plain `Ok`/`Authenticated` for the bypass): the layer would
    // have nothing to branch on and the "logged at every request" promise would be undeliverable.
    #[test]
    fn unauthenticated_policy_allows_everything_and_reports_the_bypass() {
        for header in [None, Some("Bearer whatever"), Some("garbage")] {
            assert_eq!(
                authorize(&AuthPolicy::Unauthenticated, header).expect("bypass allows"),
                AuthDecision::UnauthenticatedBypass,
                "every request under the dev flag is a reportable bypass ({header:?})"
            );
        }
    }

    #[test]
    fn verify_is_length_independent() {
        let key = ApiKey::from_secret(b"abcdef");
        // A shorter and a longer wrong key both reject — no length short-circuit leaks the length.
        assert!(!key.verify(b"abc"));
        assert!(!key.verify(b"abcdefghijklmnop"));
        assert!(key.verify(b"abcdef"), "positive control");
    }

    /// The production half of this file (everything before the test module) — the text the shape
    /// gate below reasons about, so a `==` written *in a test* cannot mask a `==` in the real
    /// compare.
    fn production_source() -> &'static str {
        include_str!("auth.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("the production half of this file")
    }

    /// The `{ … }` body of the function whose signature starts with `signature`, by brace counting.
    fn fn_body(src: &str, signature: &str) -> String {
        let start = src
            .find(signature)
            .unwrap_or_else(|| panic!("`{signature}` not found — did the signature change?"));
        let rest = src.get(start..).expect("in-bounds");
        let open = rest.find('{').expect("a function body");
        let mut depth = 0usize;
        for (i, c) in rest.char_indices().skip(open) {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return rest.get(open..=i).expect("in-bounds").to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces after `{signature}`");
    }

    // Design §11.6 promises "a timing test that the compare is constant-time IN SHAPE guards
    // against a future `==` regression". A value test cannot deliver that: both sides are hashed to
    // a fixed 32 bytes first, so a plain `==` passes every behavioural assertion unchanged
    // (finding `constant-time-compare-has-no-gate`). This gate is therefore on the production TEXT:
    // the secret comparison goes through `subtle`'s `ct_eq`, and neither the compare nor its one
    // caller carries an `==`/`!=`. RED on the inverse — rewrite the body to
    // `got == self.digest`, or make `authorize` compare the digests itself.
    #[test]
    fn verify_compares_through_the_constant_time_primitive_not_equality() {
        let prod = production_source();
        assert!(
            prod.contains("use subtle::ConstantTimeEq;"),
            "the constant-time primitive must be the one this module links"
        );

        let verify = fn_body(prod, "pub fn verify(&self, presented: &[u8]) -> bool");
        assert!(
            verify.contains(".ct_eq("),
            "`verify` must compare through subtle's `ct_eq`, got:\n{verify}"
        );
        assert!(
            !verify.contains("==") && !verify.contains("!="),
            "`verify` must not compare the secret with `==`/`!=` — that short-circuits on the \
             first differing byte, which is exactly the timing regression §11.6 names:\n{verify}"
        );

        let authorize = fn_body(prod, "pub fn authorize(");
        assert!(
            authorize.contains("key.verify("),
            "`authorize` must route the check through `ApiKey::verify`, got:\n{authorize}"
        );
        assert!(
            !authorize.contains("==") && !authorize.contains("!="),
            "`authorize` must not compare the credential itself:\n{authorize}"
        );
    }

    #[test]
    fn load_api_key_file_refuses_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key");
        std::fs::write(&path, b"topsecret\n").expect("write");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(
            load_api_key_file(&path).is_err(),
            "a group/other-readable key file must be refused (§12.18)"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let key = load_api_key_file(&path).expect("owner-only key file loads");
        // The trailing newline was trimmed, so the header value matches.
        assert!(key.verify(b"topsecret"), "trailing newline trimmed");
    }
}
