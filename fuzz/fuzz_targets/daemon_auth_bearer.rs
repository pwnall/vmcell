#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use vmcell_daemon::auth::{ApiKey, AuthDecision, AuthPolicy, authorize, extract_bearer};

// The daemon's PRE-AUTHENTICATION header parser: `authorize` → `extract_bearer` → `ApiKey::verify`.
//
// WHO SUPPLIES THE BYTES: any HTTP client that can reach vmcelld's TCP listener, with no credential
// at all. `server.rs`'s `auth_layer` wraps every route except `/healthz` and `/openapi.json`, pulls
// the raw `Authorization` header value and hands it to `authorize` — so the whole string (scheme,
// separator, token) is attacker-chosen and is parsed BEFORE any authentication decision exists.
//
// PRODUCTION PRECONDITION MIRRORED: axum reaches `authorize` only through
// `headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok())`, and `HeaderValue::to_str` succeeds
// only for VISIBLE ASCII plus tab. Bytes outside that set never reach this parser in production, so
// the harness rejects them rather than claiming coverage of unreachable inputs.
//
// PROPERTY, not no-panic (the parser is three `str` calls and cannot panic): `Authenticated` must be
// returned if and only if `extract_bearer` yielded EXACTLY the configured secret. Both directions
// are asserted, which is the iff. The intended normalization is encoded honestly rather than
// wished away — the scheme compare is ASCII-case-insensitive and the token is `trim()`ed, so
// `"bEaReR  key "` legitimately authenticates and the target must not call that a finding.
//
// WHAT WOULD BE A FINDING: any header that authenticates while carrying a token other than the
// secret (an auth bypass), or any spelling of the correct token that is refused.

const SECRET: &str = "fuzz-api-key-2f8c1e";

static POLICY: LazyLock<AuthPolicy> =
    LazyLock::new(|| AuthPolicy::Key(ApiKey::from_secret(SECRET.as_bytes())));

fn is_header_visible_ascii(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

fuzz_target!(|data: &[u8]| {
    if !data.iter().copied().all(is_header_visible_ascii) {
        return;
    }
    let Ok(header) = std::str::from_utf8(data) else {
        return;
    };

    let token = extract_bearer(Some(header));
    match authorize(&POLICY, Some(header)) {
        Ok(AuthDecision::Authenticated) => assert_eq!(
            token,
            Some(SECRET),
            "header {header:?} authenticated while presenting a different token — auth bypass"
        ),
        Ok(AuthDecision::UnauthenticatedBypass) => {
            panic!("the dev bypass must be unreachable under AuthPolicy::Key")
        }
        Err(_) => assert_ne!(
            token,
            Some(SECRET),
            "header {header:?} presented the correct secret and was refused"
        ),
    }

    // Positive controls in the same body, so the target can never go vacuous: the canonical
    // spelling authenticates, the documented normalization (case-insensitive scheme, trimmed token)
    // authenticates, and an absent header does not.
    assert!(matches!(
        authorize(&POLICY, Some(&format!("Bearer {SECRET}"))),
        Ok(AuthDecision::Authenticated)
    ));
    assert!(matches!(
        authorize(&POLICY, Some(&format!("bEaReR  {SECRET} "))),
        Ok(AuthDecision::Authenticated)
    ));
    assert!(authorize(&POLICY, None).is_err());
});
