#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell::proxy::doubles::fuzz_is_blocked;

// The egress deny-list matcher: `is_blocked`, as `ProxyHandler::route_request` calls it on the real
// production egress path (the module is named `doubles` but holds the shipped handler as well as the
// test doubles).
//
// WHO SUPPLIES THE BYTES: the guest. The handler lifts the host from the guest's own `Host` header
// or request-URI authority and matches it against the deny list, so both the string being matched
// and its spelling are attacker-chosen from inside the VM.
//
// PRODUCTION PRECONDITION MIRRORED: `req.uri().host()` / `authority().host()` yield a `&str`, so the
// predicate only ever sees UTF-8 — which is what the typed input gives it. No cap applies: the URI
// parser bounds the host long before this.
//
// PROPERTY, not no-panic — the function is `strip_suffix` + `to_ascii_lowercase` + `ends_with` and
// provably cannot panic, so a no-panic target here would be exactly the "gate that reports success
// while covering nothing" this repo keeps re-discovering. The value is entirely in a
// label-boundary or normalization divergence, i.e. an EGRESS FILTER BYPASS. Three properties, each
// stated over CONSTRUCTED inputs rather than as a restatement of the implementation, so each is red
// on a distinct real bug:
//   1. SUBDOMAIN (positive): `<label>.<domain>` is blocked by `<domain>`. Red if the `.`-prefixed
//      suffix arm is dropped, which would silently unblock every subdomain.
//   2. SIBLING (negative): `<label><domain>` with no separating dot is NOT blocked by `<domain>` —
//      `evil-example.net` must survive `example.net`. Red on a bare `ends_with`/`contains`, the
//      over-blocking form the label-boundary rule exists to reject.
//   3. NORMALIZATION: case folding and a single trailing dot cannot change the verdict. Red if
//      either normalization is dropped — the exact H-PROXY-2 bypass (`EXAMPLE.NET`, `example.net.`).
// Each carries its positive control in the same body, so the target cannot go vacuous.
//
// WHAT WOULD BE A FINDING: a host that reaches the network although a deny-list entry covers it, or
// a host blocked although no entry covers it at a label boundary.

/// Is `s` shaped like a name whose blocking verdict the three properties can predict? Rejects the
/// degenerate spellings (empty, leading/trailing dot, whitespace) whose normal form is genuinely
/// ambiguous rather than interesting — they still flow through the free-form call above.
fn is_predictable_name(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('.') && !s.ends_with('.') && !s.contains(char::is_whitespace)
}

fuzz_target!(|input: (&str, &str, Vec<&str>)| {
    let (host, domain, list) = input;
    let blocked: Vec<String> = list.iter().map(|s| (*s).to_string()).collect();

    // Free-form: any host against any list. No oracle beyond "it returns", but it is what production
    // actually evaluates and it is what drives coverage of the normalization arms.
    let verdict = fuzz_is_blocked(host, &blocked);

    // 3. NORMALIZATION invariance — DNS is case-insensitive and one trailing dot denotes the root.
    assert_eq!(
        verdict,
        fuzz_is_blocked(&host.to_ascii_uppercase(), &blocked),
        "case changed the egress verdict for {host:?} against {blocked:?}"
    );
    // Only ONE trailing dot is stripped, and deliberately so (`a.b..` is not `a.b.`), so the
    // invariance is asserted for a host that does not already carry one.
    if !host.ends_with('.') {
        assert_eq!(
            verdict,
            fuzz_is_blocked(&format!("{host}."), &blocked),
            "a trailing FQDN dot changed the egress verdict for {host:?} against {blocked:?}"
        );
    }

    if !is_predictable_name(domain) {
        return;
    }
    let one = vec![domain.to_string()];

    // Positive control: the listed domain itself always blocks, in any spelling.
    assert!(
        fuzz_is_blocked(domain, &one),
        "the listed domain {domain:?} is not blocked by its own entry"
    );
    assert!(
        fuzz_is_blocked(&domain.to_ascii_uppercase(), &one),
        "the listed domain {domain:?} escapes its own entry when upper-cased"
    );

    if is_predictable_name(host) {
        // 1. SUBDOMAIN: a strict subdomain of a listed domain is blocked.
        assert!(
            fuzz_is_blocked(&format!("{host}.{domain}"), &one),
            "subdomain {host:?}.{domain:?} is not blocked by {domain:?}"
        );
        // 2. SIBLING: a host that merely ENDS WITH the domain, with no label boundary, is not.
        assert!(
            !fuzz_is_blocked(&format!("{host}{domain}"), &one),
            "sibling label {host:?}{domain:?} is over-blocked by {domain:?} — the deny list is not \
             matching on DNS label boundaries"
        );
    }
});
