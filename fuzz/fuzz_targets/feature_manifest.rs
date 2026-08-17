#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell::feature::{Feature, FeatureDeclaration, Source};

// The feature-manifest sidecar's STRICT parser (design §7.4, invariant F6).
//
// WHO SUPPLIES THE BYTES: a downstream toolkit consumer's build output — the `.features` sidecar
// that travels beside a registered artifact (`rootfs-<label>.features`), emitted from the resolved
// registry entry and read by every cell that consumes that artifact by path. Like `injection_dest`
// this is LOCAL config rather than an off-host wire, and it is ranked accordingly: what F6 protects
// is the SILENT-ABSENCE class, not a remote-exploit boundary.
//
// WHY IT EARNS A SLOT: absence is the silent direction. A typo'd declaration that read as
// "unsupported" would produce a cell that quietly does less while every downstream check passed,
// because nothing claimed the feature — so the parser's whole job is to be strict, and a parser
// whose whole job is to be strict is exactly the thing to fuzz. The sibling precedent is
// `validator_kconfig_parse`, filed for the same reason ("a silently-empty parse would blame every
// assertion on 'symbol absent'").
//
// PRODUCTION PRECONDITION MIRRORED: none. `parse_manifest` is the validation boundary itself; it
// reads no file and takes an arbitrary body, exactly as `FeatureDeclaration::load_beside` hands it
// whatever bytes were on disk.
//
// PROPERTIES, for every ACCEPTED manifest:
//   * every key is a real `Feature` — the enum's roster, not a string the parser invented;
//   * no feature is declared twice (a duplicate stance has no defined precedence, so acceptance
//     would be a last-writer-wins the schema never states);
//   * the declaration ROUND-TRIPS: rendering it and re-parsing yields the same stances. This is the
//     differential that matters, because the renderer is what the build emits and the parser is
//     what every consumer reads — a divergence between them is a declaration that means one thing
//     at build time and another at boot.
// And for every REJECTED manifest, the error must LOCATE the offending line — by number AND by
// quoting the line's own text — so a consumer can find it rather than being told only that "the
// manifest is bad".
//
// WHAT WOULD BE A FINDING: an accepted manifest carrying an unknown key or a duplicate stance; a
// render→parse round trip that loses or changes a stance; a rejection that does not locate its line;
// any panic.
//
// FOUND, and the reason the property is now a conjunction: two bytes, `=z`. The parser's
// `Feature::parse` arm propagated a token-only refusal while its three siblings attached the line
// number, and for an empty key that token is the empty string — so the message read
// ``unknown feature ``: a feature token must be one of […]`` and quoted nothing whatsoever. The
// original property here was `names a line OR quotes a token`, and it caught that input only because
// `=z` has no token the message happened to contain. The `OR` is now an `AND` over ONE line: a
// message naming `line 7` and nothing else used to pass, and so did one quoting a token while
// pointing nowhere. The in-crate twin is `feature::manifest_locator_gates` (which pins the exact line
// per input, against the parser's own locator composer); this target is the half that supplies inputs
// nobody thought to write down.

fuzz_target!(|data: &[u8]| {
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };
    let source = Source::Rootfs("fuzz".to_string());

    match FeatureDeclaration::parse_manifest(body, source.clone()) {
        Ok(decl) => {
            for (feature, _) in &decl.stances {
                // An accepted key is a real variant, reachable through the strict parser. A key the
                // parser accepted but `Feature::parse` rejects would mean two different rosters.
                assert_eq!(
                    Feature::parse(feature.name()).expect("an accepted key must re-parse"),
                    *feature
                );
            }
            // `stances` is a `BTreeMap`, so duplicates cannot survive as separate entries — the
            // check that matters is that the parser REFUSED rather than silently collapsing them.
            // Count the declaration lines and require the map to be exactly as large.
            let declared = body
                .lines()
                .filter(|l| {
                    let code = l.split('#').next().unwrap_or("").trim();
                    !code.is_empty()
                })
                .count();
            assert_eq!(
                decl.stances.len(),
                declared,
                "an accepted manifest collapsed {} declaration line(s) into {} stance(s) — a \
                 duplicate must be REFUSED, never last-writer-wins",
                declared,
                decl.stances.len()
            );

            // Round trip: what the build emits is what every consumer reads.
            let rendered = decl.render_manifest();
            let reparsed = FeatureDeclaration::parse_manifest(&rendered, source)
                .expect("a rendered manifest must always parse");
            assert_eq!(
                reparsed.stances, decl.stances,
                "render -> parse lost or changed a stance; the emitted declaration would mean \
                 something different at boot than it did at build time"
            );
        }
        Err(e) => {
            // A refusal must be findable, and BOTH halves are load-bearing: the line NUMBER answers
            // "which of the three identical lines", and the line's own TEXT survives a consumer who
            // cannot see the numbering (a here-doc, a generated sidecar, a body assembled in memory).
            //
            // Existence over the candidate lines is all that is checkable from out here — which line
            // offended is the parser's own answer, and re-deriving it would mean reimplementing the
            // parser inside its own fuzz target. The exact-line assertions live in the in-crate twin.
            // A candidate line is reduced exactly as the parser reduces one, so this cannot demand a
            // locator for a line the parser would have skipped.
            let msg = e.to_string();
            let located = body.lines().enumerate().any(|(i, raw)| {
                let code = raw.split('#').next().unwrap_or("").trim();
                !code.is_empty() && msg.contains(&format!("line {}", i + 1)) && msg.contains(code)
            });
            assert!(
                located,
                "a rejection must locate the offending line — its NUMBER and its own text — so a \
                 consumer can find it; got {msg:?} for {body:?}"
            );
        }
    }
});
