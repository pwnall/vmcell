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
// And for every REJECTED manifest, the error must NAME something from the input, so a consumer can
// find the offending line rather than being told only that "the manifest is bad".
//
// WHAT WOULD BE A FINDING: an accepted manifest carrying an unknown key or a duplicate stance; a
// render→parse round trip that loses or changes a stance; a rejection whose message quotes nothing
// from the input; any panic.

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
            // A refusal must be findable: it names a token from the input, or the line number.
            let msg = e.to_string();
            assert!(
                msg.contains("line") || body.split_whitespace().any(|t| msg.contains(t)),
                "a rejection must quote the offending line or token so a consumer can find it; \
                 got {msg:?} for {body:?}"
            );
        }
    }
});
