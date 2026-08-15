#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_artifact_validator::kconfig::{KconfigValue, KconfigValues};

// The resolved-`.config` sidecar parser — the only hand-rolled TEXT parser on the downstream
// contract surface, escape state machine included (`unquote`).
//
// WHO SUPPLIES THE BYTES: two producers, and the second is the reason this is here. (1) A downstream
// producer's build artifact — the post-`olddefconfig` `vmlinux-<label>.config` written beside the
// kernel. (2) The GUEST: the living consumer gate (`examples/downstream-kernel`) runs
// `zcat /proc/config.gz` as an in-guest exec and feeds the returned stdout straight to `parse`, so
// the text crosses the guest→host boundary before it is parsed.
//
// PRODUCTION PRECONDITION MIRRORED: the module is pure `&str` → value with no filesystem access —
// the caller reads the sidecar (or the guest's stdout) and hands over the text. The harness gates on
// `str::from_utf8` for the same reason: both producers deliver text, and a non-UTF-8 sidecar fails
// at the caller's read, never inside `parse`.
//
// HONEST YIELD, stated rather than dressed up: LOW. The parser is total by construction — no
// indexing, no unwrap, no allocation sized from parsed input, every slice through
// `strip_prefix`/`strip_suffix`/`split_once` — and it is already well unit-tested. It is here
// because it is nearly free and because a panic on contract surface is downstream-visible, not
// because it is expected to go red.
//
// PROPERTY beyond no-panic: every symbol the parser ACCEPTS must be a well-formed kconfig symbol —
// `CONFIG_`-prefixed and free of whitespace. That is what makes the accepted map re-renderable, so
// the target proves it the honest way, by re-rendering every tristate value in canonical form and
// asserting the re-parse agrees. `Other(_)` values are excluded from the re-render because unquoting
// is deliberately lossy (a quoted string comes back unquoted), so re-rendering one would test the
// harness rather than the parser. Red on dropping the `!contains(char::is_whitespace)` filter in the
// `# CONFIG_X is not set` arm: the symbol `CONFIG_A CONFIG_B` would then be accepted, and its
// canonical re-render is a line the parser must reject.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(values) = KconfigValues::parse(text) else {
        return;
    };

    assert_eq!(values.is_empty(), values.len() == 0);

    let mut rendered = String::new();
    for (symbol, value) in values.iter() {
        assert!(
            symbol.starts_with("CONFIG_"),
            "parsed symbol {symbol:?} is not `CONFIG_`-prefixed"
        );
        assert!(
            !symbol.contains(char::is_whitespace),
            "parsed symbol {symbol:?} carries whitespace, so it cannot be re-emitted as one line"
        );
        match value {
            KconfigValue::Yes => rendered.push_str(&format!("{symbol}=y\n")),
            KconfigValue::Module => rendered.push_str(&format!("{symbol}=m\n")),
            KconfigValue::No => rendered.push_str(&format!("# {symbol} is not set\n")),
            // Unquoting is lossy on purpose; re-rendering one would test the harness.
            _ => {}
        }
    }

    let reparsed = KconfigValues::parse(&rendered)
        .expect("the canonical re-render of an accepted parse must itself parse");
    for (symbol, value) in values.iter() {
        if matches!(
            value,
            KconfigValue::Yes | KconfigValue::Module | KconfigValue::No
        ) {
            assert_eq!(
                reparsed.get(symbol),
                Some(value),
                "symbol {symbol:?} did not survive a canonical re-render"
            );
        }
    }
});
