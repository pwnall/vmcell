//! Source-level gate for design §3.5's "`main.rs` stays the thin wrapper".
//!
//! Why a source scan rather than a behavioral assertion: the property is *where the code lives*,
//! and nothing observable distinguishes a steward whose serving loop sits in the library from one
//! whose serving loop crept back into the binary. §3.5 names the hazard directly — a library/binary
//! split drifting back into a binary one convenience at a time, with nothing noticing because the
//! in-tree binary keeps compiling — and explains why the existing gate cannot see it:
//! `scripts/check-lean-tree.sh` is **package**-scoped (`cargo tree -p vmcell-steward`), and cargo
//! has no per-target dependency graph, so a lib/bin boundary *inside* one crate is invisible to it.
//!
//! Why it lives in the library rather than beside the code it scans: a `#[cfg(test)] mod` is itself
//! an item beyond `main`, so a gate hosted in `main.rs` would fail itself. `include_str!` reaches
//! the sibling file from here without adding an item to it.
//!
//! It catches: any `fn`/`struct`/`enum`/`impl`/`mod`/`const`/`static`/`trait`/`type` added to
//! `main.rs`. It cannot catch: logic smuggled *inside* `main`'s body — which is why the item count
//! is asserted **exactly**, so the day someone grows `main` itself the reviewer is the gate.
//!
//! Idiom and normalizer copied from `vmcell`'s `virtiofs_pacing_gate`
//! (`crates/vmcell/src/vmm/cloud_hypervisor.rs`), the in-tree precedent; this is that idiom's first
//! use outside that file, and it needs its own copy because it is a different crate.

const SOURCE: &str = include_str!("main.rs");

/// The item roster `main.rs` is allowed to ship: exactly `fn main`.
///
/// Asserted by **equality**, not by a subset check, so both regression directions redden — a stray
/// helper added, and `main` itself renamed or lost (which would otherwise leave the scan matching
/// nothing and passing, the way every source-scanning gate fails vacuously).
const EXPECTED_ITEMS: &[&str] = &["fn main"];

/// `main.rs`'s production text: everything before the first `#[cfg(test)]`, comment lines dropped,
/// leading whitespace trimmed, blank lines removed.
///
/// Dropping comments keeps a prose mention of `fn serve_vsock` from being scanned as a definition;
/// trimming makes the item scan anchor at the line start, which is what distinguishes a top-level
/// item from a nested one.
fn production_lines(source: &str) -> Vec<&str> {
    let production = source
        .split_once("#[cfg(test)]")
        .map_or(source, |(before, _)| before);
    production
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim_start().starts_with("//") && !line.trim_start().starts_with('#'))
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// Every top-level item `main.rs` declares, rendered as `<keyword> <name>`.
///
/// A top-level item is one whose declaration starts at column zero — nesting inside `fn main` is
/// indented, so an item found here is an item at file scope regardless of what encloses it in the
/// author's head.
fn top_level_items(lines: &[&str]) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "fn ",
        "pub fn ",
        "struct ",
        "pub struct ",
        "enum ",
        "pub enum ",
        "impl ",
        "mod ",
        "pub mod ",
        "const ",
        "pub const ",
        "static ",
        "pub static ",
        "trait ",
        "pub trait ",
        "type ",
        "pub type ",
        "use ",
        "pub use ",
        "unsafe fn ",
        "async fn ",
        "extern crate ",
    ];
    lines
        .iter()
        .filter(|line| !line.starts_with(char::is_whitespace))
        .filter_map(|line| {
            let keyword = KEYWORDS.iter().find(|k| line.starts_with(**k))?;
            let rest = line.get(keyword.len()..)?;
            // `:` is in the set so a `use std::io::Write` path survives whole; a trailing one is
            // the type ascription of `const PORT: u32`, which is not part of the name.
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            Some(format!("{keyword}{}", name.trim_end_matches(':')))
        })
        .collect()
}

#[test]
fn main_rs_declares_nothing_but_main() {
    let lines = production_lines(SOURCE);
    assert!(
        lines.len() > 3,
        "the normalizer matched almost nothing ({} lines) — it is scanning the wrong text, and a \
         gate that scans nothing passes vacuously",
        lines.len()
    );
    let items = top_level_items(&lines);
    assert_eq!(
        items, EXPECTED_ITEMS,
        "§3.5: `main.rs` must stay the thin wrapper — read /proc/cmdline, install the subscriber, \
         call `vmcell_steward::run`. Found {items:?}. Anything else belongs in the library, which \
         is what makes the same code run under both placements. If an item legitimately belongs in \
         the binary, extend EXPECTED_ITEMS deliberately — do not delete the scan."
    );
}

/// The gate's own red-on-inverse: the scanner must actually see a planted item, and must not be
/// fooled by the two shapes that would make it vacuous (AGENTS.md rule 2).
#[test]
fn the_item_scanner_rejects_a_planted_helper_and_survives_the_vacuity_shapes() {
    let thin = "fn main() -> Result<(), Box<dyn std::error::Error>> {\n    run(opts())\n}\n";
    assert_eq!(top_level_items(&production_lines(thin)), vec!["fn main"]);

    // The drift this exists for: one convenience helper at a time.
    let drifted = format!("{thin}fn serve_vsock(x: u32) {{\n    loop {{}}\n}}\n");
    assert_eq!(
        top_level_items(&production_lines(&drifted)),
        vec!["fn main", "fn serve_vsock"]
    );

    // A comment naming an item is not an item.
    let commented = format!("// fn serve_vsock is in the library now\n{thin}");
    assert_eq!(
        top_level_items(&production_lines(&commented)),
        vec!["fn main"]
    );

    // Nested items are not top-level ones (they still live in `main`, which the exact count guards).
    let nested = "fn main() {\n    struct Local;\n    let _ = Local;\n}\n";
    assert_eq!(top_level_items(&production_lines(nested)), vec!["fn main"]);

    // A `mod`, a `const`, and a `use` all count — the roster is not fn-only.
    let assorted =
        format!("{thin}mod helpers {{}}\nconst PORT: u32 = 5000;\nuse std::io::Write;\n");
    assert_eq!(
        top_level_items(&production_lines(&assorted)),
        vec!["fn main", "mod helpers", "const PORT", "use std::io::Write"]
    );

    // And the losing-`main` direction: a scan that matched nothing must not read as "thin".
    assert!(top_level_items(&production_lines("// nothing here\n")).is_empty());
}
