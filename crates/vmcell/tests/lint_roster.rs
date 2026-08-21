//! Every crate root in the workspace carries the **fail-loud lint** in its production deny block.
//!
//! WHY THIS EXISTS. AGENTS.md's "Fail loud" rule — *no bare `let _ =` on a `Result` or on an
//! accepted input* — had **no gate at all**: not a `scripts/ban-*.sh`, not a `clippy.toml` entry,
//! not a deny in any crate preamble (docs/92 Tier B, B1). The class was closed by turning on
//! `clippy::let_underscore_must_use` in each crate root's `#![cfg_attr(not(test), deny(…))]` block,
//! which is where this repo already scopes `unwrap_used`, `panic`, `print_stdout` and the B11
//! suppression lints.
//!
//! A lint spelled in twenty files is a roster, and this repo's own history is that a roster in more
//! than one place drifts (AGENTS.md rule 3; `ban-ci-script-handcopy.sh` exists for exactly that).
//! The specific hole a per-crate lint leaves is **a new crate**: it is born without the line, every
//! existing gate stays green, and the rule silently stops applying to the newest code in the tree.
//! This test is that hole's gate.
//!
//! WHY A TEST AND NOT A `scripts/ban-*.sh`. `scripts/ban-ci-script-handcopy.sh` ARM 4 requires every
//! gate-shaped script on disk to be named by the `gates` recipe, in both directions. A new script
//! therefore lands only together with a `justfile` edit; an in-source scan runs under
//! `just test-unit` / `just ci` with no roster to keep in sync. AGENTS.md records this shape too —
//! "where an in-source scan already owns one crate, the shell gate is its complement".
//!
//! RED ON THE INVERSE: delete the `clippy::let_underscore_must_use,` line from any one crate root
//! and `every_crate_root_denies_the_fail_loud_lint` names that file and fails.
//!
//! WHAT THIS CANNOT DO, stated rather than implied: it checks that the lint is *enabled*, never that
//! a given `#[expect(…, reason = "…")]` reason is true. A suppression can be present, well-formed
//! and dishonest — that half is a review's job, and it is the reason the class was collapsed into
//! documented helpers first and suppressed second.

use std::path::{Path, PathBuf};

/// The lint token, spelled exactly as it must appear in a deny block.
const LINT: &str = "clippy::let_underscore_must_use";

/// The floor for the zero-file-scan guard. The workspace has twenty crate roots today; the floor is
/// deliberately far below that, because its job is to catch a scan that found *nothing* (a moved
/// `crates/` directory, a packaged tarball, a broken ascent), not to be a second stale count.
const MIN_ROOTS: usize = 15;

/// The workspace root, found by ascending from this crate's manifest directory until a `crates/`
/// directory sits beside a `Cargo.toml`.
///
/// Panics rather than returning an `Option`: a scan that cannot find the tree must be a loud
/// misconfiguration, never a green run over zero files (the repo's zero-file-scan doctrine, which
/// eight shell gates violated until docs/90 G4 swept them).
fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("crates").is_dir() && dir.join("Cargo.toml").is_file() {
            return dir;
        }
        assert!(
            dir.pop(),
            "gate misconfigured: no workspace root (a directory holding both `Cargo.toml` and \
             `crates/`) above {}",
            env!("CARGO_MANIFEST_DIR")
        );
    }
}

/// Every crate root under `crates/`: the conventional `src/lib.rs`, `src/main.rs` and
/// `src/bin/*.rs`, **plus** any `path = "…"` a manifest declares for a `[lib]`/`[[bin]]` target.
///
/// The manifest half is what keeps the scan complete by construction: a crate whose binary lives at
/// an unconventional path would otherwise be invisible to a convention-only walk, and invisible is
/// how a roster gate quietly stops covering something.
fn crate_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let crates_dir = root.join("crates");
    let entries = std::fs::read_dir(&crates_dir).unwrap_or_else(|e| {
        panic!(
            "gate misconfigured: cannot read {}: {e}",
            crates_dir.display()
        )
    });
    for entry in entries {
        let dir = entry.expect("readdir entry").path();
        if !dir.is_dir() {
            continue;
        }
        let manifest = dir.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let mut candidates = vec![dir.join("src/lib.rs"), dir.join("src/main.rs")];
        if let Ok(bins) = std::fs::read_dir(dir.join("src/bin")) {
            for bin in bins.flatten() {
                let p = bin.path();
                if p.extension().is_some_and(|e| e == "rs") {
                    candidates.push(p);
                }
            }
        }
        // Declared target paths, so an unconventional layout is covered rather than skipped.
        //
        // SECTION-AWARE on purpose: `[[test]]`, `[[example]]` and `[[bench]]` also carry `path =`,
        // and those targets are test code, which this lint is deliberately NOT scoped to. Reading
        // `path` without its section would enrol every integration test in the roster and make the
        // gate demand a production preamble on files that must not have one.
        let text = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest.display()));
        let mut in_target_section = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_target_section = line == "[lib]" || line == "[[bin]]";
                continue;
            }
            if in_target_section
                && let Some(rest) = line.strip_prefix("path = \"")
                && let Some(rel) = rest.strip_suffix('"')
                && rel.ends_with(".rs")
            {
                candidates.push(dir.join(rel));
            }
        }
        for c in candidates {
            if c.is_file() && !roots.contains(&c) {
                roots.push(c);
            }
        }
    }
    roots.sort();
    roots
}

/// The lints named inside a crate root's `#![cfg_attr(not(test), deny(…))]` block.
///
/// Returns `None` when the file has no such block at all — a distinct failure from "the block is
/// there and the lint is missing", and worth reporting differently, because a crate that lost the
/// whole block lost `unwrap_used` and `panic` with it.
fn production_deny_block(source: &str) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#![cfg_attr(") {
            let mut block = String::new();
            let mut j = i;
            while j < lines.len() {
                block.push_str(lines[j]);
                block.push('\n');
                if lines[j].starts_with(")]") {
                    break;
                }
                j += 1;
            }
            if block.contains("not(test)") && block.contains("deny(") {
                return Some(block);
            }
            i = j;
        }
        i += 1;
    }
    None
}

#[test]
fn every_crate_root_denies_the_fail_loud_lint() {
    let root = workspace_root();
    let roots = crate_roots(&root);

    // ZERO-FILE-SCAN GUARD. The only way to open nothing is to have been pointed at nothing, so a
    // scan that found (nearly) no crate roots is a misconfiguration, never a pass.
    assert!(
        roots.len() >= MIN_ROOTS,
        "gate misconfigured: found only {} crate roots under {}/crates (expected at least \
         {MIN_ROOTS}); a scan over nothing must never report `ok`",
        roots.len(),
        root.display()
    );

    let mut missing_block: Vec<String> = Vec::new();
    let mut missing_lint: Vec<String> = Vec::new();
    for path in &roots {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        match production_deny_block(&source) {
            None => missing_block.push(rel),
            Some(block) => {
                if !block.contains(LINT) {
                    missing_lint.push(rel);
                }
            }
        }
    }

    assert!(
        missing_block.is_empty(),
        "these crate roots have no `#![cfg_attr(not(test), deny(…))]` block at all, so they carry \
         neither the fail-loud lint nor `unwrap_used`/`panic`: {missing_block:?}"
    );
    assert!(
        missing_lint.is_empty(),
        "AGENTS.md \"Fail loud\" (no bare `let _ =` on a `Result`) is enforced by `{LINT}` in each \
         crate root's production deny block. These roots do not carry it, so the rule does not \
         apply to their code: {missing_lint:?}"
    );
}

/// The positive control for the scanner itself, so the assertion above cannot pass because
/// `production_deny_block` silently returns everything or nothing.
///
/// Without this, deleting the lint check from `production_deny_block` would leave the test above
/// green — the classic shape of a gate that cannot fail.
#[test]
fn the_block_scanner_reads_the_block_and_not_the_whole_file() {
    let with_lint = "#![deny(missing_docs)]\n\
                     #![cfg_attr(\n    not(test),\n    deny(\n        clippy::unwrap_used,\n        \
                     clippy::let_underscore_must_use\n    )\n)]\nfn main() {}\n";
    let block = production_deny_block(with_lint).expect("the block must be found");
    assert!(
        block.contains(LINT),
        "the lint must be read out of the block"
    );

    // A file that MENTIONS the lint only outside the block must not count as carrying it — a
    // rustdoc paragraph or a per-statement `#[expect]` is not a crate-wide deny.
    let mention_only = "//! We removed clippy::let_underscore_must_use once.\n\
                        #![cfg_attr(\n    not(test),\n    deny(\n        clippy::unwrap_used\n    )\n)]\n\
                        fn f() {\n    #[expect(clippy::let_underscore_must_use, reason = \"x\")]\n    \
                        let _ = g();\n}\n";
    let block = production_deny_block(mention_only).expect("the block must be found");
    assert!(
        !block.contains(LINT),
        "a mention outside the deny block must NOT satisfy the roster, or the gate is decorative"
    );

    // No block at all is its own reportable state, not a silent pass.
    assert!(
        production_deny_block("#![deny(missing_docs)]\nfn main() {}\n").is_none(),
        "a file with no not(test) deny block must be reported as missing the block"
    );
}
