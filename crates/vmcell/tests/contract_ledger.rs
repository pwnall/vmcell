//! The §10.4 contract ledger's own shape, gated: each contract crate's `Cargo.toml` comment
//! changelog is an **unbroken chain** of `# <from> → <to>:` version edges, ending at the version
//! that crate publishes.
//!
//! WHY THIS EXISTS. §10.4 designates the ledger as the mechanism by which a contract break is "a
//! deliberate, findable ledger entry, never discovered by compile failure". Nothing gated the
//! mechanism itself, and it had a **two-version hole at exactly its most breaking release**: `vmcell`
//! ran `0.2 → 0.3` … `0.7 → 0.8` and then jumped to a bare `0.11.0` entry, so `0.8 → 0.9` (the
//! session layer) and `0.9 → 0.10` (the eleven-delta register that re-threaded every spawn call site,
//! renamed a `ResourceUsage` field, removed a `NetConfig` field and a `RootfsSource` variant, and
//! demoted `instance_mut`) were unwritten. A consumer migrating across that gap read nothing about
//! the largest break the crate ever shipped (docs/90 C2).
//!
//! WHY `cargo semver-checks` IS NOT THIS GATE, and the reason the review found the hole by hand:
//! semver-checks gates the version **number** against the signatures that moved. It cannot see the
//! absence of a comment, it is silent by construction on an addition, and it has no lint of any kind
//! for a behavior change behind an unchanged signature. Every one of those is a thing the ledger
//! exists to carry. The two gates are complements, not substitutes.
//!
//! WHAT THIS CANNOT DO, stated rather than implied: it checks the ledger's SHAPE, never its content.
//! An entry that is present, contiguous and correctly headed can still say nothing useful. That half
//! is a review's job — and the entry's prose is the one part of the contract no gate can supply.
//!
//! Scoped to the two crates `cargo semver-checks` covers (AGENTS.md, "The downstream toolkit
//! contract"), because §10.4 mandates the convention for exactly those two. `vmcell-protocol` and
//! `vmcell-daemon` carry the same comment convention as a courtesy; enrolling them is a followup, not
//! a silent extension of this law's scope.
//!
//! KVM-free, network-free, filesystem-free: the manifests are `include_str!`-embedded, so the check
//! runs everywhere and cargo rebuilds this test when either manifest changes (rustc records
//! `include_str!` inputs in its dep-info, so a stale copy is not reachable).

/// A version as the ledger spells it. `0.7` and `0.7.0` are the **same version** — the older entries
/// use the two-component form and the newer ones the three-component one, and the chain crosses that
/// boundary at `0.10 → 0.11.0`, so comparing the spellings as strings would report a gap that is not
/// there.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Version {
    /// Parses `MAJOR.MINOR` or `MAJOR.MINOR.PATCH`, and **nothing else**.
    ///
    /// Strict on purpose: this is what keeps prose out of the chain. The ledger is full of lines
    /// carrying an arrow between two numbers (`OCI_ROOTFS_STAGE_VERSION` 6 → 7, `vmcell-protocol
    /// 0.5 → 0.6`, `NetConfig::None` moved 2 → 3), and a parser that accepted a version with
    /// trailing text would read a sentence about another crate's bump as an edge in this one's chain.
    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = match parts.next() {
            Some(p) => p.parse().ok()?,
            None => 0,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One ledger edge, with the line it was read from so a failure can name it.
#[derive(Debug)]
struct Edge {
    from: Version,
    to: Version,
    /// 1-based, matching what an editor shows.
    line: usize,
}

/// Reads one ledger header line: `# <from> → <to>:` at the start of the line, and only there.
///
/// The single space after `#` and the `:` after the second version are both load-bearing. A
/// continuation line inside an entry is indented (`#   * BREAKING …`), and a sentence that mentions
/// an edge (`the 0.16.0 → 0.17.0 entry below says so`) either is indented or has no colon in the
/// right place — so neither is mistaken for a header.
fn parse_header(line: &str) -> Option<(Version, Version)> {
    let rest = line.strip_prefix("# ")?;
    let (from, rest) = rest.split_once(" → ")?;
    let (to, _) = rest.split_once(':')?;
    Some((Version::parse(from)?, Version::parse(to)?))
}

/// The `[package]` version a manifest declares: the first line-anchored `version = "…"`.
///
/// Line-anchored, so the `version = "…"` requirements inside dependency tables (which are indented
/// or inline) cannot be mistaken for the package's own. Pinned against cargo's own parse by
/// `the_version_parser_agrees_with_cargo`.
fn declared_version(manifest: &str) -> Option<Version> {
    manifest.lines().find_map(|line| {
        let rest = line.strip_prefix("version = \"")?;
        Version::parse(rest.strip_suffix('"')?)
    })
}

/// Audits one manifest's ledger, returning every problem found rather than only the first — a ledger
/// with two holes should report two.
///
/// The one predicate behind both this test's real-manifest leg and its four red-arm fixtures: an arm
/// proven on a fixture is proven for the manifests, because there is no second copy of it.
fn audit(name: &str, manifest: &str) -> Result<Vec<Edge>, Vec<String>> {
    let mut problems = Vec::new();

    let edges: Vec<Edge> = manifest
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            parse_header(line).map(|(from, to)| Edge {
                from,
                to,
                line: i + 1,
            })
        })
        .collect();

    // VACUITY, the arm every gate in this repo carries: a parser that matches nothing reports a
    // perfect chain. If the header convention is ever reworded, this must fail loudly rather than
    // congratulate the tree it stopped reading.
    if edges.is_empty() {
        problems.push(format!(
            "gate misconfigured: {name} yielded NO `# <from> → <to>:` ledger entries. Either the \
             ledger is gone or the header convention moved and this parser did not follow it; \
             either way the chain check below is vacuous."
        ));
        return Err(problems);
    }

    let Some(version) = declared_version(manifest) else {
        problems.push(format!(
            "gate misconfigured: {name} declares no line-anchored `version = \"…\"`, so there is \
             nothing for the chain to end at."
        ));
        return Err(problems);
    };

    for (i, edge) in edges.iter().enumerate() {
        if edge.to <= edge.from {
            problems.push(format!(
                "{name}:{}: ledger entry `{} → {}` does not step forward. A ledger edge records a \
                 release, so its `to` must be greater than its `from`.",
                edge.line, edge.from, edge.to
            ));
        }
        // DUPLICATES, both shapes, and both are the copy-paste a new entry is written by: two
        // entries leaving one version fork the chain, two arriving at one version claim the same
        // release twice.
        for other in &edges[i + 1..] {
            if other.from == edge.from {
                problems.push(format!(
                    "{name}:{}: duplicate ledger entry — `{}` is also the start of the entry at \
                     line {}. One edge per version, or the chain forks and a consumer cannot tell \
                     which path they took.",
                    other.line, other.from, edge.line
                ));
            }
            if other.to == edge.to {
                problems.push(format!(
                    "{name}:{}: duplicate ledger entry — `{}` is also the end of the entry at line \
                     {}. Two entries cannot both land one version; merge them (the register's \
                     \"this entry GROWS as each delta lands\" convention) or advance the version.",
                    other.line, other.to, edge.line
                ));
            }
        }
    }

    // THE GAP ARM — the docs/90 C2 defect itself. Checked in FILE ORDER, so a ledger that is
    // contiguous but shuffled fails too: it is read top to bottom by a human migrating upward.
    for pair in edges.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if prev.to != next.from {
            problems.push(format!(
                "{name}: LEDGER GAP — the entry at line {} ends at `{}` and the next one (line {}) \
                 starts at `{}`. Every version between them shipped with no entry, which is exactly \
                 the hole docs/90 C2 found: a consumer migrating across it reads nothing. Backfill \
                 the missing edge(s) from `docs/implementation-notes.md`.",
                prev.line, prev.to, next.line, next.from
            ));
        }
    }

    // THE CHAIN MUST REACH THE SHIPPED VERSION. This is the arm that fires on the defect this gate
    // is really for: a version bump landed without its entry (or an entry written for a bump that
    // was never applied to `version`).
    let last = edges.last().expect("non-empty, checked above");
    if last.to != version {
        problems.push(format!(
            "{name}: the ledger chain ends at `{}` (line {}) but the crate publishes `{version}`. \
             A contract-surface version bump is a deliberate, ledgered entry (§10.4) — bump and \
             entry land together, in the same change.",
            last.to, last.line
        ));
    }

    if problems.is_empty() {
        Ok(edges)
    } else {
        Err(problems)
    }
}

/// The two crates `cargo semver-checks` covers, and the two §10.4 mandates a ledger for.
const CONTRACT_MANIFESTS: [(&str, &str); 2] = [
    (
        "crates/vmcell/Cargo.toml",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
    ),
    (
        "crates/vmcell-artifact-validator/Cargo.toml",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../vmcell-artifact-validator/Cargo.toml"
        )),
    ),
];

#[test]
fn every_contract_ledger_is_an_unbroken_chain_ending_at_the_crate_version() {
    let mut failures = Vec::new();
    let mut audited = 0usize;
    for (name, manifest) in CONTRACT_MANIFESTS {
        match audit(name, manifest) {
            Ok(edges) => {
                audited += edges.len();
            }
            Err(problems) => failures.extend(problems),
        }
    }
    assert!(
        failures.is_empty(),
        "the §10.4 contract ledger is broken:\n\n{}",
        failures.join("\n\n")
    );
    // Non-vacuity across the roster, not just per manifest: an `include_str!` that ever resolved to
    // an empty or wrong file would leave this at a plausible-looking small number, so the floor is
    // asserted against what the two ledgers actually carry.
    assert!(
        audited >= 20,
        "only {audited} ledger entries across {} manifests — the roster or the parser is reading \
         something other than the ledgers",
        CONTRACT_MANIFESTS.len()
    );
}

#[test]
fn the_version_parser_agrees_with_cargo() {
    // The manifest text is read by hand here and by cargo at build time; if the two disagree, every
    // "ends at `version`" verdict above is measured against the wrong number. Only `vmcell`'s own
    // version is available as a const, which is enough to pin the parser.
    let (_, manifest) = CONTRACT_MANIFESTS[0];
    assert_eq!(
        declared_version(manifest).map(|v| v.to_string()),
        Version::parse(env!("CARGO_PKG_VERSION")).map(|v| v.to_string()),
        "the ledger gate's manifest parse disagrees with cargo's own"
    );
}

#[test]
fn two_and_three_component_spellings_are_one_version() {
    assert_eq!(Version::parse("0.7"), Version::parse("0.7.0"));
    assert!(Version::parse("0.9") < Version::parse("0.10"));
    // …and nothing else parses, which is what keeps the ledger's prose out of the chain.
    for junk in [
        "0",
        "0.7.0.1",
        "0.7 entry above",
        "v0.7",
        "0.x",
        "",
        "6 → 5",
    ] {
        assert_eq!(Version::parse(junk), None, "{junk:?} must not parse");
    }
}

#[test]
fn a_header_is_read_only_where_the_convention_puts_one() {
    assert_eq!(
        parse_header("# 0.19.0 → 0.20.0: design v33 §18 delta 8 — the ext4 producer.")
            .map(|(f, t)| (f.to_string(), t.to_string())),
        Some(("0.19.0".to_string(), "0.20.0".to_string()))
    );
    for prose in [
        // An indented continuation line, the shape every entry body uses.
        "#   * ARTIFACT: `OCI_ROOTFS_STAGE_VERSION` 6 → 7.",
        "#     ARTIFACT: `GUEST_TOOLS_APPLETS` grows `mini-init` (vmcell-protocol 0.5 → 0.6), so",
        "#   AgentClient            → StewardClient", // allow-legacy-term: verbatim quote of the
        // rename-mapping line at crates/vmcell/Cargo.toml (design v33 §18 delta 1). The ledger's own
        // fidelity note keeps that line spelled the old way on purpose; this fixture must match it
        // byte for byte to prove `parse_header` does not read it as a header.
        // A sentence that names an edge, colon and all, mid-line.
        "#     release is still ONE release; it now spans 0.16.0 and 0.17.0, and the 0.16.0 → 0.17.0",
        // The `vmcell-protocol` ledger's shape for a continuation that opens with a version.
        "# 0.4 → 0.5 entry above, whose \"the names and their order are unchanged\" sentence this",
        // Not a comment at all.
        "version = \"0.20.0\"",
    ] {
        assert!(
            parse_header(prose).is_none(),
            "must not be read as a ledger header: {prose:?}"
        );
    }
}

// ── The four red arms, on fixtures ─────────────────────────────────────────────────────────────
//
// Each fixture is the buggy ledger the corresponding arm exists to catch, so the arm is proven to
// fire without mutating a real manifest — and, because `audit` is the one predicate, proving it here
// proves it for `crates/vmcell/Cargo.toml`. Each asserts on the arm's own wording, so a fixture
// cannot pass by tripping a *different* arm.

/// Asserts `audit` rejects `manifest` with a problem containing `needle`.
fn assert_rejects(manifest: &str, needle: &str) {
    let problems = audit("fixture/Cargo.toml", manifest)
        .err()
        .unwrap_or_else(|| panic!("this ledger must be rejected:\n{manifest}"));
    assert!(
        problems.iter().any(|p| p.contains(needle)),
        "expected a problem naming {needle:?}, got:\n{}",
        problems.join("\n")
    );
}

/// A contiguous fixture ledger — the positive control every arm below is one edit away from.
const GOOD: &str = "[package]\n\
                    name = \"fixture\"\n\
                    # 0.1 → 0.2: the first edge.\n\
                    # 0.2 → 0.3.0: the second, in the other spelling.\n\
                    version = \"0.3.0\"\n";

#[test]
fn the_positive_control_passes() {
    // Without this, all four arms below could be passing because the fixture shape itself is
    // unparseable rather than because each defect is detected.
    let edges = audit("fixture/Cargo.toml", GOOD).expect("the control ledger is well-formed");
    assert_eq!(edges.len(), 2);
}

#[test]
fn a_gap_is_red() {
    assert_rejects(
        &GOOD.replace("# 0.2 → 0.3.0:", "# 0.2.5 → 0.3.0:"),
        "LEDGER GAP",
    );
}

#[test]
fn a_duplicate_is_red() {
    assert_rejects(
        &GOOD.replace(
            "# 0.2 → 0.3.0:",
            "# 0.1 → 0.2: a second entry off 0.1.\n# 0.2 → 0.3.0:",
        ),
        "duplicate ledger entry",
    );
}

#[test]
fn a_chain_that_stops_short_of_the_version_is_red() {
    // The C2 defect in its live form: the bump landed, the entry did not.
    assert_rejects(
        &GOOD.replace("version = \"0.3.0\"", "version = \"0.4.0\""),
        "the ledger chain ends at `0.3.0` (line 4) but the crate publishes `0.4.0`",
    );
}

#[test]
fn an_empty_parse_is_red() {
    // The vacuity arm: a ledger whose headers no longer match the convention this parser reads.
    assert_rejects(
        "[package]\nname = \"fixture\"\n# 0.1 -> 0.2: an ASCII arrow.\nversion = \"0.2.0\"\n",
        "gate misconfigured",
    );
    // …and a manifest with entries but no package version is the same class of misconfiguration.
    assert_rejects(
        "[package]\nname = \"fixture\"\n# 0.1 → 0.2: fine.\n",
        "declares no line-anchored",
    );
}

#[test]
fn a_backwards_edge_is_red() {
    assert_rejects(
        &GOOD.replace(
            "# 0.2 → 0.3.0:",
            "# 0.2 → 0.2: a release that went nowhere.\n",
        ),
        "does not step forward",
    );
}
