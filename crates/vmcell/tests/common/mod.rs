#![allow(dead_code)]

//! Shared integration-test harness. The generally-reusable VM-boot + capability primitives were
//! **extracted** into `vmcell_artifact_validator::harness` (design §5.4, The guest-kernel contract and the bootstrap seed / §8.5, Lineage: fork and branch) so the artifact
//! validator and these tests share one implementation; they are re-exported here so the existing
//! `common::…` call sites keep working. The genuinely test-only helpers (skip manifest, netns/nft
//! residue tooling) and the `vmm_matrix_test!` / `require_cap!` macros stay here.

// Extracted, now shared with the validator (single source of truth). Each test binary uses a
// different subset, so allow the re-export to be partially unused per binary.
#[allow(unused_imports)]
pub use vmcell_artifact_validator::harness::{
    ch_bin, crosvm_bin, fc_bin, get_rootfs, get_vmlinux, has_cap_net_admin, qemu_bin, start_vm,
};

/// Recomputes the cgroup-v2 slice name the orchestrator assigns to a VM, so a residue check can
/// target the *actual* (possibly systemd-/runner-nested) path. Test-only (residue tooling).
///
/// F2 / d3: the whole composition — leaf **and** sibling placement — is delegated to
/// `vmcell::naming::vm_slice_name`, the one law. This helper used to re-type the `{base}/{leaf}`
/// join, which made it a second copy of the very rule the residue checks exist to catch drift in;
/// the law is now `pub`, so there is nothing left to copy.
pub fn computed_cgroup_name(vmid: u32) -> String {
    vmcell::naming::vm_slice_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, vmid)
}

/// The environment variable that keeps a [`TempTree`] on disk for post-mortem inspection.
///
/// Strictly parsed at construction (AGENTS.md "every accepted input is honored or rejected"):
/// unset / `""` / `"0"` remove the tree, `"1"` keeps it, anything else panics.
pub const KEEP_TEMP_ENV: &str = "VMCELL_KEEP_TEST_TEMP";

/// Owns a test-created scratch path under [`std::env::temp_dir`] so its `Drop` removes the whole
/// tree — on the success path **and** on panic.
///
/// The defect this closes: every scratch path here used to be cleaned by a trailing
/// `let _ = std::fs::remove_dir_all(&dir)` at the bottom of the test body, which an assertion
/// panic (or a `.expect()` on a live-VM step) skips entirely — and a nextest retry re-runs the
/// same test, so one flaky live test leaked once per attempt. `tests/snapshot_restore.rs` had no
/// removal at all: its ~129 MB guest-RAM snapshot dir accumulated per run per backend until the
/// host `/tmp` hit its quota and the daemon suite went red on `Disk quota exceeded`. Ownership
/// owns cleanup, so the cleanup cannot be skipped by a control-flow path nobody thought about.
///
/// Names are **unchanged** from the hand-rolled sites (tests and operators grep for them); the
/// helper only takes over the *ownership*. The path stays under `std::env::temp_dir()` so it
/// tracks `TMPDIR` and matches where `vmm::VmTempDir` puts the per-VM scratch dir the residue
/// checks in `tests/lifecycle.rs` assert against.
///
/// Set `VMCELL_KEEP_TEST_TEMP=1` ([`KEEP_TEMP_ENV`]) to keep the tree for post-mortem inspection
/// after a failing live test; the drop then prints the retained path instead of removing it.
pub struct TempTree {
    path: std::path::PathBuf,
    keep: bool,
}

impl TempTree {
    /// Owns `<temp_dir>/<name>` **without** creating it, after removing any residue already there.
    ///
    /// For paths the code under test creates itself — a snapshot directory, a lineage scratch
    /// tree, a mock-server UDS socket — where pre-creating would mask the creation behavior (or,
    /// for a socket, break the `bind`).
    pub fn reserve(name: &str) -> Self {
        let path = std::env::temp_dir().join(Self::checked_name(name));
        remove_tree(&path).unwrap_or_else(|e| {
            panic!(
                "TempTree::reserve: clearing residue at {} failed: {e}",
                path.display()
            )
        });
        Self {
            path,
            keep: keep_requested(),
        }
    }

    /// [`TempTree::reserve`] plus `create_dir_all`, for the sites that need the directory to exist
    /// before the test writes into it.
    pub fn create(name: &str) -> Self {
        let tree = Self::reserve(name);
        std::fs::create_dir_all(&tree.path)
            .unwrap_or_else(|e| panic!("TempTree::create: {} failed: {e}", tree.path.display()));
        tree
    }

    /// The owned path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// A path inside the owned tree; it dies with the owner.
    pub fn join(&self, rel: impl AsRef<std::path::Path>) -> std::path::PathBuf {
        self.path.join(rel)
    }

    /// Keeps the tree on drop regardless of the environment — the explicit, per-site form of the
    /// [`KEEP_TEMP_ENV`] opt-in, and what lets the gate drive the retention branch without
    /// mutating the process-global environment.
    pub fn retain(mut self) -> Self {
        self.keep = true;
        self
    }

    /// Rejects a name that would put the tree somewhere other than one child of the temp dir — an
    /// empty, `..`-bearing or separator-bearing name turns the `Drop` below into a
    /// `remove_dir_all` of a directory the test does not own. The `vmcell-` prefix keeps every
    /// test scratch path inside the one namespace an operator can sweep by hand.
    fn checked_name(name: &str) -> &str {
        let want = format!("{}-", vmcell::naming::DEFAULT_RESOURCE_PREFIX);
        assert!(
            name.starts_with(&want),
            "TempTree name {name:?} must start with {want:?} so it stays in the sweepable namespace"
        );
        assert!(
            std::path::Path::new(name).components().count() == 1
                && !name.contains(std::path::MAIN_SEPARATOR)
                && !name.contains('\0'),
            "TempTree name {name:?} must be a single path component under the temp dir"
        );
        name
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.keep {
            eprintln!(
                "TempTree: retention requested ({KEEP_TEMP_ENV}=1 or `retain()`), keeping {} for \
                 post-mortem inspection",
                self.path.display()
            );
            return;
        }
        // Best-effort *and* loud: a `Drop` cannot propagate, and panicking here would mask the
        // test's own failure, so a removal error is reported rather than swallowed.
        if let Err(e) = remove_tree(&self.path) {
            eprintln!("TempTree: removing {} failed: {e}", self.path.display());
        }
    }
}

/// Removes `path` whether it is a directory tree, a file, or a socket; absent is success.
fn remove_tree(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether [`KEEP_TEMP_ENV`] asks for the tree to be retained.
fn keep_requested() -> bool {
    keep_from_env_value(std::env::var_os(KEEP_TEMP_ENV).as_deref())
}

/// The strict parse of a [`KEEP_TEMP_ENV`] value, split out so the gate can drive it directly
/// instead of mutating the process-global environment out from under the rest of the binary.
/// Unset / `""` / `"0"` remove; `"1"` keeps; anything else is REJECTED (fail loud) rather than
/// silently read as "remove".
pub fn keep_from_env_value(value: Option<&std::ffi::OsStr>) -> bool {
    match value {
        None => false,
        Some(v) => match v.to_str() {
            Some("") | Some("0") => false,
            Some("1") => true,
            other => panic!("{KEEP_TEMP_ENV} must be unset, \"0\" or \"1\"; got {other:?}"),
        },
    }
}

/// Where a capability skip is recorded — the **one** place the manifest path is decided, so a
/// reader (a gate asserting that a skip was recorded) cannot drift from the writer.
///
/// `VMCELL_SKIP_MANIFEST` when the suite recipes set it (the run-scoped, durable path
/// `just skip-manifest-show` prints); otherwise a per-PID temp file, which is what makes a bare
/// `cargo nextest run` record somewhere rather than nowhere.
pub fn skip_manifest_path() -> std::path::PathBuf {
    std::env::var_os("VMCELL_SKIP_MANIFEST")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("vmcell-skips-{}.txt", std::process::id()))
        })
}

/// Records a capability-driven test skip to a durable, run-scoped manifest so the skip is an
/// auditable artifact rather than an invisible nextest pass (H-TEST-3). Best-effort by design.
///
/// The manifest is deliberately **not** a [`TempTree`]: it is the run's audit artifact, read after
/// the suite exits (`just`'s recipes point `VMCELL_SKIP_MANIFEST` at a durable path), so an owner
/// that deleted it would delete the evidence.
pub fn record_capability_skip(vmm: &str, capability: &str) {
    record_capability_skip_to(&skip_manifest_path(), vmm, capability);
}

/// [`record_capability_skip`] with the sink as a parameter — the one writer, aimed.
///
/// The seam exists for the gates: proving that a skip is *recorded* rather than merely printed
/// means observing the file afterwards, and doing that against the run's own manifest would append
/// a synthetic `SKIP` a reviewer reads as a real capability gap. A false entry in the audit
/// artifact is worse than the gap it pretends to describe, so a gate aims this at a scratch path
/// and the batteries call the one-argument form above.
pub fn record_capability_skip_to(manifest: &std::path::Path, vmm: &str, capability: &str) {
    use std::io::Write as _;
    let line = format!("SKIP {vmm} {capability}\n");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                eprintln!(
                    "record_capability_skip: append to {} failed: {e}",
                    manifest.display()
                );
            }
        }
        Err(e) => eprintln!(
            "record_capability_skip: open {} failed: {e}",
            manifest.display()
        ),
    }
}

/// The backend the ext4 battery's capability skip is attributed to.
///
/// Cloud Hypervisor because the §15.4 ext4 battery is CH-only (`ext4_cell`'s module docs say why:
/// the image is a host-side packing product and the reader is the guest kernel's ext4 driver). The
/// pair is spelled once here so the law that writes the line and the gate that asserts it was
/// written cannot drift.
/// Gated on `pipeline` alone, not on `ext4-producer`: the line's *identity* names a capability that
/// is absent, and "this build was compiled without the producer" is one of the ways it can be
/// absent (`rootfs::ext4_route`'s feature-off arm returns exactly that refusal). A pair that
/// vanished with the feature would leave the configuration that most needs to record a skip with no
/// way to spell one.
#[cfg(feature = "pipeline")]
pub const EXT4_SKIP_VMM: &str = "cloud-hypervisor";

/// The capability the ext4 battery's skip names — see [`EXT4_SKIP_VMM`].
#[cfg(feature = "pipeline")]
pub const EXT4_SKIP_CAPABILITY: &str = "ext4_producer";

/// **The one law** every §15.4 ext4 leg asks before it packs (design §4.7, §18 delta 8): probes the
/// host's external ext4 producer, and records a reviewable capability skip when the facility is
/// **absent**.
///
/// `Some(producer)` is the product's own receipt that both halves of the gate ran — the version and
/// the dlopen'd libarchive. It cannot be forged: `Ext4Producer`'s fields are private to `vmcell`, so
/// a probe is the only thing that mints one, and a leg that takes the receipt as an argument
/// (`ext4_cell`'s `pack_ext4_rootfs`) cannot pack without one. Obtaining a receipt *behind* this
/// law is a different question, and the one the call-site scan in `ext4_producer.rs` answers.
///
/// `None`, after appending `SKIP cloud-hypervisor ext4_producer` to the run's skip manifest, when
/// the probe classifies the facility as absent (§7.2) — which is what makes the gap show up in
/// `just skip-manifest-show` instead of passing as green.
///
/// A probe result the product calls **broken** — present but unexecutable, an unparseable banner —
/// **panics**: that is a host misconfiguration this battery must not paper over, and it is exactly
/// the distinction §7.2 rule 3 draws. Skipping on it would be the `println!("SKIP") + return`
/// green-PASS defect wearing the probe's clothes.
///
/// # Why the law lives here and not in the batteries
///
/// The three delta-8 files answered an absent `mkfs.ext4` three different ways, and two of the
/// three were wrong: `ext4_producer.rs` **panicked**, which on GitHub's `ubuntu-24.04` runner
/// (e2fsprogs 1.47.0 — one patch release below the `-d <tarball>` gate) meant four red tests on
/// `test-unit` plus the same four retried four times each by `test-integration`'s profile, for four
/// commits; `repack_outside_checkout.rs` printed a bare `println!("SKIP")` and returned, which AGENTS.md
/// names as a green PASS — its doc comment claimed to record a skip and no `record_capability_skip`
/// call existed anywhere in the file (docs/90 G3).
///
/// A **fourth** answer appeared anyway, which is what this paragraph used to credit the enumerated
/// call-site scan in `ext4_producer.rs` with preventing. `rootfs_registry.rs` hand-spelled the skip
/// identity and printed its own SKIP line — the two shapes that scan's arms 4 and 5 exist to catch —
/// and it was invisible **twice over**: first because the scan names three files and never opened
/// the fourth, and then, once the file was inside a roster, because rustfmt had wrapped the
/// `println!` across two lines while the ban was one string. So the enumerated scan is
/// **complemented**, not trusted: [`ext4_answer_findings`] discovers its own roster (any test file
/// naming the format in code), matches every needle whitespace-free (`dense`), and adds the
/// in-crate half — driven from `rootfs_registry.rs`, with per-arm red-on-inverse against fixture
/// trees.
///
/// The residual, stated rather than left to be rediscovered: **two scans now run over overlapping
/// rosters, and neither subsumes the other.** `every_ext4_battery_asks_the_one_law` keeps a
/// call-site count floor and the structural arm asserting the direct probe lives in this file;
/// [`ext4_answer_findings`] keeps the discovery, the whitespace-blind matching, the empty-tree
/// `gate misconfigured` arms and the crate half. The two already disagree on what "asks the law"
/// means — the enumerated one accepts only this function, while the law has two doors and the
/// discovered one accepts both, so a battery that entered the enumerated roster through
/// [`classify_ext4_refusal`] would be flagged by it. A later pass should consolidate them
/// deliberately, keeping every arm: two scans drifting apart by accident is exactly how the
/// enumerated one came to be green about a file it had never read.
///
/// The recorded skip is not the whole fix: a permanently-skipped battery is coverage nobody reads,
/// so `.github/workflows/ci.yml` **obtains** the facility (a pinned, checksum-verified e2fsprogs
/// built from source) ahead of the suites, non-gating, so a failed install degrades to this
/// recorded skip instead of a red job. `ci_obtains_the_ext4_facility_rather_than_living_with_the_skip`
/// is that step's gate.
#[cfg(all(feature = "pipeline", feature = "ext4-producer"))]
#[must_use]
pub fn probe_ext4_or_record_skip() -> Option<vmcell::artifact::ext4::Ext4Producer> {
    classify_ext4_probe(
        vmcell::artifact::ext4::Ext4Producer::probe(),
        &skip_manifest_path(),
    )
}

/// [`probe_ext4_or_record_skip`]'s body, with the probe's verdict and the skip sink as parameters.
///
/// Both seams exist for one reason: the absent-facility arm is the arm that matters and it is
/// unreachable on a host that *has* e2fsprogs — which every host that can run the battery does. A
/// gate hands this a synthetic `CapabilityUnavailable` plus a scratch manifest and watches the line
/// appear, so the difference between "printed SKIP" and "recorded SKIP" can go red. The batteries
/// call the no-argument form above; nothing else calls this.
#[cfg(all(feature = "pipeline", feature = "ext4-producer"))]
#[must_use]
pub fn classify_ext4_probe(
    probed: vmcell::error::Result<vmcell::artifact::ext4::Ext4Producer>,
    manifest: &std::path::Path,
) -> Option<vmcell::artifact::ext4::Ext4Producer> {
    match probed {
        Ok(producer) => Some(producer),
        // One core, two doors: everything about *classifying* a refusal — which outcome is an absent
        // facility, what line the manifest gets, what a broken tool does — lives below, so the
        // probe-first door and the refusal-first door cannot answer the same host differently.
        Err(refusal) => {
            classify_ext4_refusal(&refusal, manifest);
            None
        }
    }
}

/// [`classify_ext4_probe`]'s core, entered from the **other side**: a leg that already holds the
/// product's typed refusal, because asking the probe first would skip past the door it exists to
/// assert.
///
/// `rootfs_registry`'s `a_registered_ext4_label_packs_an_ext4_image` is that leg. It cannot
/// pre-probe: the whole point of the leg is that a registry entry declaring `format: ext4` reaches
/// the *format-selecting* tail rather than the erofs-only door, and the refusal it reads is what
/// discriminates the two (`CapabilityUnavailable` from §4.7's version gate versus the door's
/// `Error::Artifact` naming itself). So it hands its refusal here instead of spelling the answer
/// itself — which is exactly what it used to do: `record_capability_skip("cloud-hypervisor",
/// "ext4_producer")` with both halves of the identity hand-typed, followed by its own
/// `println!("SKIP: …")`. That is a **fourth** answer to an absent `mkfs.ext4`, and it was invisible
/// to the call-site scan because the scan enumerated three files and this was the fourth. The scan
/// discovers its roster now ([`ext4_answer_findings`]), and the identity belongs to
/// [`EXT4_SKIP_VMM`] / [`EXT4_SKIP_CAPABILITY`] here.
///
/// Records `SKIP cloud-hypervisor ext4_producer` for an absent facility (§7.2) and **panics** for
/// anything else, exactly as [`probe_ext4_or_record_skip`] does — see its rustdoc for why the
/// broken-versus-absent distinction is the whole point.
#[cfg(feature = "pipeline")]
pub fn classify_ext4_refusal(refusal: &vmcell::error::Error, manifest: &std::path::Path) {
    match refusal {
        vmcell::error::Error::CapabilityUnavailable { op, needed } => {
            record_capability_skip_to(manifest, EXT4_SKIP_VMM, EXT4_SKIP_CAPABILITY);
            println!(
                "SKIP: this host cannot produce ext4 rootfs images ({op}: {needed}). The §15.4 \
                 ext4 battery {}",
                ext4_facility_requirement()
            );
        }
        other => panic!(
            "the ext4 producer is present but BROKEN on this host, which is a misconfiguration and \
             not an absent facility — fix it rather than skipping the delta-8 gates: {other}"
        ),
    }
}

/// What the SKIP line above says the host is missing.
///
/// Two forms because the constants that name the version gate live behind the feature that ships
/// the producer, while the skip's identity does not: with `ext4-producer` off, the absent facility
/// *is* the feature.
#[cfg(all(feature = "pipeline", feature = "ext4-producer"))]
fn ext4_facility_requirement() -> String {
    let (ma, mi, pa) = vmcell::artifact::ext4::MIN_E2FSPROGS_VERSION;
    format!(
        "needs `{}` from e2fsprogs >= {ma}.{mi}.{pa}, with libarchive support",
        vmcell::artifact::ext4::EXT4_PRODUCER_BIN
    )
}

/// The `ext4-producer`-off form of [`ext4_facility_requirement`].
#[cfg(all(feature = "pipeline", not(feature = "ext4-producer")))]
fn ext4_facility_requirement() -> String {
    "needs a `vmcell` built with the `ext4-producer` feature, which this build was compiled without"
        .to_string()
}

// -------------------------------------------------------------------------------------------------
// The ext4 skip law's CALL-SITE SCAN — discovering, not enumerated
// -------------------------------------------------------------------------------------------------

/// `text` with whole-line comments removed — Rust `//` and YAML `#` alike.
///
/// Every scan below runs on the stripped form, so prose that *quotes* a banned shape (the rustdoc
/// above quotes `println!("SKIP") + return`, and four batteries name it too) is never a false
/// positive. Stripping can only hide a hit, never invent one; the needles below all live on
/// statement lines, and a whole-line `#` in a Rust file is an attribute, which carries none of them.
#[must_use]
pub fn code_only(text: &str) -> String {
    text.lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with('#') && !t.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `text` with **all** whitespace removed, which is the form every needle below is matched against.
///
/// Not fastidiousness — the defect this scan was widened for was invisible to a line-wise needle
/// even after the file entered the roster. `rootfs_registry.rs` printed its own skip as
///
/// ```text
/// println!(
///     "SKIP: this host cannot produce ext4 rootfs images …"
/// );
/// ```
///
/// and `println!("SKIP` matches that nowhere: rustfmt had wrapped the call, so the banned shape was
/// two lines and the ban was one string. Matching whitespace-free means the needles stay readable
/// literals a reviewer can grep for while the scan sees past every wrap the formatter chooses. It
/// also lets `Ext4Producer::probe()` be caught when it is broken across lines, and it is why the
/// print ban can be `println!("SKIP` rather than the far blunter `"SKIP` — which would flag
/// `ext4_producer.rs`'s own `format!("SKIP {} {}\n")`, the *expected* manifest line its gate composes.
#[must_use]
fn dense(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Whether `code` carries `needle`, both read [`dense`]ly — the one comparison every arm below uses,
/// so no arm can be defeated by where a formatter put a line break.
#[must_use]
fn carries(code: &str, needle: &str) -> bool {
    dense(code).contains(&dense(needle))
}

/// What makes a test file an **ext4 battery**: naming the declared format in *code* is what puts it
/// on the path where an absent external producer can refuse it.
const EXT4_BATTERY_NEEDLE: &str = "RootfsFormat::Ext4";

/// …and what makes one a *packer*, which is what obliges it to have an answer for that refusal. A
/// file that only does filename or key math over the format never meets the facility.
const EXT4_PACK_NEEDLES: [&str; 3] = [
    "pack_rootfs_with_injection(",
    "pack_ext4_rootfs(",
    "Ext4Producer",
];

/// The one law's two doors: [`probe_ext4_or_record_skip`] (ask first) and
/// [`classify_ext4_refusal`] (hand it the refusal you already hold).
const EXT4_LAW_NEEDLES: [&str; 2] = ["probe_ext4_or_record_skip(", "classify_ext4_refusal("];

/// The `*.rs` files directly in `dir`, sorted, as `(name, code_only(source))`.
///
/// Deliberately **shallow**: it is what keeps the law's own file — `tests/common/mod.rs`, one
/// directory down — out of the scanned set, so every needle below can be a literal. The scan that
/// used to live inside one of the files it scanned had to *compose* each needle out of fragments to
/// avoid matching itself, and a needle assembled at runtime is one nobody can grep for.
fn rust_sources_shallow(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "rs"))
        .collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.push((name, code_only(&text)));
        }
    }
    out
}

/// [`rust_sources_shallow`] over a whole tree, for the in-crate half of the scan.
fn rust_sources_recursive(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            out.extend(rust_sources_recursive(&path));
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push((path.to_string_lossy().into_owned(), code_only(&text)));
        }
    }
    out
}

/// **The call-site scan** (AGENTS.md: "a gate binds the call sites, not just the extracted
/// predicate"), as a pure function over two trees: every violation it finds, as a line a reviewer
/// can act on. Empty means green.
///
/// # Why it discovers its roster instead of listing it
///
/// The scan this replaces named three battery files. `rootfs_registry.rs` was the fourth — it
/// answered an absent `mkfs.ext4` with a hand-spelled
/// `record_capability_skip("cloud-hypervisor", "ext4_producer")` and its own `println!("SKIP: …")`,
/// which is *precisely* the pair of shapes arms 4 and 5 exist to catch, and both arms were green
/// because the scan never opened that file. An enumerated roster gates the files somebody remembered;
/// a discovered one gates the battery the day it appears, which is the only version of this gate
/// whose coverage cannot rot. The cost is that the discovery needle is now load-bearing, so it is
/// named once ([`EXT4_BATTERY_NEEDLE`]) and its own emptiness is a finding.
///
/// # What it asserts, and why each arm exists
///
/// Over the test batteries discovered in `tests_dir` (any file whose code names the ext4 format):
/// 1. it declares `mod common;`, so the law is *reachable* — docs/90 G3's file did not, which is how
///    its doc comment came to claim a skip-recording call that existed nowhere in it;
/// 2. a battery that **packs** asks one of the law's two doors;
/// 3. none re-probes the producer directly, which is how three files came to answer an absent
///    facility three different ways, two of them wrong (a red CI job and a green PASS);
/// 4. none prints its own `SKIP` — the shape AGENTS.md names as a green PASS, because nothing
///    reaches `VMCELL_SKIP_MANIFEST` and `just skip-manifest-show` then shows the reviewer no gap;
/// 5. none records its own manifest line — the `SKIP <vmm> <capability>` identity belongs to the
///    law, so a battery that composes its own is a second copy of it.
///
/// And over the crate itself (`src_dir`), where the skip sink is **unreachable** — an in-crate unit
/// test has no `mod common;` — the two shapes an author reaches for instead: 6. a printed `SKIP`,
/// which is a green PASS with no manifest line at all (docs/90 found exactly that in
/// `artifact/rootfs/oci.rs`), and 7. a second writer of the manifest, which would put the path law in
/// two places. The crate's honest answer is the one `oci.rs` carries now: claim only what was
/// verified, corroborate the absence against the product's own route, and leave the *recording* to
/// the batteries that can reach the sink.
///
/// A tree that yields nothing is `gate misconfigured`, never a green `ok:` (AGENTS.md): the only way
/// to open nothing is to have been pointed at nothing.
///
/// # Scope, deliberately
///
/// Two trees, both this crate's: `crates/vmcell/tests` (where the law is reachable) and
/// `crates/vmcell/src` (where it is not). Two files elsewhere name the ext4 format and neither is a
/// battery — `vmcell-cli`'s `main.rs` *selects* the format for a build it hands to this crate, and
/// `examples/downstream-kernel/tests/contract.rs` does filename math and asserts the erofs door's
/// refusal without ever packing. Adding them would demand `mod common;` of an out-of-tree workspace
/// that cannot reach the law, which is a false positive, and false positives are how a scan gets
/// routed around.
#[must_use]
pub fn ext4_answer_findings(tests_dir: &std::path::Path, src_dir: &std::path::Path) -> Vec<String> {
    let mut findings = Vec::new();
    let sources = rust_sources_shallow(tests_dir);
    if sources.is_empty() {
        findings.push(format!(
            "gate misconfigured: no `*.rs` under {} — a scan that opens nothing passes every arm",
            tests_dir.display()
        ));
    }
    let batteries: Vec<&(String, String)> = sources
        .iter()
        .filter(|(_, code)| carries(code, EXT4_BATTERY_NEEDLE))
        .collect();
    if !sources.is_empty() && batteries.is_empty() {
        findings.push(format!(
            "gate misconfigured: no file under {} names `{EXT4_BATTERY_NEEDLE}` in code — the \
             roster this gate binds is empty, so every arm below is vacuous",
            tests_dir.display()
        ));
    }
    for (name, code) in batteries {
        if !code.contains("fn ") {
            findings.push(format!(
                "gate misconfigured: {name} stripped to no code at all, so its arms are vacuous"
            ));
            continue;
        }
        let packs = EXT4_PACK_NEEDLES.iter().any(|n| carries(code, n));
        if packs && !carries(code, "mod common;") {
            findings.push(format!(
                "{name} packs an ext4 image but does not declare `mod common;`, so it cannot reach \
                 the one skip law at all — docs/90 G3's file was in exactly this state, and its doc \
                 comment claimed a skip-recording call that existed nowhere in it"
            ));
        }
        if packs && !EXT4_LAW_NEEDLES.iter().any(|n| carries(code, n)) {
            findings.push(format!(
                "{name} packs an ext4 image without asking the one law ({}) — every leg that packs \
                 needs one, or it is assuming the facility",
                EXT4_LAW_NEEDLES.join(" / ")
            ));
        }
        if carries(code, "Ext4Producer::probe()") {
            findings.push(format!(
                "{name} probes the producer directly instead of through the one law — that is how \
                 the batteries came to answer an absent facility three different ways, two of them \
                 wrong (a red CI job and a green PASS). `Ext4Producer::probe_binary` is NOT banned: \
                 driving it against a stub is what produces the refusals the law classifies"
            ));
        }
        if carries(code, "println!(\"SKIP") {
            findings.push(format!(
                "{name} prints its own SKIP instead of recording one. That shape is a green PASS \
                 (AGENTS.md): nothing reaches VMCELL_SKIP_MANIFEST, so `just skip-manifest-show` \
                 shows the reviewer no gap. Route it through the one law, which prints AND records"
            ));
        }
        if carries(code, "record_capability_skip") {
            findings.push(format!(
                "{name} records its own capability skip. The `SKIP <vmm> <capability>` identity \
                 belongs to the one law (EXT4_SKIP_VMM / EXT4_SKIP_CAPABILITY), so a battery that \
                 composes its own is a second copy of it — and a hand-spelled pair is what the \
                 registry battery shipped until docs/90's audit read it"
            ));
        }
    }

    let in_crate = rust_sources_recursive(src_dir);
    if in_crate.is_empty() {
        findings.push(format!(
            "gate misconfigured: no `*.rs` under {} — the in-crate half of this scan opened nothing",
            src_dir.display()
        ));
    }
    for (path, code) in &in_crate {
        if carries(code, "println!(\"SKIP") {
            findings.push(format!(
                "{path} prints a SKIP from inside the crate, where the skip sink is UNREACHABLE (no \
                 `mod common;`), so nothing lands in VMCELL_SKIP_MANIFEST and the leg reports a \
                 green PASS for a claim it never verified. An in-crate leg must instead claim only \
                 what it checked and corroborate the absence against the product's own route"
            ));
        }
        if carries(code, "VMCELL_SKIP_MANIFEST") {
            findings.push(format!(
                "{path} names the skip manifest from inside the crate — the manifest path law has \
                 exactly one writer (`record_capability_skip_to` in tests/common/mod.rs), and a \
                 second one is a copy of it that can drift. The crate's public API deliberately \
                 exposes none: `examples/downstream-kernel` documents VMCELL_SKIP_MANIFEST as \
                 having no consumer-callable surface"
            ));
        }
    }
    findings
}

/// [`ext4_answer_findings`] against this checkout, with the floors that say the discovery actually
/// found the tree — the asserting entry point every battery's gate calls.
///
/// The floor is a *count*, not a list of names: enumerating today's four batteries here would
/// re-introduce the roster this scan exists to stop maintaining. A shrink is still a stop-and-check,
/// which is what the floor buys.
pub fn assert_ext4_batteries_answer_through_the_one_law() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = crate_dir.join("tests");
    let src_dir = crate_dir.join("src");
    let findings = ext4_answer_findings(&tests_dir, &src_dir);
    assert!(
        findings.is_empty(),
        "an absent ext4 facility must have exactly ONE answer in this tree:\n  - {}",
        findings.join("\n  - ")
    );
    let batteries = rust_sources_shallow(&tests_dir)
        .into_iter()
        .filter(|(_, code)| carries(code, EXT4_BATTERY_NEEDLE))
        .count();
    assert!(
        batteries >= 4,
        "the scan discovered only {batteries} ext4 batteries under {}; four carry the format today, \
         so a smaller roster means the discovery needle (`{EXT4_BATTERY_NEEDLE}`) stopped matching \
         the code it is meant to find and every arm above went quiet",
        tests_dir.display()
    );
}

/// Reaps orphaned `vmcell-net-*` **and** `vmcell-seg-*` network namespaces before a
/// privileged/netns test. Test-only.
///
/// v30 §18 delta 8: the segment class needs its **own** sweep call. `cleanup_orphan_netns` filters
/// by a literal starts-with prefix, and `netns_sweep_prefix` is `vmcell-net-` — so before this,
/// a leaked `vmcell-seg-*` was reaped by nothing at all (not this helper, not
/// `HostOrphanScanner::scan_netns`), and an aborted segment test poisoned the next run's segid.
pub fn clean_vmcell_netns() {
    // Match by the same one-law filters the naming produces (default prefix), not hard-coded
    // strings. Both classes, because the two stems are deliberately distinct.
    for prefix in [
        vmcell::naming::netns_sweep_prefix(vmcell::naming::DEFAULT_RESOURCE_PREFIX),
        vmcell::naming::segment_netns_sweep_prefix(vmcell::naming::DEFAULT_RESOURCE_PREFIX),
    ] {
        let removed = vmcell::net::cleanup_orphan_netns(&prefix);
        if !removed.is_empty() {
            println!("clean_vmcell_netns: reaped orphaned namespaces: {removed:?}");
        }
    }
}

/// Reads the applied nftables ruleset for `table` inside network namespace `netns` from the host
/// (the host-observable side of the H-PROXY-1 TPROXY check). Test-only.
pub fn nft_list_table_in_netns(netns: &str, table: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "nft", "list", "table"])
        .args(table.split_whitespace())
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

#[macro_export]
macro_rules! require_cap {
    ($caps:expr, $field:ident, $vmm:expr) => {
        if !$caps.$field {
            if vmcell::vmm::Vmm::id(&$vmm) == "cloud-hypervisor" {
                panic!("SKIP == PASS ERROR: Primary backend (cloud-hypervisor) MUST support capability `{}`", stringify!($field));
            } else {
                $crate::common::record_capability_skip(
                    vmcell::vmm::Vmm::id(&$vmm),
                    stringify!($field),
                );
                println!("SKIP: backend `{}` lacks capability `{}`", vmcell::vmm::Vmm::id(&$vmm), stringify!($field));
                return;
            }
        }
    };
}

#[macro_export]
macro_rules! vmm_matrix_test {
    ($name:ident, |$vmm:ident| $body:block) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[cfg(feature = "cloud-hypervisor")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn cloud_hypervisor() {
                let $vmm =
                    vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(super::common::ch_bin());
                $body
            }

            #[cfg(feature = "firecracker")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn firecracker() {
                let $vmm = vmcell_firecracker::Firecracker::new(super::common::fc_bin());
                $body
            }

            #[cfg(feature = "qemu")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn qemu() {
                let $vmm = vmcell_qemu::Qemu::new(super::common::qemu_bin());
                $body
            }

            #[cfg(feature = "crosvm")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn crosvm() {
                let $vmm = vmcell_crosvm::Crosvm::new(super::common::crosvm_bin());
                $body
            }
        }
    };
}
