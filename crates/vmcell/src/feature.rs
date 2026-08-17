//! The feature vocabulary and the one intersection site (design §7.4, invariant F6).
//!
//! **A cell's feature set is computed, not assumed.** Three capability descriptors exist and, until
//! v33, none of them met: [`crate::vmm::VmmCapabilities`] (what the backend supports),
//! [`crate::hostcaps::HostCapabilities`] (what the host offers), and — nothing at all for an
//! artifact. The moment a rootfs or a handler is selectable, "what can this cell do" stops being a
//! property of the backend and becomes a property of the **combination**.
//!
//! The platform has already been bitten by uncentralized multi-source logic once
//! ([`crate::vmm::config_has_vhost_user_device`] exists precisely because per-backend copies
//! diverged), so F6 puts the intersection in exactly one place — [`crate::feature::FeatureSet::intersect`] — with a
//! call-site source scan beside it, because a gate on the extracted predicate is not a gate on the
//! claim.
//!
//! # The four load-bearing clauses
//!
//! 1. **Unknown feature names are errors, not absences.** Absence is the silent direction: a typo'd
//!    declaration that reads as "unsupported" produces a cell that quietly does less, and every
//!    downstream check passes because nothing claimed the feature. [`crate::feature::Feature`] makes the typo a
//!    compile error at a Rust declaration site; [`crate::feature::Feature::parse`] makes it a hard error *naming the
//!    token* at a pins/sidecar site — the same shape `KconfigValues::parse` already uses, for the
//!    same recorded reason. The backend half of the roster is parity-gated against
//!    `VmmCapabilities` in **both** directions, so a descriptor that grows a field reddens the
//!    vocabulary until it states a stance.
//! 2. **Provenance on every removal, carried as data.** A consumer reads
//!    `snapshot_restore: unavailable (rootfs "debian-systemd" declares no-snapshot)`, never a bare
//!    `false`. [`crate::feature::Removal`] carries `{feature, by, reason}`; [`crate::error::Error::unsupported`]
//!    composes the typed refusal *from* a `Removal`, so the feature string is [`crate::feature::Feature::name`] by
//!    construction — which retires both the prose refusal strings and the substring matchers they
//!    bred in the tests.
//! 3. **A consumer can demand at construction.** `VmConfig::builder(..).require(Feature)` resolves
//!    at `MicroVm::start` against the computed set, so "this cell cannot snapshot" is answered
//!    before the VM boots, with the removal's provenance in the error.
//! 4. **Granularity is decided up front.** One variant per `VmmCapabilities` field, name-for-name,
//!    plus only artifact properties with a validated §10.6 check behind them. A variant that later
//!    splits breaks every declaration in every overlay, so no speculative splits are minted here —
//!    the concurrent-fan-out distinction stays on [`crate::feature::Feature::RestoreRotatesHostPaths`], which the
//!    descriptor already carries.
//!
//! # Pay-for-what-you-use
//!
//! The intersection is arithmetic over small sets at `start`, reading sidecars already resolved with
//! the artifacts; nothing boots and nothing dials. A cell that never calls `require`/`why_absent`
//! computes the same set and pays microseconds.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use crate::error::{Error, Result};

/// A capability a cell may or may not have, in vmcell's own vocabulary.
///
/// **Not a string**, and deliberately **not `#[non_exhaustive]`**, for the same reason
/// [`crate::vmm::VmmCapabilities`] is not: adding a variant must force every declarer to state a
/// stance rather than silently defaulting to absent.
///
/// The first nine variants are one-per-`VmmCapabilities`-field, name-for-name — the N-VMM-1 norm
/// promoted from a comment to a type law, pinned in both directions by
/// `feature_roster_matches_vmm_capabilities_fields`. The last three are artifact-declared
/// properties, each with a §10.6 conformance check behind it (the narrow-name doctrine: a variant
/// claims exactly what is validated).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Feature {
    /// The backend can snapshot a paused VM and restore it (`VmmCapabilities::snapshot_restore`).
    SnapshotRestore,
    /// The backend restores guest RAM lazily / on demand (`VmmCapabilities::lazy_restore`).
    LazyRestore,
    /// The backend can attach virtio-fs shared directories (`VmmCapabilities::virtio_fs_shares`).
    VirtioFsShares,
    /// The backend can drive a vhost-user-net frontend for the unprivileged NAT
    /// (`VmmCapabilities::unprivileged_vhost_user_net`).
    UnprivilegedVhostUserNet,
    /// The backend exposes `/dev/kvm` inside the guest (`VmmCapabilities::nested_virt`).
    NestedVirt,
    /// The backend can attach a virtio-console device (`VmmCapabilities::virtio_console`).
    VirtioConsole,
    /// A restore programs fresh host-visible identities (guest CID), so clones may fan out
    /// concurrently rather than in one lineage (`VmmCapabilities::restore_rotates_host_paths`).
    RestoreRotatesHostPaths,
    /// The backend has a disk I/O rate limiter (`VmmCapabilities::disk_io_throttle`).
    DiskIoThrottle,
    /// The backend can pass a host USB device through (`VmmCapabilities::usb_host_passthrough`).
    UsbHostPassthrough,
    /// The artifact carries a steward the declared placement can start — the **artifact half** of
    /// §3.5's fact. The placement itself contributes through [`Source::Config`]: placement `None`
    /// removes `ControlPlane` with config provenance. Per-op guards stay authoritative (§7.2 rule:
    /// the descriptor is queryable, never a replacement for the per-write check).
    ControlPlane,
    /// The rootfs artifact preserved `security.*` xattrs through packing (§4.7).
    XattrPreserved,
    /// The kernel carries `CONFIG_IKCONFIG_PROC`, so `/proc/config.gz` is readable in-guest — the
    /// §5.6 example's data-plane proof.
    ProcConfigGz,
}

impl Feature {
    /// Every feature, in declaration order. The roster the parity gate and the strict parser read.
    pub const ALL: [Feature; 12] = [
        Feature::SnapshotRestore,
        Feature::LazyRestore,
        Feature::VirtioFsShares,
        Feature::UnprivilegedVhostUserNet,
        Feature::NestedVirt,
        Feature::VirtioConsole,
        Feature::RestoreRotatesHostPaths,
        Feature::DiskIoThrottle,
        Feature::UsbHostPassthrough,
        Feature::ControlPlane,
        Feature::XattrPreserved,
        Feature::ProcConfigGz,
    ];

    /// The feature's canonical name — **the string every refusal and every declaration uses**.
    ///
    /// For the nine backend-capability variants this is byte-identical to the `VmmCapabilities`
    /// field name (pinned in both directions). Composing a refusal string by hand instead of from
    /// this is the F6 violation the `no_production_site_hand_spells_a_feature_string` sweep catches.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Feature::SnapshotRestore => "snapshot_restore",
            Feature::LazyRestore => "lazy_restore",
            Feature::VirtioFsShares => "virtio_fs_shares",
            Feature::UnprivilegedVhostUserNet => "unprivileged_vhost_user_net",
            Feature::NestedVirt => "nested_virt",
            Feature::VirtioConsole => "virtio_console",
            Feature::RestoreRotatesHostPaths => "restore_rotates_host_paths",
            Feature::DiskIoThrottle => "disk_io_throttle",
            Feature::UsbHostPassthrough => "usb_host_passthrough",
            Feature::ControlPlane => "control_plane",
            Feature::XattrPreserved => "xattr_preserved",
            Feature::ProcConfigGz => "proc_config_gz",
        }
    }

    /// `true` for the nine variants that mirror a [`crate::vmm::VmmCapabilities`] field.
    ///
    /// The split matters at exactly one place: the backend contributes those nine from its
    /// descriptor, and contributes nothing about the other three (an artifact property is not the
    /// backend's to declare).
    #[must_use]
    pub const fn is_backend_capability(self) -> bool {
        !matches!(
            self,
            Feature::ControlPlane | Feature::XattrPreserved | Feature::ProcConfigGz
        )
    }

    /// The whole vocabulary rendered for a refusal: `snapshot_restore, lazy_restore, …`.
    ///
    /// The **one** renderer of the roster, shared by [`Feature::parse`]'s unknown-token refusal and
    /// by [`FeatureDeclaration::parse_manifest`]'s empty-name refusal, so two refusals cannot come
    /// to list two different rosters. Composed from [`Feature::name`], which is what makes F6's
    /// "refusal feature strings are `Feature::name()` by construction" true of the *list* as well as
    /// of the single name.
    fn names_joined() -> String {
        Feature::ALL
            .iter()
            .map(|f| f.name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Parses a declaration token **strictly**: an unknown token is an error naming it, never a
    /// silent absence.
    ///
    /// This is clause 1, and it is the whole reason the enum exists rather than a `&str`. A typo'd
    /// misspelled `snapshot_restore` that parsed to "absent" would produce a cell that quietly does less while
    /// every downstream check passes, because nothing claimed the feature.
    ///
    /// It answers about a **token**, so it knows nothing about where that token came from: a caller
    /// that reads tokens out of a file attaches its own locator (the sidecar parser does it through
    /// its own `manifest_line_error` composer; the registry does it with the pins key). Propagating
    /// this error unchanged from a line-oriented parser is the defect the `feature_manifest` fuzz
    /// target found.
    ///
    /// # Errors
    ///
    /// [`Error::Artifact`] naming the offending token and listing the known names.
    pub fn parse(token: &str) -> Result<Feature> {
        Feature::ALL
            .into_iter()
            .find(|f| f.name() == token)
            .ok_or_else(|| {
                Error::Artifact(format!(
                    "unknown feature `{token}`: a feature token must be one of [{}]. \
                     An unknown token is an ERROR, not an absence (F6) — a typo that read as \
                     `unsupported` would produce a cell that quietly does less while every \
                     downstream check passed, because nothing claimed the feature.",
                    Feature::names_joined()
                ))
            })
    }
}

/// **The** unknown feature token every gate in this file refuses: a **wrong word, not a
/// misspelling**.
///
/// The fixture this replaces was `snapshot_restore` with its trailing `e` dropped — derived from
/// [`Feature::name`] rather than typed, which was the wrong axis to defend on. That truncation is a
/// **prefix of a valid name**, and [`Feature::parse`]'s refusal echoes the entire vocabulary through
/// [`Feature::names_joined`] — so `msg.contains(typo)` was satisfied by the roster echo alone.
/// Measured: a `parse` whose message read ``unknown feature `virtio_console` `` for that truncated
/// input left both `unknown_feature_token_is_a_hard_error_naming_it` and
/// `manifest_parse_is_strict_and_round_trips` **green**, as did one naming no token at all.
/// That is AGENTS.md's banned substring matcher on a roster-composed refusal, and it is
/// the same vacuity `examples/downstream-kernel/tests/contract.rs`'s `BOGUS_FEATURE_TOKEN` closed —
/// this is that fixture's in-crate twin, spelled identically on purpose rather than as a second
/// invention.
///
/// A real-word near miss closes both halves the truncation opened: no dictionary corrects
/// `restored`, so the `typos` gate has no opinion and nobody will later "fix" the fixture; and no
/// valid token contains it, so a `contains` can only pass when the refusal really echoes what it
/// refused. It is also the *tighter* fixture — a parser that accepted any token merely *starting
/// with* a valid name would take this one and still reject the truncation it replaces.
#[cfg(test)]
const BOGUS_FEATURE_TOKEN: &str = "snapshot_restored";

/// A second unknown token, used only to prove the roster echo does not carry
/// [`BOGUS_FEATURE_TOKEN`]. Real words, so the spell checker has no opinion about it either.
///
/// Gated with its one consumer rather than with [`BOGUS_FEATURE_TOKEN`], which both test modules
/// use: the non-vacuity control belongs beside the first use, the way the sibling fixture's does.
#[cfg(all(test, feature = "host-common"))]
const OTHER_BOGUS_FEATURE_TOKEN: &str = "not_a_feature";

/// `msg` with the composed roster echo replaced by a placeholder — the form a **token** needle is
/// matched against.
///
/// [`Feature::parse`]'s refusal and [`FeatureDeclaration::parse_manifest`]'s empty-name arm both
/// list the whole vocabulary. A `contains` over the raw message therefore cannot distinguish "the
/// refusal names the token it refused" from "the token is a substring of some valid name", which is
/// exactly how the fixture above came to be vacuous. Excising the echo first makes the needle
/// structurally about the rest of the message, whatever token a later leg picks: the fixture choice
/// and the assertion shape are two independent defenses, and this is the one that does not depend
/// on anybody remembering.
///
/// It can only ever *narrow* a haystack, so it cannot manufacture a pass. Asserting the echo is
/// **present** stays a separate assertion at the sites that claim it, because a silent no-op here
/// would weaken the excision without failing anything.
#[cfg(test)]
fn without_the_roster_echo(msg: &str) -> String {
    msg.replace(&Feature::names_joined(), "<the roster, echoed>")
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Who removed a feature from a cell's set.
///
/// The provenance axes, in the fixed order [`FeatureSet::why_absent`] reports them: artifact
/// (kernel → rootfs → handler) → backend → host → config. Deterministic, never insertion-order luck.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Source {
    /// The VMM backend, by its `Vmm::id()`.
    ///
    /// `String` rather than the §7.4 sketch's `&'static str` (names advisory, behavior binds):
    /// `Vmm::id()` returns a borrowed `&str`, and every sibling axis already carries an owned
    /// label, so one representation is one fewer lifetime in every signature that touches a
    /// `Removal`. Recorded in the implementation notes.
    Backend(String),
    /// The kernel artifact, by its label.
    Kernel(String),
    /// The rootfs artifact, by its label.
    Rootfs(String),
    /// The guest-handler artifact, by its label.
    Handler(String),
    /// The host, via [`crate::hostcaps::HostCapabilities`].
    Host,
    /// The cell's own configuration (a declared steward placement, a config-only eligibility arm).
    Config,
}

impl Source {
    /// The axis order removals are reported in — lower sorts first in [`FeatureSet::why_absent`].
    ///
    /// Artifact axes come first because an artifact declaration is the most specific statement
    /// about a cell: "this rootfs cannot snapshot" is a more useful answer than "this backend can",
    /// and the §18 delta-9 proof cell asserts exactly that ordering.
    const fn axis_rank(&self) -> u8 {
        match self {
            Source::Kernel(_) => 0,
            Source::Rootfs(_) => 1,
            Source::Handler(_) => 2,
            Source::Backend(_) => 3,
            Source::Host => 4,
            Source::Config => 5,
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Backend(n) => write!(f, "backend \"{n}\""),
            Source::Kernel(l) => write!(f, "kernel \"{l}\""),
            Source::Rootfs(l) => write!(f, "rootfs \"{l}\""),
            Source::Handler(l) => write!(f, "handler \"{l}\""),
            Source::Host => f.write_str("host"),
            Source::Config => f.write_str("config"),
        }
    }
}

/// Why a feature is **not** in a cell's set. Never a bare `false`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Removal {
    /// The feature that is absent.
    pub feature: Feature,
    /// Who removed it.
    pub by: Source,
    /// Why, in one clause, rendered into the typed refusal.
    pub reason: &'static str,
}

impl fmt::Display for Removal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: unavailable ({} {})",
            self.feature.name(),
            self.by,
            self.reason
        )
    }
}

/// **The one refusal** every backend returns when a vhost-user device blocks snapshot/restore (S1).
///
/// Four backends spelled this four different ways (`"snapshot with a vhost-user device"`,
/// `"snapshot/restore with a vhost-user device"`, and two longer variants), which is what bred
/// `feature.contains("vhost-user")` in three test suites. The predicate has been one law
/// (`config_has_vhost_user_device`) since S1 landed; the *refusal* is one law now too, so the four
/// cannot drift apart again and a test matches `Feature::SnapshotRestore.name()` exactly.
pub const VHOST_USER_BLOCKS_SNAPSHOT: Removal = Removal {
    feature: Feature::SnapshotRestore,
    by: Source::Config,
    reason: "attaches a vhost-user device (a virtio-fs share, the unprivileged NAT, or an \
             external vsock daemon), which is not migratable",
};

/// The one refusal for QEMU's snapshot path when the config asks for the external vsock daemon.
///
/// A snapshot-eligible QEMU must use the **in-kernel** vsock transport: the external
/// `vhost-device-vsock` daemon is itself a vhost-user device, so it trips S1.
pub const IN_KERNEL_VSOCK_REQUIRED_FOR_SNAPSHOT: Removal = Removal {
    feature: Feature::SnapshotRestore,
    by: Source::Config,
    reason: "selects the external vsock daemon; a snapshot-eligible QEMU needs the in-kernel \
             vsock transport (set snapshotting = true)",
};

/// A declaration an artifact makes about itself.
///
/// The registry entry (§10.5) is the one authority; the feature-manifest sidecar is its travel form,
/// emitted from the resolved entry at build time. An artifact with **no** declaration contributes
/// the baseline — exactly what the canonical artifacts provide — stated, not silent, which is why
/// [`FeatureDeclaration::baseline`] exists rather than an empty map defaulting to "absent".
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FeatureDeclaration {
    /// The declaring artifact's provenance (used verbatim as the [`Source`] of any removal).
    pub source: Option<Source>,
    /// Explicit stances. A feature absent from this map is **not** declared absent — it simply is
    /// not this artifact's to speak about, and the axis contributes nothing for it.
    pub stances: BTreeMap<Feature, bool>,
}

/// The feature-manifest sidecar path that travels beside `artifact` (§7.4): `rootfs.erofs` →
/// `rootfs.features`, `rootfs-debian-systemd.erofs` → `rootfs-debian-systemd.features`,
/// `vmlinux` → `vmlinux.features`.
///
/// The **one** composer, called by the reader ([`FeatureDeclaration::load_beside`]) and by the
/// producer ([`crate::artifact::rootfs::RootfsFeaturesStage`]) alike. A sidecar whose writer and
/// reader spell the name separately is a declaration that silently stops being read: the reader
/// finds nothing, falls back to the baseline exactly as it is *supposed* to for an un-annotated
/// artifact, and says nothing about it.
///
/// **It REPLACES the extension** (`Path::with_extension`), which is the dominant sidecar law in the
/// artifacts dir — the pipeline derives every stage's `.cache_key` the same way, and the
/// label-sanitizing filename suffixes (`rootfs_filename_suffix`, `kernel_filename_suffix`) exist
/// precisely to make replacement safe for a dotted label. §7.4 spells the file
/// `rootfs-debian-systemd.features`, and `load_beside` shipped with this law in §18 delta 2, so
/// changing it now would silently orphan any sidecar already written.
///
/// **Deliberately not the law [`crate::artifact::kernel::resolved_config_path`] uses**, which
/// APPENDS (`vmlinux-6.12.94` → `vmlinux-6.12.94.config`). That one takes a path whose *label* may
/// carry dots, where replacement would eat the trailing `.94` and point two labels at one config.
/// The tree therefore holds two sidecar-naming laws on purpose; each states its reason at its own
/// site, and neither is the default to reach for without reading the other.
#[must_use]
pub fn feature_manifest_path(artifact: &std::path::Path) -> std::path::PathBuf {
    artifact.with_extension("features")
}

/// **The one locator** every [`FeatureDeclaration::parse_manifest`] refusal carries: the 1-based
/// line number *and* the offending line's own code text.
///
/// Kept as a composer rather than a format string repeated per arm because the drift had already
/// shipped: three of the parser's four arms hand-attached `idx + 1` and the `Feature::parse` arm
/// forgot, propagating a token-only refusal. The `feature_manifest` fuzz target found it with **two
/// bytes** — `=z`, where the key before `=` is empty, so the propagated message read
/// ``unknown feature ``: …`` and quoted neither a line number nor any byte of the input. A rule that
/// each arm must remember is a rule a *new* arm can forget; a composer every arm goes through is one
/// it cannot, and `every_manifest_refusal_goes_through_the_one_locator_composer` scans the call sites
/// so the composer cannot be bypassed either.
///
/// Both halves are load-bearing. The **number** answers "which of the three identical lines"; the
/// **text** survives a consumer who cannot see the numbering (a here-doc, a generated sidecar, a
/// body assembled in memory). The line is quoted at full length on purpose: this is local build
/// config, not a guest-controlled frame, and the truncating render would defeat the very property
/// the fuzz target asserts.
fn manifest_locator(line_number: usize, line: &str) -> String {
    format!("feature manifest line {line_number} (`{line}`)")
}

/// Composes one [`FeatureDeclaration::parse_manifest`] refusal: [`manifest_locator`], then `detail`.
///
/// `detail` says only what is wrong; it never restates the line or its number, because that is this
/// function's job.
fn manifest_line_error(line_number: usize, line: &str, detail: String) -> Error {
    Error::Artifact(format!("{}: {detail}", manifest_locator(line_number, line)))
}

impl FeatureDeclaration {
    /// The baseline declaration: what the canonical artifacts provide, with no stance of their own.
    ///
    /// Pre-v33 artifacts carry no sidecar and get exactly this, so they keep working unchanged —
    /// and the fact that they do is *stated here*, not left to an empty-map coincidence.
    #[must_use]
    pub fn baseline(source: Source) -> Self {
        FeatureDeclaration {
            source: Some(source),
            stances: BTreeMap::new(),
        }
    }

    /// Parses a feature-manifest sidecar body: one `name = true|false` per line, `#` comments and
    /// blank lines ignored.
    ///
    /// Strict on **both** halves — an unknown feature name and an unparseable boolean are each hard
    /// errors naming the offending token (F6 clause 1).
    ///
    /// **Every** refusal is located, through the one `manifest_line_error` composer: a consumer
    /// reads which line offended and what that line said, never just "the manifest is bad". The five
    /// malformed shapes are kept *distinct*, because the fix differs per shape: no `=` at all, an
    /// empty name before the `=`, an unknown name, a stance that is not a boolean, and a duplicate.
    /// The empty-name arm is the one this fix SPLIT OUT: an empty name is a malformed **line**, not an
    /// unknown feature, and reporting it as ``unknown feature `` `` named nothing a consumer could
    /// search for.
    ///
    /// # Errors
    ///
    /// [`Error::Artifact`] naming the line, the line's text, and the offending token.
    pub fn parse_manifest(body: &str, source: Source) -> Result<Self> {
        let mut stances = BTreeMap::new();
        for (idx, raw) in body.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            // The one locator, bound to this line once: every refusal below is `reject(…)`, so no
            // arm can ship a message a consumer cannot locate and none can attach the wrong line.
            let reject = |detail: String| manifest_line_error(idx + 1, line, detail);
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| reject("expected `<feature> = <true|false>`".to_string()))?;
            let key = key.trim();
            if key.is_empty() {
                // NOT `Feature::parse("")`'s refusal: nothing was misspelled, so "unknown feature"
                // would send a consumer looking for a token that is not there. The roster still
                // travels — composed, never hand-listed — because "which names are legal" is the
                // consumer's very next question.
                return Err(reject(format!(
                    "no feature name before the `=`; expected `<feature> = <true|false>`, where \
                     `<feature>` is one of [{}]",
                    Feature::names_joined()
                )));
            }
            let feature = Feature::parse(key).map_err(|e| reject(e.to_string()))?;
            let stance = match value.trim() {
                "true" => true,
                "false" => false,
                other => {
                    return Err(reject(format!(
                        "`{}` must be `true` or `false`, got `{other}`. A stance is stated or the \
                         manifest is rejected — never defaulted.",
                        feature.name()
                    )));
                }
            };
            if stances.insert(feature, stance).is_some() {
                return Err(reject(format!(
                    "`{}` is declared twice; a duplicate stance has no defined precedence, so it \
                     is rejected rather than last-writer-wins.",
                    feature.name()
                )));
            }
        }
        Ok(FeatureDeclaration {
            source: Some(source),
            stances,
        })
    }

    /// Loads the feature-manifest sidecar that travels beside `artifact`, or the **baseline**
    /// when there is none.
    ///
    /// The sidecar path is [`feature_manifest_path`], the one composer the producer
    /// ([`crate::artifact::rootfs::RootfsFeaturesStage`]) writes through, so reader and writer
    /// cannot drift onto two spellings of one file.
    ///
    /// **An absent sidecar is the baseline, stated** (§7.4): the canonical artifacts *are* the
    /// baseline, so every pre-v33 artifact keeps working unchanged. It is deliberately not "declare
    /// everything absent" — that would make an un-annotated artifact look maximally incapable, the
    /// silent direction F6 exists to close.
    ///
    /// # Errors
    ///
    /// [`Error::Artifact`] when the sidecar exists but does not parse. A malformed sidecar is a
    /// hard error, never a fallback to the baseline: falling back would let a typo'd declaration
    /// read as "no declaration", which is the same silent-absence failure one level up.
    pub fn load_beside(artifact: &std::path::Path, source: Source) -> Result<Self> {
        let sidecar = feature_manifest_path(artifact);
        match std::fs::read_to_string(&sidecar) {
            Ok(body) => FeatureDeclaration::parse_manifest(&body, source)
                .map_err(|e| Error::Artifact(format!("{}: {e}", sidecar.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(FeatureDeclaration::baseline(source))
            }
            Err(e) => Err(Error::Artifact(format!(
                "cannot read the feature manifest {}: {e}",
                sidecar.display()
            ))),
        }
    }

    /// Renders the sidecar body this declaration parses back from (round-trip pinned by unit test).
    #[must_use]
    pub fn render_manifest(&self) -> String {
        let mut out = String::from(
            "# vmcell feature manifest (design §7.4). Emitted from the resolved registry entry;\n\
             # the entry is the one authority and this is its travel form.\n",
        );
        for (feature, stance) in &self.stances {
            out.push_str(feature.name());
            out.push_str(" = ");
            out.push_str(if *stance { "true" } else { "false" });
            out.push('\n');
        }
        out
    }
}

/// The computed feature set of one cell: backend × host × artifacts, intersected.
///
/// Gated on `host-common` with the rest of the intersection machinery: computing a set needs
/// [`crate::vmm::VmmCapabilities`], which only the host build has. The **vocabulary** above
/// ([`Feature`], [`Source`], [`Removal`], [`FeatureDeclaration`]) is deliberately ungated — it is
/// what [`crate::error::Error::from_removal`] composes refusals from, and `error` compiles in every
/// feature configuration.
#[cfg(feature = "host-common")]
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FeatureSet {
    removals: BTreeMap<Feature, Vec<Removal>>,
}

#[cfg(feature = "host-common")]
impl FeatureSet {
    /// **The one intersection site (F6).**
    ///
    /// Every axis is a *remover*: a feature is present unless something took it away, and every
    /// removal names who and why. That framing is what makes the set an intersection rather than a
    /// rename of the backend flags — the two-sided provenance gate proves it by showing the same
    /// artifact's removal named by the rootfs on one backend and by the backend on another.
    ///
    /// `caps` is the backend descriptor, `host` the host's declaration (`None` when the probe was
    /// not run — a host axis that did not speak removes nothing, it does not remove everything),
    /// and `artifacts` the per-artifact declarations in axis order.
    #[must_use]
    pub fn intersect(
        backend: &str,
        caps: &crate::vmm::VmmCapabilities,
        host: Option<&HostDeclaration>,
        artifacts: &[FeatureDeclaration],
    ) -> Self {
        let mut set = FeatureSet::default();

        // The backend axis: the descriptor stays the backend's ONE declaration input, read
        // field-for-variant through the parity-gated mapping rather than a second vocabulary.
        for feature in Feature::ALL {
            if feature.is_backend_capability() && !backend_supports(caps, feature) {
                set.remove(Removal {
                    feature,
                    by: Source::Backend(backend.to_string()),
                    reason: "does not support it",
                });
            }
        }

        // The host axis. A `None` host is "not probed", which removes nothing — the F1 distinction
        // between an absent facility and an unasked question.
        if let Some(host) = host {
            for (feature, reason) in host.removals() {
                set.remove(Removal {
                    feature,
                    by: Source::Host,
                    reason,
                });
            }
        }

        // The artifact axes. Only an EXPLICIT `false` removes: a feature absent from a
        // declaration's map is not that artifact's to speak about.
        for decl in artifacts {
            let Some(source) = decl.source.clone() else {
                continue;
            };
            for (feature, stance) in &decl.stances {
                if !*stance {
                    set.remove(Removal {
                        feature: *feature,
                        by: source.clone(),
                        reason: "declares it absent",
                    });
                }
            }
        }

        set
    }

    /// Records one removal, preserving every remover under a feature (see [`Self::removals`]).
    fn remove(&mut self, removal: Removal) {
        self.removals
            .entry(removal.feature)
            .or_default()
            .push(removal);
    }

    /// Adds a removal after construction — the config axis, applied by the one intersection caller.
    ///
    /// Kept separate from [`Self::intersect`]'s inputs because a config-derived removal
    /// (a declared steward placement, §3.5) is not a declaration an artifact or a backend made.
    pub fn remove_by_config(&mut self, feature: Feature, reason: &'static str) {
        self.remove(Removal {
            feature,
            by: Source::Config,
            reason,
        });
    }

    /// Is the feature present in this cell?
    #[must_use]
    pub fn has(&self, f: Feature) -> bool {
        !self.removals.contains_key(&f)
    }

    /// `None` when present; `Some(&Removal)` naming who removed it and why.
    ///
    /// Under multiple removers this reports the **first in the fixed axis order** artifact →
    /// backend → host → config, so the answer is deterministic rather than insertion-order luck.
    /// [`Self::removals`] returns every one.
    #[must_use]
    pub fn why_absent(&self, f: Feature) -> Option<&Removal> {
        self.removals
            .get(&f)?
            .iter()
            .min_by_key(|r| r.by.axis_rank())
    }

    /// Every removal recorded for `f`, in the order they were applied. Empty when present.
    #[must_use]
    pub fn removals(&self, f: Feature) -> &[Removal] {
        self.removals.get(&f).map_or(&[], Vec::as_slice)
    }

    /// Resolves a consumer's `require(..)` list against the computed set.
    ///
    /// This is clause 3, and it runs at `MicroVm::start` — before anything boots — so "this cell
    /// cannot snapshot" is answered with provenance rather than at the first `snapshot()` call.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] composed from the first unmet requirement's [`Removal`], so the
    /// error's `feature` string is [`Feature::name`] by construction.
    pub fn require_all(&self, backend: &str, required: &[Feature]) -> Result<()> {
        for f in required {
            if let Some(removal) = self.why_absent(*f) {
                return Err(Error::from_removal(backend, removal));
            }
        }
        Ok(())
    }
}

/// The host's contribution to the intersection, **derived from — never probed beside** —
/// [`crate::hostcaps::HostCapabilities`].
///
/// A thin newtype rather than a second descriptor: the host axis speaks about exactly the features
/// it can actually decide (today that is [`Feature::NestedVirt`], and nothing else), and says
/// nothing about the rest. The facts themselves come from the one start-up descriptor, which is
/// where §7.2 rule 1 puts every host probe; this type is the projection of it that the intersection
/// consumes, so growing the axis means growing `HostCapabilities` and
/// [`Self::from_host_capabilities`], never adding a read here.
#[cfg(feature = "host-common")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HostDeclaration {
    /// Whether the host has nested virtualization enabled
    /// ([`crate::hostcaps::HostCapabilities::nested_virt`]).
    pub nested_virt: bool,
}

#[cfg(feature = "host-common")]
impl HostDeclaration {
    /// Derives the host axis from the one start-up [`crate::hostcaps::HostCapabilities`] descriptor.
    ///
    /// **This is what makes §7.4's "the host contributes `HostCapabilities`" true.** Before docs/90
    /// D5 it was not: this type ran its own `/sys/module/*/parameters/nested` read, so the host axis
    /// had two probes and the descriptor §7.4 named contributed nothing — while this module's own
    /// rustdoc claimed the derivation that did not exist. A caller holding the boot-time descriptor
    /// (the daemon logs one, §11.2) passes it here rather than re-probing.
    ///
    /// Nested virtualization is the worked example of why the intersection earns its keep (§7.4):
    /// it is true only when the backend advertises it, **and** the kernel artifact declares the KVM
    /// symbols, **and** the host has nested enabled — three axes the pre-v33 tree checked in three
    /// unrelated places with three different failure shapes. This carries the third.
    #[must_use]
    pub fn from_host_capabilities(caps: &crate::hostcaps::HostCapabilities) -> Self {
        HostDeclaration {
            nested_virt: caps.nested_virt,
        }
    }

    /// Probes the host axis, for a caller that has **no** descriptor in hand.
    ///
    /// One probe, not two: this runs [`crate::hostcaps::HostCapabilities::probe`] and projects it
    /// through [`Self::from_host_capabilities`], so the nested-virt read has exactly one
    /// implementation and one home (the descriptor's). The extra reads a full probe performs are
    /// `/proc/self/status`, `/dev/kvm` and three cgroup control files — microseconds against a VM
    /// boot, and cheaper than the second source of truth this used to be. A caller that already
    /// probed should pass its descriptor instead.
    #[must_use]
    pub fn probe() -> Self {
        Self::from_host_capabilities(&crate::hostcaps::HostCapabilities::probe())
    }

    fn removals(&self) -> Vec<(Feature, &'static str)> {
        let mut out = Vec::new();
        if !self.nested_virt {
            out.push((
                Feature::NestedVirt,
                "does not have nested virtualization enabled",
            ));
        }
        out
    }
}

/// Reads one backend-capability variant out of the descriptor.
///
/// The **one** field↔variant mapping. Exhaustive on `Feature` so a new variant is a compile error
/// here, and parity-gated against the descriptor's field list in both directions by
/// `feature_roster_matches_vmm_capabilities_fields`.
#[cfg(feature = "host-common")]
fn backend_supports(caps: &crate::vmm::VmmCapabilities, feature: Feature) -> bool {
    match feature {
        Feature::SnapshotRestore => caps.snapshot_restore,
        Feature::LazyRestore => caps.lazy_restore,
        Feature::VirtioFsShares => caps.virtio_fs_shares,
        Feature::UnprivilegedVhostUserNet => caps.unprivileged_vhost_user_net,
        Feature::NestedVirt => caps.nested_virt,
        Feature::VirtioConsole => caps.virtio_console,
        Feature::RestoreRotatesHostPaths => caps.restore_rotates_host_paths,
        Feature::DiskIoThrottle => caps.disk_io_throttle,
        Feature::UsbHostPassthrough => caps.usb_host_passthrough,
        // Artifact properties: the backend has no stance. Reached only if a caller asks
        // `backend_supports` about a non-backend feature, which `intersect` guards against.
        Feature::ControlPlane | Feature::XattrPreserved | Feature::ProcConfigGz => true,
    }
}

#[cfg(all(test, feature = "host-common"))]
mod host_tests {
    use super::*;

    fn caps_all(v: bool) -> crate::vmm::VmmCapabilities {
        crate::vmm::VmmCapabilities {
            snapshot_restore: v,
            lazy_restore: v,
            virtio_fs_shares: v,
            unprivileged_vhost_user_net: v,
            nested_virt: v,
            virtio_console: v,
            restore_rotates_host_paths: v,
            disk_io_throttle: v,
            usb_host_passthrough: v,
        }
    }

    /// F6 clause 1's structural half: the nine backend variants' names are EXACTLY the descriptor's
    /// field names, in both directions.
    ///
    /// This is the exhaustive-literal law extended across a type boundary. `backend_supports` is
    /// exhaustive on `Feature`, so a new *variant* is already a compile error; this test covers the
    /// other direction — a `VmmCapabilities` that grows a **field** must redden the vocabulary
    /// until it states a stance, and no compiler check can see that.
    #[test]
    fn feature_roster_matches_vmm_capabilities_fields() {
        // The descriptor's field names, read out of the source of truth rather than retyped.
        let src = include_str!("vmm/mod.rs");
        let start = src
            .find("pub struct VmmCapabilities {")
            .expect("VmmCapabilities struct definition");
        let body = &src[start..];
        let end = body.find("\n}").expect("struct terminator");
        let mut fields: Vec<&str> = body[..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let rest = l.strip_prefix("pub ")?;
                let (name, _) = rest.split_once(':')?;
                Some(name)
            })
            .collect();
        fields.sort_unstable();

        let mut variants: Vec<&str> = Feature::ALL
            .iter()
            .filter(|f| f.is_backend_capability())
            .map(|f| f.name())
            .collect();
        variants.sort_unstable();

        assert_eq!(
            variants, fields,
            "the backend half of the Feature roster must equal VmmCapabilities' fields \
             name-for-name, in BOTH directions (F6 / N-VMM-1 promoted to a type law). A field \
             added to the descriptor without a Feature variant would be a capability no \
             declaration can speak about; a variant without a field would be a feature no backend \
             can support."
        );
    }

    /// The strict parse: an unknown token is an error NAMING it, never a silent absence.
    ///
    /// Both halves of that claim, and neither by a bare substring match on the raw message. The
    /// refusal echoes the whole vocabulary, so the **roster** half is asserted against
    /// [`Feature::names_joined`] — the composer, not a fragment of it — and the **token** half
    /// against the message with that echo excised ([`without_the_roster_echo`]).
    ///
    /// RED on the inverse, measured three ways — one arm per shape this defect has. A `parse`
    /// naming the wrong token, and one naming no token at all, each fail the first assertion (both
    /// passed what it replaces: see [`BOGUS_FEATURE_TOKEN`]); reverting the fixture to a prefix of a
    /// valid name fails the non-vacuity leg instead, because the roster echo then carries it.
    #[test]
    fn unknown_feature_token_is_a_hard_error_naming_it() {
        let err = Feature::parse(BOGUS_FEATURE_TOKEN).expect_err("a wrong word must not parse");
        let msg = err.to_string();
        assert!(
            without_the_roster_echo(&msg).contains(BOGUS_FEATURE_TOKEN),
            "the error must name the offending token OUTSIDE the echoed roster, so the token is \
             findable and the assertion is not satisfied by the vocabulary listing; got: {msg}"
        );
        assert!(
            msg.contains(&Feature::names_joined()),
            "the error must list the known names so the fix is obvious; got: {msg}"
        );

        // NON-VACUITY of the token assertion, demonstrated rather than argued — the shape the
        // sibling `examples/downstream-kernel/tests/contract.rs` already ships. A refusal about a
        // DIFFERENT unknown token must not carry this one's spelling: the only text the two
        // refusals share is the roster echo, so this leg IS the empirical proof that
        // `BOGUS_FEATURE_TOKEN` is not inside it — and the arm that reddens the day somebody
        // spells the fixture as a substring of a valid name again.
        let other = Feature::parse(OTHER_BOGUS_FEATURE_TOKEN)
            .expect_err("the second wrong word must not parse either")
            .to_string();
        assert!(
            !other.contains(BOGUS_FEATURE_TOKEN),
            "`{BOGUS_FEATURE_TOKEN}` must not appear in a refusal that is not about it, or the \
             assertion above is matching the echoed vocabulary instead of the refused token: \
             {other}"
        );

        // Positive control: the correctly-spelled sibling parses.
        assert_eq!(
            Feature::parse("snapshot_restore").expect("the correct spelling parses"),
            Feature::SnapshotRestore
        );
    }

    /// Every name round-trips through the strict parser — no variant is unreachable by declaration.
    #[test]
    fn every_feature_name_round_trips() {
        for f in Feature::ALL {
            assert_eq!(Feature::parse(f.name()).expect("round trip"), f);
        }
        assert_eq!(
            Feature::ALL.len(),
            Feature::ALL
                .iter()
                .map(|f| f.name())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "two variants share a name, so one is unreachable through the parser"
        );
    }

    /// **F6's headline gate: the two-sided provenance pair.**
    ///
    /// The SAME artifact declaration, intersected against two different backends. On the backend
    /// that supports snapshotting, the removal names the ROOTFS; on the one that does not, it names
    /// the BACKEND. That is what proves the intersection is an intersection and not a rename of the
    /// backend flags — a set that merely echoed `VmmCapabilities` would name the backend both
    /// times, and a set that merely echoed the artifact would name the rootfs both times.
    #[test]
    fn two_sided_provenance_names_the_rootfs_on_one_backend_and_the_backend_on_the_other() {
        let mut stances = BTreeMap::new();
        stances.insert(Feature::SnapshotRestore, false);
        let rootfs = FeatureDeclaration {
            source: Some(Source::Rootfs("debian-systemd".into())),
            stances,
        };

        // Backend A snapshots; the only remover is the artifact.
        let a = FeatureSet::intersect(
            "cloud-hypervisor",
            &caps_all(true),
            None,
            std::slice::from_ref(&rootfs),
        );
        assert!(!a.has(Feature::SnapshotRestore));
        assert_eq!(
            a.why_absent(Feature::SnapshotRestore).map(|r| &r.by),
            Some(&Source::Rootfs("debian-systemd".into())),
            "with a capable backend the artifact is the only remover, and must be named"
        );

        // Backend B does not; BOTH removed it, and the fixed axis order reports the artifact first.
        let b = FeatureSet::intersect("crosvm", &caps_all(false), None, &[rootfs]);
        assert!(!b.has(Feature::SnapshotRestore));
        assert_eq!(
            b.removals(Feature::SnapshotRestore).len(),
            2,
            "both axes removed it and the set records ALL removers"
        );
        // The backend removal is present and correctly attributed — the half that differs.
        assert!(
            b.removals(Feature::SnapshotRestore)
                .iter()
                .any(|r| r.by == Source::Backend("crosvm".into())),
            "the incapable backend must appear as a remover"
        );
        // And a feature the artifact says nothing about is removed by the BACKEND alone.
        assert_eq!(
            b.why_absent(Feature::DiskIoThrottle).map(|r| &r.by),
            Some(&Source::Backend("crosvm".into())),
            "a feature no artifact declares is the backend's to remove, and the provenance says so"
        );
        assert!(
            a.has(Feature::DiskIoThrottle),
            "positive control: the capable backend keeps the feature the incapable one removed"
        );
    }

    /// `why_absent` is deterministic under multiple removers — fixed axis order, not insertion luck.
    #[test]
    fn why_absent_reports_the_fixed_axis_order_not_insertion_order() {
        let mut stances = BTreeMap::new();
        stances.insert(Feature::NestedVirt, false);
        let kernel = FeatureDeclaration {
            source: Some(Source::Kernel("6.12.94".into())),
            stances,
        };
        // Host removes it too, and is inserted BEFORE the artifact axis inside `intersect`.
        let set = FeatureSet::intersect(
            "qemu",
            &caps_all(true),
            Some(&HostDeclaration { nested_virt: false }),
            &[kernel],
        );
        assert_eq!(set.removals(Feature::NestedVirt).len(), 2);
        assert_eq!(
            set.why_absent(Feature::NestedVirt).map(|r| &r.by),
            Some(&Source::Kernel("6.12.94".into())),
            "the artifact axis outranks the host axis regardless of application order"
        );
    }

    /// An artifact that declares nothing removes nothing — the baseline is stated, not silent.
    #[test]
    fn a_baseline_declaration_removes_nothing() {
        let set = FeatureSet::intersect(
            "cloud-hypervisor",
            &caps_all(true),
            None,
            &[FeatureDeclaration::baseline(Source::Rootfs(
                "default".into(),
            ))],
        );
        for f in Feature::ALL {
            assert!(
                set.has(f),
                "{f} must survive a baseline declaration on a fully-capable backend"
            );
        }
    }

    /// docs/90 D5: the host axis is **derived from** the one `HostCapabilities` descriptor, which is
    /// what §7.4's "the host contributes `HostCapabilities`" says and what the code did not do.
    ///
    /// Both directions, and through the whole intersection rather than at the projection alone — a
    /// derivation that hardcoded a stance, or read anything other than the descriptor's field, goes
    /// red here. The complementary half is
    /// `the_host_axis_reads_the_nested_parameter_in_exactly_one_place`: this test proves the
    /// derivation is faithful, the scan proves nothing probes beside it.
    #[test]
    fn the_host_axis_is_derived_from_the_one_host_capabilities_descriptor() {
        let host_with = |nested: bool| crate::hostcaps::HostCapabilities {
            cap_net_admin: false,
            cap_sys_admin: false,
            kvm_accessible: true,
            netns_reachable: false,
            delegated_controllers: std::collections::BTreeSet::new(),
            domain_leaf: false,
            nested_virt: nested,
        };

        for nested in [true, false] {
            assert_eq!(
                HostDeclaration::from_host_capabilities(&host_with(nested)),
                HostDeclaration {
                    nested_virt: nested
                },
                "the declaration must carry the descriptor's stance, not one of its own"
            );
        }

        // Through the intersection: a descriptor saying "nested off" removes the feature with HOST
        // provenance on a fully-capable backend…
        let off = FeatureSet::intersect(
            "cloud-hypervisor",
            &caps_all(true),
            Some(&HostDeclaration::from_host_capabilities(&host_with(false))),
            &[],
        );
        let removal = off
            .why_absent(Feature::NestedVirt)
            .expect("a host that says nested is off removes it");
        assert_eq!(removal.by, Source::Host);
        assert_eq!(removal.feature.name(), "nested_virt");
        // …and the same descriptor with the stance flipped is the positive control.
        assert!(
            FeatureSet::intersect(
                "cloud-hypervisor",
                &caps_all(true),
                Some(&HostDeclaration::from_host_capabilities(&host_with(true))),
                &[],
            )
            .has(Feature::NestedVirt),
            "positive control: a descriptor saying nested is ON must keep the feature"
        );

        // `probe()` is the no-descriptor convenience, and it must agree with the derivation applied
        // to a fresh probe — i.e. it is a projection, not a second source of truth.
        assert_eq!(
            HostDeclaration::probe(),
            HostDeclaration::from_host_capabilities(&crate::hostcaps::HostCapabilities::probe()),
            "probe() must be from_host_capabilities(HostCapabilities::probe()) on this host"
        );
    }

    /// An unprobed host axis removes nothing — "not asked" is not "absent" (the F1 distinction).
    #[test]
    fn an_unprobed_host_removes_nothing() {
        let set = FeatureSet::intersect("qemu", &caps_all(true), None, &[]);
        assert!(
            set.has(Feature::NestedVirt),
            "a host axis that did not speak must not remove everything it could have"
        );
        let probed = FeatureSet::intersect(
            "qemu",
            &caps_all(true),
            Some(&HostDeclaration { nested_virt: false }),
            &[],
        );
        assert!(
            !probed.has(Feature::NestedVirt),
            "positive control: a probed host that says no DOES remove it"
        );
    }

    /// `require` refuses before boot, and the refusal's feature string is `Feature::name()` by
    /// construction — never a hand-spelled fragment.
    #[test]
    fn require_refuses_with_the_removals_provenance() {
        let mut stances = BTreeMap::new();
        stances.insert(Feature::SnapshotRestore, false);
        let set = FeatureSet::intersect(
            "cloud-hypervisor",
            &caps_all(true),
            None,
            &[FeatureDeclaration {
                source: Some(Source::Rootfs("debian-systemd".into())),
                stances,
            }],
        );
        let err = set
            .require_all("cloud-hypervisor", &[Feature::SnapshotRestore])
            .expect_err("a removed feature must be refused");
        let Error::Unsupported { vmm, feature } = &err else {
            panic!("require must produce a typed Unsupported, got {err:?}");
        };
        // `vmm` is "who says so": when an ARTIFACT is the remover it carries that provenance, so
        // the message does not blame the backend for a rootfs's declaration. When the backend is
        // the remover it renders as the bare backend name, byte-identically to every pre-v33 site
        // (pinned by `a_backend_removal_renders_exactly_as_it_did_before_v33`).
        assert!(
            vmm.starts_with("cloud-hypervisor") && vmm.contains("rootfs"),
            "an artifact removal must name the artifact, not just the backend; got {vmm:?}"
        );
        assert_eq!(
            feature,
            Feature::SnapshotRestore.name(),
            "the feature string is Feature::name() by construction (F6)"
        );
        assert!(
            err.to_string().contains("debian-systemd"),
            "the provenance travels into the rendered error: {err}"
        );
        // Positive control: a feature that survived is not refused.
        set.require_all("cloud-hypervisor", &[Feature::VirtioConsole])
            .expect("a present feature must not be refused");
    }

    /// A BACKEND removal renders byte-identically to the pre-v33 spelling.
    ///
    /// This is what design §7.4's "`Error::Unsupported { vmm, feature }` keeps its public shape"
    /// buys: every one of the ~20 backend refusal sites produces exactly the message it produced
    /// before, so no consumer matching on the rendered text breaks. Only an ARTIFACT or HOST
    /// removal — a thing that could not happen before v33 — renders differently.
    #[test]
    fn a_backend_removal_renders_exactly_as_it_did_before_v33() {
        let by_ctor = Error::unsupported("crosvm", Feature::SnapshotRestore);
        let by_removal = Error::from_removal(
            "crosvm",
            &Removal {
                feature: Feature::SnapshotRestore,
                by: Source::Backend("crosvm".into()),
                reason: "does not support it",
            },
        );
        assert_eq!(by_ctor.to_string(), by_removal.to_string());
        assert_eq!(
            by_ctor.to_string(),
            "Unsupported feature in crosvm: snapshot_restore",
            "the pre-v33 rendering is pinned; a change here breaks every consumer matching the text"
        );
        // A DIFFERENT backend's removal does NOT collapse to the bare name — the guard is
        // `name == vmm`, not "is a Backend", so a cross-backend removal still names its source.
        let cross = Error::from_removal(
            "qemu",
            &Removal {
                feature: Feature::SnapshotRestore,
                by: Source::Backend("crosvm".into()),
                reason: "does not support it",
            },
        );
        assert!(cross.to_string().contains("crosvm"), "{cross}");
    }

    /// The sidecar parser is strict on both halves and round-trips.
    #[test]
    fn manifest_parse_is_strict_and_round_trips() {
        let src = Source::Rootfs("debian-systemd".into());
        let decl = FeatureDeclaration::parse_manifest(
            "# a comment\n\nsnapshot_restore = false\nxattr_preserved = true\n",
            src.clone(),
        )
        .expect("a well-formed manifest parses");
        assert_eq!(decl.stances.get(&Feature::SnapshotRestore), Some(&false));
        assert_eq!(decl.stances.get(&Feature::XattrPreserved), Some(&true));

        let round = FeatureDeclaration::parse_manifest(&decl.render_manifest(), src.clone())
            .expect("the rendered manifest parses back");
        assert_eq!(round.stances, decl.stances);

        // An unknown feature name is an error naming the token — and naming THAT token. Two
        // assertions, because two different things carry a token for free here: the roster echo
        // carries any token that is a substring of a valid name (excised, see
        // `BOGUS_FEATURE_TOKEN`), and the locator quotes the whole offending line, so it carries
        // the declared token whatever the propagated detail says. What neither can fake is being
        // *about* this token: a token-blind parser collapses every unknown-token refusal to one
        // text, so the refusal composed for a DIFFERENT unknown token must not be what travelled.
        let e = FeatureDeclaration::parse_manifest(
            &format!("{BOGUS_FEATURE_TOKEN} = false\n"),
            src.clone(),
        )
        .expect_err("an unknown token must not parse");
        assert!(
            without_the_roster_echo(&e.to_string()).contains(BOGUS_FEATURE_TOKEN),
            "{e}"
        );
        assert!(
            !e.to_string().contains(
                &Feature::parse(OTHER_BOGUS_FEATURE_TOKEN)
                    .expect_err("the second wrong word must not parse either")
                    .to_string()
            ),
            "the propagated refusal must be about the token this manifest declared, not a text \
             every unknown token would share: {e}"
        );

        // A non-boolean stance is an error NAMING the value — never defaulted.
        let e = FeatureDeclaration::parse_manifest("snapshot_restore = maybe\n", src.clone())
            .expect_err("a non-boolean stance must not parse");
        assert!(e.to_string().contains("maybe"), "{e}");

        // A duplicate stance has no defined precedence, so it is rejected.
        let e = FeatureDeclaration::parse_manifest(
            "snapshot_restore = true\nsnapshot_restore = false\n",
            src,
        )
        .expect_err("a duplicate stance must not parse");
        assert!(e.to_string().contains("twice"), "{e}");
    }

    /// The one sidecar-name law, pinned over every artifact filename shape the artifacts dir holds
    /// — including the dotted-label hazard the REPLACE law makes real.
    ///
    /// The producer (`RootfsFeaturesStage::out_path`) and the reader (`load_beside`) both compose
    /// through this function, so what this pins is the *shape*: `.erofs` is eaten, a suffixed
    /// filename keeps its whole suffix, an extension-less kernel gains one — and a filename whose
    /// LABEL still carries dots (`vmlinux-6.12.94`) would have its `.94` eaten, which is exactly
    /// why the filename composers sanitize `.`→`-` before a sidecar is ever named. The sanitized
    /// spelling is the one that actually reaches this function.
    ///
    /// RED on switching the law to APPEND (`kernel::resolved_config_path`'s): every expectation
    /// below gains the payload's own extension.
    #[test]
    fn the_feature_manifest_path_law_is_replace_and_round_trips_the_artifact_names() {
        for (artifact, sidecar) in [
            ("rootfs.erofs", "rootfs.features"),
            (
                "rootfs-debian-systemd.erofs",
                "rootfs-debian-systemd.features",
            ),
            ("vmlinux", "vmlinux.features"),
            ("vmlinux-6-12-94", "vmlinux-6-12-94.features"),
        ] {
            assert_eq!(
                feature_manifest_path(std::path::Path::new("/artifacts").join(artifact).as_path()),
                std::path::Path::new("/artifacts").join(sidecar),
                "`{artifact}` must carry `{sidecar}`"
            );
        }

        // The dotted spelling the sanitizers exist to keep out of the artifacts dir: named here so
        // the hazard is recorded as a *property of the law*, not rediscovered by a labelled build.
        assert_eq!(
            feature_manifest_path(std::path::Path::new("vmlinux-6.12.94")),
            std::path::Path::new("vmlinux-6.12.features"),
        );
    }

    /// The producer→reader round trip at the type level: a stance map renders to a manifest,
    /// travels as bytes, and parses back to the same stances beside the artifact it describes.
    ///
    /// The registry half (`rootfs.<label>.features` → this map) is gated in `rootfs_registry.rs`;
    /// what this pins is that the two halves of the sidecar are one law — `render_manifest` writes
    /// what `load_beside` reads, at the path `feature_manifest_path` names.
    ///
    /// RED on a producer that writes to a hand-composed path: `load_beside` finds nothing and
    /// returns the baseline, whose stances are empty.
    #[test]
    fn a_declaration_round_trips_through_the_sidecar_beside_its_artifact() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let artifact = tmp.path().join("rootfs.erofs");
        std::fs::write(&artifact, b"not really an image").expect("write the artifact");

        let declared = FeatureDeclaration {
            source: None,
            stances: BTreeMap::from([
                (Feature::SnapshotRestore, false),
                (Feature::XattrPreserved, false),
            ]),
        };
        std::fs::write(feature_manifest_path(&artifact), declared.render_manifest())
            .expect("write the sidecar");

        let loaded = FeatureDeclaration::load_beside(&artifact, Source::Rootfs("rootfs".into()))
            .expect("the sidecar parses");
        assert_eq!(
            loaded.stances.get(&Feature::SnapshotRestore),
            Some(&false),
            "the declared stance must survive the round trip"
        );
        assert_eq!(loaded.stances, declared.stances);
    }
}

/// **Every sidecar refusal is locatable** — the gate for the defect the `feature_manifest` fuzz
/// target found (GitHub Actions run 32017582821, two consecutive nightly reds).
///
/// Ungated on `host-common`, like the vocabulary it exercises: [`FeatureDeclaration::parse_manifest`]
/// is the validation boundary a *consumer* reads a sidecar through, so it compiles — and must be
/// gated — in every feature configuration `cargo hack` builds.
///
/// The crash was two bytes, `=z`. The parser's `Feature::parse` arm propagated a token-only refusal,
/// and for an empty key that token is the empty string, so the message named nothing at all. What
/// makes it a *class* rather than a typo is the shape: three of the four arms hand-attached the line
/// number and the fourth forgot. These gates therefore hold three different halves, and none covers
/// another's:
///
/// * `every_refusal_arm_carries_the_line_number_and_the_offending_line` — the behaviour, per arm,
///   asserted against the composed locator rather than a hand-typed sentence;
/// * `every_manifest_refusal_goes_through_the_one_locator_composer` — the **call sites**, because a
///   green per-arm test standing beside a new hand-rolled arm is exactly the completeness-audit
///   failure shape;
/// * `the_two_byte_fuzz_crash_input_is_locatable` — the discovered input itself. `fuzz/.gitignore`
///   commits `seed-*` corpora only, for the six targets whose *reachability* needs a seed; it keeps
///   no crash reproducers in tree (`/artifacts` is ignored and the workflow uploads them instead).
///   So this test is where those bytes live permanently, and it re-asserts the fuzz target's own
///   property rather than a weaker in-crate paraphrase of it.
#[cfg(test)]
mod manifest_locator_gates {
    use super::*;

    /// The exact bytes from the reddened nightly run's reproducer
    /// (`fuzz-artifacts/feature_manifest/crash-cb6cb176a6b17e5ba5906726719f5e94f0fb214a`).
    ///
    /// Held as bytes, then read as UTF-8 the way the target does, so this fixture is the artifact
    /// rather than a retyping of what it "meant".
    const FUZZ_CRASH_INPUT: &[u8] = b"=z";

    /// A raw line's code part (comment stripped, trimmed), or `None` when it declares nothing.
    ///
    /// The same reduction [`FeatureDeclaration::parse_manifest`] performs, so a candidate line is
    /// exactly what the parser would have called one.
    fn code_of(raw: &str) -> Option<&str> {
        let code = raw.split('#').next().unwrap_or("").trim();
        (!code.is_empty()).then_some(code)
    }

    /// The `feature_manifest` fuzz target's REJECTED-manifest property, in one place.
    ///
    /// A refusal must point at one real declaration line **by number and by quoting its own text**.
    /// Existence over the candidate lines is all that is checkable from outside the parser (which
    /// line failed is the parser's own answer); the table gate below pins the exact line for each
    /// known input, so the two together say "the right line, and always a line".
    fn is_locatable(body: &str, msg: &str) -> bool {
        body.lines().enumerate().any(|(i, raw)| {
            code_of(raw)
                .is_some_and(|code| msg.contains(&format!("line {}", i + 1)) && msg.contains(code))
        })
    }

    fn reject(body: &str) -> String {
        FeatureDeclaration::parse_manifest(body, Source::Rootfs("gate".into()))
            .map(|d| format!("{d:?}"))
            .expect_err("this body must be refused")
            .to_string()
    }

    /// **One assertion per error arm: the refusal names the line and quotes it.**
    ///
    /// Driven with a degenerate input per arm, each asserted against
    /// [`manifest_locator`] — the composer, not a hand-typed sentence, so a reworded detail cannot
    /// redden this and a dropped locator cannot pass it. Every needle beyond the locator is composed
    /// too ([`Feature::name`] / [`Feature::names_joined`] / [`BOGUS_FEATURE_TOKEN`]), and every
    /// needle that is not the roster itself is matched against the detail with the roster echo
    /// excised ([`without_the_roster_echo`]) — which is what keeps this off the substring-matcher
    /// ban F6 carries. The unknown-name leg needed both: its needle used to be a truncation of a
    /// valid name, so the echo matched it whatever the refusal said, and only the *sibling*
    /// interior-whitespace leg in this same table kept the test from passing for a refusal that
    /// named the wrong token.
    ///
    /// The last assertions hold a second half of the same defect: the five malformed shapes must stay
    /// DISTINGUISHABLE, because the fix differs per shape. A parser that answered "the manifest is
    /// bad" five times would satisfy every locator assertion above and still leave a consumer with
    /// nothing to change — so no detail may appear under two different arms, and the table must drive
    /// all five.
    ///
    /// RED on the inverse, demonstrated four ways: reverting the `Feature::parse` arm to a bare `?`
    /// (the shipped defect) reddens the empty-name legs; hardcoding `1` in place of `idx + 1` reddens
    /// the later-line legs; dropping `line` from [`manifest_locator`] reddens all of them; and
    /// rewording one arm's detail onto another's reddens the distinctness assertion alone.
    #[test]
    fn every_refusal_arm_carries_the_line_number_and_the_offending_line() {
        let real = Feature::SnapshotRestore.name();
        // A token with interior whitespace — derived, because no spelling of it is a substring of
        // the roster and a rename must not leave it aimed at a name that no longer exists.
        let spaced = real.replace('_', " ");
        // The one roster echo, bound once: it is both a needle (the empty-name arm owes it) and the
        // text every OTHER needle must be matched outside of.
        let roster = Feature::names_joined();

        // (arm, body, offending line number, that line's code, composed identifiers the detail owes).
        let cases: Vec<(&str, String, usize, String, Vec<String>)> = vec![
            // The crash: an empty key before `=`. The arm that shipped unlocated.
            (
                "empty-name",
                String::from_utf8(FUZZ_CRASH_INPUT.to_vec()).expect("the fixture is UTF-8"),
                1,
                "=z".to_string(),
                vec![roster.clone()],
            ),
            // A bare `=`: empty on BOTH sides. Still the empty-name arm, because the name is read
            // first — and there is nothing else to name.
            (
                "empty-name",
                "=".to_string(),
                1,
                "=".to_string(),
                vec![roster.clone()],
            ),
            // The same defect on a LATER line, past a comment and a blank: the number must be the
            // line's, not the first line's. Without this leg a hardcoded `1` passes every other leg.
            (
                "empty-name",
                format!("# a comment\n\n{real} = true\n=z\n"),
                4,
                "=z".to_string(),
                vec![roster.clone()],
            ),
            // …and past a line whose comment is what empties it, so the enumeration counts SOURCE
            // lines rather than declarations.
            (
                "empty-name",
                format!("{real} = true\n# just a comment\n=z\n"),
                3,
                "=z".to_string(),
                vec![roster.clone()],
            ),
            // An unknown name: the token travels (that half always worked) and now so does the line.
            (
                "unknown-name",
                format!("{BOGUS_FEATURE_TOKEN} = false\n"),
                1,
                format!("{BOGUS_FEATURE_TOKEN} = false"),
                vec![BOGUS_FEATURE_TOKEN.to_string()],
            ),
            // A name with interior whitespace: `split_once('=')` accepts it as a key, so it reaches
            // the unknown-name arm rather than the malformed-line one.
            (
                "unknown-name",
                format!("{spaced} = true\n"),
                1,
                format!("{spaced} = true"),
                vec![spaced.clone()],
            ),
            // No `=` at all. The detail deliberately names no token: the locator already quotes the
            // whole line, and restating it was the duplication the composer removed.
            (
                "no-equals",
                format!("{real}\n"),
                1,
                real.to_string(),
                vec![],
            ),
            // A stance that is not a boolean, on line 2 — the value is quoted and so is the feature.
            (
                "non-boolean-stance",
                format!("# header\n{real} = maybe\n"),
                2,
                format!("{real} = maybe"),
                vec![real.to_string(), "maybe".to_string()],
            ),
            // A stance that is only whitespace: the empty value must be refused, never defaulted.
            (
                "non-boolean-stance",
                format!("{real} =\n"),
                1,
                format!("{real} ="),
                vec![real.to_string()],
            ),
            // A duplicate stance, refused at the SECOND line — the one that made it a duplicate.
            (
                "duplicate",
                format!("{real} = true\n{real} = false\n"),
                2,
                format!("{real} = false"),
                vec![real.to_string()],
            ),
            // A trailing comment on the offending line: the locator quotes the CODE, so the comment
            // is not mistaken for part of the declaration.
            (
                "empty-name",
                "=z # this line is the offender\n".to_string(),
                1,
                "=z".to_string(),
                vec![roster.clone()],
            ),
        ];

        // detail → the arm that produced it, so a detail shared across arms is caught below.
        let mut details: std::collections::BTreeMap<String, &str> = Default::default();
        for (arm, body, line_number, code, needles) in &cases {
            let msg = reject(body);
            // `Error::Artifact`'s own `Display` prefixes the variant, so the locator is asserted as
            // the head of the *message* the parser composed, not of the rendered error. Splitting on
            // the composed locator is also how the detail is isolated — no hand-typed fragment of
            // the format, so a reworded locator cannot silently turn this into a whole-message
            // comparison.
            let locator = manifest_locator(*line_number, code);
            let (_, detail) = msg.split_once(&locator).unwrap_or_else(|| {
                panic!(
                    "the refusal must carry the composed locator {locator:?} — the line number \
                     answers `which of the identical lines` and the quoted text survives a consumer \
                     who cannot see the numbering. Got {msg:?} for {body:?}"
                )
            });
            assert!(
                detail.starts_with(": "),
                "the locator must be followed immediately by the detail: {msg:?}"
            );
            for needle in needles {
                // The roster echo is excised before the match — unless the needle IS the roster,
                // which is the one needle whose whole point is that the echo is there. Any other
                // needle that happened to be a substring of a valid feature name would otherwise be
                // found inside the echo whether or not the refusal named what it refused: that is
                // the vacuity `BOGUS_FEATURE_TOKEN` records, and excising makes it unreachable for
                // whatever token a future leg picks.
                let haystack = if needle == &roster {
                    detail.to_string()
                } else {
                    without_the_roster_echo(detail)
                };
                assert!(
                    haystack.contains(needle.as_str()),
                    "the detail must carry the composed identifier {needle:?} so the fix is \
                     obvious; got {detail:?} for {body:?}"
                );
            }
            // And the fuzz target's own property, on every one of these inputs.
            assert!(
                is_locatable(body, &msg),
                "the `feature_manifest` fuzz property must hold for {body:?}: {msg:?}"
            );
            // Two inputs on the SAME arm may share a detail (`=z` and `=` do); two arms may not.
            if let Some(other) = details.insert(detail.to_string(), arm)
                && other != *arm
            {
                panic!(
                    "the `{arm}` and `{other}` arms produced the same detail {detail:?} — each \
                     malformed shape needs its own, because the fix differs per shape"
                );
            }
        }
        // Non-vacuity: the table must drive EVERY refusal arm, or the distinctness check above is a
        // statement about the arms somebody remembered.
        let arms: std::collections::BTreeSet<&str> = cases.iter().map(|(arm, ..)| *arm).collect();
        assert_eq!(
            arms.len(),
            5,
            "gate misconfigured: `parse_manifest` has five refusal arms and the table drives \
             {arms:?}"
        );
        assert!(
            details.len() >= arms.len(),
            "gate misconfigured: {} distinct detail(s) for {} arm(s): {details:#?}",
            details.len(),
            arms.len()
        );
    }

    /// **The discovered input, permanently.** Two bytes, `=z`, from the nightly reproducer.
    ///
    /// This target keeps no in-tree corpus (see the module's own note), so the fixture lives here.
    /// It re-asserts the fuzz target's property verbatim through [`is_locatable`] rather than a
    /// weaker paraphrase, because the point of a regression fixture is that the *same* property that
    /// went red stays green.
    ///
    /// RED on the inverse: restore `let feature = Feature::parse(key.trim())?;` and this fails with
    /// the message the run reported — ``unknown feature ``: a feature token must be one of […]``,
    /// which quotes neither a line number nor any byte of `=z`.
    #[test]
    fn the_two_byte_fuzz_crash_input_is_locatable() {
        let body = std::str::from_utf8(FUZZ_CRASH_INPUT).expect("the reproducer is UTF-8");
        let msg = reject(body);
        assert!(
            is_locatable(body, &msg),
            "the reproducer's refusal must name its line and quote it: {msg:?}"
        );
        // Non-vacuity: `is_locatable` is an existence check, so prove it can say no. The pre-fix
        // message is reconstructed from the one place that composes it, not retyped.
        let unlocated = Feature::parse("")
            .expect_err("the empty token is not a feature")
            .to_string();
        assert!(
            !is_locatable(body, &unlocated),
            "gate misconfigured: `is_locatable` accepts the very message that reddened the nightly \
             run, so it would pass with no locator anywhere: {unlocated:?}"
        );
    }

    /// An empty name is a malformed **line**, not an unknown feature.
    ///
    /// The distinction is the actionable half of the fix: ``unknown feature `` `` sends a consumer
    /// looking for a token that is not in their file. Asserted by *identity* against the propagated
    /// refusal rather than by matching prose, so it survives any rewording of either message.
    #[test]
    fn an_empty_name_is_a_malformed_line_not_an_unknown_feature() {
        let propagated = Feature::parse("")
            .expect_err("the empty token is not a feature")
            .to_string();
        for body in ["=z", "=", " = true", "\t=false"] {
            let msg = reject(body);
            assert!(
                !msg.contains(&propagated),
                "an empty name must not be reported as `Feature::parse`'s unknown-token refusal — \
                 nothing was misspelled: {msg:?}"
            );
            // The roster still travels, composed: "which names are legal" is the next question.
            assert!(
                msg.contains(&Feature::names_joined()),
                "the empty-name refusal must list the legal names: {msg:?}"
            );
        }
        // Positive control: a name that IS unknown still gets the unknown-token refusal, so the arm
        // above narrowed the message rather than deleting a distinction. The needle is the WHOLE
        // composed refusal rather than the token, so this one was never satisfiable by the roster
        // echo — but it takes `BOGUS_FEATURE_TOKEN` anyway, so the file holds exactly one spelling
        // of "an unknown feature token" and nobody copies the truncation idiom out of here.
        assert!(
            reject(&format!("{BOGUS_FEATURE_TOKEN} = true")).contains(
                &Feature::parse(BOGUS_FEATURE_TOKEN)
                    .expect_err("a wrong word must not parse")
                    .to_string()
            ),
            "an actually-unknown token must still carry `Feature::parse`'s refusal"
        );
    }

    /// A line that declares nothing is not a refusal at all — the parser's tolerances, pinned.
    ///
    /// The negative control for every gate above: if blank, whitespace-only and comment-only lines
    /// started erroring, the locator gates would go green on inputs that must never reach an arm.
    #[test]
    fn a_line_that_declares_nothing_is_not_a_refusal_at_all() {
        for body in [
            "",
            "\n\n",
            " \t ",
            "# just a comment\n",
            "   # indented\n\n \t\n",
        ] {
            let decl = FeatureDeclaration::parse_manifest(body, Source::Rootfs("gate".into()))
                .unwrap_or_else(|e| panic!("{body:?} declares nothing and must parse: {e}"));
            assert!(decl.stances.is_empty(), "{body:?} declared a stance");
        }
    }

    /// **The call-site half: no arm composes its own refusal.**
    ///
    /// Two of the completeness-audit PARTIALs were invisible because a green unit test stood beside
    /// an unchanged call site, and this defect is that shape exactly — every *tested* arm carried the
    /// line number, and the untested one did not. So the gate is a source scan over
    /// [`FeatureDeclaration::parse_manifest`]'s own body: it must construct no [`Error`] except
    /// through the `reject` closure that binds [`manifest_line_error`] to this line.
    ///
    /// RED on the inverse: put a bare `Error::Artifact(format!(…))` in any arm.
    #[test]
    fn every_manifest_refusal_goes_through_the_one_locator_composer() {
        let src = include_str!("feature.rs");
        let start = src
            .find("pub fn parse_manifest(")
            .expect("gate misconfigured: parse_manifest was renamed");
        let body = &src[start..];
        let end = body
            .find("\n    }")
            .expect("gate misconfigured: the method's closing brace was not found");
        let body = &body[..end];

        // Non-vacuity: the slice must be the real loop, or this scans the wrong text.
        assert!(
            body.contains("body.lines().enumerate()"),
            "gate misconfigured: the sliced body is not the line loop:\n{body}"
        );
        assert!(
            body.matches("reject(").count() >= 5,
            "gate misconfigured: only {} `reject(` site(s) in the parser — the composer is not what \
             the arms use, so this scan proves nothing",
            body.matches("reject(").count()
        );

        let hand_rolled: Vec<&str> = body
            .lines()
            .filter(|l| {
                let code = l.split("//").next().unwrap_or("");
                code.contains("Error::") || code.contains("Artifact(")
            })
            .collect();
        assert!(
            hand_rolled.is_empty(),
            "every refusal in `parse_manifest` must go through the one locator composer (a bare \
             `Error::…` cannot carry the line, which is how `=z` shipped a message naming nothing). \
             Offending line(s): {hand_rolled:#?}"
        );
    }
}

/// F6's **call-site** gates: source scans over the whole workspace, not over one extracted
/// predicate.
///
/// They live here rather than in `scripts/` because a call-site scan is a Rust source-scan test (the
/// shipped precedent is `vmcell-qemu`'s `virtiofs_pacing_gate`), so the one `gates` recipe's roster
/// — and `ban-ci-script-handcopy.sh`'s both-direction assertion over it — does not grow.
///
/// They walk `crates/*/src/**.rs` at run time rather than `include_str!`-ing a fixed list, because a
/// fixed list is itself a roster that can go stale: a NEW backend crate would be invisible to a
/// hardcoded scan while being exactly the place the law is most likely to be broken. That tree-walk
/// idiom is the one `vmcell-privilege`'s blessing-copy scan already uses.
#[cfg(test)]
mod call_site_gates {
    use super::*;

    /// Every `.rs` file under `crates/*/src/`, with its path.
    fn production_sources() -> Vec<(std::path::PathBuf, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && let Ok(body) = std::fs::read_to_string(&p)
                {
                    out.push((p, body));
                }
            }
        }
        // Tests run with CWD = the crate root, so `../` is the `crates/` directory.
        let crates = std::path::Path::new("..");
        let mut out = Vec::new();
        for e in std::fs::read_dir(crates)
            .expect("crates/ is readable")
            .flatten()
        {
            let src = e.path().join("src");
            if src.is_dir() {
                walk(&src, &mut out);
            }
        }
        assert!(
            out.len() > 50,
            "the tree walk found only {} sources — it is not reaching crates/*/src, so both gates \
             below would pass vacuously",
            out.len()
        );
        out
    }

    /// Strips `//` line comments and `#[cfg(test)]`-ish test modules is deliberately NOT attempted;
    /// instead each scan states what it tolerates. Only line comments are dropped, because a rule
    /// quoted in prose must not read as a violation.
    fn code_lines(body: &str) -> impl Iterator<Item = (usize, &str)> {
        body.lines().enumerate().filter_map(|(i, l)| {
            let code = l.split("//").next().unwrap_or("");
            (!code.trim().is_empty()).then_some((i + 1, code))
        })
    }

    /// **F6: exactly one computation site — on the cell path, and never in a backend.**
    ///
    /// What F6 actually forbids is a **second reader of the descriptor**: two places that answer
    /// "what can this cell do" and drift apart, which is the history
    /// `config_has_vhost_user_device` was extracted from. So the rule is scoped to where that
    /// drift can happen, and it is scoped by DERIVATION, not by a crate list that would go stale:
    ///
    /// * **the cell path** (`crates/vmcell/src`) calls [`FeatureSet::intersect`] exactly once,
    ///   from `orchestrator::resolve_cell_features`. A second call here is the uncentralized form.
    /// * **no backend crate** calls it at all — a backend's whole job is to *declare* through
    ///   `VmmCapabilities`; one that computed the cell's set would be answering a question it is an
    ///   input to. "Is this a backend crate" is derived by looking for `impl Vmm for`, so a new
    ///   backend is covered the day it lands rather than the day someone remembers to list it.
    ///
    /// A **consumer** crate calling `intersect` is the law being *used*, not broken — that is the
    /// public API's whole point, and `vmcell-artifact-validator`'s `Substrate` is the in-tree
    /// example: it computes a backend×host substrate through this one law precisely so it is not a
    /// second reader of `VmmCapabilities`. An earlier cut of this gate banned every call outside
    /// the orchestrator and would have forbidden that — and every downstream consumer with it.
    #[test]
    fn the_feature_intersection_has_exactly_one_computation_site() {
        let sources = production_sources();

        // Which crates implement `Vmm`? Derived, so a new backend needs no edit here.
        let mut backend_crates: std::collections::BTreeSet<String> = Default::default();
        for (path, body) in &sources {
            if body.contains("impl Vmm for") || body.contains("impl vmcell::vmm::Vmm for") {
                // `../<crate>/src/…` → `<crate>`
                if let Some(c) = path.components().nth(1) {
                    backend_crates.insert(c.as_os_str().to_string_lossy().into_owned());
                }
            }
        }
        assert!(
            backend_crates.len() >= 3,
            "the `impl Vmm for` derivation found only {backend_crates:?} — it is not seeing the \
             backend crates, so the no-backend half of this gate would pass vacuously"
        );

        let mut cell_path_sites: Vec<String> = Vec::new();
        let mut backend_sites: Vec<String> = Vec::new();
        for (path, body) in &sources {
            if path.ends_with("feature.rs") {
                continue; // the definition and its own unit tests live here
            }
            let krate = path
                .components()
                .nth(1)
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .unwrap_or_default();
            for (line, code) in code_lines(body) {
                if !code.contains("FeatureSet::intersect(") {
                    continue;
                }
                let site = format!("{}:{line}", path.display());
                if krate == "vmcell" {
                    cell_path_sites.push(site);
                } else if backend_crates.contains(&krate) {
                    backend_sites.push(site);
                }
            }
        }

        assert_eq!(
            cell_path_sites.len(),
            1,
            "the cell path must compute its feature set in EXACTLY ONE place (F6, §7.4); found \
             {}: {cell_path_sites:#?}",
            cell_path_sites.len()
        );
        assert!(
            cell_path_sites[0].contains("orchestrator.rs"),
            "the one computation site must be `orchestrator::resolve_cell_features`; found {}",
            cell_path_sites[0]
        );
        assert!(
            backend_sites.is_empty(),
            "a BACKEND must never compute a cell's feature set — it is an INPUT to the \
             intersection, not a reader of it (F6). Offending site(s): {backend_sites:#?}"
        );
    }

    /// **F6: no production site hand-spells a feature string.**
    ///
    /// A `feature:` field initialized with a string literal is only legal when the literal is a
    /// single snake_case token that is NOT one of the vocabulary's names — the two carve-outs are
    /// refusals about things the descriptor genuinely does not carry (`vmm_seccomp`, `seccomp_log`,
    /// `vhost_user_socket`, `boot_after_restore`), whose granularity §7.4 clause 4 deliberately
    /// declines to mint variants for.
    ///
    /// Two shapes are banned:
    ///
    /// * **prose** — a literal containing a space or a parenthesis. Ten sites carried these
    ///   (`"snapshot with a vhost-user device"` and siblings), and they bred
    ///   `feature.contains("vhost-user")` and five more substring matchers: assertions strictly
    ///   weaker than the comments above them claimed.
    /// * **a hand-spelled vocabulary name** — a literal equal to some `Feature::name()`. Those must
    ///   be constructed through `Error::unsupported`/`Error::from_removal`, so the roster and the
    ///   refusals can never drift.
    #[test]
    fn no_production_site_hand_spells_a_feature_string() {
        let names: std::collections::BTreeSet<&str> =
            Feature::ALL.iter().map(|f| f.name()).collect();
        let mut violations: Vec<String> = Vec::new();
        for (path, body) in production_sources() {
            if path.ends_with("feature.rs") {
                continue; // the vocabulary itself defines the names
            }
            for (line, code) in code_lines(&body) {
                let Some(rest) = code.split_once("feature: \"") else {
                    continue;
                };
                let Some((literal, _)) = rest.1.split_once('"') else {
                    // No closing quote on this line: a CONTINUED string literal, which is by
                    // construction long prose. This arm exists because the first cut of this gate
                    // `continue`d here and therefore missed `MicroVm::snapshot`'s guard — a
                    // 2-line refusal reading "snapshot of a VM with a custom init (VmConfig::init)
                    // that replaces the steward — …". A unit test caught it instead, which is
                    // precisely the "the gate must catch it, not the test that happens to run"
                    // lesson; the hole is closed rather than noted.
                    violations.push(format!(
                        "{}:{line}: multi-line feature string — a continued literal is prose by \
                         construction; say WHY through a `Removal`",
                        path.display()
                    ));
                    continue;
                };
                if literal.contains(' ') || literal.contains('(') {
                    violations.push(format!(
                        "{}:{line}: prose feature string {literal:?} — say WHY through a `Removal`, \
                         never by decorating the feature name",
                        path.display()
                    ));
                } else if names.contains(literal) {
                    violations.push(format!(
                        "{}:{line}: hand-spelled vocabulary name {literal:?} — construct it with \
                         `Error::unsupported(vmm, Feature::…)` so the string is `Feature::name()` \
                         by construction",
                        path.display()
                    ));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "F6: {} production site(s) hand-spell a feature string:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }

    /// **docs/90 D5: the host axis has exactly ONE probe, and it lives in the descriptor.**
    ///
    /// §7.4 says the host contributes `HostCapabilities`; §7.2 rule 1 says that descriptor is probed
    /// **once**. Both were true of everything except the axis §7.4 named: `HostDeclaration::probe`
    /// read `/sys/module/*/parameters/nested` itself, beside the descriptor, and its own rustdoc
    /// claimed the derivation it did not perform. The read now lives in
    /// `hostcaps::nested_virt_enabled` and the declaration is a projection of the descriptor.
    ///
    /// A derivation test alone would not hold that: it proves the projection is faithful, not that
    /// nothing probes beside it — which is exactly the completeness-audit lesson (a green unit test
    /// standing beside an unchanged call site). So this is the call-site half, and it is scoped by
    /// the parameter path rather than by a function name, because the defect shape is a *reader*
    /// appearing anywhere — a backend deciding nested-virt for itself, a daemon short-cutting the
    /// descriptor — not a particular spelling.
    ///
    /// `hostcaps.rs` is tolerated whole: it owns the read and the test that pins the decode. Doc
    /// comments are stripped by `code_lines`, so prose quoting the path is not a violation — but a
    /// *code* line spelling it is, including this test's own needle, which is why the needle is
    /// composed rather than written out (the first cut of this gate reported itself, at the one line
    /// that had to be exempt-free).
    #[test]
    fn the_host_axis_reads_the_nested_parameter_in_exactly_one_place() {
        let param = ["parameters", "nested"].join("/");
        let param = param.as_str();
        let mut sites: Vec<String> = Vec::new();
        for (path, body) in production_sources() {
            if path.ends_with("hostcaps.rs") {
                continue; // the law's home
            }
            for (line, code) in code_lines(&body) {
                if code.contains(param) {
                    sites.push(format!("{}:{line}", path.display()));
                }
            }
        }
        assert!(
            sites.is_empty(),
            "the host axis must read `{param}` in exactly ONE place — \
             `hostcaps::nested_virt_enabled`, projected into `feature::HostDeclaration` through \
             `from_host_capabilities` — so §7.4's \"the host contributes HostCapabilities\" and \
             §7.2 rule 1's one probe both hold. Second reader(s): {sites:#?}"
        );

        // Non-vacuity: the home this gate exempts must actually contain the read, or the scan is
        // green because the law moved somewhere it is no longer looking.
        let home = production_sources()
            .into_iter()
            .find(|(path, _)| path.ends_with("hostcaps.rs"))
            .map(|(_, body)| body)
            .expect("gate misconfigured: crates/vmcell/src/hostcaps.rs was not scanned");
        assert!(
            code_lines(&home).any(|(_, code)| code.contains(param)),
            "gate misconfigured: hostcaps.rs no longer reads `{param}` — the one probe moved, so \
             this scan would pass with no reader anywhere"
        );
    }
}
