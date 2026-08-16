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

    /// Parses a declaration token **strictly**: an unknown token is an error naming it, never a
    /// silent absence.
    ///
    /// This is clause 1, and it is the whole reason the enum exists rather than a `&str`. A typo'd
    /// misspelled `snapshot_restore` that parsed to "absent" would produce a cell that quietly does less while
    /// every downstream check passes, because nothing claimed the feature.
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
                    Feature::ALL
                        .iter()
                        .map(|f| f.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }
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
    /// # Errors
    ///
    /// [`Error::Artifact`] naming the line and the offending token.
    pub fn parse_manifest(body: &str, source: Source) -> Result<Self> {
        let mut stances = BTreeMap::new();
        for (idx, raw) in body.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                Error::Artifact(format!(
                    "feature manifest line {}: expected `<feature> = <true|false>`, got `{line}`",
                    idx + 1
                ))
            })?;
            let feature = Feature::parse(key.trim())?;
            let stance = match value.trim() {
                "true" => true,
                "false" => false,
                other => {
                    return Err(Error::Artifact(format!(
                        "feature manifest line {}: `{}` must be `true` or `false`, got `{other}`. \
                         A stance is stated or the manifest is rejected — never defaulted.",
                        idx + 1,
                        feature.name()
                    )));
                }
            };
            if stances.insert(feature, stance).is_some() {
                return Err(Error::Artifact(format!(
                    "feature manifest line {}: `{}` is declared twice; a duplicate stance has no \
                     defined precedence, so it is rejected rather than last-writer-wins.",
                    idx + 1,
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
    /// The sidecar path is `artifact.with_extension("features")` — the same law the `.cache_key`
    /// sidecar already uses, so `rootfs-debian-systemd.erofs` carries
    /// `rootfs-debian-systemd.features` exactly as §7.4 spells it.
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
        let sidecar = artifact.with_extension("features");
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

/// The host's contribution to the intersection, derived from [`crate::hostcaps::HostCapabilities`].
///
/// A thin newtype rather than a second descriptor: the host axis speaks about exactly the features
/// it can actually decide, and says nothing about the rest.
#[cfg(feature = "host-common")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HostDeclaration {
    /// Whether the host has nested virtualization enabled (`kvm_intel.nested` / `kvm_amd.nested`).
    pub nested_virt: bool,
}

#[cfg(feature = "host-common")]
impl HostDeclaration {
    /// Probes the host axis.
    ///
    /// Nested virtualization is the worked example of why the intersection earns its keep (§7.4):
    /// it is true only when the backend advertises it, **and** the kernel artifact declares the KVM
    /// symbols, **and** the host has nested enabled — three axes the pre-v33 tree checked in three
    /// unrelated places with three different failure shapes. This reads the third.
    ///
    /// A module parameter that cannot be read is treated as **enabled**, not disabled: the host axis
    /// removes a feature only when it can positively say the facility is off. An unreadable
    /// `/sys/module/*/parameters/nested` (a non-KVM host, a locked-down sysfs) is an unasked
    /// question, and the F1 distinction between "absent facility" and "unasked question" is exactly
    /// what keeps an unprobed axis from removing everything it could have.
    #[must_use]
    pub fn probe() -> Self {
        let nested = ["kvm_intel", "kvm_amd"].iter().find_map(|m| {
            std::fs::read_to_string(format!("/sys/module/{m}/parameters/nested"))
                .ok()
                .map(|v| matches!(v.trim(), "Y" | "1" | "y"))
        });
        HostDeclaration {
            nested_virt: nested.unwrap_or(true),
        }
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
    #[test]
    fn unknown_feature_token_is_a_hard_error_naming_it() {
        // The typo is DERIVED from the real name (drop its last byte), not typed as a literal.
        // Two reasons: a hand-typed misspelling drifts if the feature is ever renamed, and the
        // `typos` gate reads a literal misspelling as the defect it exists to catch — a fixture
        // that has to be exempted from a gate is a fixture that will be "fixed" by someone later.
        let real = Feature::SnapshotRestore.name();
        let typo = &real[..real.len() - 1];
        let err = Feature::parse(typo).expect_err("a typo must not parse");
        let msg = err.to_string();
        assert!(
            msg.contains(typo),
            "the error must name the offending token so the typo is findable; got: {msg}"
        );
        assert!(
            msg.contains(Feature::SnapshotRestore.name()),
            "the error must list the known names so the fix is obvious; got: {msg}"
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

        // An unknown feature name is an error NAMING the token. Derived, not typed (see
        // `unknown_feature_token_is_a_hard_error_naming_it`).
        let real = Feature::SnapshotRestore.name();
        let typo = &real[..real.len() - 1];
        let e = FeatureDeclaration::parse_manifest(&format!("{typo} = false\n"), src.clone())
            .expect_err("an unknown token must not parse");
        assert!(e.to_string().contains(typo), "{e}");

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
}

/// F6's **call-site** gates: source scans over the whole workspace, not over one extracted
/// predicate.
///
/// Both live here rather than in `scripts/` because a call-site scan is a Rust source-scan test (the
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
}
