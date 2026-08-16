//! Error types and result alias for the vmcell framework.

#![forbid(unsafe_code)]

/// Represents errors that can occur during testing.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error communicating with the Virtual Machine Monitor (VMM) API.
    #[error("VMM API error (status {status}): {body}")]
    VmmApi {
        /// HTTP status code from the VMM.
        status: u16,
        /// Response body.
        body: String,
    },
    /// A general VMM error.
    #[error("VMM error: {0}")]
    Vmm(String),
    /// An error related to the steward.
    #[error("Steward error: {0}")]
    Steward(String),
    /// An error related to networking.
    #[error("Network error: {0}")]
    Network(String),
    /// An error related to the egress proxy.
    #[error("Proxy error: {0}")]
    Proxy(String),
    /// An error related to resource limits and cgroups.
    #[error("Cgroup error: {0}")]
    Cgroup(String),
    /// An error related to the artifact build pipeline.
    #[error("Artifact error: {0}")]
    Artifact(String),
    /// An error related to configuration validation.
    #[error("Config validation error: {0}")]
    Config(String),
    /// A timeout error.
    #[error("Timeout error: {0}")]
    Timeout(String),
    /// A custom serialization/deserialization error string.
    #[error("Serialization error: {0}")]
    Serialize(String),
    /// A JSON serialization error.
    // `serde_json` is a shared host-service dep (VMM config/bundle), pulled by
    // `host-common`, so the variant tracks that feature rather than each backend.
    #[cfg(feature = "host-common")]
    #[error("JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    /// A Postcard serialization error.
    #[error("Postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    /// A Hyper error.
    // `hyper` backs the shared HTTP-over-Unix VMM client, pulled by `host-common`.
    #[cfg(feature = "host-common")]
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    /// An HTTP error.
    #[cfg(feature = "host-common")]
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::http::Error),
    /// A QMP error.
    #[error("QMP error: {0}")]
    Qmp(String),
    /// A Reqwest HTTP error.
    // Distinct prefix from `Error::Http` (the hyper VMM client) so a bare log line
    // is unambiguous about which HTTP backend failed (N-ORCH-2).
    #[cfg(feature = "pipeline")]
    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// A subprocess execution error.
    #[error("Subprocess error: {0}")]
    Subprocess(String),
    /// Resource exhaustion (e.g., CIDs, VMIDs).
    #[error("Resource exhaustion: {0}")]
    Exhaustion(String),
    /// An I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// An unsupported operation or feature.
    ///
    /// The **shape is fixed** (design §7.4 clause 2: "`Error::Unsupported { vmm, feature }` keeps
    /// its public shape"); what v33 changed is that `feature` is now
    /// [`crate::feature::Feature::name`] by construction at every production site, never a
    /// hand-spelled prose fragment — see [`Error::from_removal`].
    #[error("Unsupported feature in {vmm}: {feature}")]
    Unsupported {
        /// **Who says so.** The VMM backend (e.g. `"qemu"`) when the backend is the remover — the
        /// spelling every pre-v33 site produced and still produces, byte-identically. When an
        /// *artifact* or the *host* is the remover, this carries that provenance instead
        /// (`cloud-hypervisor (rootfs "debian-systemd" declares it absent)`), because
        /// "Unsupported feature in `<the backend>`" would blame the backend for a rootfs's
        /// declaration — exactly the dishonesty §7.4 exists to retire. The machine-readable
        /// provenance is [`crate::feature::FeatureSet::why_absent`]; this field is its rendering.
        vmm: String,
        /// The unsupported feature — always a [`crate::feature::Feature::name`] at a production
        /// site, so a caller matches `feature == Feature::SnapshotRestore.name()` rather than
        /// `feature.contains("vhost-user")`. The substring-matcher class is retired with the prose
        /// strings that bred it (F6).
        feature: String,
    },
    /// A *requested functional* operation cannot be enforced because the host
    /// capability it needs is absent — for example a cgroup controller that is
    /// not delegated to the per-VM slice, so a requested `memory.max`/`cpu.max`
    /// limit would be silently ignored.
    ///
    /// Per the §7.2 (The fail-loud capability contract and HostCapabilities)
    /// fail-loud capability contract this is returned (matchable,
    /// carrying the missing capability and its remediation) instead of logging a
    /// warning and returning `Ok`, so a caller never receives a VM whose
    /// requested limits were not applied.
    #[error("capability unavailable for {op}: needs {needed}")]
    CapabilityUnavailable {
        /// The operation that could not be enforced (e.g. "cgroup memory.max limit").
        op: String,
        /// The exact missing capability and its remediation (e.g.
        /// `'memory' controller delegated to <parent>/cgroup.subtree_control`).
        // Backticks (a code span) so rustdoc does not treat `<parent>` as an HTML
        // tag — an unclosed tag hard-fails `cargo doc` (M-HOST-1).
        needed: String,
    },
}

impl Error {
    /// The typed refusal for a feature the backend itself does not support.
    ///
    /// **The one way a production site spells a feature refusal** (F6). The `feature` string is
    /// [`crate::feature::Feature::name`] by construction, which is what retires both the prose
    /// strings (`"snapshot with a vhost-user device"` and nine siblings) and the substring matchers
    /// they bred in the tests. A site that needs to say *why* beyond the feature name says it
    /// through a [`crate::feature::Removal`] and [`Error::from_removal`], never by decorating the
    /// feature string — a decorated string is a string a test then matches on a fragment of.
    #[must_use]
    pub fn unsupported(vmm: &str, feature: crate::feature::Feature) -> Self {
        Error::Unsupported {
            vmm: vmm.to_string(),
            feature: feature.name().to_string(),
        }
    }

    /// The typed refusal composed from a [`crate::feature::Removal`], so the provenance travels.
    ///
    /// When the remover is the backend itself the rendering is **byte-identical** to
    /// [`Error::unsupported`] — every pre-v33 backend refusal reads exactly as it did. When an
    /// artifact or the host is the remover, `vmm` carries that provenance so the message names who
    /// actually said no.
    #[must_use]
    pub fn from_removal(vmm: &str, removal: &crate::feature::Removal) -> Self {
        let who = match &removal.by {
            // The backend is the default remover; its rendering is the pre-v33 one, unchanged.
            crate::feature::Source::Backend(name) if name == vmm => vmm.to_string(),
            other => format!("{vmm} ({other} {})", removal.reason),
        };
        Error::Unsupported {
            vmm: who,
            feature: removal.feature.name().to_string(),
        }
    }
}

/// A specialized Result type for vmcell.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::Vmm("failed to boot".to_string()).to_string(),
            "VMM error: failed to boot"
        );
        assert_eq!(
            Error::Steward("connection failed".to_string()).to_string(),
            "Steward error: connection failed"
        );
        assert_eq!(
            Error::Serialize("unknown error".to_string()).to_string(),
            "Serialization error: unknown error"
        );
    }

    #[test]
    fn test_capability_unavailable_display_and_match() {
        let err = Error::CapabilityUnavailable {
            op: "cgroup memory.max limit".to_string(),
            needed: "'memory' controller delegated".to_string(),
        };
        // Display carries both the op and the missing capability (a caller greps
        // these for remediation); an inverted format string goes red here.
        assert_eq!(
            err.to_string(),
            "capability unavailable for cgroup memory.max limit: needs 'memory' controller delegated"
        );
        // The variant must be matchable (not a stringly-typed `Vmm`/`Cgroup`).
        assert!(matches!(err, Error::CapabilityUnavailable { .. }));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert_eq!(err.to_string(), "IO error: file missing");
    }
}
