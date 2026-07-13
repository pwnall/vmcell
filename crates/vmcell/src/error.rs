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
    /// An error related to the guest agent.
    #[error("Agent error: {0}")]
    Agent(String),
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
    #[error("Unsupported feature in {vmm}: {feature}")]
    Unsupported {
        /// The VMM backend (e.g., "qemu", "cloud-hypervisor").
        vmm: String,
        /// The unsupported feature (e.g., "snapshot", "virtio-fs").
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
            Error::Agent("connection failed".to_string()).to_string(),
            "Agent error: connection failed"
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
