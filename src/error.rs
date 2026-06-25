//! Error types and result alias for the imp-testing framework.

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
    #[cfg(any(
        feature = "cloud-hypervisor",
        feature = "firecracker",
        feature = "qemu",
        feature = "cli"
    ))]
    #[error("JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    /// A Postcard serialization error.
    #[error("Postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    /// A Reqwest HTTP error.
    #[cfg(feature = "pipeline")]
    #[error("HTTP error: {0}")]
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
}

/// A specialized Result type for imp-testing.
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
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert_eq!(err.to_string(), "IO error: file missing");
    }
}
