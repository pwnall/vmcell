//! Error types and result alias for the imp-testing framework.

/// Represents errors that can occur during testing.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error related to the Virtual Machine Monitor.
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
    /// An I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Catch-all for other errors.
    #[error("Other error: {0}")]
    Other(String),
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
            Error::Other("unknown error".to_string()).to_string(),
            "Other error: unknown error"
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
