/// Represents errors that can occur during testing.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error related to the Virtual Machine Monitor.
    #[error("VMM error: {0}")]
    Vmm(String),
    /// An I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Catch-all for other errors.
    #[error("Other error: {0}")]
    Other(String),
}

/// A specialized Result type for imp-testing.
pub type Result<T> = std::result::Result<T, Error>;
