#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("VMM error: {0}")]
    Vmm(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
