//! The single artifact-name predicate (design v21 §D3.1 / invariant §D9.1).
//!
//! Artifact names map **directly** to files: name `k1` is the file `<artifacts-dir>/k1`. That makes
//! this a **security boundary** of the same class as the test-runner's exec-target confinement — a
//! name that path-traverses (`../../etc/passwd`) or is absolute would let a client read or clobber
//! files outside the store. So there is exactly ONE function that turns a client-supplied name into a
//! path, unit-tested against its buggy inverses; no store op or VM-API reference ever calls
//! `dir.join(client_string)` itself.
//!
//! Compiled with **no** feature gate so the client can pre-validate a name before uploading — the
//! same predicate on both sides of the wire.

use std::path::{Path, PathBuf};

/// The maximum artifact-name length in bytes. Well under `NAME_MAX` (255 on most Linux
/// filesystems) so `<dir>/<name>` never hits a path-length limit, and long enough for
/// any real `vmlinux-<version>` / `rootfs-<profile>.erofs` name.
pub const MAX_ARTIFACT_NAME_LEN: usize = 128;

/// Why an artifact name was rejected. Carries the offending name for a clear operator message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidName {
    /// The name was empty.
    Empty,
    /// The name exceeded [`MAX_ARTIFACT_NAME_LEN`] bytes.
    TooLong,
    /// The name was exactly `.` or `..` (the traversal family).
    DotOrDotDot,
    /// The name started with `-` (would be read as a flag by a tool) or `.` (hidden; enables
    /// the `.`/`..` family).
    LeadingDashOrDot,
    /// The name contained a byte outside the allowed set `[A-Za-z0-9._-]` (this rejects `/`,
    /// `\0`, whitespace, and every path separator, so no subdirectory or traversal is
    /// representable).
    IllegalByte(u8),
}

impl std::fmt::Display for InvalidName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "artifact name must not be empty"),
            Self::TooLong => write!(
                f,
                "artifact name must be at most {MAX_ARTIFACT_NAME_LEN} bytes"
            ),
            Self::DotOrDotDot => write!(f, "artifact name must not be `.` or `..`"),
            Self::LeadingDashOrDot => {
                write!(f, "artifact name must not start with `-` or `.`")
            }
            Self::IllegalByte(b) => write!(
                f,
                "artifact name may only contain [A-Za-z0-9._-]; found byte {b:#04x}"
            ),
        }
    }
}

impl std::error::Error for InvalidName {}

/// Returns `true` iff `b` is in the allowed artifact-name byte set `[A-Za-z0-9._-]`.
///
/// An **allowlist**, not a denylist of "bad" substrings — a denylist is the divergence trap the
/// rubric warns against (you always forget one). Because `/` is absent, no path separator and no
/// subdirectory is representable, so the joined path is always a direct child of the store dir.
const fn is_allowed_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// Validates a client-supplied artifact name (the pure predicate; no filesystem access).
///
/// Accept rule: non-empty, ≤ [`MAX_ARTIFACT_NAME_LEN`] bytes, every byte in `[A-Za-z0-9._-]`, not
/// `.`/`..`, and not starting with `-` or `.`.
///
/// # Errors
/// Returns the specific [`InvalidName`] reason so the operator sees exactly what was wrong.
pub fn validate_artifact_name(name: &str) -> Result<(), InvalidName> {
    if name.is_empty() {
        return Err(InvalidName::Empty);
    }
    if name.len() > MAX_ARTIFACT_NAME_LEN {
        return Err(InvalidName::TooLong);
    }
    if name == "." || name == ".." {
        return Err(InvalidName::DotOrDotDot);
    }
    // First byte: reject leading `-` (flag-injection) and leading `.` (hidden / dotfile family).
    // `.first()` (not `[0]`) keeps the crate-wide `indexing_slicing` deny satisfied.
    if matches!(name.as_bytes().first(), Some(b'-' | b'.')) {
        return Err(InvalidName::LeadingDashOrDot);
    }
    for &b in name.as_bytes() {
        if !is_allowed_byte(b) {
            return Err(InvalidName::IllegalByte(b));
        }
    }
    Ok(())
}

/// The ONLY function that turns a client-supplied artifact name into a path. Every store op and every
/// VM-API artifact reference resolves through it (invariant §D9.1); no caller constructs
/// `dir.join(name)` on a client string directly.
///
/// On success the result is exactly `dir.join(name)` with `name` a single validated component — no
/// `/`, no `..`, no absolute path is representable, so the result is always a direct child of `dir`.
///
/// # Errors
/// Returns [`InvalidName`] when the name fails [`validate_artifact_name`].
pub fn resolve_artifact_path(dir: &Path, name: &str) -> Result<PathBuf, InvalidName> {
    validate_artifact_name(name)?;
    Ok(dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Red-on-inverse: each buggy relaxation of the predicate would ACCEPT one of these and let a
    // client escape the store. Every one must reject.
    #[test]
    fn rejects_traversal_and_injection() {
        for bad in [
            "..",
            ".",
            "../etc/passwd",
            "a/b", // `/` is not in the allowed set
            "/abs",
            "-rf",     // leading dash: flag injection
            ".hidden", // leading dot
            "",        // empty
            "a b",     // space
            "a\tb",    // tab
        ] {
            assert!(validate_artifact_name(bad).is_err(), "must reject {bad:?}");
        }
        // A NUL byte (would truncate a C path) is rejected as an illegal byte.
        assert!(validate_artifact_name("a\0b").is_err(), "must reject NUL");
        // Over-length rejects.
        let long = "a".repeat(MAX_ARTIFACT_NAME_LEN + 1);
        assert_eq!(validate_artifact_name(&long), Err(InvalidName::TooLong));
    }

    // Positive control (AGENTS.md "a negative security result needs a positive control"): the real
    // artifact names the store uses accept AND join to exactly the direct child.
    #[test]
    fn accepts_real_names_and_joins_to_direct_child() {
        let dir = Path::new("/var/lib/vmcell/artifacts");
        for good in [
            "vmlinux",
            "vmlinux-6.12.94",
            "rootfs.erofs",
            "k1",
            "snap_2024",
        ] {
            assert!(validate_artifact_name(good).is_ok(), "must accept {good:?}");
            let p = resolve_artifact_path(dir, good).expect("valid");
            assert_eq!(p, dir.join(good));
            // The resolved path is always a direct child — its parent is the store dir.
            assert_eq!(
                p.parent(),
                Some(dir),
                "must be a direct child of the store dir"
            );
        }
    }

    #[test]
    fn resolve_rejects_the_same_names_validate_does() {
        let dir = Path::new("/store");
        assert!(resolve_artifact_path(dir, "../escape").is_err());
        assert!(resolve_artifact_path(dir, "ok").is_ok());
    }
}
