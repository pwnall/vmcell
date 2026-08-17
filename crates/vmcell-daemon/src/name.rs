//! The single artifact-name predicate (design §11.3, The artifact store / invariant §13, Cross-cutting invariants).
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

/// `NAME_MAX`: the kernel's ceiling on **one filename component** (255 bytes on every filesystem the
/// store runs on). The budget every file the store writes for an artifact has to fit inside — which
/// is why it is not itself the name ceiling; see [`MAX_ARTIFACT_NAME_LEN`].
const NAME_MAX: usize = 255;

/// The maximum artifact-name length in bytes: `NAME_MAX` **minus the digest-sidecar suffix**, because
/// an accepted name has to fit twice — as `<name>` and as `<name>`[`SHA256_SIDECAR_SUFFIX`] (design
/// §11.3, The artifact store).
///
/// A bare-`NAME_MAX` ceiling accepted a 249-byte name, persisted the artifact, and *then* failed its
/// sidecar write with `ENAMETOOLONG` — a deterministic 500 on a well-formed request, and (before the
/// rollback in `ArtifactStore::create`) a burned name in a create-only store (finding
/// `sidecar-suffix-overruns-name-max`). The atomic upload's temp file carries an independent random
/// name (`NamedTempFile::new_in`), so no *temp* suffix has to fit in this budget.
pub const MAX_ARTIFACT_NAME_LEN: usize = NAME_MAX - SHA256_SIDECAR_SUFFIX.len();

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
    /// The name is well-formed but ends in the reserved [`SHA256_SIDECAR_SUFFIX`] (digest sidecars
    /// are the store's own bookkeeping, never a client-nameable artifact).
    ReservedSuffix,
}

impl std::fmt::Display for InvalidName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "artifact name must not be empty"),
            Self::TooLong => write!(
                f,
                "artifact name must be at most {MAX_ARTIFACT_NAME_LEN} bytes \
                 (NAME_MAX less the `{SHA256_SIDECAR_SUFFIX}` sidecar suffix, which the store writes \
                  beside the artifact)"
            ),
            Self::DotOrDotDot => write!(f, "artifact name must not be `.` or `..`"),
            Self::LeadingDashOrDot => {
                write!(f, "artifact name must not start with `-` or `.`")
            }
            Self::IllegalByte(b) => write!(
                f,
                "artifact name may only contain [A-Za-z0-9._-]; found byte {b:#04x}"
            ),
            Self::ReservedSuffix => write!(
                f,
                "artifact name must not end in `{SHA256_SIDECAR_SUFFIX}` (reserved for digest sidecars)"
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

/// The reserved suffix for digest sidecars (design §11.3, The artifact store). `<artifact>.sha256`
/// holds the hex SHA-256 computed once at upload so `list`/`info` read it back in O(1) instead of
/// re-hashing the whole body. A client cannot name an artifact with this suffix (it would shadow a
/// real artifact's sidecar and vanish from `list`).
pub const SHA256_SIDECAR_SUFFIX: &str = ".sha256";

/// The ONE reserved-name predicate (AGENTS.md "one law, one predicate"): true iff `name` names a
/// digest sidecar rather than a client artifact.
///
/// [`validate_artifact_name`] itself rejects such a name, so **no verb can pick a weaker
/// validator** — the reservation used to live in `ArtifactStore::create`/`info`/`delete` only, and
/// `Registry::snapshot`, which validates through [`validate_artifact_name`], happily created an
/// undeletable `<name>.sha256` **directory** that then broke every later upload of `<name>`
/// (finding `snapshot-skips-the-reserved-sidecar-predicate`). The store still consults this
/// predicate directly, but only to pick its per-verb *reaction* (400 on create, 404 on info/delete,
/// skip in list) — never to decide the law.
#[must_use]
pub fn is_reserved_sidecar_name(name: &str) -> bool {
    name.ends_with(SHA256_SIDECAR_SUFFIX)
}

/// Validates a client-supplied artifact name (the pure predicate; no filesystem access).
///
/// Accept rule: non-empty, ≤ [`MAX_ARTIFACT_NAME_LEN`] bytes, every byte in `[A-Za-z0-9._-]`, not
/// `.`/`..`, not starting with `-` or `.`, and not ending in the reserved
/// [`SHA256_SIDECAR_SUFFIX`].
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
    // The reserved digest-sidecar suffix is part of the NAME law, not of one verb's manners: every
    // caller of this predicate — the store's four verbs, `Registry::snapshot`'s prefix, a
    // `restore_from` prefix, and the client's pre-upload check — inherits it.
    if is_reserved_sidecar_name(name) {
        return Err(InvalidName::ReservedSuffix);
    }
    Ok(())
}

/// The ONLY function that turns a client-supplied artifact name into a path. Every store op and every
/// VM-API artifact reference resolves through it (invariant §13, Cross-cutting invariants); no caller constructs
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

    // The length ceiling leaves room for the digest sidecar: an accepted name has to fit as `<name>`
    // AND as `<name>.sha256`, or a well-formed upload persists and then fails its sidecar write with
    // ENAMETOOLONG — deterministic for 249–255 bytes (finding `sidecar-suffix-overruns-name-max`).
    // RED on the inverse (`MAX_ARTIFACT_NAME_LEN = NAME_MAX`): the 249-byte name is accepted here and
    // the store 500s on it (the store-side leg of this gate is
    // `create_rejects_a_name_whose_sidecar_would_not_fit`).
    #[test]
    fn the_length_ceiling_leaves_room_for_the_digest_sidecar() {
        let longest = "a".repeat(MAX_ARTIFACT_NAME_LEN);
        assert!(
            validate_artifact_name(&longest).is_ok(),
            "the ceiling itself is accepted"
        );
        assert_eq!(
            longest.len() + SHA256_SIDECAR_SUFFIX.len(),
            NAME_MAX,
            "the longest accepted name's sidecar lands exactly ON NAME_MAX — no byte over, none wasted"
        );
        // The first over-length name is the shortest one whose sidecar would not fit.
        assert_eq!(
            validate_artifact_name(&"a".repeat(MAX_ARTIFACT_NAME_LEN + 1)),
            Err(InvalidName::TooLong)
        );
        assert!(
            InvalidName::TooLong
                .to_string()
                .contains(SHA256_SIDECAR_SUFFIX),
            "the operator message must say WHY the ceiling is short of NAME_MAX: {}",
            InvalidName::TooLong
        );
    }

    // The reserved digest-sidecar suffix is part of THE name law, so a caller cannot pick a weaker
    // validator (finding `snapshot-skips-the-reserved-sidecar-predicate`: `Registry::snapshot`
    // validated with this function, which did not carry the rule, and created an undeletable
    // `<name>.sha256` directory). RED on the inverse — a `validate_artifact_name` without the
    // suffix arm accepts `rootfs.sha256`.
    #[test]
    fn validate_rejects_the_reserved_sidecar_suffix() {
        for reserved in ["rootfs.sha256", "k.sha256", "a.b.sha256"] {
            assert_eq!(
                validate_artifact_name(reserved),
                Err(InvalidName::ReservedSuffix),
                "must reject {reserved:?}"
            );
            assert!(is_reserved_sidecar_name(reserved));
            assert!(resolve_artifact_path(Path::new("/store"), reserved).is_err());
        }
        // Positive control: the same stems without the reserved suffix are accepted, and a name
        // that merely CONTAINS the suffix text is not reserved.
        for good in ["rootfs", "k", "sha256", "k.sha256.img"] {
            assert!(validate_artifact_name(good).is_ok(), "must accept {good:?}");
            assert!(!is_reserved_sidecar_name(good));
        }
    }
}
