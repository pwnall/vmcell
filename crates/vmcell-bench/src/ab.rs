//! A/B arms: what a run is pinned to, the guards that make a control real, and the interleaved
//! plan.
//!
//! WHY GUARDS AT ALL. The 2026-08-21 comparison was driven by shell, and both of its controls
//! failed *silently* — the run produced a full matrix of confident numbers that answered a
//! different question than the one asked. A control that cannot go red is not a control, so every
//! precondition of this harness is a function that returns a typed error naming its fix, and every
//! one of them has a red-on-inverse test that builds the violating condition in a tempdir.
//!
//! WHY DIGESTS AND NOT ENVIRONMENT VARIABLES. The driver exported `$VMCELL_KERNEL` to pin both arms
//! to one guest kernel. The *old* arm's `bench-vm` predates that variable and composes
//! `<artifacts_dir>/vmlinux` itself, so the arms booted 6.12.94 against 6.12.104 for an entire
//! matrix. Exporting a variable is a statement about the driver; a digest is a statement about the
//! bytes the VM booted, and only the second one is evidence.
//!
//! WHY SOME GUARDS RUN AFTER THE RUN. A digest taken at `prepare` time answers "are these two files
//! the same bytes", not "is that the file the child opened". `bench-vm` resolves `$VMCELL_KERNEL`
//! and `$VMCELL_ROOTFS` ahead of the artifacts dir, so an override inherited from the operator's
//! shell redirects every arm at one artifact while the manifests still record per-arm ones — the
//! 2026-08-21 control failing from the other side. [`guard_booted_artifacts`] and
//! [`guard_vmm_binaries`] read the runs' own reports, because that is the only witness to what a
//! process actually opened and executed.
//!
//! WHAT THIS MODULE DELIBERATELY DOES NOT DO. There is no "compare against a stored baseline from
//! another machine" mode, and adding one would re-open the defect that motivated the tool: the
//! canonical results table had been measured on different hardware, so absolute milliseconds could
//! not answer "did we regress". Everything here compares two arms on ONE host in ONE session.

use crate::report::{BenchReport, BinSource};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Read size for [`sha256_file`]. A rootfs image is hundreds of MiB and a `vmlinux` tens; the
/// digest streams so an arm's artifacts are never held in memory at once.
const DIGEST_CHUNK_BYTES: usize = 64 * 1024;

/// How many hex characters of a digest the human-facing messages print.
const SHORT_DIGEST_CHARS: usize = 12;

/// A file pinned by content, not by path.
///
/// The path alone is what the 2026-08-21 pass trusted, and a concurrent `cargo build --release`
/// overwrote the file behind it mid-session while `git status` stayed clean.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DigestedFile {
    /// Where the file was when the manifest was written.
    pub path: PathBuf,
    /// Lowercase-hex SHA-256 of its contents at that moment.
    pub sha256: String,
}

impl DigestedFile {
    /// Digests `path` now.
    ///
    /// # Errors
    ///
    /// [`AbError::Io`] if the file cannot be opened or read.
    pub fn digest(path: impl Into<PathBuf>) -> Result<Self, AbError> {
        let path = path.into();
        let sha256 = sha256_file(&path)?;
        Ok(Self { path, sha256 })
    }

    /// Re-digests the file and returns the digest found **when it no longer matches**; `None` is
    /// "still the bytes this manifest pinned".
    ///
    /// WHY NOT A `bool`. It shipped as `is_unchanged() -> bool` with no caller at all, while
    /// [`guard_binaries_unchanged`] spelled the same law inline — because the guard's error names
    /// the digest it *found*, and a bool cannot carry it. Two spellings of one law is how the two
    /// diverge; the found digest is the reason there were two, so it travels in the answer.
    ///
    /// # Errors
    ///
    /// [`AbError::Io`] if the file cannot be opened or read — including because it is *gone*,
    /// which is a failure and not a pass: a staged arm binary that vanished mid-session cannot
    /// have produced the numbers about to be compared.
    pub fn changed_digest(&self) -> Result<Option<String>, AbError> {
        let found = sha256_file(&self.path)?;
        Ok((found != self.sha256).then_some(found))
    }
}

/// The lowercase-hex SHA-256 of the file at `path`, streamed in `DIGEST_CHUNK_BYTES` chunks so
/// a hundreds-of-MiB rootfs is never held in memory.
///
/// # Errors
///
/// [`AbError::Io`] if the file cannot be opened or read.
pub fn sha256_file(path: &Path) -> Result<String, AbError> {
    use sha2::Digest as _;

    let mut file = std::fs::File::open(path).map_err(|source| AbError::Io {
        path: path.to_path_buf(),
        action: "open",
        source,
    })?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0_u8; DIGEST_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buf).map_err(|source| AbError::Io {
            path: path.to_path_buf(),
            action: "read",
            source,
        })?;
        if read == 0 {
            break;
        }
        match buf.get(..read) {
            Some(chunk) => hasher.update(chunk),
            // `read <= buf.len()` is `Read`'s contract, so this arm is unreachable against a sane
            // reader. It fails loud anyway rather than carrying a suppression whose proof would
            // outlive whatever replaced the reader.
            None => {
                return Err(AbError::Io {
                    path: path.to_path_buf(),
                    action: "read",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "reader reported more bytes than the buffer holds",
                    ),
                });
            }
        }
    }
    // sha2 0.11 `finalize()` returns a `hybrid_array::Array` (no `LowerHex`).
    let out: [u8; 32] = hasher.finalize().into();
    Ok(out.iter().map(|b| format!("{b:02x}")).collect())
}

/// Everything one arm of a comparison is pinned to: written by `bench-ab prepare`, verified by
/// `bench-ab run`.
///
/// The three artifacts are [`DigestedFile`]s rather than paths because all three were, at some
/// point on 2026-08-21, a path that pointed at bytes nobody had checked: the kernel (the control
/// that did not apply), the staged `bench-vm` (swapped by a concurrent build), and the rootfs
/// (which is a *warning*, not an error — see [`guard_distinct_rootfs`]).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ArmManifest {
    /// The name this arm is reported under, e.g. `head`, `v0.22.0`.
    pub label: String,
    /// The git ref the arm was ASKED for (`HEAD`, a branch, a tag), verbatim.
    ///
    /// A ref is a moving name, and before the 2026-08-21 review this argument was the only thing
    /// recorded: `prepare` reused an existing `<worktree>/.git` without checking WHERE it was, so
    /// re-preparing a label at a new ref rebuilt the old tree and filed it under the new name.
    /// [`Self::git_commit`] is the fact; this is the request.
    pub git_ref: Option<String>,
    /// The commit `git_ref` resolved to — and the commit the worktree was verified to be at after
    /// `prepare` finished, not merely the one it was asked for.
    ///
    /// `#[serde(default)]` so a manifest written before this field existed still loads, as `None`:
    /// "this arm predates the check" is a true statement, where a fabricated commit would not be.
    #[serde(default)]
    pub git_commit: Option<String>,
    /// The staged `bench-vm` this arm runs.
    pub bench_vm: DigestedFile,
    /// The staged `vmcelld`, for the modes that need a daemon. `bench-vm` locates it as its own
    /// *sibling*, which is why it is staged beside `bench_vm` rather than left in `target/release`.
    pub vmcelld: Option<DigestedFile>,
    /// The artifacts directory this arm boots out of.
    pub artifacts_dir: PathBuf,
    /// The guest kernel in `artifacts_dir`. Equal across arms is the control — see
    /// [`guard_same_kernel`].
    pub kernel: DigestedFile,
    /// The rootfs image in `artifacts_dir`.
    pub rootfs: DigestedFile,
}

impl ArmManifest {
    /// Reads a manifest from `path`.
    ///
    /// # Errors
    ///
    /// [`AbError::Io`] if the file cannot be read, [`AbError::Json`] if it is not a manifest.
    pub fn load(path: &Path) -> Result<Self, AbError> {
        let text = std::fs::read_to_string(path).map_err(|source| AbError::Io {
            path: path.to_path_buf(),
            action: "read",
            source,
        })?;
        serde_json::from_str(&text).map_err(|source| AbError::Json {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Writes the manifest to `path` as pretty JSON with a trailing newline.
    ///
    /// # Errors
    ///
    /// [`AbError::Json`] if it cannot be serialized, [`AbError::Io`] if it cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), AbError> {
        let mut text = serde_json::to_string_pretty(self).map_err(|source| AbError::Json {
            path: path.to_path_buf(),
            source,
        })?;
        text.push('\n');
        std::fs::write(path, text).map_err(|source| AbError::Io {
            path: path.to_path_buf(),
            action: "write",
            source,
        })
    }
}

/// A loud note from [`guard_distinct_rootfs`]: two or more arms boot the same guest image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRootfsWarning {
    /// The digest the arms share.
    pub sha256: String,
    /// The labels of the arms sharing it, in the order they were passed.
    pub labels: Vec<String>,
}

impl std::fmt::Display for SharedRootfsWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "arms {} boot the SAME rootfs (sha256 {}…), so the guest side of this comparison is a \
             tree against itself. Legitimate when only host code changed; if the guest side was \
             meant to differ, one arm's rootfs build did not take and every guest-side delta below \
             is noise.",
            self.labels.join(", "),
            short_digest(&self.sha256)
        )
    }
}

/// What a guard refuses with. Every variant names the fix, because a guard that only says "no"
/// gets worked around.
#[derive(Debug)]
pub enum AbError {
    /// A file could not be opened, read or written.
    Io {
        /// The file.
        path: PathBuf,
        /// What was being attempted: `open`, `read`, `write`.
        action: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A manifest could not be parsed or serialized.
    Json {
        /// The manifest file.
        path: PathBuf,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// A guard was handed fewer arms than it can compare.
    NotEnoughArms {
        /// The guard that was called.
        guard: &'static str,
        /// How many arms it got.
        count: usize,
    },
    /// The arms do not share a guest kernel.
    KernelMismatch {
        /// `(label, kernel sha256)` for every arm, in the order they were passed.
        arms: Vec<(String, String)>,
    },
    /// A staged binary changed between `prepare` and `run`.
    BinaryChanged {
        /// The arm it belongs to.
        label: String,
        /// `bench-vm` or `vmcelld`.
        role: &'static str,
        /// Where it is staged.
        path: PathBuf,
        /// The digest the manifest recorded.
        expected: String,
        /// The digest on disk now.
        found: String,
    },
    /// Two arms of one backend executed different VMM binaries.
    VmmBinaryMismatch {
        /// The backend whose arms disagreed.
        backend: String,
        /// `(arm label, resolved path, how it was resolved)` for every arm of that backend.
        resolved: Vec<(String, String, BinSource)>,
    },
    /// A report arrived under a label no manifest describes.
    UnknownArm {
        /// The label the report carried.
        label: String,
        /// The labels there are manifests for.
        known: Vec<String>,
    },
    /// A run booted a kernel or rootfs its own arm was not pinned to.
    BootedArtifactMismatch {
        /// The arm whose report disagreed with its manifest.
        label: String,
        /// `kernel` or `rootfs`.
        role: &'static str,
        /// What the manifest pinned.
        expected: PathBuf,
        /// What the report says the run actually booted.
        found: PathBuf,
    },
    /// The kernels the runs NAMED do not hash equal, read back after the run.
    BootedKernelMismatch {
        /// `(arm label, the kernel that arm's reports named, its digest now)`, one entry per
        /// (arm, path) pair.
        arms: Vec<(String, PathBuf, String)>,
    },
}

impl std::fmt::Display for AbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io {
                path,
                action,
                source,
            } => write!(f, "cannot {action} {}: {source}", path.display()),
            Self::Json { path, source } => {
                write!(
                    f,
                    "{} is not a valid arm manifest: {source}",
                    path.display()
                )
            }
            Self::NotEnoughArms { guard, count } => write!(
                f,
                "{guard} was handed {count} arm(s); an A/B comparison needs at least two. A guard \
                 that passes over nothing is a green verdict about a run that never happened."
            ),
            Self::KernelMismatch { arms } => {
                write!(f, "the arms do not boot the same guest kernel: ")?;
                let mut first = true;
                for (label, sha) in arms {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    write!(f, "{label}={}…", short_digest(sha))?;
                }
                write!(
                    f,
                    ". Exporting $VMCELL_KERNEL is NOT enough and this is why the check exists: a \
                     `bench-vm` built before that variable existed composes \
                     <artifacts_dir>/vmlinux itself and never reads the environment, so the arms \
                     boot different kernels while the driver reports one (it shipped as 6.12.94 \
                     against 6.12.104 for a whole matrix). THE FIX IS A FILE COPY: put one vmlinux \
                     into every arm's artifacts dir — `bench-ab prepare` does this — and re-run \
                     prepare for the arms whose digest differs."
                )
            }
            Self::BinaryChanged {
                label,
                role,
                path,
                expected,
                found,
            } => write!(
                f,
                "arm `{label}`'s {role} changed under the run: {} was staged as {}… and is now \
                 {}…. A concurrent build overwrote a staged binary mid-session — `git status` \
                 stays clean while this happens, so the numbers would have measured a build nobody \
                 named. THE FIX: re-run `bench-ab prepare --label {label}`, and keep other builds \
                 out of target/ab-arms/ while a run is in flight.",
                path.display(),
                short_digest(expected),
                short_digest(found)
            ),
            Self::VmmBinaryMismatch { backend, resolved } => {
                write!(
                    f,
                    "backend `{backend}` did not run the same VMM binary in every arm: "
                )?;
                let mut first = true;
                for (label, path, source) in resolved {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    write!(f, "{label}={path} ({source})")?;
                }
                write!(
                    f,
                    ". An arm that predates $VMCELL_{{CH,FC,QEMU,CROSVM}}_BIN hardcodes the name \
                     and finds whatever is first on PATH, so the export applied to one arm only — \
                     the same class as the kernel control, one crate over, and only the emitted \
                     report can see it. THE FIX: shim the intended binary onto PATH for the old \
                     arm (a directory holding that one name, prepended to PATH), so both arms \
                     resolve the same file whether or not they read the variable."
                )
            }
            Self::UnknownArm { label, known } => write!(
                f,
                "a report arrived labelled `{label}`, and no manifest describes it (prepared \
                 arms: {}). A guard that quietly skips a run it cannot attribute passes over \
                 exactly the run that went wrong, so this refuses instead. THE FIX: pass the \
                 labels you prepared, or `bench-ab prepare --label {label}`.",
                known.join(", ")
            ),
            Self::BootedArtifactMismatch {
                label,
                role,
                expected,
                found,
            } => write!(
                f,
                "arm `{label}` booted a {role} its manifest never pinned: the report names {}, \
                 the manifest pins {}. `bench-vm` resolves $VMCELL_KERNEL and $VMCELL_ROOTFS \
                 AHEAD of the artifacts dir, so an operator with either exported — README's \
                 VMCELL_* contract table documents both — sends every arm at ONE guest artifact \
                 while this harness reports per-arm ones. That is the 2026-08-21 kernel control \
                 arriving through the parent's shell instead of through an old binary, and \
                 `guard_same_kernel` cannot see it: it compares what PREPARE recorded, not what \
                 the child resolved. THE FIX: `bench-ab` strips those variables from every child, \
                 so a mismatch here means the arm was re-prepared into a different artifacts dir \
                 — re-run `bench-ab prepare --label {label}` — or that a spawn site was added \
                 that does not seal them.",
                found.display(),
                expected.display()
            ),
            Self::BootedKernelMismatch { arms } => {
                write!(
                    f,
                    "the arms did not boot the same guest kernel, as read back from the files \
                     their own reports named: "
                )?;
                let mut first = true;
                for (label, path, sha) in arms {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    write!(f, "{label}={} ({}…)", path.display(), short_digest(sha))?;
                }
                write!(
                    f,
                    ". This is the POST-RUN twin of the same-kernel control: prepare-time digests \
                     cannot see a child that resolved another file, nor a vmlinux rewritten \
                     underneath the matrix by a concurrent `vmcell build`. THE FIX: re-run \
                     `bench-ab prepare` for both arms so one vmlinux is copied into each arm's \
                     artifacts dir, and keep other builds out of target/ab-worktrees/ while a run \
                     is in flight."
                )
            }
        }
    }
}

impl std::error::Error for AbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::NotEnoughArms { .. }
            | Self::KernelMismatch { .. }
            | Self::BinaryChanged { .. }
            | Self::VmmBinaryMismatch { .. }
            | Self::UnknownArm { .. }
            | Self::BootedArtifactMismatch { .. }
            | Self::BootedKernelMismatch { .. } => None,
        }
    }
}

/// The first [`SHORT_DIGEST_CHARS`] of a hex digest, for messages. Falls back to the whole string
/// when it is shorter, so a malformed digest is shown rather than swallowed.
fn short_digest(sha: &str) -> &str {
    sha.get(..SHORT_DIGEST_CHARS).unwrap_or(sha)
}

/// GUARD 1 — every arm boots the same guest kernel.
///
/// This is the control the 2026-08-21 pass thought it had. See [`AbError::KernelMismatch`] for why
/// the fix is a file copy and not an environment variable.
///
/// # Errors
///
/// [`AbError::NotEnoughArms`] for fewer than two arms — a guard that passes over one arm is a
/// vacuous green. [`AbError::KernelMismatch`] when the digests differ.
pub fn guard_same_kernel(arms: &[ArmManifest]) -> Result<(), AbError> {
    if arms.len() < 2 {
        return Err(AbError::NotEnoughArms {
            guard: "guard_same_kernel",
            count: arms.len(),
        });
    }
    let mut digests = arms.iter().map(|arm| arm.kernel.sha256.as_str());
    let first = digests.next().unwrap_or_default();
    if digests.all(|sha| sha == first) {
        return Ok(());
    }
    Err(AbError::KernelMismatch {
        arms: arms
            .iter()
            .map(|arm| (arm.label.clone(), arm.kernel.sha256.clone()))
            .collect(),
    })
}

/// GUARD 2 — the arm's staged binaries are still the bytes the manifest pinned.
///
/// Called immediately before each run, not once at start-up: the swap that motivated this landed
/// *during* a matrix, between two of its cells.
///
/// # Errors
///
/// [`AbError::BinaryChanged`] when a digest moved; [`AbError::Io`] when a staged binary cannot be
/// read at all (including because it is gone).
pub fn guard_binaries_unchanged(arm: &ArmManifest) -> Result<(), AbError> {
    for (role, file) in [
        Some(("bench-vm", &arm.bench_vm)),
        arm.vmcelld.as_ref().map(|d| ("vmcelld", d)),
    ]
    .into_iter()
    .flatten()
    {
        // Through `DigestedFile::changed_digest`, not a second re-digest-and-compare here: this
        // guard's inline copy is what left that method with no caller and no test.
        if let Some(found) = file.changed_digest()? {
            return Err(AbError::BinaryChanged {
                label: arm.label.clone(),
                role,
                path: file.path.clone(),
                expected: file.sha256.clone(),
                found,
            });
        }
    }
    Ok(())
}

/// GUARD 3 — the arms boot different guest images. **A warning, not an error.**
///
/// Two arms sharing a rootfs digest are comparing a tree against itself on the guest side, which is
/// entirely legitimate when only host code changed — so this returns notes for the caller to print
/// rather than refusing the run. It is `#[must_use]` for the obvious reason: a warning nobody
/// prints is a warning that does not exist, and `let _ = guard_distinct_rootfs(..)` is denied by
/// this crate's fail-loud lint.
///
/// Deliberate shape shift from the sketch, recorded here rather than left silent: the spec wrote
/// this guard as `-> Result<()>` alongside the other three, but its own rule is "loud note, not an
/// error". A `Result` that is always `Ok` teaches every caller to ignore it.
#[must_use]
pub fn guard_distinct_rootfs(arms: &[ArmManifest]) -> Vec<SharedRootfsWarning> {
    let mut by_digest: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for arm in arms {
        by_digest
            .entry(arm.rootfs.sha256.as_str())
            .or_default()
            .push(arm.label.clone());
    }
    by_digest
        .into_iter()
        .filter(|(_, labels)| labels.len() > 1)
        .map(|(sha256, labels)| SharedRootfsWarning {
            sha256: sha256.to_string(),
            labels,
        })
        .collect()
}

/// GUARD 4 — every arm of a backend executed the same VMM binary, as reported by the runs
/// themselves.
///
/// Runs are passed as `(arm label, report)` pairs — a shape shift from the sketched
/// `&[BenchReport]`, recorded here: a report knows its backend but not which arm produced it, and
/// an error that cannot name the offending arm sends the reader back to the shell history that
/// caused the defect in the first place.
///
/// Grouped by backend because a matrix legitimately spans several: comparing Cloud Hypervisor's
/// binary against QEMU's would fail every honest run. Within a backend a single report is left
/// alone — one arm having produced no report for that backend is the *plan's* problem, and it
/// shows up as a missing comparison rather than as a false accusation here.
///
/// # Errors
///
/// [`AbError::NotEnoughArms`] for fewer than two runs; [`AbError::VmmBinaryMismatch`] when one
/// backend's arms resolved different binaries.
pub fn guard_vmm_binaries<'a, I>(runs: I) -> Result<(), AbError>
where
    I: IntoIterator<Item = (&'a str, &'a BenchReport)>,
{
    let runs: Vec<(&str, &BenchReport)> = runs.into_iter().collect();
    if runs.len() < 2 {
        return Err(AbError::NotEnoughArms {
            guard: "guard_vmm_binaries",
            count: runs.len(),
        });
    }
    let mut by_backend: BTreeMap<&str, Vec<(&str, &BenchReport)>> = BTreeMap::new();
    for (label, report) in runs {
        by_backend
            .entry(report.backend.as_str())
            .or_default()
            .push((label, report));
    }
    for (backend, group) in by_backend {
        let mut binaries = group.iter().map(|(_, report)| report.vmm_binary.as_str());
        let first = binaries.next().unwrap_or_default();
        if binaries.all(|binary| binary == first) {
            continue;
        }
        return Err(AbError::VmmBinaryMismatch {
            backend: backend.to_string(),
            resolved: group
                .iter()
                .map(|(label, report)| {
                    (
                        (*label).to_string(),
                        report.vmm_binary.clone(),
                        report.vmm_binary_source.clone(),
                    )
                })
                .collect(),
        });
    }
    Ok(())
}

/// GUARD 5 — every run booted ITS OWN arm's artifacts, and the arms agree on the kernel.
///
/// THE POST-RUN TWIN OF [`guard_vmm_binaries`], and the answer to the question
/// [`guard_same_kernel`] structurally cannot ask. That guard compares digests recorded at
/// **prepare** time; it is a statement about two files on disk before anything ran. It stays green
/// against a child that resolved a *different* file — and `bench-vm` resolves `$VMCELL_KERNEL` and
/// `$VMCELL_ROOTFS` ahead of the artifacts dir, so an inherited export from the operator's shell
/// (README documents both, `ci.yml` exports them) pointed every arm at one guest artifact while the
/// manifests still recorded per-arm ones. The report is the only witness to what a run actually
/// opened, so this reads the reports.
///
/// Two questions, in order:
///
/// 1. **Did each run boot its own arm's pinned pair?** The reported `kernel` and `rootfs` must be
///    the paths that arm's manifest names. Both, not just the kernel: a leaked `$VMCELL_ROOTFS`
///    makes every guest-side delta a tree compared against itself, which is the *warning* case of
///    [`guard_distinct_rootfs`] arriving silently instead of loudly.
/// 2. **Do the arms agree on the kernel, NOW?** The kernel each report named is re-hashed from
///    disk, so a vmlinux rewritten underneath the matrix by a concurrent `vmcell build` fails here
///    the way a swapped binary fails [`guard_binaries_unchanged`]. The rootfs is deliberately NOT
///    compared across arms — two arms are *supposed* to boot different guest images.
///
/// Runs are `(arm label, report)` pairs, the same shape [`guard_vmm_binaries`] takes and for the
/// same reason: a report knows its backend, never which arm produced it.
///
/// # Errors
///
/// [`AbError::NotEnoughArms`] for fewer than two runs; [`AbError::UnknownArm`] for a report whose
/// label no manifest describes; [`AbError::BootedArtifactMismatch`] when a run booted something its
/// arm was not pinned to; [`AbError::BootedKernelMismatch`] when the named kernels do not hash
/// equal; [`AbError::Io`] when one of them cannot be read back at all.
pub fn guard_booted_artifacts<'a, I>(arms: &[ArmManifest], runs: I) -> Result<(), AbError>
where
    I: IntoIterator<Item = (&'a str, &'a BenchReport)>,
{
    let runs: Vec<(&str, &BenchReport)> = runs.into_iter().collect();
    if runs.len() < 2 {
        return Err(AbError::NotEnoughArms {
            guard: "guard_booted_artifacts",
            count: runs.len(),
        });
    }
    let by_label: BTreeMap<&str, &ArmManifest> =
        arms.iter().map(|arm| (arm.label.as_str(), arm)).collect();

    for (label, report) in &runs {
        let arm = by_label.get(label).ok_or_else(|| AbError::UnknownArm {
            label: (*label).to_string(),
            known: arms.iter().map(|arm| arm.label.clone()).collect(),
        })?;
        for (role, expected, found) in [
            ("kernel", &arm.kernel.path, &report.kernel),
            ("rootfs", &arm.rootfs.path, &report.rootfs),
        ] {
            if expected != found {
                return Err(AbError::BootedArtifactMismatch {
                    label: (*label).to_string(),
                    role,
                    expected: expected.clone(),
                    found: found.clone(),
                });
            }
        }
    }

    // One digest per DISTINCT kernel path, not one per run: a matrix is tens of runs over two
    // files, and re-hashing a 40 MiB vmlinux thirty times is the kind of cost that gets a control
    // deleted. Keyed by `(label, path)` so the failure message has one line per arm rather than
    // one per cell.
    let mut digests: BTreeMap<&Path, String> = BTreeMap::new();
    let mut booted: BTreeMap<(&str, &Path), String> = BTreeMap::new();
    for (label, report) in &runs {
        let kernel = report.kernel.as_path();
        let sha = match digests.get(kernel) {
            Some(sha) => sha.clone(),
            None => {
                let sha = sha256_file(kernel)?;
                digests.insert(kernel, sha.clone());
                sha
            }
        };
        booted.insert((label, kernel), sha);
    }
    let mut shas = booted.values().map(String::as_str);
    let first = shas.next().unwrap_or_default();
    if shas.all(|sha| sha == first) {
        return Ok(());
    }
    Err(AbError::BootedKernelMismatch {
        arms: booted
            .into_iter()
            .map(|((label, path), sha)| (label.to_string(), path.to_path_buf(), sha))
            .collect(),
    })
}

/// One cell of the matrix: what `bench-vm` is asked to measure.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// `--backend`.
    pub backend: String,
    /// `--mode`.
    pub mode: String,
    /// Extra `bench-vm` arguments, passed through verbatim.
    pub extra_args: Vec<String>,
}

impl Spec {
    /// A spec with no extra arguments.
    #[must_use]
    pub fn new(backend: impl Into<String>, mode: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            mode: mode.into(),
            extra_args: Vec::new(),
        }
    }

    /// Adds pass-through `bench-vm` arguments.
    #[must_use]
    pub fn with_args<S: Into<String>>(mut self, args: impl IntoIterator<Item = S>) -> Self {
        self.extra_args = args.into_iter().map(Into::into).collect();
        self
    }

    /// The identifier this spec's results are aggregated under.
    ///
    /// Includes the extra arguments: two specs differing only in `--mem-mib` are two different
    /// measurements, and an id that collapsed them would pool the samples silently — the same
    /// defect as the unqualified phase-budget row names the report module exists to prevent.
    #[must_use]
    pub fn id(&self) -> String {
        if self.extra_args.is_empty() {
            format!("{}/{}", self.backend, self.mode)
        } else {
            format!(
                "{}/{} [{}]",
                self.backend,
                self.mode,
                self.extra_args.join(" ")
            )
        }
    }
}

/// One scheduled execution: this arm, this spec, this repeat.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The arm's label.
    pub arm: String,
    /// What to measure.
    pub spec: Spec,
    /// Zero-based repeat index.
    pub repeat: usize,
}

/// The interleaved execution plan.
///
/// Two properties, both load-bearing:
///
/// * **The arms of one (spec, repeat) run back to back**, so whatever the host was doing is as
///   close to shared between them as a sequential harness can make it.
/// * **The leading arm rotates** with `(repeat + spec index)`, so each arm leads within ±1 of every
///   other. A fixed leader hands the *second* arm every cache the first one warmed, and a
///   monotonic host drift — thermal, page-cache, another tenant ramping up — then reads as a
///   consistent, entirely fictional win for one side. That is the exact failure the 2026-08-21
///   pass could not rule out, having measured its two sides on different machines.
///
/// Returns an empty plan for an empty arm list, an empty spec list, or zero repeats: there is
/// nothing to schedule, and the caller's own emptiness check is a better place to complain than a
/// panic here.
#[must_use]
pub fn interleave(arms: &[String], specs: &[Spec], repeats: usize) -> Vec<Run> {
    let arm_count = arms.len();
    if arm_count == 0 || specs.is_empty() || repeats == 0 {
        return Vec::new();
    }
    let mut plan = Vec::with_capacity(arm_count * specs.len() * repeats);
    for repeat in 0..repeats {
        for (spec_index, spec) in specs.iter().enumerate() {
            let lead = (repeat + spec_index) % arm_count;
            // `cycle().skip(lead).take(n)` is the rotation without an index: every arm exactly
            // once, starting at the leader.
            for arm in arms.iter().cycle().skip(lead).take(arm_count) {
                plan.push(Run {
                    arm: arm.clone(),
                    spec: spec.clone(),
                    repeat,
                });
            }
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Metric, REPORT_SCHEMA_VERSION, Unit};
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    /// Writes `contents` to `dir/name` and returns the path.
    fn write_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write fixture");
        path
    }

    /// An arm whose four pinned files live in `dir`, with the kernel and rootfs bytes given so a
    /// test can make two arms agree or disagree on exactly one of them.
    fn arm(dir: &Path, label: &str, kernel: &[u8], rootfs: &[u8]) -> ArmManifest {
        let sub = dir.join(label);
        std::fs::create_dir_all(&sub).expect("create arm dir");
        let bench_vm = write_file(&sub, "bench-vm", format!("bench-vm for {label}").as_bytes());
        let vmcelld = write_file(&sub, "vmcelld", format!("vmcelld for {label}").as_bytes());
        let kernel_path = write_file(&sub, "vmlinux", kernel);
        let rootfs_path = write_file(&sub, "rootfs.erofs", rootfs);
        ArmManifest {
            label: label.to_string(),
            git_ref: Some(format!("refs/tags/{label}")),
            git_commit: Some(format!("{label}-commit")),
            bench_vm: DigestedFile::digest(bench_vm).expect("digest bench-vm"),
            vmcelld: Some(DigestedFile::digest(vmcelld).expect("digest vmcelld")),
            artifacts_dir: sub.clone(),
            kernel: DigestedFile::digest(kernel_path).expect("digest kernel"),
            rootfs: DigestedFile::digest(rootfs_path).expect("digest rootfs"),
        }
    }

    fn report(backend: &str, vmm_binary: &str, source: BinSource) -> BenchReport {
        BenchReport {
            schema_version: REPORT_SCHEMA_VERSION,
            backend: backend.to_string(),
            mode: "latency".to_string(),
            vmm_binary: vmm_binary.to_string(),
            vmm_binary_source: source,
            kernel: PathBuf::from("/artifacts/vmlinux"),
            rootfs: PathBuf::from("/artifacts/rootfs.erofs"),
            knobs: BTreeMap::new(),
            metrics: vec![Metric::new(
                "cold_boot",
                Unit::Millis,
                5,
                40.0,
                44.0,
                45.0,
                45.0,
            )],
            notes: Vec::new(),
        }
    }

    #[test]
    fn sha256_matches_the_published_vector_for_abc() {
        // NIST FIPS 180-4 worked example, not this code's output: SHA-256("abc").
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(dir.path(), "abc", b"abc");
        assert_eq!(
            sha256_file(&path).expect("digest"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_streams_across_chunk_boundaries() {
        // The digest reads in 64 KiB chunks, so a payload spanning several of them proves the loop
        // feeds every byte exactly once — a bug that only shows up above the buffer size is
        // invisible to a small fixture. Cross-checked against the same bytes hashed in one shot.
        use sha2::Digest as _;
        let dir = TempDir::new().expect("tempdir");
        let bytes: Vec<u8> = (0..(DIGEST_CHUNK_BYTES * 2 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        let path = write_file(dir.path(), "big", &bytes);
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        let expected: [u8; 32] = hasher.finalize().into();
        let expected: String = expected.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sha256_file(&path).expect("digest"), expected);
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_pass() {
        let dir = TempDir::new().expect("tempdir");
        let missing = dir.path().join("never-existed");
        match sha256_file(&missing) {
            Err(AbError::Io { action, .. }) => assert_eq!(action, "open"),
            other => panic!("expected an IO refusal, got {other:?}"),
        }
    }

    // The re-verification law itself, both arms plus the vanished one. Its CALL SITE is
    // `guard_binaries_unchanged`, whose four tests below are what bind it: invert this method
    // (return `Ok(None)` on a mismatch) and the guard's swapped-binary and vanished-binary tests
    // go red together with the asserts here. RED on the inverse also for the `Some` arm carrying
    // the digest — a `Some(String::new())` would leave the guard's message naming nothing.
    #[test]
    fn a_pinned_file_answers_with_the_digest_it_changed_to() {
        let tmp = TempDir::new().expect("tempdir");
        let path = write_file(tmp.path(), "bench-vm", b"the staged arm");
        let pinned = DigestedFile::digest(&path).expect("digest");

        // Unchanged: no answer at all, which is what lets the guard say nothing.
        assert_eq!(pinned.changed_digest().expect("re-digest"), None);

        // Swapped underneath the run — the 2026-08-21 shape, a concurrent `cargo build --release`
        // over the staged binary while `git status` stayed clean.
        std::fs::write(&path, b"a patched build").expect("overwrite");
        let found = pinned
            .changed_digest()
            .expect("re-digest")
            .expect("a swapped file must answer");
        assert_eq!(
            found,
            sha256_file(&path).expect("digest the new bytes"),
            "the answer must be the digest actually found, which is what the guard's message \
             quotes"
        );
        assert_ne!(found, pinned.sha256);

        // Gone is an ERROR, never `Ok(None)`: a staged binary that vanished mid-session cannot
        // have produced the numbers about to be compared.
        std::fs::remove_file(&path).expect("remove");
        assert!(matches!(pinned.changed_digest(), Err(AbError::Io { .. })));
    }

    #[test]
    fn manifest_round_trips_through_its_file() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = arm(dir.path(), "head", b"kernel-A", b"rootfs-A");
        let path = dir.path().join("arm.json");
        manifest.save(&path).expect("save");
        assert_eq!(ArmManifest::load(&path).expect("load"), manifest);
    }

    // ---- GUARD 1: guard_same_kernel -------------------------------------------------------

    #[test]
    fn guard_same_kernel_errors_when_the_arms_boot_different_kernels() {
        // RED ON THE INVERSE: two arms whose vmlinux bytes differ — literally the 6.12.94 vs
        // 6.12.104 pair the exported $VMCELL_KERNEL failed to prevent.
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux 6.12.94", b"rootfs-B"),
        ];
        match guard_same_kernel(&arms) {
            Err(AbError::KernelMismatch { arms: reported }) => {
                assert_eq!(reported.len(), 2);
                let message = AbError::KernelMismatch { arms: reported }.to_string();
                // The message must carry the FIX, not just the finding: the export is not enough.
                assert!(message.contains("VMCELL_KERNEL"), "{message}");
                assert!(message.contains("FILE COPY"), "{message}");
                assert!(message.contains("head"), "{message}");
            }
            other => panic!("expected a kernel mismatch, got {other:?}"),
        }
    }

    #[test]
    fn guard_same_kernel_passes_when_one_vmlinux_was_copied_into_both() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux 6.12.104", b"rootfs-B"),
        ];
        guard_same_kernel(&arms).expect("identical kernel digests are the control being honoured");
    }

    #[test]
    fn guard_same_kernel_refuses_to_pass_over_fewer_than_two_arms() {
        let dir = TempDir::new().expect("tempdir");
        let one = vec![arm(dir.path(), "head", b"vmlinux", b"rootfs")];
        assert!(matches!(
            guard_same_kernel(&one),
            Err(AbError::NotEnoughArms { count: 1, .. })
        ));
        assert!(matches!(
            guard_same_kernel(&[]),
            Err(AbError::NotEnoughArms { count: 0, .. })
        ));
    }

    // ---- GUARD 2: guard_binaries_unchanged ------------------------------------------------

    #[test]
    fn guard_binaries_unchanged_errors_when_bench_vm_was_swapped_under_the_run() {
        // RED ON THE INVERSE: stage the arm, then overwrite the staged bench-vm the way a
        // concurrent `cargo build --release` did on 2026-08-21 — the path is unchanged, the
        // mtime-based intuition is unchanged, and `git status` would be clean.
        let dir = TempDir::new().expect("tempdir");
        let manifest = arm(dir.path(), "head", b"vmlinux", b"rootfs");
        std::fs::write(&manifest.bench_vm.path, b"patched bench-vm").expect("overwrite");
        match guard_binaries_unchanged(&manifest) {
            Err(AbError::BinaryChanged {
                label,
                role,
                expected,
                found,
                ..
            }) => {
                assert_eq!(label, "head");
                assert_eq!(role, "bench-vm");
                assert_ne!(expected, found);
            }
            other => panic!("expected a swapped-binary refusal, got {other:?}"),
        }
    }

    #[test]
    fn guard_binaries_unchanged_covers_the_sibling_daemon_too() {
        // The daemon is the half that would otherwise slip through: `bench-vm` finds `vmcelld` as
        // its own sibling, so a stale or rebuilt daemon changes what the arm measures without
        // touching `bench-vm` at all.
        let dir = TempDir::new().expect("tempdir");
        let manifest = arm(dir.path(), "head", b"vmlinux", b"rootfs");
        let daemon = manifest.vmcelld.as_ref().expect("fixture stages a daemon");
        std::fs::write(&daemon.path, b"patched vmcelld").expect("overwrite");
        match guard_binaries_unchanged(&manifest) {
            Err(AbError::BinaryChanged { role, .. }) => assert_eq!(role, "vmcelld"),
            other => panic!("expected a swapped-daemon refusal, got {other:?}"),
        }
    }

    #[test]
    fn guard_binaries_unchanged_passes_on_an_untouched_arm() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = arm(dir.path(), "head", b"vmlinux", b"rootfs");
        guard_binaries_unchanged(&manifest).expect("nothing touched the staged binaries");
    }

    #[test]
    fn guard_binaries_unchanged_errors_when_a_staged_binary_vanished() {
        // A deleted binary must not read as "unchanged": the arm cannot have run.
        let dir = TempDir::new().expect("tempdir");
        let manifest = arm(dir.path(), "head", b"vmlinux", b"rootfs");
        std::fs::remove_file(&manifest.bench_vm.path).expect("remove");
        assert!(matches!(
            guard_binaries_unchanged(&manifest),
            Err(AbError::Io { action: "open", .. })
        ));
    }

    // ---- GUARD 3: guard_distinct_rootfs ---------------------------------------------------

    #[test]
    fn guard_distinct_rootfs_warns_when_two_arms_share_an_image() {
        // RED ON THE INVERSE: identical rootfs bytes in two arms. This one WARNS rather than
        // fails — a host-only change legitimately compares one guest image against itself — so the
        // assertion is that the note is produced and names both arms.
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux", b"rootfs-SAME"),
            arm(dir.path(), "v0.22.0", b"vmlinux", b"rootfs-SAME"),
        ];
        let warnings = guard_distinct_rootfs(&arms);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let warning = warnings.first().expect("one warning");
        assert_eq!(warning.labels, vec!["head", "v0.22.0"]);
        let rendered = warning.to_string();
        assert!(rendered.contains("head"), "{rendered}");
        assert!(rendered.contains("v0.22.0"), "{rendered}");
        assert!(rendered.contains("SAME rootfs"), "{rendered}");
    }

    #[test]
    fn guard_distinct_rootfs_is_silent_when_the_images_differ() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux", b"rootfs-B"),
        ];
        assert!(guard_distinct_rootfs(&arms).is_empty());
    }

    // ---- GUARD 4: guard_vmm_binaries ------------------------------------------------------

    #[test]
    fn guard_vmm_binaries_errors_when_one_arm_fell_back_to_path() {
        // RED ON THE INVERSE, through the artifact the run actually leaves behind: the reports are
        // written to a tempdir as JSON and read back the way `bench-ab run` reads them, because
        // the whole lesson is that only the emitted report — not the driver's belief about its own
        // exports — can see this.
        let dir = TempDir::new().expect("tempdir");
        let head = report(
            "cloud-hypervisor",
            "/home/x/.local/bin/cloud-hypervisor",
            BinSource::EnvVar {
                name: "VMCELL_CH_BIN".to_string(),
            },
        );
        let old = report(
            "cloud-hypervisor",
            "/usr/bin/cloud-hypervisor",
            BinSource::Path,
        );
        let head_path = write_file(
            dir.path(),
            "head.json",
            head.to_json().expect("json").as_bytes(),
        );
        let old_path = write_file(
            dir.path(),
            "old.json",
            old.to_json().expect("json").as_bytes(),
        );
        let head = BenchReport::from_json(&std::fs::read_to_string(head_path).expect("read"))
            .expect("parse");
        let old = BenchReport::from_json(&std::fs::read_to_string(old_path).expect("read"))
            .expect("parse");

        match guard_vmm_binaries([("head", &head), ("v0.22.0", &old)]) {
            Err(AbError::VmmBinaryMismatch { backend, resolved }) => {
                assert_eq!(backend, "cloud-hypervisor");
                let message = AbError::VmmBinaryMismatch { backend, resolved }.to_string();
                assert!(message.contains("head"), "{message}");
                assert!(message.contains("via $VMCELL_CH_BIN"), "{message}");
                assert!(message.contains("found on PATH"), "{message}");
                assert!(message.contains("shim"), "{message}");
            }
            other => panic!("expected a VMM binary mismatch, got {other:?}"),
        }
    }

    #[test]
    fn guard_vmm_binaries_passes_when_both_arms_resolved_the_same_file() {
        // The positive control for the negative result above, and it deliberately differs in HOW
        // the two arms resolved it: the same file found by two routes is the shim working, which
        // is exactly the state the fix produces.
        let same = "/usr/bin/cloud-hypervisor";
        let head = report(
            "cloud-hypervisor",
            same,
            BinSource::EnvVar {
                name: "VMCELL_CH_BIN".to_string(),
            },
        );
        let old = report("cloud-hypervisor", same, BinSource::Path);
        guard_vmm_binaries([("head", &head), ("v0.22.0", &old)]).expect("same binary, both arms");
    }

    #[test]
    fn guard_vmm_binaries_compares_within_a_backend_not_across_the_matrix() {
        // A matrix spans backends, and Cloud Hypervisor's binary is *supposed* to differ from
        // QEMU's. Without the grouping this guard would refuse every honest multi-backend run.
        let ch_head = report(
            "cloud-hypervisor",
            "/usr/bin/cloud-hypervisor",
            BinSource::Path,
        );
        let ch_old = report(
            "cloud-hypervisor",
            "/usr/bin/cloud-hypervisor",
            BinSource::Path,
        );
        let qemu_head = report("qemu", "/usr/bin/qemu-system-x86_64", BinSource::Path);
        let qemu_old = report("qemu", "/usr/bin/qemu-system-x86_64", BinSource::Path);
        guard_vmm_binaries([
            ("head", &ch_head),
            ("v0.22.0", &ch_old),
            ("head", &qemu_head),
            ("v0.22.0", &qemu_old),
        ])
        .expect("each backend agrees with itself");

        // ...and it still catches a mismatch inside ONE backend of that same matrix.
        let qemu_old_elsewhere =
            report("qemu", "/opt/qemu/bin/qemu-system-x86_64", BinSource::Path);
        assert!(matches!(
            guard_vmm_binaries([
                ("head", &ch_head),
                ("v0.22.0", &ch_old),
                ("head", &qemu_head),
                ("v0.22.0", &qemu_old_elsewhere),
            ]),
            Err(AbError::VmmBinaryMismatch { .. })
        ));
    }

    #[test]
    fn guard_vmm_binaries_refuses_to_pass_over_a_single_run() {
        let only = report(
            "cloud-hypervisor",
            "/usr/bin/cloud-hypervisor",
            BinSource::Path,
        );
        assert!(matches!(
            guard_vmm_binaries([("head", &only)]),
            Err(AbError::NotEnoughArms { count: 1, .. })
        ));
    }

    // ---- GUARD 5: guard_booted_artifacts ---------------------------------------------------

    /// A report that names the pair `arm` was pinned to — the shape an honest run emits, since
    /// `bench-vm` composes both paths from `$VMCELL_ARTIFACTS_DIR`.
    fn report_for(arm: &ArmManifest) -> BenchReport {
        let mut report = report(
            "cloud-hypervisor",
            "/usr/bin/cloud-hypervisor",
            BinSource::Path,
        );
        report.kernel = arm.kernel.path.clone();
        report.rootfs = arm.rootfs.path.clone();
        report
    }

    #[test]
    fn guard_booted_artifacts_errors_when_a_child_resolved_a_foreign_kernel() {
        // RED ON THE INVERSE, and it is the inverse the PRE-run control cannot produce: both arms
        // are prepared correctly (identical kernel bytes, `guard_same_kernel` green), and the
        // defect is entirely in what the CHILD resolved — an inherited `$VMCELL_KERNEL` from the
        // operator's shell, which `bench-vm` honors ahead of the artifacts dir.
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux 6.12.104", b"rootfs-B"),
        ];
        guard_same_kernel(&arms).expect("prepare-time digests agree — and see nothing");

        let head = report_for(&arms[0]);
        let mut leaked = report_for(&arms[1]);
        leaked.kernel = PathBuf::from("/home/x/kernels/vmlinux-6.12.94");
        match guard_booted_artifacts(&arms, [("head", &head), ("v0.22.0", &leaked)]) {
            Err(AbError::BootedArtifactMismatch {
                label, role, found, ..
            }) => {
                assert_eq!(label, "v0.22.0");
                assert_eq!(role, "kernel");
                assert_eq!(found, PathBuf::from("/home/x/kernels/vmlinux-6.12.94"));
                let message = AbError::BootedArtifactMismatch {
                    label,
                    role,
                    expected: arms[1].kernel.path.clone(),
                    found,
                }
                .to_string();
                // The message must name the variable and the fix, not just the difference.
                assert!(message.contains("VMCELL_KERNEL"), "{message}");
                assert!(message.contains("guard_same_kernel"), "{message}");
            }
            other => panic!("expected a booted-artifact mismatch, got {other:?}"),
        }
    }

    #[test]
    fn guard_booted_artifacts_covers_the_rootfs_too() {
        // The half a kernel-only check would miss: a leaked `$VMCELL_ROOTFS` makes both arms boot
        // ONE guest image, which is `guard_distinct_rootfs`'s warning arriving silently — the arms
        // are still pinned to different images, so nothing before the run can see it.
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux", b"rootfs-B"),
        ];
        let head = report_for(&arms[0]);
        let mut leaked = report_for(&arms[1]);
        leaked.rootfs = arms[0].rootfs.path.clone();
        assert!(matches!(
            guard_booted_artifacts(&arms, [("head", &head), ("v0.22.0", &leaked)]),
            Err(AbError::BootedArtifactMismatch { role: "rootfs", .. })
        ));
    }

    #[test]
    fn guard_booted_artifacts_passes_when_every_run_booted_its_own_pinned_pair() {
        // The positive control, with two repeats per arm so the per-path digest cache is exercised
        // rather than trivially bypassed.
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux 6.12.104", b"rootfs-B"),
        ];
        let head = report_for(&arms[0]);
        let old = report_for(&arms[1]);
        guard_booted_artifacts(
            &arms,
            [
                ("head", &head),
                ("v0.22.0", &old),
                ("head", &head),
                ("v0.22.0", &old),
            ],
        )
        .expect("each run booted the pair its own arm pins");
    }

    #[test]
    fn guard_booted_artifacts_catches_a_kernel_rewritten_after_prepare() {
        // THE CASE NO PREPARE-TIME DIGEST CAN REACH: both arms were prepared from one vmlinux, the
        // pre-run control passes on the recorded digests, and then a concurrent `vmcell build` in
        // one worktree rewrites that arm's kernel mid-matrix — the same class as the swapped
        // `bench-vm`, one artifact over, and `guard_binaries_unchanged` only re-digests binaries.
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux 6.12.104", b"rootfs-B"),
        ];
        guard_same_kernel(&arms)
            .expect("the recorded digests still agree — that is the blind spot");
        let head = report_for(&arms[0]);
        let old = report_for(&arms[1]);
        std::fs::write(&arms[1].kernel.path, b"vmlinux 6.12.94 rebuilt mid-run").expect("rewrite");
        match guard_booted_artifacts(&arms, [("head", &head), ("v0.22.0", &old)]) {
            Err(AbError::BootedKernelMismatch { arms: reported }) => {
                assert_eq!(reported.len(), 2, "{reported:?}");
                let message = AbError::BootedKernelMismatch { arms: reported }.to_string();
                assert!(message.contains("POST-RUN"), "{message}");
                assert!(message.contains("bench-ab prepare"), "{message}");
            }
            other => panic!("expected a booted-kernel mismatch, got {other:?}"),
        }
    }

    #[test]
    fn guard_booted_artifacts_refuses_a_report_it_cannot_attribute() {
        // A guard that silently skips an unattributable run passes over exactly the run that went
        // wrong.
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm(dir.path(), "head", b"vmlinux", b"rootfs-A"),
            arm(dir.path(), "v0.22.0", b"vmlinux", b"rootfs-B"),
        ];
        let head = report_for(&arms[0]);
        match guard_booted_artifacts(&arms, [("head", &head), ("typo", &head)]) {
            Err(AbError::UnknownArm { label, known }) => {
                assert_eq!(label, "typo");
                assert_eq!(known, vec!["head", "v0.22.0"]);
            }
            other => panic!("expected an unknown-arm refusal, got {other:?}"),
        }
    }

    #[test]
    fn guard_booted_artifacts_refuses_to_pass_over_a_single_run() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![arm(dir.path(), "head", b"vmlinux", b"rootfs-A")];
        let head = report_for(&arms[0]);
        assert!(matches!(
            guard_booted_artifacts(&arms, [("head", &head)]),
            Err(AbError::NotEnoughArms { count: 1, .. })
        ));
    }

    // ---- interleave -----------------------------------------------------------------------

    fn labels(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn interleave_schedules_every_cell_exactly_once() {
        let arms = labels(&["head", "v0.22.0"]);
        let specs = vec![
            Spec::new("cloud-hypervisor", "latency"),
            Spec::new("qemu", "latency"),
            Spec::new("cloud-hypervisor", "vsock-rtt"),
        ];
        let repeats = 5;
        let plan = interleave(&arms, &specs, repeats);

        assert_eq!(plan.len(), arms.len() * specs.len() * repeats);
        let unique: BTreeSet<(String, String, usize)> = plan
            .iter()
            .map(|run| (run.arm.clone(), run.spec.id(), run.repeat))
            .collect();
        assert_eq!(
            unique.len(),
            plan.len(),
            "a (arm, spec, repeat) cell was scheduled twice"
        );
        for arm in &arms {
            for spec in &specs {
                for repeat in 0..repeats {
                    assert!(
                        unique.contains(&(arm.clone(), spec.id(), repeat)),
                        "cell ({arm}, {}, {repeat}) was never scheduled",
                        spec.id()
                    );
                }
            }
        }
    }

    #[test]
    fn interleave_alternates_the_leading_arm_within_one() {
        let arms = labels(&["head", "v0.22.0"]);
        let specs = vec![
            Spec::new("cloud-hypervisor", "latency"),
            Spec::new("qemu", "latency"),
            Spec::new("cloud-hypervisor", "vsock-rtt"),
        ];
        // An ODD repeat count on purpose: with an even one, "each arm leads equally" holds for a
        // schedule that alternates and for one that is merely balanced by luck, and ±1 is the
        // property that has to survive the odd case.
        let repeats = 5;
        let plan = interleave(&arms, &specs, repeats);

        let mut leads: BTreeMap<&str, usize> = BTreeMap::new();
        let mut leads_per_spec: BTreeMap<(String, &str), usize> = BTreeMap::new();
        for block in plan.chunks(arms.len()) {
            let lead = block.first().expect("a block is never empty");
            *leads.entry(lead.arm.as_str()).or_default() += 1;
            *leads_per_spec
                .entry((lead.spec.id(), lead.arm.as_str()))
                .or_default() += 1;
            // The other half of the property: the arms of one (spec, repeat) run back to back, so
            // the host state they see is as close to shared as a sequential harness gets.
            let in_block: BTreeSet<&str> = block.iter().map(|run| run.arm.as_str()).collect();
            assert_eq!(
                in_block.len(),
                arms.len(),
                "a block repeated an arm: {block:?}"
            );
            assert!(
                block
                    .iter()
                    .all(|run| run.spec == lead.spec && run.repeat == lead.repeat),
                "a block mixed specs or repeats: {block:?}"
            );
        }

        let counts: Vec<usize> = arms
            .iter()
            .map(|arm| leads.get(arm.as_str()).copied().unwrap_or(0))
            .collect();
        let lo = counts.iter().min().copied().unwrap_or(0);
        let hi = counts.iter().max().copied().unwrap_or(0);
        assert!(hi - lo <= 1, "lead counts are not balanced: {leads:?}");

        for spec in &specs {
            let per_spec: Vec<usize> = arms
                .iter()
                .map(|arm| {
                    leads_per_spec
                        .get(&(spec.id(), arm.as_str()))
                        .copied()
                        .unwrap_or(0)
                })
                .collect();
            let lo = per_spec.iter().min().copied().unwrap_or(0);
            let hi = per_spec.iter().max().copied().unwrap_or(0);
            assert!(
                hi - lo <= 1,
                "lead counts for {} are not balanced: {per_spec:?}",
                spec.id()
            );
        }
    }

    #[test]
    fn interleave_is_empty_when_there_is_nothing_to_schedule() {
        let arms = labels(&["head", "v0.22.0"]);
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        assert!(interleave(&arms, &specs, 0).is_empty());
        assert!(interleave(&arms, &[], 3).is_empty());
        assert!(interleave(&[], &specs, 3).is_empty());
    }

    #[test]
    fn spec_ids_separate_runs_that_differ_only_in_arguments() {
        let plain = Spec::new("cloud-hypervisor", "latency");
        let bigger = Spec::new("cloud-hypervisor", "latency").with_args(["--mem-mib", "1024"]);
        assert_eq!(plain.id(), "cloud-hypervisor/latency");
        assert_ne!(plain.id(), bigger.id());
        assert!(bigger.id().contains("--mem-mib"), "{}", bigger.id());
    }
}
