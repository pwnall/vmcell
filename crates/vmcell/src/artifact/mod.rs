//! VM artifact building and pipeline management.
//!
//! This module coordinates the building of artifacts required to boot and run
//! virtual machines, such as the kernel, root filesystem, and snapshots.

#![forbid(unsafe_code)]

use crate::error::Result;
#[cfg(feature = "pipeline")]
/// Reproducible fetch-and-verify manifest for the vmcell-owned artifacts (v15 §10, The artifact build pipeline).
pub mod bundle;
#[cfg(feature = "pipeline")]
/// Guest agent building stage.
pub mod guest_agent;
#[cfg(feature = "pipeline")]
/// Guest test-helper (`vmcell-guest-tools`) building stage.
pub mod guest_tools;
#[cfg(feature = "pipeline")]
/// Kernel building stage.
pub mod kernel;
#[cfg(feature = "pipeline")]
/// Root filesystem building stage.
pub mod rootfs;
#[cfg(feature = "pipeline")]
/// Snapshot building stage.
pub mod snapshot;
/// Tar to EROFS conversion utility.
#[cfg(feature = "am-fs-erofs")]
pub mod tar2erofs;

use std::path::{Path, PathBuf};

/// The VM-artifacts directory: `$VMCELL_ARTIFACTS_DIR`, else
/// `<workspace-root>/target/vmcell-artifacts`. The single source of truth for where built
/// artifacts (kernel, rootfs, CA) live.
///
/// v15: the default is anchored on the **workspace root** (not a CWD-relative
/// `target/vmcell-artifacts`) so it resolves identically whether the caller is the `vmcell`
/// CLI (CWD = workspace root) or an integration-test binary that cargo/nextest run with the
/// CWD set to `crates/vmcell/` — the workspace split changed the latter, which otherwise made
/// the suites fail-loud with "vmlinux artifact missing".
#[must_use]
pub fn artifacts_dir() -> PathBuf {
    resolve_artifacts_dir(std::env::var_os("VMCELL_ARTIFACTS_DIR"), &workspace_root())
}

/// Pure resolver behind [`artifacts_dir`], factored out so the default can be unit-tested
/// without mutating (and racing on) the process environment. The default is anchored on the
/// provided `ws_root`.
fn resolve_artifacts_dir(var: Option<std::ffi::OsString>, ws_root: &Path) -> PathBuf {
    var.map(PathBuf::from)
        .unwrap_or_else(|| ws_root.join("target/vmcell-artifacts"))
}

/// The guest kernel image path: `$VMCELL_KERNEL`, else `<artifacts_dir>/vmlinux`.
#[must_use]
pub fn kernel_path() -> PathBuf {
    std::env::var_os("VMCELL_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| artifacts_dir().join("vmlinux"))
}

/// The rootfs erofs path: `$VMCELL_ROOTFS`, else `<artifacts_dir>/rootfs.erofs`.
#[must_use]
pub fn rootfs_path() -> PathBuf {
    std::env::var_os("VMCELL_ROOTFS")
        .map(PathBuf::from)
        .unwrap_or_else(|| artifacts_dir().join("rootfs.erofs"))
}

/// Ensures the default test VM artifacts (guest-agent, guest-tools, erofs rootfs) are current,
/// building them **at most once per test session**, driven by the same content hashes the build
/// pipeline uses. The integration-test harness calls this from `get_vmlinux`/`get_rootfs`, so a
/// source edit to the guest agent, guest tools, a dep bump, or the rootfs packer transparently
/// re-packs the rootfs instead of the suite silently running against a **stale** image (the cache
/// blind spot that shipped two packer regressions this cycle) or failing loud with "artifact
/// missing".
///
/// The guest KERNEL is deliberately **not** built here: a host-`make` compile takes minutes, far
/// past a per-test timeout, so it is built once out-of-band (`vmcell build --kernel-source
/// host-make`) and this fails loud with that instruction if it is absent. The guest binaries and
/// the erofs rootfs repack in seconds, well within a test's slow-timeout.
///
/// No-ops when `$VMCELL_ROOTFS` is set (the caller — e.g. `vmcell-artifact-validator` validating a
/// custom candidate — manages its own rootfs).
///
/// Coordination (the "at most once" guarantee): a per-process `OnceLock` collapses repeat calls
/// within a process; a cross-process advisory `flock` on `<dir>/.build.lock` serializes concurrent
/// test runs so they never double-write the rootfs; and a `<dir>/.build.stamp` keyed on the input
/// fingerprint lets a warm session skip the pipeline walk (and the 150 MB output re-hash) entirely.
///
/// # Errors
/// Returns [`crate::Error::Artifact`] if the kernel is missing (with the one-command fix) or the
/// build fails, and [`crate::Error::Io`] on a lock/stamp I/O failure.
#[cfg(feature = "pipeline")]
pub fn ensure_test_artifacts() -> crate::error::Result<()> {
    // Process-global write-once memo of the build OUTCOME — this IS the "at most once per session"
    // mechanism: repeat get_vmlinux/get_rootfs calls in a process reuse it (no borrowed state).
    static ENSURED: std::sync::OnceLock<std::result::Result<(), String>> =
        std::sync::OnceLock::new(); // allow-global-state: write-once artifact-build memo; test-support only
    // Cache the OUTCOME per process so the second call (get_rootfs after get_vmlinux, or the next
    // test in a shared-process binary) is free. A failure is cached too — the first missing-kernel
    // panic is the same on every subsequent call, without re-running the probe.
    ENSURED
        .get_or_init(ensure_test_artifacts_inner)
        .clone()
        .map_err(crate::error::Error::Artifact)
}

/// The uncached body of [`ensure_test_artifacts`]. Returns a raw message on error (not an [`Error`])
/// so `OnceLock` can memoize it — the `Error` type is not `Clone` — and so the public wrapper adds
/// exactly one `Artifact error:` prefix rather than nesting one.
#[cfg(feature = "pipeline")]
fn ensure_test_artifacts_inner() -> std::result::Result<(), String> {
    // A caller-supplied rootfs is externally managed — never auto-build over it.
    if std::env::var_os("VMCELL_ROOTFS").is_some() {
        return Ok(());
    }

    // The kernel is built out-of-band (slow, rarely changes); require it, do not build it here.
    let kernel = kernel_path();
    if !kernel.exists() {
        return Err(format!(
            "guest kernel missing at {}. Build it once (slow, rarely changes): \
             `cargo run -p vmcell-cli --bin vmcell -- build --kernel-source host-make`",
            kernel.display()
        ));
    }

    let dir = artifacts_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // Cross-process exclusive lock: two concurrent `just test-*` runs must not double-write the
    // rootfs. Held until this function returns (the fresh-path releases it in microseconds).
    let _lock = BuildLock::acquire(&dir.join(".build.lock")).map_err(|e| e.to_string())?;

    // Cheap freshness stamp over EVERY input the fast stages consume (hashes ~10 MB of source, not
    // the 150 MB outputs). A warm session matches on the first try and skips the pipeline entirely.
    let fingerprint = fast_artifacts_fingerprint(&dir).map_err(|e| e.to_string())?;
    let stamp_path = dir.join(".build.stamp");
    let stamp = std::fs::read_to_string(&stamp_path).ok();
    if artifacts_stamp_fresh(stamp.as_deref(), &fingerprint, rootfs_path().exists()) {
        return Ok(());
    }

    // The fingerprint moved, so an input changed. A PACKER edit is invisible to the rootfs stage's
    // own `cache_key` (it folds the agent/tools BINARIES + CA, not the packing logic), so invalidate
    // its sidecar to force a re-pack; agent/tools SOURCE edits already flip their own stage keys.
    let rootfs_sidecar = dir.join("rootfs.cache_key");
    match std::fs::remove_file(&rootfs_sidecar) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }

    build_fast_pipeline(&dir).map_err(|e| e.to_string())?;

    std::fs::write(&stamp_path, &fingerprint).map_err(|e| e.to_string())?;
    Ok(())
}

/// The at-most-once skip decision: the built artifacts are fresh — and the pipeline may be skipped
/// — iff the rootfs output EXISTS **and** the recorded stamp equals the current input fingerprint.
/// Pure, so the "only skip when nothing changed AND the output is present" contract is unit-testable
/// KVM-free (dropping the `rootfs_exists` guard would leave a deleted rootfs never rebuilt).
#[cfg(feature = "pipeline")]
fn artifacts_stamp_fresh(stamp: Option<&str>, fingerprint: &str, rootfs_exists: bool) -> bool {
    rootfs_exists && stamp == Some(fingerprint)
}

/// The fingerprint of everything the fast (non-kernel) stages consume: the guest-agent and
/// guest-tools SOURCE closures (which already fold `Cargo.lock`, so a dep bump like the reqwest one
/// invalidates it), the resolved pins, the baked proxy CA, and the rootfs packer source. Any change
/// here re-packs the rootfs. Reuses the pipeline's own closure/file hashers ("use our hashing").
#[cfg(feature = "pipeline")]
fn fast_artifacts_fingerprint(_dir: &Path) -> crate::error::Result<String> {
    fast_artifacts_fingerprint_with(pins_overlay_path().as_deref())
}

/// The body of [`fast_artifacts_fingerprint`] with the pins overlay passed in rather than read from
/// the process environment — the [`resolve_artifacts_dir`] precedent, so the "an overlay edit must
/// move this fingerprint" contract is unit-testable with no `std::env` mutation and therefore no
/// cross-test env-var race.
#[cfg(feature = "pipeline")]
fn fast_artifacts_fingerprint_with(overlay_file: Option<&Path>) -> crate::error::Result<String> {
    let ws = workspace_root();
    let mut h = blake3::Hasher::new();
    // v1 → v2 with the pins overlay (§18 delta 1): the pins half of this fold changed shape, so
    // every existing `.build.stamp` must invalidate rather than read as fresh under the new rules.
    h.update(b"vmcell-test-artifacts-fingerprint-v2\0");
    h.update(guest_agent_closure_hash(&ws)?.as_bytes());
    h.update(b"\0");
    h.update(guest_tools_closure_hash(&ws)?.as_bytes());
    h.update(b"\0");
    // The one pins fold (embedded baseline + the `$VMCELL_PINS` overlay), shared with
    // `ResolvePinsStage::cache_key` (§10.2, The stage model and the five cache-key rules). Without
    // the overlay here an overlay edit leaves this stamp matching, `ensure_test_artifacts`
    // short-circuits the whole pipeline, and `$VMCELL_PINS` is silently ignored in a warm workspace
    // — the accept-then-ignore class the overlay exists to kill. Unlike the cache key, this fold
    // may fail: a referenced-but-unreadable overlay is a hard error naming the path.
    fold_pins_identity(&mut h, overlay_file)?;
    h.update(b"\0");
    #[cfg(feature = "proxy")]
    {
        let ca = crate::proxy::tls::CaManager::new()?;
        h.update(ca.ca_cert_pem().as_bytes());
    }
    h.update(b"\0");
    // Rootfs PACKER source — NOT folded by the rootfs `cache_key`, so hash it here so a packer edit
    // re-packs (the blind spot behind this cycle's exec-bit + trust-store regressions). A read
    // failure folds a distinct marker so the stale hash can never masquerade as unchanged.
    for rel in [
        "crates/vmcell/src/artifact/tar2erofs.rs",
        "crates/vmcell/src/artifact/rootfs/mod.rs",
        "crates/vmcell/src/artifact/rootfs/oci.rs",
    ] {
        match hash_file(&ws.join(rel)) {
            Ok(fh) => h.update(fh.as_bytes()),
            Err(_) => h.update(format!("missing-packer-src:{rel}\0").as_bytes()),
        };
    }
    Ok(h.finalize().to_hex().to_string())
}

/// Runs the kernel-less build pipeline (ResolvePins → guest-agent → guest-tools → rootfs) once,
/// hash-gated. The OCI rootfs stage does not consume the kernel (ART-9), so omitting the slow
/// kernel stage is sound. Executed on a fresh current-thread runtime in a dedicated OS thread: this
/// fn is called from the SYNC harness while the test's own tokio runtime is active, and a direct
/// `block_on` inside a runtime panics — a separate thread has no ambient runtime.
#[cfg(feature = "pipeline")]
fn build_fast_pipeline(dir: &Path) -> crate::error::Result<()> {
    let dir = dir.to_path_buf();
    // The pins baseline is embedded (`COMMITTED_PINS`), so this bootstrap no longer hunts the
    // workspace for `pins.json`; only the optional `$VMCELL_PINS` overlay is a path (§10.2).
    let overlay_file = pins_overlay_path();
    let joined = std::thread::scope(|s| {
        s.spawn(move || -> crate::error::Result<()> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(crate::error::Error::Io)?;
            rt.block_on(async move {
                Pipeline::new(dir.clone())
                    .add_stage(Box::new(ResolvePinsStage { overlay_file }))
                    .add_stage(Box::new(crate::artifact::guest_agent::GuestAgentStage {}))
                    .add_stage(Box::new(crate::artifact::guest_tools::GuestToolsStage {}))
                    .add_stage(Box::new(crate::artifact::rootfs::RootfsStage {
                        image_override: None,
                        agent_musl: None,
                        extra: Vec::new(),
                    }))
                    .build(&Cache::default())
                    .await
                    .map(|_| ())
            })
        })
        .join()
    });
    match joined {
        Ok(inner) => inner,
        Err(_) => Err(crate::error::Error::Artifact(
            "artifact build thread panicked".into(),
        )),
    }
}

/// An advisory `flock(LOCK_EX)` held for the lifetime of the value (nix's safe RAII `Flock`, which
/// unlocks on drop — so this module keeps its `#![forbid(unsafe_code)]`). Serializes
/// [`ensure_test_artifacts`] across concurrent test processes so they never race on the rootfs.
#[cfg(feature = "pipeline")]
struct BuildLock(
    #[expect(dead_code, reason = "held only for its Drop, which releases the flock")]
    nix::fcntl::Flock<std::fs::File>,
);

#[cfg(feature = "pipeline")]
impl BuildLock {
    fn acquire(path: &Path) -> crate::error::Result<Self> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(crate::error::Error::Io)?;
        let locked = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, e)| crate::error::Error::Io(std::io::Error::from(e)))?;
        Ok(Self(locked))
    }
}

/// The cloud-hypervisor binary path: `$VMCELL_CH_BIN`, else bare `cloud-hypervisor`
/// (resolved on `PATH`).
///
/// The single source of truth for the CH binary so every stage that boots a VM
/// (the snapshot stage and the mmdebstrap builder stage) reads the **same** env var.
/// Previously the snapshot stage read `CLOUD_HYPERVISOR_PATH` while the builder read
/// `VMCELL_CH_BIN`, so overriding one left the other on the default — the kind of
/// per-call-site drift §10.1 (Artifacts produced) consolidation and the `VMCELL_*` namespacing of §9.7-C (Features and build shapes)
/// exist to prevent.
///
/// Public so out-of-crate artifact builders (`vmcell-rootfs-builder`,
/// `vmcell-kernel-builder`) that boot a builder VM resolve the CH binary the same
/// way — one resolver, no per-call-site drift.
#[cfg(feature = "pipeline")]
pub fn ch_binary_path() -> String {
    std::env::var("VMCELL_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())
}

/// Inputs for an artifact building stage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StageInputs {
    /// Artifacts generated by previous stages.
    pub artifacts: std::collections::HashMap<String, PathBuf>,
    /// Resolved string values (e.g. from pins.json) to pass down.
    pub pins: std::collections::HashMap<String, String>,
}

/// Outputs from an artifact building stage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StageOutputs {
    /// Artifacts generated by this stage.
    pub artifacts: std::collections::HashMap<String, PathBuf>,
    /// Resolved string values (e.g. from pins.json) to pass down.
    pub pins: std::collections::HashMap<String, String>,
}

/// A cache key that uniquely identifies the inputs to a stage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheKey(pub String);

impl CacheKey {
    /// Wraps a precomputed cache-key string.
    ///
    /// Out-of-crate [`Stage`] implementations must use this constructor: the type
    /// is `#[non_exhaustive]`, so the tuple cannot be built directly from another
    /// crate.
    #[must_use]
    pub fn new(key: String) -> Self {
        Self(key)
    }
}

use async_trait::async_trait;

#[async_trait]
/// A building block of the artifact pipeline.
pub trait Stage: Send + Sync {
    /// The name of this stage.
    fn name(&self) -> &str;
    /// Computes a cache key based on the stage configuration and inputs.
    fn cache_key(&self, inputs: &StageInputs) -> CacheKey;
    /// Returns the target path for the artifact.
    fn out_path(&self, target_dir: &Path) -> PathBuf;
    /// Executes the stage, building the output artifact at the given path.
    ///
    /// # Errors
    /// Returns an error if the build fails.
    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs>;
}

/// Cache for previously built artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cache {}
/// Artifacts resulting from a pipeline build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Artifacts {
    /// A mapping from artifact name to its location on disk.
    pub paths: std::collections::HashMap<String, PathBuf>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CacheMetadata {
    key: String,
    hash: String,
    pins: std::collections::HashMap<String, String>,
    #[serde(default)]
    artifacts: std::collections::HashMap<String, PathBuf>,
}

/// Streams `path` through blake3 and returns its lowercase-hex content hash.
///
/// Public so out-of-crate artifact builders fold upstream/injected content into their
/// own cache keys with the *same* hasher `vmcell`'s stages use (blake3, never
/// `DefaultHasher`) — content that travels, not a `target/`-relative path string.
///
/// # Errors
/// Returns [`crate::error::Error::Io`] if `path` cannot be opened or read.
pub fn hash_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(crate::error::Error::Io)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf).map_err(crate::error::Error::Io)?;
        if n == 0 {
            break;
        }
        // `n <= buf.len()` always (read never returns more than the buffer), so `get(..n)` is
        // `Some`; the `if let` avoids both a panic (no `# Panics`) and an index-slice.
        if let Some(chunk) = buf.get(..n) {
            hasher.update(chunk);
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Content hash of a stage output, whether it is a single **file** or a **directory**.
///
/// A file hashes to exactly [`hash_file`] (so existing file sidecars stay valid). A
/// directory (e.g. the `SnapshotStage` output — ART-1) hashes over the root directory's
/// own mode plus a deterministic, sorted recursive walk — relative name + type + (files)
/// mode + content, (symlinks) target — so the whole tree is content-addressed and a
/// byte-corrupted file inside it (or a `chmod` on the root itself) is rejected on the
/// cache-hit path exactly like a tampered single-file artifact. Using
/// `hash_file` on a directory `File::open`s it and reads → `EISDIR`, which silently
/// defeated caching *and* tamper-verification for every directory output.
///
/// Public so out-of-crate artifact builders content-address a directory or file output
/// with the same walk `vmcell`'s stages use.
///
/// # Errors
/// Returns [`crate::error::Error::Io`] if `path` (or any entry under it) cannot be read.
pub fn hash_output(path: &Path) -> Result<String> {
    let meta = std::fs::symlink_metadata(path).map_err(crate::error::Error::Io)?;
    if meta.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vmcell-dir-v1\0");
        // Fold the ROOT directory's own mode (L-ART-5): a chmod on the snapshot root
        // must change the hash, exactly like a chmod on any subdirectory inside the
        // tree (`hash_dir_into` folds per-entry modes but not the top-level dir's).
        hasher.update(b"m");
        hasher.update(&meta.permissions().mode().to_le_bytes());
        hash_dir_into(&mut hasher, path)?;
        Ok(hasher.finalize().to_hex().to_string())
    } else {
        hash_file(path)
    }
}

/// Folds a directory's contents into `hasher` over a deterministic sorted walk, so the
/// hash is stable regardless of the filesystem's `read_dir` ordering.
fn hash_dir_into(hasher: &mut blake3::Hasher, dir: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)
        .map_err(crate::error::Error::Io)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(crate::error::Error::Io)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let file_type = entry.file_type().map_err(crate::error::Error::Io)?;
        let path = entry.path();
        // `OsStr::as_bytes` preserves non-UTF-8 names (L-ART-5): `to_string_lossy` collapses
        // distinct non-UTF-8 names to U+FFFD, so two different filenames could hash the same.
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        if file_type.is_dir() {
            hasher.update(b"d");
            // Fold the directory's own mode (L-ART-5) so a chmod on a directory inside the
            // tree changes the hash (previously only file modes were folded).
            let meta = entry.metadata().map_err(crate::error::Error::Io)?;
            hasher.update(&meta.permissions().mode().to_le_bytes());
            hash_dir_into(hasher, &path)?;
        } else if file_type.is_symlink() {
            hasher.update(b"l");
            let target = std::fs::read_link(&path).map_err(crate::error::Error::Io)?;
            // Preserve a non-UTF-8 symlink target too (L-ART-5).
            hasher.update(target.as_os_str().as_bytes());
        } else {
            hasher.update(b"f");
            let meta = entry.metadata().map_err(crate::error::Error::Io)?;
            hasher.update(&meta.permissions().mode().to_le_bytes());
            hasher.update(hash_file(&path)?.as_bytes());
        }
        hasher.update(b"\x1e");
    }
    Ok(())
}

/// Removes `path` if it exists, returning `Ok(())` when it is already absent and
/// propagating every other I/O error (e.g. permission denied).
///
/// Handles both a **file** (`remove_file`) and a **directory** (`remove_dir_all`) — the
/// snapshot stage's output is a directory (ART-1/ART-2), so a `remove_file`-only path
/// returned `EISDIR` and made `reset_to(<stage at/before snapshot>)` fail once the
/// snapshot dir existed, defeating invalidation. A symlink is removed as a link, never
/// followed into its target's tree.
///
/// Used by [`Pipeline::reset_to`] so a failed invalidation is loud, never a silent `Ok`
/// that leaves a stale cached artifact behind.
///
/// # Errors
/// Returns [`crate::error::Error::Io`] if the path exists but cannot be removed.
fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path).map_err(crate::error::Error::Io),
        Ok(_) => std::fs::remove_file(path).map_err(crate::error::Error::Io),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(crate::error::Error::Io(e)),
    }
}

/// Folds the upstream `artifacts` into `hasher` in a deterministic, key-sorted order,
/// hashing each artifact's on-disk **content** (the identity that travels) rather than its
/// absolute path under `target_dir`. An artifact not yet materialized on disk folds a
/// stable `<unmaterialized>` marker (never its absolute path).
///
/// Iterating the raw `HashMap` would feed blake3 in a process-random order (spurious cache
/// misses) and would key on `target_dir`-relative path strings (a rebuilt upstream at the
/// same path would not invalidate the key). Sorting + content-hashing fixes both.
///
/// Public so out-of-crate artifact builders fold the same consumed-artifact set into
/// their own cache keys deterministically (`vmcell-rootfs-builder` folds the seed
/// kernel + injected agent/tools this way).
#[cfg(feature = "pipeline")]
pub fn hash_artifacts_sorted(
    hasher: &mut blake3::Hasher,
    artifacts: &std::collections::HashMap<String, PathBuf>,
) {
    let sorted: std::collections::BTreeMap<&String, &PathBuf> = artifacts.iter().collect();
    for (k, v) in sorted {
        hasher.update(k.as_bytes());
        // `hash_output` (not `hash_file`) so a DIRECTORY artifact (e.g. the snapshot-stage
        // output) is content-hashed over its recursive walk (M-ART-6). `hash_file` on a
        // directory `File::open`s it and reads -> `EISDIR`, indistinguishable from the
        // genuine-miss `NotFound` arm below — so a content change to a file INSIDE a
        // directory artifact would not invalidate a downstream key.
        match hash_output(v) {
            Ok(content_hash) => {
                hasher.update(b"c:");
                hasher.update(content_hash.as_bytes());
            }
            Err(_) => {
                // The artifact is not materialized on disk yet. Fold a STABLE marker —
                // never the absolute `PathBuf` under `target/`, a non-traveling identity
                // (B4/ART-8): keying on the absolute path makes the cache key vary by where
                // `target/` lives and lets a rebuilt upstream at the same path go unnoticed.
                // The resulting cache miss re-runs the stage, whose `run()` then fails loud
                // on the genuinely-missing input.
                hasher.update(b"u:<unmaterialized>");
            }
        }
    }
}

/// vmcell's own committed `pins.json`, embedded at compile time — the **baseline** every pins
/// resolution starts from (§10.2, The stage model and the five cache-key rules).
///
/// Embedded rather than read from disk so a git-dep consumer workspace needs no fragile filesystem
/// hunt for the vmcell checkout; inside the vmcell workspace the embedded copy and the on-disk file
/// are the same committed bytes by construction, and `include_str!` registers a rebuild dependency
/// so editing `pins.json` recompiles this crate and moves every derived cache key with it. This is
/// the **one** baseline source: keeping a caller-supplied `pins_file` path alongside it would be two
/// sources of truth with no stated precedence (§18 delta 1 retired that field).
///
/// Reaching outside the crate directory is safe here because `vmcell` is `publish = false` and a
/// git-dep consumer checks out the whole repository; it would break `cargo package`/`cargo vendor`
/// of this crate directory alone.
const COMMITTED_PINS: &str = include_str!("../../../../pins.json");

/// Unambiguous field separator for the pins folds, so distinct (baseline, overlay, …) splits
/// cannot concatenate to the same byte stream (non-injective-hash defense).
const PINS_FOLD_SEP: &[u8] = b"\x1f";

/// Folds the **pins identity** — the embedded baseline plus the optional overlay — into `h`.
///
/// The one fold law for pins (AGENTS.md "one law, one predicate"): [`ResolvePinsStage::cache_key`]
/// and [`fast_artifacts_fingerprint`] both route through it, so an overlay edit cannot move one and
/// leave the other stale. Without it in the *fingerprint*, `ensure_test_artifacts` short-circuits on
/// a matching `.build.stamp` and `$VMCELL_PINS` is silently ignored in a warm workspace.
///
/// The three overlay states fold under mutually exclusive prefixes — absent, content, unreadable —
/// so an empty overlay file can never alias "no overlay" and a read error can never alias either
/// (`unwrap_or_default()` collapses all three, ART-11). The read happens before any content prefix
/// is folded, so an error leaves a well-defined prefix for the caller to complete.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] naming the overlay path when it cannot be read.
fn fold_pins_identity(h: &mut blake3::Hasher, overlay_file: Option<&Path>) -> Result<()> {
    // The baseline is a compile-time constant, so folding it is not a no-op: editing `pins.json`
    // recompiles this crate (the `include_str!` rebuild dependency) and these bytes move with it.
    h.update(COMMITTED_PINS.as_bytes());
    h.update(PINS_FOLD_SEP);
    match overlay_file {
        None => {
            h.update(b"pins-overlay-absent");
        }
        Some(path) => {
            let content = read_pins_overlay(path)?;
            h.update(b"pins-overlay-content");
            h.update(PINS_FOLD_SEP);
            h.update(content.as_bytes());
        }
    }
    Ok(())
}

/// The pins **overlay** path from the environment: `$VMCELL_PINS`, else `None`.
///
/// The single resolver for the `VMCELL_PINS` half of the `VMCELL_*` env contract (§10.4, The
/// downstream toolkit contract), so the CLI, the workspace test bootstrap, and the toolkit build
/// entry points all read the same variable. An empty value is *not* treated as unset: it is passed
/// through as a path and fails loud on read, because silently ignoring `VMCELL_PINS=$UNSET_VAR`
/// would be exactly the accept-then-ignore class the overlay exists to kill.
#[must_use]
pub fn pins_overlay_path() -> Option<PathBuf> {
    std::env::var_os("VMCELL_PINS").map(PathBuf::from)
}

/// The known top-level pins namespaces, for the overlay rejection message only.
///
/// **Not** the accept-list: [`flatten_pins_namespace`] is the single authority on what a namespace
/// is (one law, one predicate — an accept-list beside a flatten-list is the duplicate that always
/// diverges). A unit test pins every entry here against that authority.
const KNOWN_PINS_NAMESPACES: [&str; 9] = [
    "kernel",
    "kernel_prebuilt",
    "kernels",
    "kernel_fragments",
    "rootfs",
    "builder_base",
    "cloud_hypervisor",
    "virtiofsd",
    "debian_snapshot_timestamp",
];

/// The JSON shape a top-level pins namespace's value must have.
///
/// Declared by the [`flatten_pins_namespace`] arm that consumes it — never a second table beside the
/// dispatch — so the overlay's shape check and the flattening read the same law. A namespace whose
/// value has the wrong shape flattens to *nothing*, which is why the overlay parser rejects the
/// mismatch instead of accepting a document that resolves to the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinsNamespaceShape {
    /// A JSON object of sub-keys (`kernel`, `kernels`, `kernel_fragments`, `rootfs`, …).
    Object,
    /// A bare JSON string (`cloud_hypervisor`, `virtiofsd`, `debian_snapshot_timestamp`).
    Scalar,
}

impl PinsNamespaceShape {
    /// Whether `value` has this shape.
    fn matches(self, value: &serde_json::Value) -> bool {
        match self {
            Self::Object => value.is_object(),
            Self::Scalar => value.is_string(),
        }
    }

    /// How the shape reads in a rejection message.
    fn describe(self) -> &'static str {
        match self {
            Self::Object => "a JSON object of sub-keys",
            Self::Scalar => "a JSON string",
        }
    }
}

/// Flattens one top-level pins namespace into `out`, returning that namespace's declared **shape**
/// — or `None` when `name` is not a pins namespace at all.
///
/// This one `match` is the pin schema: [`flatten_pins_document`] drives the baseline flattening
/// from it and [`pins_namespace_shape`] answers the overlay parser's two strictness questions (is
/// this a namespace? does its value have that namespace's shape?) with the very same dispatch, so
/// the three can never drift.
///
/// Sub-keys stay permissive by design (§10.2): a typo'd `kernel.source_ur1` is ignored here and is
/// caught downstream by the referenced-but-absent hard errors (`Missing kernel_source_url pin`,
/// `missing kernel fragment ...`). The strictness the overlay adds is scoped to the **top level**,
/// where a typo — in the key *or* in the value's shape — would otherwise silently resolve the whole
/// namespace from the baseline.
fn flatten_pins_namespace(
    name: &str,
    value: &serde_json::Value,
    out: &mut std::collections::HashMap<String, String>,
) -> Option<PinsNamespaceShape> {
    match name {
        "kernel" => {
            if let Some(sha) = value.get("source_sha256").and_then(|v| v.as_str()) {
                out.insert("kernel_source_sha256".to_string(), sha.to_string());
            }
            if let Some(url) = value.get("source_url").and_then(|v| v.as_str()) {
                out.insert("kernel_source_url".to_string(), url.to_string());
            }
            if let Some(cfg) = value.get("microvm_config").and_then(|v| v.as_str()) {
                out.insert("kernel_microvm_config".to_string(), cfg.to_string());
            }
            Some(PinsNamespaceShape::Object)
        }
        // The prebuilt-kernel bootstrap pin (§5.4, The guest-kernel contract and the bootstrap
        // seed): a digest-pinned `vmlinux` the in-`vmcell` `PrebuiltKernelBuilder` downloads and
        // SHA-verifies as the bootstrap seed (the seed the in-VM `vmcell-kernel-builder` boots its
        // builder VM on). Emitted only when present; absent → the prebuilt bootstrap fails loud and
        // host-make is the guaranteed fallback seed.
        "kernel_prebuilt" => {
            if let Some(url) = value.get("url").and_then(|v| v.as_str()) {
                out.insert("kernel_prebuilt_url".to_string(), url.to_string());
            }
            if let Some(sha) = value.get("sha256").and_then(|v| v.as_str()) {
                out.insert("kernel_prebuilt_sha256".to_string(), sha.to_string());
            }
            // Optional archive extraction: many prebuilt `vmlinux` binaries (e.g. the validated
            // Kata Containers kernel, §5.4, The guest-kernel contract and the bootstrap seed) ship
            // *inside* a compressed tar. When `archive_member` is set, the download is a
            // `.tar.zst`/`.tar` archive verified against `archive_sha256`; the named member is
            // extracted and re-verified against `sha256`. Both digests fold into the cache key so
            // re-pointing either invalidates the artifact.
            if let Some(m) = value.get("archive_member").and_then(|v| v.as_str()) {
                out.insert("kernel_prebuilt_archive_member".to_string(), m.to_string());
            }
            if let Some(s) = value.get("archive_sha256").and_then(|v| v.as_str()) {
                out.insert("kernel_prebuilt_archive_sha256".to_string(), s.to_string());
            }
            Some(PinsNamespaceShape::Object)
        }
        // The multi-kernel registry: each `kernels.<label>` → keyed pins
        // (`kernel_<label>_source_url` / `_source_sha256`), so a labelled `KernelStage` can build
        // `vmlinux-<label>` — the kernel-version benchmark dimension. They share the default
        // `kernel`'s `microvm_config`. New labels within the namespace are legal in an overlay.
        "kernels" => {
            if let Some(kernels) = value.as_object() {
                for (label, spec) in kernels {
                    if let Some(url) = spec.get("source_url").and_then(|v| v.as_str()) {
                        out.insert(format!("kernel_{label}_source_url"), url.to_string());
                    }
                    if let Some(sha) = spec.get("source_sha256").and_then(|v| v.as_str()) {
                        out.insert(format!("kernel_{label}_source_sha256"), sha.to_string());
                    }
                }
            }
            Some(PinsNamespaceShape::Object)
        }
        // The kernel config-fragment registry (§5.2, The config fragment): each
        // `kernel_fragments.<NAME>` → a `kernel_fragments_<NAME>` pin holding that fragment's
        // KConfig text, which a `KernelStage` with `fragments = [NAME, ...]` layers onto the base
        // config (content-addressed, so editing a fragment's text invalidates the cache).
        "kernel_fragments" => {
            if let Some(fragments) = value.as_object() {
                for (fragment, cfg) in fragments {
                    if let Some(text) = cfg.as_str() {
                        out.insert(format!("kernel_fragments_{fragment}"), text.to_string());
                    }
                }
            }
            Some(PinsNamespaceShape::Object)
        }
        "rootfs" => {
            if let Some(img) = value.get("image").and_then(|v| v.as_str()) {
                out.insert("rootfs_image".to_string(), img.to_string());
            }
            if let Some(dig) = value.get("digest").and_then(|v| v.as_str()) {
                out.insert("rootfs_digest".to_string(), dig.to_string());
            }
            Some(PinsNamespaceShape::Object)
        }
        // The builder-base override pair `resolve_builder_base` prefers over `rootfs_*`
        // (`artifact::rootfs::resolve_builder_base`). It was consumed but had no producer, so a
        // legitimate downstream override of the in-VM builder base had no way in and — worse — the
        // overlay's strict parser would have rejected the key. Both halves or neither: the
        // half-specified case is `resolve_builder_base`'s existing hard error.
        "builder_base" => {
            if let Some(img) = value.get("image").and_then(|v| v.as_str()) {
                out.insert("builder_base_image".to_string(), img.to_string());
            }
            if let Some(dig) = value.get("digest").and_then(|v| v.as_str()) {
                out.insert("builder_base_digest".to_string(), dig.to_string());
            }
            Some(PinsNamespaceShape::Object)
        }
        // The CH/virtiofsd build identity for the snapshot pool (§10.2, The stage model and the
        // five cache-key rules / M-ART-7): a snapshot is only valid for the exact CH build that
        // produced it, so the snapshot stage folds the `cloud_hypervisor` pin into its cache key.
        "cloud_hypervisor" | "virtiofsd" => {
            if let Some(v) = value.as_str() {
                out.insert(name.to_string(), v.to_string());
            }
            Some(PinsNamespaceShape::Scalar)
        }
        // The snapshot.debian.org timestamp the mmdebstrap source requires.
        "debian_snapshot_timestamp" => {
            if let Some(ts) = value.as_str() {
                out.insert("debian_snapshot_timestamp".to_string(), ts.to_string());
            }
            Some(PinsNamespaceShape::Scalar)
        }
        _ => None,
    }
}

/// The declared shape of the pins namespace `name`, or `None` when it is not a namespace.
///
/// Answered by running [`flatten_pins_namespace`]'s own dispatch against a JSON `null` (which
/// matches no leaf probe, so nothing is emitted and the discard map stays empty): the overlay's
/// accept-list and its shape table **are** the flatten dispatch, never a second copy of it.
fn pins_namespace_shape(name: &str) -> Option<PinsNamespaceShape> {
    let mut discard = std::collections::HashMap::new();
    flatten_pins_namespace(name, &serde_json::Value::Null, &mut discard)
}

/// Flattens a whole pins document into the flat map every stage reads.
///
/// The **baseline** keeps its ignore-unknown semantics on purpose (§10.2): `pins.json` is
/// vmcell-committed, not caller input. Only the overlay is strict — see [`parse_pins_overlay`].
fn flatten_pins_document(json: &serde_json::Value) -> std::collections::HashMap<String, String> {
    let mut pins_map = std::collections::HashMap::new();
    if let Some(obj) = json.as_object() {
        for (name, value) in obj {
            // The shape answer is deliberately discarded here: an unrecognized top-level key in
            // the committed baseline is ignored, exactly as before the overlay landed.
            let _shape = flatten_pins_namespace(name, value, &mut pins_map);
        }
    }
    // `rootfs.debian_snapshot_timestamp` is the historical nesting; the top-level pin (emitted by
    // the namespace dispatch above) wins when both are present.
    if !pins_map.contains_key("debian_snapshot_timestamp")
        && let Some(ts) = json
            .get("rootfs")
            .and_then(|r| r.get("debian_snapshot_timestamp"))
            .and_then(|v| v.as_str())
    {
        pins_map.insert("debian_snapshot_timestamp".to_string(), ts.to_string());
    }
    pins_map
}

/// Reads a pins overlay file, failing loud with the path on any I/O error.
///
/// A referenced-but-absent overlay is never a skipped fold: `$VMCELL_PINS` pointing at nothing is
/// a configuration error, not "no overlay".
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] naming `path` when it cannot be read.
fn read_pins_overlay(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        crate::error::Error::Artifact(format!(
            "failed to read pins overlay {}: {e}",
            path.display()
        ))
    })
}

/// Parses a pins **overlay** document — strictly (§10.2, The stage model and the five cache-key
/// rules).
///
/// Stricter than the baseline's [`flatten_pins_document`] at exactly one level — the top one, where
/// both the key **and** the value's shape must match the pin schema ([`pins_namespace_shape`]).
/// Reference-time errors cannot catch a typo'd *override*: `{"kerne1": …}` would simply resolve the
/// whole `kernel` namespace from the baseline and build the wrong kernel with a green log, and
/// `{"cloud_hypervisor": {"version": "46.0"}}` — the natural shape to guess, since most namespaces
/// *are* objects — would flatten to nothing and drop the CH build identity out of the snapshot cache
/// key (the M-ART-7 stale-snapshot hazard the pin exists to prevent; unlike `kernel.*`, that pin has
/// no referenced-but-absent backstop, `artifact/snapshot.rs` folds it with `unwrap_or_default`). Both
/// are rejected here, naming the key.
///
/// Sub-key strictness stays out of scope (§10.2): those typos are caught by the referenced-but-absent
/// hard errors.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] for malformed JSON, a non-object document, a top-level
/// key matching no known pins namespace, or a top-level value whose shape is not the one that
/// namespace declares.
fn parse_pins_overlay(content: &str, source: &Path) -> Result<serde_json::Value> {
    let json = serde_json::from_str::<serde_json::Value>(content).map_err(|e| {
        crate::error::Error::Artifact(format!(
            "malformed pins overlay JSON at {}: {e}",
            source.display()
        ))
    })?;
    let obj = json.as_object().ok_or_else(|| {
        crate::error::Error::Artifact(format!(
            "pins overlay {} must be a JSON object of pin namespaces",
            source.display()
        ))
    })?;
    for (name, value) in obj {
        let Some(shape) = pins_namespace_shape(name) else {
            return Err(crate::error::Error::Artifact(format!(
                "unknown pins overlay key `{name}` in {} (known namespaces: {}); \
                 a misspelled override would otherwise silently resolve from the committed \
                 baseline (§10.2)",
                source.display(),
                KNOWN_PINS_NAMESPACES.join(", ")
            )));
        };
        if !shape.matches(value) {
            return Err(crate::error::Error::Artifact(format!(
                "pins overlay key `{name}` in {} must be {}; a wrong-shaped override contributes \
                 no pins and would silently resolve from the committed baseline (§10.2)",
                source.display(),
                shape.describe()
            )));
        }
    }
    Ok(json)
}

/// Merges `overlay` over `baseline` **leaf-wise**, in place.
///
/// An overlay object merges into a baseline object key by key; any other overlay value replaces the
/// baseline value outright — which is what makes a leaf override work. This is exactly §10.2's "a
/// flattened key present in the overlay wins": every pin key is a leaf of the namespace tree, so
/// merging leaf-wise and flattening once is identical to flattening both documents and merging the
/// flat maps. An overlay setting only `kernel.source_url` therefore keeps the baseline's
/// `kernel.microvm_config`, which a document-level namespace replacement would drop.
///
/// What this function does **not** do is police shapes: the replace-outright arm applied to a
/// *namespace* (an overlay handing the scalar `"https://…"` to the object namespace `kernel`) is a
/// whole-namespace replacement that would wipe the baseline's siblings. That is unreachable from an
/// overlay file because [`parse_pins_overlay`]'s shape check rejects it before the merge runs — one
/// law, at the parse boundary, not a second copy here. Below the top level shapes stay unpoliced by
/// design (§10.2): a `kernel.microvm_config` given an object replaces the baseline's string, the
/// flatten then emits no pin, and the referenced-but-absent hard error names it.
fn merge_pins_documents(baseline: &mut serde_json::Value, overlay: &serde_json::Value) {
    match (baseline.as_object_mut(), overlay.as_object()) {
        (Some(base_obj), Some(overlay_obj)) => {
            for (key, value) in overlay_obj {
                match base_obj.get_mut(key) {
                    Some(existing) => merge_pins_documents(existing, value),
                    None => {
                        base_obj.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        _ => *baseline = overlay.clone(),
    }
}

/// Resolves the pins **document**: the committed baseline with `overlay_file` merged over it.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if the embedded baseline is malformed (a build-time
/// impossibility, checked anyway rather than swallowed), or if the overlay cannot be read or fails
/// the strict parse.
fn resolve_pins_document(overlay_file: Option<&Path>) -> Result<serde_json::Value> {
    let mut doc = serde_json::from_str::<serde_json::Value>(COMMITTED_PINS).map_err(|e| {
        crate::error::Error::Artifact(format!("malformed committed pins.json: {e}"))
    })?;
    if let Some(path) = overlay_file {
        let overlay = parse_pins_overlay(&read_pins_overlay(path)?, path)?;
        merge_pins_documents(&mut doc, &overlay);
    }
    Ok(doc)
}

/// Resolves the flat pin map a downstream consumer builds against: vmcell's committed baseline with
/// the optional overlay merged over it (§10.2 / §10.4 — contract surface).
///
/// This is the pipeline's own resolution, minus the `guest_agent_src_hash` entry that
/// [`ResolvePinsStage`] adds from the workspace source closure (which no consumer workspace has).
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if the overlay cannot be read, is not JSON, is not a
/// JSON object, carries a top-level key matching no known pins namespace, or gives a known
/// namespace a value of the wrong shape.
pub fn resolve_pins(
    overlay_file: Option<&Path>,
) -> Result<std::collections::HashMap<String, String>> {
    Ok(flatten_pins_document(&resolve_pins_document(overlay_file)?))
}

/// One entry of the merged `kernels` registry: a build label and the KConfig fragment set that
/// label declares (§5.5, Kernel as a benchmark dimension).
///
/// The label alone fully determines the build — that is the point of the `fragments` key: before
/// v30 a fragment set was reachable only by constructing a [`kernel::KernelStage`] programmatically,
/// so `vmcell build-kernels` could never build one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KernelRegistryEntry {
    /// The registry label, e.g. `"6.12.94"` — the `kernels.<label>` key and the `vmlinux-<label>`
    /// artifact name.
    pub label: String,
    /// The KConfig fragment names this label declares, in the order written. Empty when the entry
    /// carries no `fragments` key (today's committed entries), which is exactly today's behavior.
    /// Each name resolves to `kernel_fragments_<NAME>` in the pins registry.
    pub fragments: Vec<String>,
}

/// The merged `kernels` registry in **sorted label order** — the set, and the per-label fragment
/// sets, that `vmcell build-kernels` builds.
///
/// Resolved through the same baseline+overlay merge as the pipeline stage, so a downstream-added
/// `kernels.<label>` is buildable by the exact CLI command the toolkit contract advertises. A
/// second, overlay-blind enumeration beside the stage would leave that label resolvable but
/// unbuildable.
///
/// The order is **byte-lexicographic on the label** and pinned by a unit test rather than inherited
/// from `serde_json`'s `BTreeMap` backing (§5.5): a transitive dependency enabling `preserve_order`
/// would otherwise silently switch the build order to document order. Byte order is not version
/// order — `6.12.94` builds before `6.6.143` — which is deliberate: the labels are opaque strings,
/// and inventing a version collation would be a second, guessing law.
///
/// # Errors
/// As [`resolve_pins`], plus [`crate::error::Error::Artifact`] when a `kernels.<label>` entry's
/// `fragments` key is not an array of non-empty strings (a malformed override is named, never
/// silently ignored).
pub fn resolve_kernel_registry(overlay_file: Option<&Path>) -> Result<Vec<KernelRegistryEntry>> {
    let doc = resolve_pins_document(overlay_file)?;
    let Some(kernels) = doc.get("kernels").and_then(|k| k.as_object()) else {
        return Ok(Vec::new());
    };
    let entries: Vec<KernelRegistryEntry> = kernels
        .iter()
        .map(|(label, spec)| {
            Ok(KernelRegistryEntry {
                label: label.clone(),
                fragments: kernel_entry_fragments(label, spec)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(sort_kernel_registry(entries))
}

/// Puts a kernel registry into the pinned **build order**: byte-lexicographic on the label (§5.5).
///
/// Its own function so the ordering law can be exercised on a deliberately unsorted input. Through
/// the public resolver the order is currently *also* what `serde_json`'s default `BTreeMap` map
/// backing produces, so an end-to-end test cannot tell "sorted on purpose" from "sorted by
/// accident" — which is exactly the unpinned-order hazard §5.5 names: a transitive dep enabling
/// `preserve_order` swaps the backing to document order, and then this call is the only thing
/// keeping the promise.
fn sort_kernel_registry(mut entries: Vec<KernelRegistryEntry>) -> Vec<KernelRegistryEntry> {
    entries.sort_by(|a, b| a.label.cmp(&b.label));
    entries
}

/// The fragment names declared by one `kernels.<label>` entry (§5.5).
///
/// The whole strictness of this reader is the point: `fragments` is an *accepted input*, so a
/// wrong-shaped one is rejected naming the label rather than dropped. The surrounding pins schema
/// stays permissive below the top level by design (§10.2), but a silently-ignored `fragments` key
/// would build an *uninstrumented* kernel and report success — the accept-then-ignore class, on the
/// exact key a downstream fragment author writes.
///
/// # Errors
/// [`crate::error::Error::Artifact`] when `fragments` is present but is not an array, holds a
/// non-string element, or holds an empty name.
fn kernel_entry_fragments(label: &str, spec: &serde_json::Value) -> Result<Vec<String>> {
    let Some(value) = spec.get("fragments") else {
        return Ok(Vec::new());
    };
    let array = value.as_array().ok_or_else(|| {
        crate::error::Error::Artifact(format!(
            "pins `kernels.{label}.fragments` must be an array of fragment names \
             (e.g. [\"KASAN\", \"LOCKDEP\"]), each resolving to a `kernel_fragments.<NAME>` entry"
        ))
    })?;
    array
        .iter()
        .map(|item| match item.as_str() {
            Some(name) if !name.is_empty() => Ok(name.to_string()),
            _ => Err(crate::error::Error::Artifact(format!(
                "pins `kernels.{label}.fragments` must hold non-empty fragment NAMES, got {item}"
            ))),
        })
        .collect()
}

/// The labels of the merged `kernels` registry, sorted — the set `vmcell build-kernels` builds.
///
/// The label half of [`resolve_kernel_registry`], which it delegates to so the roster and the
/// per-label fragment sets can never come from two different readers.
///
/// # Errors
/// As [`resolve_kernel_registry`].
pub fn resolve_kernel_labels(overlay_file: Option<&Path>) -> Result<Vec<String>> {
    Ok(resolve_kernel_registry(overlay_file)?
        .into_iter()
        .map(|e| e.label)
        .collect())
}

/// The pins overlay a build entry point uses: an explicit `flag` wins, else `$VMCELL_PINS`
/// ([`pins_overlay_path`]), else none — the committed baseline alone.
///
/// The one flag-beats-env law (§10.4, The downstream toolkit contract), shared by the CLI's
/// pipeline subcommands and the library build entry points, so `VMCELL_PINS` cannot reach one and
/// be ignored by the other.
#[must_use]
pub fn pins_overlay_or_env(flag: Option<&Path>) -> Option<PathBuf> {
    flag.map(Path::to_path_buf).or_else(pins_overlay_path)
}

/// Builds the labelled kernel `label` from the pins `kernels` registry into `target_dir`, returning
/// the path of the built `vmlinux-<label>` (§5.6, The downstream kernel toolkit; §18 delta 3).
///
/// This is the **library** build entry point a git-dep consumer calls from its own harness, the
/// counterpart of `vmcell build-kernels --pins <file>`: it assembles
/// [`ResolvePinsStage`] (baseline + overlay) → [`kernel::KernelStage`] with the label's declared
/// fragments and runs that pipeline. The resolved-config sidecar lands beside the kernel at
/// [`kernel::resolved_config_path`], which is what a fragment author asserts against.
///
/// `overlay_file` follows [`pins_overlay_or_env`] (explicit path, else `$VMCELL_PINS`), so a
/// consumer's `kernel_fragments.<NAME>` + `kernels.<label>` additions need no vmcell-source edit.
///
/// **Producer scope (a recorded deviation from the §18 sketch's `build_labelled_kernel(label,
/// &env)`).** It offers the host-`make` producer only — the one compiling producer `vmcell` can
/// name. The in-VM builder lives in `vmcell-kernel-builder`, which depends on `vmcell`; naming it
/// here would invert that edge and break §9.1's acyclicity, so the in-VM producer stays reachable
/// through the composition root (`vmcell build-kernels --kernel-source in-vm`). With no in-VM
/// producer there is no `CidAllocator` to inject either, so the sketch's `&HostEnv` parameter would
/// carry nothing this function uses and is replaced by the explicit `target_dir` + `overlay_file`.
///
/// **It runs with no vmcell source checkout present**, which is the whole point: it does not ride
/// [`ensure_test_artifacts`] (the vmcell-workspace test bootstrap, whose fingerprint hashes the
/// guest-agent source closure out of the vmcell tree), and the two stages it does assemble read
/// nothing from that tree — [`ResolvePinsStage`] resolves the `guest_agent_src_hash` pin only when
/// a checkout is actually there (`vmcell_source_root`), and [`kernel::KernelStage`] reads only
/// `kernel_*` pins. Landing the entry point without that second half made every downstream call
/// die at stage 0 on a missing `crates/vmcell-guest-agent/src/main.rs`; the
/// `resolve_pins_runs_outside_the_vmcell_source_tree` gate re-execs this crate's test binary from
/// outside the checkout so that cannot return.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] when the overlay cannot be resolved, when `label` is
/// not in the merged `kernels` registry (naming the labels that are), or when the build fails.
#[cfg(feature = "pipeline")]
pub async fn build_labelled_kernel(
    label: &str,
    target_dir: &Path,
    overlay_file: Option<&Path>,
) -> Result<PathBuf> {
    let overlay = pins_overlay_or_env(overlay_file);
    let registry = resolve_kernel_registry(overlay.as_deref())?;
    let entry = registry.iter().find(|e| e.label == label).ok_or_else(|| {
        crate::error::Error::Artifact(format!(
            "unknown kernel label `{label}`: the resolved pins `kernels` registry holds [{}] \
                 (add yours through a pins overlay, §10.2)",
            registry
                .iter()
                .map(|e| e.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    let stage = kernel::KernelStage {
        http_client: std::sync::Arc::new(kernel::ReqwestClient),
        label: Some(entry.label.clone()),
        fragments: Some(entry.fragments.clone()),
    };
    let out_path = Stage::out_path(&stage, target_dir);
    Pipeline::new(target_dir.to_path_buf())
        .add_stage(Box::new(ResolvePinsStage {
            overlay_file: overlay,
        }))
        .add_stage(Box::new(stage))
        .build(&Cache::default())
        .await?;
    Ok(out_path)
}

/// Computes the blake3 hash of the guest-agent source file at `path`.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if the source cannot be read. This is a hard
/// stop on purpose: a missing guest-agent source must not silently degrade to an `"unknown"`
/// pin (which would leave a stale agent baked into every downstream rootfs).
fn guest_agent_src_hash(path: &Path) -> Result<String> {
    let src = std::fs::read_to_string(path).map_err(|e| {
        crate::error::Error::Artifact(format!(
            "failed to read guest-agent source at {}: {}",
            path.display(),
            e
        ))
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(src.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

/// The workspace root — the anchor for the artifacts dir and the guest-agent /
/// guest-tools source closures (v15 §9.1, Workspace layout). Ascends from `CARGO_MANIFEST_DIR` (the
/// `vmcell` crate dir under the workspace) — or, when that is unset, the **absolute**
/// process CWD — to the directory that owns the member crates, so the resolved paths
/// are stable regardless of where the binary runs.
///
/// The CWD fallback uses [`std::env::current_dir`] (absolute) rather than a bare `.`
/// **on purpose**: cargo/nextest run a workspace member's test binaries with the CWD
/// set to that member's dir (`crates/vmcell/`), and a relative `.` has no usable
/// ancestors to ascend, so the artifacts under the workspace `target/` would not be
/// found. The marker is `crates/vmcell-protocol/Cargo.toml`, a stable landmark.
pub(crate) fn workspace_root() -> PathBuf {
    let start = source_search_start();
    // No marker found (e.g. a bare binary run outside the workspace, or a downstream consumer's
    // own workspace) — fall back to the starting dir so callers still get a usable,
    // absolute-when-possible anchor.
    find_vmcell_source_root(&start).unwrap_or(start)
}

/// The directory the vmcell-source-root ascent starts from: `CARGO_MANIFEST_DIR` when set (the
/// crate dir under the workspace), else the **absolute** process CWD. Named once so
/// [`workspace_root`] and [`vmcell_source_root`] cannot start from different places.
fn source_search_start() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The **one** vmcell-source-tree predicate: the ancestor of `start` that owns the member crates
/// (marker `crates/vmcell-protocol/Cargo.toml`), or `None` when there is none.
///
/// Pure (takes its start dir) so the "not in a vmcell checkout" answer is testable without
/// mutating process-global state.
fn find_vmcell_source_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join("crates/vmcell-protocol/Cargo.toml").is_file())
        .map(Path::to_path_buf)
}

/// The vmcell **source** checkout this process is running inside, or `None` when it is not running
/// inside one — a git-dep consumer's own workspace, or an installed `vmcell` binary (§10.4, the
/// downstream toolkit contract).
///
/// [`workspace_root`] answers "where do artifacts and source closures anchor", and must always
/// produce a path; this answers "is vmcell's own source here at all", which downstream is legitimately
/// **no**. Anything that reads vmcell's own sources (the guest-agent / guest-tools closures) asks
/// this one and honors the `None`, instead of asking `workspace_root` and hard-erroring on a
/// fallback directory that never had those sources.
pub(crate) fn vmcell_source_root() -> Option<PathBuf> {
    find_vmcell_source_root(&source_search_start())
}

/// Recursively collects every `*.rs` file under `dir` into `out`.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if `dir` (or a subdirectory) cannot
/// be read — the agent logic must exist, so a missing source tree is a hard stop
/// rather than a silent partial hash.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        crate::error::Error::Artifact(format!(
            "failed to read guest-agent source dir {}: {}",
            dir.display(),
            e
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(crate::error::Error::Io)?;
        let file_type = entry.file_type().map_err(crate::error::Error::Io)?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Hashes the **full source closure** the `vmcell-guest-agent` binary compiles
/// from: every `*.rs` under `crates/vmcell-guest-agent/src/` (the binary entry
/// point plus the reaper library it links — `ReaperCoordinator`,
/// `exit_code_from_termination`) **plus** every `*.rs` under
/// `crates/vmcell-protocol/src/` (the shared wire `protocol` it links) **plus**
/// `Cargo.lock` (the pinned dependency versions). All paths are taken relative to
/// the workspace root and folded in a deterministic, sorted order.
///
/// Hashing only the binary wrapper (the old behavior) left every downstream cache
/// key blind to a change in the agent's real logic: editing the reaper or the
/// post-restore vsock re-bind left the hash unchanged, so all three cache keys
/// (resolve-pins, guest-agent, rootfs) hit and a **stale agent binary was re-baked
/// into `rootfs.erofs`**. The closure must travel as one identity (H-CACHE-1).
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if the binary entry point is missing,
/// either source tree cannot be read, or any closure file cannot be read — a hard
/// stop, never a silent partial or `"unknown"` hash.
pub(crate) fn guest_agent_closure_hash(ws_root: &Path) -> Result<String> {
    // The agent binary entry point is mandatory; its absence is the same hard stop.
    let main_rs = ws_root.join("crates/vmcell-guest-agent/src/main.rs");
    if !main_rs.is_file() {
        return Err(crate::error::Error::Artifact(format!(
            "guest-agent binary source missing at {}",
            main_rs.display()
        )));
    }
    let mut files: Vec<PathBuf> = Vec::new();
    // Every Rust source file the agent binary links: its own crate (main + reaper
    // lib) plus the shared wire-protocol crate.
    collect_rs_files(&ws_root.join("crates/vmcell-guest-agent/src"), &mut files)?;
    collect_rs_files(&ws_root.join("crates/vmcell-protocol/src"), &mut files)?;
    // Cargo.lock pins the dependency versions the agent compiles against; fold it
    // if present (a workspace may build the lock only on demand).
    let lock = ws_root.join("Cargo.lock");
    if lock.is_file() {
        files.push(lock);
    }
    // Deterministic order regardless of `read_dir` order.
    files.sort();

    let mut hasher = blake3::Hasher::new();
    for f in &files {
        // Fold the workspace-relative path (so a rename/move invalidates) with an
        // unambiguous delimiter, then the file's content hash.
        let rel = f.strip_prefix(ws_root).unwrap_or(f.as_path());
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(guest_agent_src_hash(f)?.as_bytes());
        hasher.update(b"\0");
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Hashes the **source closure** the `vmcell-guest-tools` helper binary compiles
/// from: every `*.rs` under `crates/vmcell-guest-tools/src/` **plus** `Cargo.lock`
/// (the pinned dependency versions). Files are taken relative to the workspace
/// root and folded in a deterministic, sorted order with a stable hasher (blake3)
/// — mirroring [`guest_agent_closure_hash`].
///
/// Folding `Cargo.lock` is the whole point: `vmcell-guest-tools` links
/// reqwest/rustls, so a dependency bump changes the **built** helper while the
/// `.rs` source is byte-identical. Hashing only the source (the old behavior) left
/// the cache key unchanged on a bump, so the stage hit cache and a stale
/// `ip`/`curl`/`kvm-ok` helper was re-baked into the rootfs (§10.2, The stage model and the five cache-key rules — caching rules
/// 3-4). The closure must travel as one identity.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if the binary source is missing, or
/// any closure file cannot be read — a hard stop, never a silent partial hash (the
/// old `if let Ok(content)` swallow that quietly produced a content-blind key).
#[cfg(feature = "pipeline")]
pub(crate) fn guest_tools_closure_hash(ws_root: &Path) -> Result<String> {
    // The bin source is mandatory; its absence is a hard stop.
    let main_rs = ws_root.join("crates/vmcell-guest-tools/src/main.rs");
    if !main_rs.is_file() {
        return Err(crate::error::Error::Artifact(format!(
            "guest-tools binary source missing at {}",
            main_rs.display()
        )));
    }
    let mut files: Vec<PathBuf> = Vec::new();
    collect_rs_files(&ws_root.join("crates/vmcell-guest-tools/src"), &mut files)?;
    // Cargo.lock pins the dependency versions the helper compiles against; fold it
    // if present (a workspace may build the lock only on demand).
    let lock = ws_root.join("Cargo.lock");
    if lock.is_file() {
        files.push(lock);
    }
    // Deterministic order regardless of filesystem enumeration.
    files.sort();

    let mut hasher = blake3::Hasher::new();
    for f in &files {
        // Fold the workspace-relative path (so a rename/move invalidates) with an
        // unambiguous delimiter, then the file's content hash. `guest_agent_src_hash`
        // is a generic fail-hard file-content hash reused here.
        let rel = f.strip_prefix(ws_root).unwrap_or(f.as_path());
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(guest_agent_src_hash(f)?.as_bytes());
        hasher.update(b"\0");
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// A pipeline of stages to build all necessary test VM artifacts.
///
/// The fields are private: a stage list is only assembled through
/// [`Pipeline::new`] + [`Pipeline::add_stage`], so an external caller cannot
/// mutate `stages` to drop or reorder Stage 0 (`ResolvePinsStage`) and bypass the
/// "Stage 0 resolves pins" invariant.
pub struct Pipeline {
    /// The sequence of stages to run.
    stages: Vec<Box<dyn Stage>>,
    /// The target directory for built artifacts.
    target_dir: PathBuf,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pipeline {{ {} stages }}", self.stages.len())
    }
}

impl Pipeline {
    /// Creates an empty pipeline that writes artifacts under `target_dir`.
    #[must_use]
    pub fn new(target_dir: PathBuf) -> Self {
        Self {
            stages: Vec::new(),
            target_dir,
        }
    }

    /// Appends a stage to the pipeline, returning `self` for chaining.
    #[must_use]
    pub fn add_stage(mut self, stage: Box<dyn Stage>) -> Self {
        self.stages.push(stage);
        self
    }

    /// Builds all artifacts in the pipeline.
    ///
    /// # Errors
    /// Returns an error if any stage fails.
    pub async fn build(&self, _cache: &Cache) -> Result<Artifacts> {
        let dir = &self.target_dir;
        match tokio::fs::create_dir_all(dir).await {
            Ok(_) => {}
            Err(e) => return Err(crate::error::Error::Io(e)),
        }

        let mut inputs = StageInputs::default();

        for stage in &self.stages {
            let out_path = stage.out_path(dir);

            let key = stage.cache_key(&inputs);
            let key_path = out_path.with_extension("cache_key");

            let mut cached = false;
            let mut cached_pins = std::collections::HashMap::new();
            let mut cached_artifacts = std::collections::HashMap::new();

            if out_path.exists() && key_path.exists() {
                // The sidecar EXISTS (checked above), so a read failure is a real I/O error
                // (permission denied / EISDIR), never a genuine miss. Fail loud (L-ART-4)
                // rather than silently treat a locked/tampered cache as a rebuild.
                let metadata_str =
                    std::fs::read_to_string(&key_path).map_err(crate::error::Error::Io)?;
                if let Ok(metadata) = serde_json::from_str::<CacheMetadata>(&metadata_str) {
                    if metadata.key == key.0 {
                        // `hash_output` (not `hash_file`) so a DIRECTORY output (the snapshot
                        // stage — ART-1) is content-hashed over a sorted walk and
                        // tamper-verified. The output EXISTS (checked), so a hash failure is a
                        // real I/O error, not a miss — surface it, don't silently rebuild
                        // (L-ART-4).
                        let actual_hash = hash_output(&out_path)?;
                        if actual_hash == metadata.hash {
                            // A stage may publish SIBLING artifacts beside its payload (the
                            // kernel's resolved-config sidecar, §5.6). Only the payload is
                            // hash-verified above, so a hit that re-publishes a path which no
                            // longer exists would hand downstream a dangling artifact and never
                            // regenerate it — `run()` is not called on a hit. Treat a vanished
                            // registered artifact as a MISS: the rebuild is the only thing that can
                            // put it back.
                            let missing =
                                metadata.artifacts.values().find(|p| !p.exists()).cloned();
                            if let Some(gone) = missing {
                                tracing::info!(
                                    "Rebuilding stage {}: registered artifact {} is missing",
                                    stage.name(),
                                    gone.display()
                                );
                            } else {
                                cached = true;
                                cached_pins = metadata.pins;
                                cached_artifacts = metadata.artifacts;
                            }
                        } else {
                            return Err(crate::error::Error::Artifact(format!(
                                "Tampered artifact for stage {}: payload hash mismatch",
                                stage.name()
                            )));
                        }
                    }
                } else {
                    // Fallback for old cache key format: just a string
                    if metadata_str == key.0 {
                        // Can't verify hash or recover pins. Miss cache to force rebuild and get proper format.
                        tracing::warn!(
                            "Cache invalid for stage {}: old cache format",
                            stage.name()
                        );
                    }
                }
            }

            if cached {
                tracing::info!("Skipping stage {} (cached)", stage.name());
                if cached_artifacts.is_empty() {
                    inputs
                        .artifacts
                        .insert(stage.name().to_string(), out_path.clone());
                } else {
                    for (k, v) in cached_artifacts {
                        inputs.artifacts.insert(k, v);
                    }
                }
                for (k, v) in cached_pins {
                    inputs.pins.insert(k, v);
                }
            } else {
                tracing::info!("Running stage {}", stage.name());
                let outputs = stage.run(&inputs, &out_path).await?;

                // Hash payload and write metadata. `hash_output` handles a directory
                // output (the snapshot stage — ART-1): `hash_file` `File::open`ed the dir
                // and `EISDIR`-ed into the `warn!` arm, so no `.cache_key` sidecar was ever
                // written and the most expensive stage was never cached or tamper-verified.
                if out_path.exists() {
                    match hash_output(&out_path) {
                        Ok(hash) => {
                            let metadata = CacheMetadata {
                                key: key.0.clone(),
                                hash,
                                pins: outputs.pins.clone(),
                                artifacts: outputs.artifacts.clone(),
                            };
                            if let Ok(json) = serde_json::to_string(&metadata)
                                && let Err(e) = std::fs::write(&key_path, json)
                            {
                                tracing::warn!(
                                    "Failed to write cache key for stage {}: {}",
                                    stage.name(),
                                    e
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to hash output for stage {}: {}",
                                stage.name(),
                                e
                            );
                        }
                    }
                }

                for (k, v) in outputs.artifacts {
                    inputs.artifacts.insert(k, v);
                }
                for (k, v) in outputs.pins {
                    inputs.pins.insert(k, v);
                }
            }
        }

        Ok(Artifacts {
            paths: inputs.artifacts,
        })
    }

    /// Resets the pipeline to run a specific stage again.
    ///
    /// # Errors
    /// Returns an error if the reset fails.
    pub fn reset_to(&self, stage: &str, _cache: &Cache) -> Result<()> {
        let dir = &self.target_dir;
        let mut found = false;
        for s in &self.stages {
            if s.name() == stage {
                found = true;
            }
            if found {
                let out_path = s.out_path(dir);
                let key_path = out_path.with_extension("cache_key");
                // `reset_to`'s contract is to INVALIDATE the named stage and every
                // stage after it. A swallowed removal failure (the old `let _ =`)
                // would report `Ok` while leaving a VALID cached artifact + sidecar,
                // so the next `build()` serves the stale artifact. Propagate every
                // error except "already absent" (idempotent for a not-yet-built stage).
                remove_if_present(&out_path)?;
                remove_if_present(&key_path)?;
            }
        }
        if !found {
            return Err(crate::error::Error::Artifact(format!(
                "Stage not found: {stage}"
            )));
        }
        Ok(())
    }
}

/// Pipeline Stage 0: publishes the resolved pins lock into the pipeline.
///
/// Despite the "resolve" name, this stage does **not** perform live version→digest
/// resolution (that is the deferred `ARTIFACT-PIPELINE-5`); it takes the *already
/// committed* `pins.json` (embedded at compile time) as its baseline, merges the optional
/// overlay over it, writes the resolved document to `resolved_pins.json`, flattens its entries into
/// the propagated `pins` map, and folds in the guest-agent source-closure hash so downstream stages
/// consume pins purely from memory (ART-6).
///
/// The pre-overlay `pins_file: PathBuf` field is gone (§18 delta 1): the baseline is embedded, so a
/// consumer workspace needs no path, and carrying both a path and the embedded copy would be two
/// sources of truth with no stated precedence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvePinsStage {
    /// The pins **overlay** (§10.2, The stage model and the five cache-key rules): a JSON document
    /// whose top-level pin namespaces override the committed baseline key by key, letting a
    /// downstream extend the registry without forking `pins.json`. `None` resolves the baseline
    /// alone. Set from `--pins`, from `$VMCELL_PINS` via [`pins_overlay_path`], or directly.
    pub overlay_file: Option<PathBuf>,
}

#[async_trait]
impl Stage for ResolvePinsStage {
    fn name(&self) -> &str {
        "resolve_pins"
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's resolution logic changes so stale outputs are not served.
        // 1 → 2 (§18 delta 1, cache-key rule 4): the fold gained the pins OVERLAY and moved the
        // baseline to the compile-time-embedded `pins.json`, so no v1 output may be served.
        const STAGE_VERSION: u32 = 2;
        // The shared pins-fold separator, so distinct (pins, overlay, agent-hash) splits cannot
        // concatenate to the same byte stream (non-injective-hash defense).
        const SEP: &[u8] = PINS_FOLD_SEP;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        hasher.update(SEP);
        // The one pins fold (baseline + overlay), shared with `fast_artifacts_fingerprint`. A read
        // failure folds a DISTINCT error marker rather than `unwrap_or_default()`'s empty string
        // (ART-11) — the resulting cache miss drives `run()`, which fails hard with the real cause.
        // Mirrors `GuestToolsStage::cache_key`.
        if let Err(e) = fold_pins_identity(&mut hasher, self.overlay_file.as_deref()) {
            hasher.update(format!("resolve-pins-overlay-read-error:{e}").as_bytes());
        }
        hasher.update(SEP);
        // Fold the FULL guest-agent source closure (bin wrapper + src/agent/** +
        // Cargo.lock), not just the thin wrapper, so a change to `src/agent/mod.rs`
        // invalidates the resolved pins. Otherwise a cache hit here skips re-hashing
        // the agent and a stale `guest_agent_src_hash` propagates downstream — the
        // stale-agent-baked-into-rootfs bug (H-CACHE-1). A closure-hash failure folds a
        // distinct error marker (not `unwrap_or_default()`'s `""`) for the same ART-11
        // reason.
        // Outside a vmcell checkout there is no closure to fold; the DISTINCT
        // `NO_VMCELL_SOURCE_TREE` marker keeps that case from colliding with any hex hash (and
        // with the error marker above), so a consumer's key and an in-tree key never alias.
        match resolve_guest_agent_pin(vmcell_source_root().as_deref()) {
            Ok(Some(h)) => hasher.update(h.as_bytes()),
            Ok(None) => hasher.update(NO_VMCELL_SOURCE_TREE),
            Err(e) => hasher.update(format!("resolve-pins-agent-closure-error:{e}").as_bytes()),
        };
        CacheKey(format!("resolve-pins-{}", hasher.finalize().to_hex()))
    }

    fn out_path(&self, target_dir: &Path) -> PathBuf {
        target_dir.join("resolved_pins.json")
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        resolve_pins_into(
            self.overlay_file.as_deref(),
            vmcell_source_root().as_deref(),
            out,
        )
        .await
    }
}

/// The cache-key marker folded by [`ResolvePinsStage`] when this process is not running inside a
/// vmcell source checkout, so there is no guest-agent closure to fold (§10.4).
const NO_VMCELL_SOURCE_TREE: &[u8] = b"resolve-pins-no-vmcell-source-tree";

/// The **one** `guest_agent_src_hash` pin law, shared by [`ResolvePinsStage`]'s `cache_key` and
/// `run` so the key and the published pin map can never disagree about it.
///
/// * Inside a vmcell checkout (`Some(root)`): hash the FULL agent source closure and **fail hard**
///   if any of it is missing. Hashing only the thin `main.rs` wrapper left a `src/agent/mod.rs`
///   change invisible to every downstream cache key, baking a stale agent into the rootfs
///   (H-CACHE-1); a silent `"unknown"` fallback would do the same without invalidating any key.
/// * Outside one (`None`): there is **no** agent source to hash, so the pin is absent rather than
///   fabricated. It is a rootfs-lineage pin — `KernelStage` reads only `kernel_*` — so requiring it
///   unconditionally made the downstream kernel toolkit (§5.6) die at stage 0 in exactly the
///   consumer position §10.4 advertises, with an error about a vmcell source file the consumer
///   never had. The producer of a rootfs still fails loud downstream: `GuestAgentStage` builds the
///   agent by `cargo build -p vmcell-guest-agent` in that same absent tree.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] when a vmcell checkout IS present but its guest-agent
/// source closure cannot be read.
fn resolve_guest_agent_pin(source_root: Option<&Path>) -> Result<Option<String>> {
    match source_root {
        Some(root) => guest_agent_closure_hash(root).map(Some),
        None => Ok(None),
    }
}

/// The body of [`ResolvePinsStage::run`], with the vmcell-source-tree seam explicit so the
/// **consumer position** (`source_root = None`) is drivable in-process rather than only by
/// re-execing outside the checkout.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] when the overlay cannot be resolved or rendered, and
/// [`crate::error::Error::Io`] when the artifact cannot be written.
async fn resolve_pins_into(
    overlay_file: Option<&Path>,
    source_root: Option<&Path>,
    out: &Path,
) -> Result<StageOutputs> {
    // Resolve ONCE, then both publish and flatten that same document — so the artifact and the
    // propagated pin map can never disagree.
    let doc = resolve_pins_document(overlay_file)?;
    // `resolved_pins.json` is a published artifact (and a `vmcell bundle` entry), so it must be
    // the document the pins were actually resolved from. With no overlay that is the committed
    // baseline VERBATIM — byte-identical to the pre-overlay artifact, the §18 delta-1 migration
    // promise. With an overlay it is the MERGED document: copying either input verbatim there
    // would ship a lying artifact.
    let rendered = match overlay_file {
        None => COMMITTED_PINS.to_string(),
        Some(_) => {
            serde_json::to_string_pretty(&doc).map_err(|e| {
                crate::error::Error::Artifact(format!("failed to render resolved pins: {e}"))
            })? + "\n"
        }
    };
    tokio::fs::write(out, rendered.as_bytes())
        .await
        .map_err(crate::error::Error::Io)?;

    let mut pins_map = flatten_pins_document(&doc);

    // The guest-agent source identity, through the one `resolve_guest_agent_pin` law: folded from
    // the full closure in a vmcell checkout, absent (never fabricated) outside one.
    if let Some(agent_hash) = resolve_guest_agent_pin(source_root)? {
        pins_map.insert("guest_agent_src_hash".to_string(), agent_hash);
    }

    let mut outputs = StageOutputs::default();
    outputs
        .artifacts
        .insert("resolved_pins".to_string(), out.to_path_buf());
    outputs.pins = pins_map;
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture for the schema tests below: the production string → flat-map path
    /// (`serde_json` + [`flatten_pins_document`]). It delegates — it is NOT a second copy of the
    /// flatten law. The former production `parse_pins_json` retired when the stage's baseline
    /// became the embedded `COMMITTED_PINS` constant (§18 delta 1); the only runtime string it
    /// still parses is the overlay, which goes through the strict [`parse_pins_overlay`].
    fn parse_pins_json(content: &str) -> Result<std::collections::HashMap<String, String>> {
        let json = serde_json::from_str::<serde_json::Value>(content)
            .map_err(|e| crate::error::Error::Artifact(format!("malformed pins JSON: {e}")))?;
        Ok(flatten_pins_document(&json))
    }

    // The at-most-once auto-build skip decision (`ensure_test_artifacts`). Fresh iff the rootfs
    // output exists AND the stamp matches the current input fingerprint — so a source/dep/packer
    // change (stamp mismatch) OR a deleted rootfs (output absent) both force a rebuild. Red-on-inverse:
    // dropping the `rootfs_exists` guard makes the deleted-rootfs case wrongly "fresh"; dropping the
    // stamp compare makes a changed input wrongly "fresh".
    #[cfg(feature = "pipeline")]
    #[test]
    fn artifacts_stamp_fresh_requires_present_output_and_matching_stamp() {
        let fp = "fingerprint-abc";
        // Fresh: output present and stamp matches.
        assert!(artifacts_stamp_fresh(Some(fp), fp, true));
        // NOT fresh: output missing (a deleted rootfs must rebuild even with a matching stamp).
        assert!(!artifacts_stamp_fresh(Some(fp), fp, false));
        // NOT fresh: an input changed (stamp differs), or no stamp yet.
        assert!(!artifacts_stamp_fresh(Some("stale"), fp, true));
        assert!(!artifacts_stamp_fresh(None, fp, true));
    }

    // Guards the consolidated artifacts-dir default: a buggy resolver that drops the
    // default (or points it at `/tmp/...`) goes red here. Exercises the PURE inner fn so
    // there is no `std::env` mutation and therefore no cross-test env-var race.
    #[test]
    fn test_resolve_artifacts_dir_default_and_override() {
        // The default is anchored on the provided workspace root (so it resolves the same
        // regardless of the process CWD — the v15 workspace-split fix).
        let default = resolve_artifacts_dir(None, Path::new("/ws"));
        assert_eq!(default, PathBuf::from("/ws/target/vmcell-artifacts"));
        let overridden = resolve_artifacts_dir(Some("x/y".into()), Path::new("/ws"));
        assert_eq!(overridden, PathBuf::from("x/y"));
    }

    // Guards ARTIFACT-PIPELINE-5: a buggy impl that never emits
    // `debian_snapshot_timestamp` (so the mmdebstrap source can't run) goes red here.
    #[test]
    fn test_parse_pins_emits_debian_snapshot_timestamp() {
        let top = r#"{ "debian_snapshot_timestamp": "20240101T000000Z" }"#;
        let map = parse_pins_json(top).expect("valid pins JSON");
        assert_eq!(
            map.get("debian_snapshot_timestamp").map(String::as_str),
            Some("20240101T000000Z")
        );

        // Also accepted when nested under `rootfs`.
        let nested = r#"{ "rootfs": { "image": "docker.io/library/debian",
            "digest": "sha256:abc", "debian_snapshot_timestamp": "20240202T000000Z" } }"#;
        let map = parse_pins_json(nested).expect("valid pins JSON");
        assert_eq!(
            map.get("debian_snapshot_timestamp").map(String::as_str),
            Some("20240202T000000Z")
        );
        assert_eq!(
            map.get("rootfs_digest").map(String::as_str),
            Some("sha256:abc")
        );
    }

    // §5.4 (The guest-kernel contract and the bootstrap seed): the `kernel_prebuilt` bootstrap block flattens to `kernel_prebuilt_url` /
    // `kernel_prebuilt_sha256`; a doc with no such block leaves the keys absent (so the
    // prebuilt bootstrap fails loud rather than fetching from an empty URL).
    #[test]
    fn test_parse_pins_flattens_kernel_prebuilt() {
        let json = r#"{ "kernel_prebuilt": { "url": "https://h/vmlinux", "sha256": "abc123" } }"#;
        let map = parse_pins_json(json).expect("valid pins JSON");
        assert_eq!(
            map.get("kernel_prebuilt_url").map(String::as_str),
            Some("https://h/vmlinux")
        );
        assert_eq!(
            map.get("kernel_prebuilt_sha256").map(String::as_str),
            Some("abc123")
        );

        // Absent block → absent keys.
        let empty = parse_pins_json(r#"{ "rootfs": { "image": "i", "digest": "d" } }"#)
            .expect("valid pins JSON");
        assert!(!empty.contains_key("kernel_prebuilt_url"));
        assert!(!empty.contains_key("kernel_prebuilt_sha256"));
    }

    // §5.5 GATE (delta 3) — the BUILD ORDER law, on an input the map backing cannot pre-sort for
    // it. Through `resolve_kernel_registry` the order today also happens to be what serde_json's
    // `BTreeMap` yields, so only this direct call can tell "sorted on purpose" from "sorted by
    // accident" (and it is the call that keeps the promise if a transitive dep ever enables
    // `preserve_order`). RED on the inverse (a no-op `sort_kernel_registry`): the reversed input
    // below comes back reversed. Byte-lexicographic, NOT version order — a "fix" to semver
    // collation reddens the dotted pair too.
    #[test]
    fn kernel_registry_is_sorted_byte_lexicographically() {
        let entry = |label: &str| KernelRegistryEntry {
            label: label.to_string(),
            fragments: Vec::new(),
        };
        let sorted = sort_kernel_registry(vec![
            entry("zz"),
            entry("6.6.143"),
            entry("6.12.94"),
            entry("aa"),
        ]);
        assert_eq!(
            sorted.iter().map(|e| e.label.as_str()).collect::<Vec<_>>(),
            vec!["6.12.94", "6.6.143", "aa", "zz"],
            "labels build in byte-lexicographic order (6.12.94 before 6.6.143)"
        );
        // The fragment sets ride along with their labels rather than being re-paired by index.
        let carried = sort_kernel_registry(vec![
            KernelRegistryEntry {
                label: "b".into(),
                fragments: vec!["B_FRAG".into()],
            },
            KernelRegistryEntry {
                label: "a".into(),
                fragments: vec!["A_FRAG".into()],
            },
        ]);
        assert_eq!(carried[0].label, "a");
        assert_eq!(carried[0].fragments, vec!["A_FRAG".to_string()]);
    }

    // Guards the multi-kernel dimension: each `kernels.<label>` must flatten to
    // `kernel_<label>_source_url` / `_source_sha256` so a labelled KernelStage can
    // build it. A buggy impl that ignores `kernels` returns None for these keys.
    #[test]
    fn test_parse_pins_flattens_kernel_registry() {
        let json = r#"{
            "kernel": { "source_url": "u-default", "source_sha256": "s-default" },
            "kernels": {
                "6.6.143":  { "source_url": "u-66",  "source_sha256": "s-66"  },
                "6.12.94":  { "source_url": "u-612", "source_sha256": "s-612" }
            }
        }"#;
        let map = parse_pins_json(json).expect("valid pins JSON");
        assert_eq!(
            map.get("kernel_6.6.143_source_url").map(String::as_str),
            Some("u-66")
        );
        assert_eq!(
            map.get("kernel_6.6.143_source_sha256").map(String::as_str),
            Some("s-66")
        );
        assert_eq!(
            map.get("kernel_6.12.94_source_url").map(String::as_str),
            Some("u-612")
        );
        assert_eq!(
            map.get("kernel_6.12.94_source_sha256").map(String::as_str),
            Some("s-612")
        );
        // The default `kernel` pins stay intact alongside the registry.
        assert_eq!(
            map.get("kernel_source_url").map(String::as_str),
            Some("u-default")
        );
    }

    // §5.2 (The config fragment): each `kernel_fragments.<NAME>` must flatten to a `kernel_fragments_<NAME>` pin
    // carrying that fragment's KConfig text, so a `KernelStage` with `fragments=[NAME]` can
    // resolve it. A buggy impl that ignores `kernel_fragments` returns None for these keys
    // and the kernel build would then fail loud on the missing fragment.
    #[test]
    fn test_parse_pins_flattens_kernel_fragments() {
        let json = r#"{
            "kernel_fragments": {
                "KASAN":   "CONFIG_KASAN=y\n",
                "LOCKDEP": "CONFIG_LOCKDEP=y\n"
            }
        }"#;
        let map = parse_pins_json(json).expect("valid pins JSON");
        assert_eq!(
            map.get("kernel_fragments_KASAN").map(String::as_str),
            Some("CONFIG_KASAN=y\n")
        );
        assert_eq!(
            map.get("kernel_fragments_LOCKDEP").map(String::as_str),
            Some("CONFIG_LOCKDEP=y\n")
        );
    }

    // Guards DESIGN-DIVERGENCE-3: a buggy impl that swallows a missing guest-agent source
    // into an `"unknown"` pin (instead of failing hard) would return Ok here.
    #[test]
    fn test_guest_agent_src_hash_fails_hard_on_missing() {
        let missing = Path::new("/nonexistent/imp/does-not-exist/vmcell-guest-agent.rs");
        let res = guest_agent_src_hash(missing);
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "missing guest-agent source must be a hard error, got {res:?}"
        );
    }

    // Guards DESIGN-DIVERGENCE-3 (the hash actually tracks content): different source
    // bytes must yield a different hash, and the same bytes a stable one.
    #[test]
    fn test_guest_agent_src_hash_tracks_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("agent.rs");
        std::fs::write(&p, b"fn main() {}").expect("write");
        let h1 = guest_agent_src_hash(&p).expect("hash");
        let h1b = guest_agent_src_hash(&p).expect("hash");
        assert_eq!(h1, h1b, "hash must be deterministic for identical content");

        std::fs::write(&p, b"fn main() { /* changed */ }").expect("write");
        let h2 = guest_agent_src_hash(&p).expect("hash");
        assert_ne!(h1, h2, "changed source content must change the hash");
    }

    // Guards M-PIPE-3 on the one pins document that is still parsed from a string at runtime, the
    // OVERLAY: malformed JSON must fail loud, not degrade to an empty map that later surfaces as a
    // misleading "Missing X pin". The buggy `if let Ok(json)` swallow returns an empty overlay (Ok)
    // → this `Err` match goes red. The message names the offending file.
    #[test]
    fn test_parse_pins_overlay_rejects_malformed_json() {
        let res = parse_pins_overlay("{ this is : not json ]", Path::new("/tmp/over.json"));
        let Err(crate::error::Error::Artifact(msg)) = res else {
            panic!("malformed pins overlay JSON must be a hard error, got {res:?}");
        };
        assert!(
            msg.contains("/tmp/over.json"),
            "the rejection must name the overlay file, got {msg}"
        );
    }

    // Guards H-CACHE-1: the guest-agent identity must cover the FULL source closure
    // (bin wrapper + every src/agent/**/*.rs + Cargo.lock), not just the thin wrapper.
    // The buggy wrapper-only hash leaves a change to `src/agent/mod.rs` invisible, so
    // the rootfs cache key does NOT change and a stale agent is re-baked into the
    // rootfs. We mutate a NON-wrapper agent file and assert both the closure hash and
    // the downstream rootfs cache key change — both stay equal on the buggy version.
    #[cfg(feature = "pipeline")]
    #[test]
    fn test_guest_agent_closure_hash_tracks_agent_module_change() {
        use crate::artifact::rootfs::RootfsStage;

        // A fixture "workspace root" mirroring the real v15 layout: the guest-agent
        // member (binary entry point + reaper lib) PLUS the shared protocol crate it
        // links. Editing the real tree is avoided on purpose.
        let root = tempfile::tempdir().expect("tempdir");
        let agent_src = root.path().join("crates/vmcell-guest-agent/src");
        let proto_src = root.path().join("crates/vmcell-protocol/src");
        std::fs::create_dir_all(&agent_src).expect("mkdir agent src");
        std::fs::create_dir_all(&proto_src).expect("mkdir protocol src");
        // The workspace-root marker the closure-hash anchor ascends to.
        std::fs::write(
            root.path().join("crates/vmcell-protocol/Cargo.toml"),
            b"[package]\nname=\"vmcell-protocol\"\n",
        )
        .expect("write protocol manifest");
        std::fs::write(agent_src.join("main.rs"), b"fn main() {}").expect("write bin");
        std::fs::write(agent_src.join("lib.rs"), b"pub fn reaper() {}").expect("write lib");
        std::fs::write(proto_src.join("lib.rs"), b"pub struct Msg;").expect("write proto");
        std::fs::write(root.path().join("Cargo.lock"), b"# lock v1").expect("write lock");

        let h1 = guest_agent_closure_hash(root.path()).expect("closure hash 1");

        let rootfs = RootfsStage {
            image_override: None,
            agent_musl: None,
            extra: Vec::new(),
        };
        let mut inputs1 = StageInputs::default();
        inputs1
            .pins
            .insert("guest_agent_src_hash".into(), h1.clone());
        let rootfs_key1 = rootfs.cache_key(&inputs1);

        // Mutate the agent IMPLEMENTATION (not the binary entry point). main.rs is
        // byte-identical, so the buggy entry-point-only hash would be UNCHANGED here.
        std::fs::write(agent_src.join("lib.rs"), b"pub fn reaper() { /* fixed */ }")
            .expect("rewrite lib");
        let h2 = guest_agent_closure_hash(root.path()).expect("closure hash 2");
        assert_ne!(
            h1, h2,
            "a change to the guest-agent reaper lib must change the source closure hash"
        );

        let mut inputs2 = StageInputs::default();
        inputs2.pins.insert("guest_agent_src_hash".into(), h2);
        let rootfs_key2 = rootfs.cache_key(&inputs2);
        assert_ne!(
            rootfs_key1, rootfs_key2,
            "rootfs cache key must change when an agent implementation file changes"
        );
    }

    // Guards H-CACHE-1's hard-stop half: a missing bin wrapper (or src/agent tree)
    // must be a hard error, never a silent partial/empty closure hash.
    #[test]
    fn test_guest_agent_closure_hash_fails_hard_on_missing_bin() {
        let empty = tempfile::tempdir().expect("tempdir");
        let res = guest_agent_closure_hash(empty.path());
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "missing guest-agent bin wrapper must be a hard error, got {res:?}"
        );
    }

    // §10.4 GATE (delta 3, F1): the vmcell-source-tree predicate must answer NO outside a vmcell
    // checkout. `workspace_root` cannot answer it — it falls back to the start dir — so an
    // "is vmcell's own source here" question asked through it always says yes and then explodes on
    // a file that dir never had. RED on the inverse (an ascent that returns the start dir when the
    // marker is absent): the temp dir comes back as `Some`.
    #[test]
    fn find_vmcell_source_root_answers_no_outside_a_checkout() {
        let outside = tempfile::tempdir().expect("tempdir");
        let nested = outside.path().join("consumer/crates/acme");
        std::fs::create_dir_all(&nested).expect("mkdir consumer tree");
        assert_eq!(
            find_vmcell_source_root(&nested),
            None,
            "a consumer workspace is NOT a vmcell source checkout"
        );
        // Positive control: the same ascent finds the marker when it IS there, and returns the
        // MARKER-owning dir (not the start dir) — so the None above is a real answer, not a
        // predicate that never matches.
        let checkout = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(checkout.path().join("crates/vmcell-protocol"))
            .expect("mkdir marker dir");
        std::fs::write(
            checkout.path().join("crates/vmcell-protocol/Cargo.toml"),
            b"[package]\n",
        )
        .expect("write marker");
        let deep = checkout.path().join("crates/vmcell/src");
        std::fs::create_dir_all(&deep).expect("mkdir deep");
        assert_eq!(
            find_vmcell_source_root(&deep).as_deref(),
            Some(checkout.path()),
            "the ascent must find the marker-owning root from a member crate dir"
        );
    }

    // §10.4 GATE (delta 3, F1): the `guest_agent_src_hash` pin is a ROOTFS-lineage pin, and
    // requiring it outside a vmcell checkout is what made the §5.6 toolkit unusable from the
    // consumer position it advertises. Absent checkout => no pin, no error; present-but-broken
    // checkout => still a hard error (H-CACHE-1 stays fixed).
    // RED on the inverse (`guest_agent_closure_hash(&workspace_root())?` unconditionally): the
    // `None` arm errors instead of yielding `Ok(None)`.
    #[test]
    fn guest_agent_pin_is_absent_without_a_checkout_and_hard_errors_with_a_broken_one() {
        assert_eq!(
            resolve_guest_agent_pin(None).expect("no checkout is not an error"),
            None,
            "outside a vmcell checkout there is no agent source to hash — the pin must be \
             ABSENT, never fabricated"
        );
        let broken = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(broken.path().join("crates/vmcell-protocol"))
            .expect("mkdir marker dir");
        std::fs::write(
            broken.path().join("crates/vmcell-protocol/Cargo.toml"),
            b"[package]\n",
        )
        .expect("write marker");
        let res = resolve_guest_agent_pin(Some(broken.path()));
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "a checkout whose guest-agent source is missing must still hard-error \
             (H-CACHE-1), got {res:?}"
        );
    }

    // §10.4 GATE (delta 3, F1): the CONSUMER POSITION, driven through the real
    // `ResolvePinsStage::run` body. It must publish `resolved_pins.json`, propagate the `kernel_*`
    // pins the labelled-kernel build reads, and simply omit `guest_agent_src_hash`.
    // RED on the inverse: restoring the unconditional agent-closure hash makes this assert fail
    // in-tree (the pin comes back) and makes the real downstream call fail outright — which is the
    // bug the re-exec gate in `tests/kernel_toolkit.rs` reproduces end to end.
    #[cfg(feature = "pipeline")]
    #[tokio::test]
    async fn resolve_pins_into_omits_the_agent_pin_without_a_checkout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("resolved_pins.json");
        let outputs = resolve_pins_into(None, None, &out)
            .await
            .expect("resolving pins must not need a vmcell source checkout");
        assert!(
            out.is_file(),
            "the resolved-pins artifact must be published"
        );
        assert!(
            outputs.pins.contains_key("kernel_source_url"),
            "the kernel pins the §5.6 toolkit reads must still travel"
        );
        assert!(
            !outputs.pins.contains_key("guest_agent_src_hash"),
            "the rootfs-lineage agent pin must be ABSENT outside a checkout, got {:?}",
            outputs.pins.get("guest_agent_src_hash")
        );
    }

    // Guards §10.2 (The stage model and the five cache-key rules) caching rules 3-4 for vmcell-guest-tools: the helper links
    // reqwest/rustls, so a dependency bump changes Cargo.lock but NOT the `.rs`
    // source. The closure hash must fold Cargo.lock so the bump invalidates the
    // key. The buggy source-only hash (the old `if let Ok(content)` over just the
    // .rs) stays EQUAL across the lock change below and so re-bakes a stale helper.
    #[cfg(feature = "pipeline")]
    #[test]
    fn test_guest_tools_closure_hash_tracks_cargo_lock() {
        let root = tempfile::tempdir().expect("tempdir");
        let tools_src = root.path().join("crates/vmcell-guest-tools/src");
        std::fs::create_dir_all(&tools_src).expect("mkdir tools src");
        std::fs::write(tools_src.join("main.rs"), b"fn main() {}").expect("write bin");
        std::fs::write(root.path().join("Cargo.lock"), b"# lock v1").expect("write lock");

        let h1 = guest_tools_closure_hash(root.path()).expect("closure hash 1");

        // Bump a dependency: Cargo.lock changes, the helper `.rs` source does not.
        std::fs::write(root.path().join("Cargo.lock"), b"# lock v2 (dep bump)")
            .expect("rewrite lock");
        let h2 = guest_tools_closure_hash(root.path()).expect("closure hash 2");
        assert_ne!(
            h1, h2,
            "a Cargo.lock change (dependency bump) must change the guest-tools closure hash"
        );

        // Sanity: identical inputs hash identically (deterministic).
        std::fs::write(root.path().join("Cargo.lock"), b"# lock v1").expect("restore lock");
        let h1b = guest_tools_closure_hash(root.path()).expect("closure hash 1b");
        assert_eq!(h1, h1b, "identical closure inputs must hash identically");
    }

    // Guards the hard-stop half: a missing guest-tools bin source must be a hard
    // error, never a silent partial/empty closure hash that hits a stale cache.
    #[cfg(feature = "pipeline")]
    #[test]
    fn test_guest_tools_closure_hash_fails_hard_on_missing_bin() {
        let empty = tempfile::tempdir().expect("tempdir");
        let res = guest_tools_closure_hash(empty.path());
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "missing guest-tools bin source must be a hard error, got {res:?}"
        );
    }

    // ART-8: an unmaterialized upstream artifact must fold a STABLE marker, never its
    // absolute `PathBuf` — otherwise the key varies by where `target/` lives and a rebuilt
    // upstream at the same path is invisible. Two DIFFERENT absent absolute paths under the
    // same artifact key must produce the SAME fold. The buggy `p:` + `to_string_lossy`
    // path-fold makes these diverge → red here.
    #[cfg(feature = "pipeline")]
    #[test]
    fn test_hash_artifacts_unmaterialized_is_path_independent() {
        let mut m1 = std::collections::HashMap::new();
        m1.insert("k".to_string(), PathBuf::from("/nonexistent/aaa/x"));
        let mut m2 = std::collections::HashMap::new();
        m2.insert("k".to_string(), PathBuf::from("/nonexistent/bbb/deeper/y"));
        let mut h1 = blake3::Hasher::new();
        hash_artifacts_sorted(&mut h1, &m1);
        let mut h2 = blake3::Hasher::new();
        hash_artifacts_sorted(&mut h2, &m2);
        assert_eq!(
            h1.finalize(),
            h2.finalize(),
            "an absent artifact must fold a stable marker, not its absolute path (ART-8)"
        );
    }

    // ART-1: a directory output hashes deterministically over its content, and a
    // byte-corrupted file INSIDE it changes the hash — so the cache-hit tamper check can
    // reject it. `hash_file` would `File::open` the dir and `EISDIR` here instead.
    #[test]
    fn test_hash_output_directory_deterministic_and_tamper_sensitive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snap = dir.path().join("snapshot");
        std::fs::create_dir_all(snap.join("mem")).expect("mkdir");
        std::fs::write(snap.join("state.json"), b"state-v1").expect("write");
        std::fs::write(snap.join("mem/pages.bin"), b"pages-v1").expect("write");

        let h1 = hash_output(&snap).expect("hash dir");
        let h1b = hash_output(&snap).expect("hash dir again");
        assert_eq!(h1, h1b, "directory content hash must be deterministic");

        // Corrupt one file inside the directory: the hash must change.
        std::fs::write(snap.join("mem/pages.bin"), b"pages-TAMPERED").expect("write");
        let h2 = hash_output(&snap).expect("hash dir after tamper");
        assert_ne!(
            h1, h2,
            "a corrupted file inside the directory must change the content hash"
        );
    }

    // ART-2: `remove_if_present` purges a NON-EMPTY directory (via `remove_dir_all`),
    // removes a file, and treats an already-absent path as success — never `EISDIR` on a
    // directory (which defeated `reset_to` for the snapshot stage).
    #[test]
    fn test_remove_if_present_file_dir_and_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");

        // A regular file is removed.
        let f = tmp.path().join("file");
        std::fs::write(&f, b"x").expect("write");
        remove_if_present(&f).expect("remove file");
        assert!(!f.exists());

        // A non-empty directory (the snapshot-dir case) is purged, not EISDIR-errored.
        let d = tmp.path().join("dir");
        std::fs::create_dir_all(d.join("sub")).expect("mkdir");
        std::fs::write(d.join("sub/inner"), b"y").expect("write");
        remove_if_present(&d).expect("remove dir must succeed, not EISDIR");
        assert!(!d.exists());

        // An already-absent path is idempotent success.
        remove_if_present(&tmp.path().join("never")).expect("absent is Ok");
    }

    // M-ART-7: `parse_pins_json` must emit the CH/virtiofsd build identity so the snapshot
    // stage can fold it. A buggy impl that ignores these keys returns None -> red.
    #[test]
    fn test_parse_pins_emits_ch_virtiofsd_identity() {
        let json = r#"{ "cloud_hypervisor": "v40.0", "virtiofsd": "v1.11.0" }"#;
        let map = parse_pins_json(json).expect("valid pins JSON");
        assert_eq!(
            map.get("cloud_hypervisor").map(String::as_str),
            Some("v40.0")
        );
        assert_eq!(map.get("virtiofsd").map(String::as_str), Some("v1.11.0"));
    }

    // M-ART-6: a DIRECTORY artifact must be content-hashed by `hash_artifacts_sorted`, so a
    // content change to a file inside it changes the fold. The buggy `hash_file`-on-a-dir
    // EISDIRs and folds the `unmaterialized` marker regardless -> the two folds stay equal.
    #[cfg(feature = "pipeline")]
    #[test]
    fn test_hash_artifacts_sorted_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snap = dir.path().join("snapshot");
        std::fs::create_dir_all(&snap).expect("mkdir");
        std::fs::write(snap.join("state.bin"), b"state-v1").expect("write");
        let mut m = std::collections::HashMap::new();
        m.insert("snapshot".to_string(), snap.clone());

        let mut h1 = blake3::Hasher::new();
        hash_artifacts_sorted(&mut h1, &m);
        let d1 = h1.finalize();

        std::fs::write(snap.join("state.bin"), b"state-v2-tampered").expect("write");
        let mut h2 = blake3::Hasher::new();
        hash_artifacts_sorted(&mut h2, &m);
        let d2 = h2.finalize();

        assert_ne!(
            d1, d2,
            "a directory artifact's content change must change the fold (M-ART-6)"
        );
    }

    // L-ART-5: `hash_dir_into` must preserve non-UTF-8 names/targets (not `to_string_lossy`)
    // and fold directory modes. (1) two distinct non-UTF-8 filenames that collapse to the
    // same U+FFFD must hash differently; (2) a chmod on a directory inside the tree must
    // change the hash. Both go red on the lossy / no-dir-mode buggy version.
    #[test]
    fn test_hash_dir_preserves_non_utf8_names_and_dir_modes() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();

        let name_a = std::ffi::OsStr::from_bytes(b"\xff");
        let name_b = std::ffi::OsStr::from_bytes(b"\xfe");
        let pa = root.join(name_a);
        std::fs::write(&pa, b"x").unwrap();
        let h_a = hash_output(&root).expect("hash");
        std::fs::rename(&pa, root.join(name_b)).unwrap();
        let h_b = hash_output(&root).expect("hash");
        assert_ne!(
            h_a, h_b,
            "distinct non-UTF-8 names must not collapse to the same hash (L-ART-5)"
        );

        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let h1 = hash_output(&root).expect("hash");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        let h2 = hash_output(&root).expect("hash");
        assert_ne!(
            h1, h2,
            "a directory-mode change inside the tree must change the hash (L-ART-5)"
        );
    }

    // L-ART-5 (root): `hash_output` must fold the ROOT directory's own mode, so a
    // chmod on the snapshot ROOT changes the tamper hash. The buggy version folds
    // only per-entry modes (via `hash_dir_into`), leaving the root mode outside the
    // hash -> the two hashes stay equal and this `assert_ne!` reddens.
    #[test]
    fn test_hash_output_folds_root_dir_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("snapshot");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("state.bin"), b"state-v1").unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let h1 = hash_output(&root).expect("hash");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let h2 = hash_output(&root).expect("hash");
        assert_ne!(
            h1, h2,
            "a chmod on the snapshot ROOT must change the content hash (L-ART-5)"
        );
    }

    /// A trivial stage whose output is a fixed file, for the cache-bookkeeping tests.
    struct TrivialStage;
    #[async_trait::async_trait]
    impl Stage for TrivialStage {
        fn name(&self) -> &str {
            "trivial"
        }
        fn cache_key(&self, _: &StageInputs) -> CacheKey {
            CacheKey("trivial-k".into())
        }
        fn out_path(&self, t: &Path) -> PathBuf {
            t.join("trivial_out")
        }
        async fn run(&self, _: &StageInputs, out: &Path) -> Result<StageOutputs> {
            tokio::fs::write(out, b"out")
                .await
                .map_err(crate::error::Error::Io)?;
            Ok(StageOutputs::default())
        }
    }

    // L-ART-4: an existing-but-unreadable cache sidecar must fail the build LOUD, never fall
    // through to a silent rebuild. A directory at the sidecar path makes `read_to_string`
    // EISDIR regardless of uid; the buggy `if let Ok(metadata_str)` swallows it (build Ok),
    // so this `is_err()` assertion goes red on the old behavior.
    #[tokio::test]
    async fn test_build_fails_loud_on_unreadable_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().to_path_buf();
        let out = target.join("trivial_out");
        std::fs::write(&out, b"out").unwrap();
        std::fs::create_dir_all(out.with_extension("cache_key")).unwrap();
        let pipeline = Pipeline::new(target).add_stage(Box::new(TrivialStage));
        let res = pipeline.build(&Cache::default()).await;
        assert!(
            res.is_err(),
            "an existing-but-unreadable cache sidecar must fail the build loud (L-ART-4)"
        );
    }

    /// Stage A of the warm-hit restoration test: constant key, emits a pin + an artifact.
    #[cfg(feature = "pipeline")]
    struct WarmStageA;
    #[cfg(feature = "pipeline")]
    #[async_trait::async_trait]
    impl Stage for WarmStageA {
        fn name(&self) -> &str {
            "A"
        }
        fn cache_key(&self, _: &StageInputs) -> CacheKey {
            CacheKey("A-const".into())
        }
        fn out_path(&self, t: &Path) -> PathBuf {
            t.join("A_out")
        }
        async fn run(&self, _: &StageInputs, out: &Path) -> Result<StageOutputs> {
            tokio::fs::write(out, b"a-content")
                .await
                .map_err(crate::error::Error::Io)?;
            let mut o = StageOutputs::default();
            o.pins.insert("my_pin".into(), "value".into());
            o.artifacts.insert("my_artifact".into(), out.to_path_buf());
            Ok(o)
        }
    }

    /// Stage B: its key folds both the restored pin AND the restored artifact content, and
    /// its run() requires both — so deleting either restoration loop re-runs it.
    #[cfg(feature = "pipeline")]
    struct WarmStageB {
        runs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    #[cfg(feature = "pipeline")]
    #[async_trait::async_trait]
    impl Stage for WarmStageB {
        fn name(&self) -> &str {
            "B"
        }
        fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
            let mut h = blake3::Hasher::new();
            h.update(b"B");
            match inputs.pins.get("my_pin") {
                Some(v) => h.update(v.as_bytes()),
                None => h.update(b"<no-pin>"),
            };
            let filtered: std::collections::HashMap<String, PathBuf> = inputs
                .artifacts
                .iter()
                .filter(|(k, _)| k.as_str() == "my_artifact")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            hash_artifacts_sorted(&mut h, &filtered);
            CacheKey(format!("B-{}", h.finalize().to_hex()))
        }
        fn out_path(&self, t: &Path) -> PathBuf {
            t.join("B_out")
        }
        async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
            self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            inputs
                .pins
                .get("my_pin")
                .ok_or_else(|| crate::error::Error::Artifact("Missing pin my_pin".into()))?;
            inputs.artifacts.get("my_artifact").ok_or_else(|| {
                crate::error::Error::Artifact("Missing artifact my_artifact".into())
            })?;
            tokio::fs::write(out, b"b-content")
                .await
                .map_err(crate::error::Error::Io)?;
            Ok(StageOutputs::default())
        }
    }

    // M-ART-12: on a warm cache hit of stage A, its cached pins AND artifacts must be
    // restored into `inputs` so a downstream stage B still keys/consumes them. Deleting the
    // `cached_pins` loop (B fails "Missing pin"/re-runs) or the `cached_artifacts` loop (B
    // re-keys and re-runs) makes B run a second time -> the `== 1` assertion goes red.
    #[cfg(feature = "pipeline")]
    #[tokio::test]
    async fn test_warm_hit_restores_pins_and_artifacts_downstream() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mk = || {
            Pipeline::new(dir.path().to_path_buf())
                .add_stage(Box::new(WarmStageA))
                .add_stage(Box::new(WarmStageB { runs: runs.clone() }))
        };
        // Cold build: A and B both run.
        mk().build(&Cache::default()).await.expect("cold build");
        assert_eq!(
            runs.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "B runs once on the cold build"
        );
        // Warm build: A cache-hits and MUST restore my_pin + my_artifact so B stays cached.
        mk().build(&Cache::default()).await.expect("warm build");
        assert_eq!(
            runs.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "B must stay cached on the warm build; a dropped restoration loop re-runs it (M-ART-12)"
        );
    }

    // ---- The pins overlay (§18 delta 1 / §10.2, The stage model and the five cache-key rules) ----

    /// Writes an overlay document into `dir` and returns its path.
    fn write_overlay(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("overlay.json");
        std::fs::write(&path, body).expect("write overlay");
        path
    }

    // GATE (delta 1) — OVERLAY WINS, and wins at the FLATTENED KEY level. An overlay that sets only
    // `kernel.source_url` must replace that one pin and leave the baseline's siblings standing.
    // Red-on-inverse: (a) a merge that lets the baseline win leaves `source_url` at the cdn.kernel.org
    // pin; (b) a whole-namespace REPLACEMENT merge (`*baseline = overlay` on `kernel`) drops
    // `kernel_microvm_config` and `kernel_source_sha256` — the exact trap that would build a kernel
    // with no microvm config. Both assertions below go red on their respective bug.
    #[test]
    fn pins_overlay_wins_per_key_and_keeps_baseline_siblings() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = write_overlay(
            tmp.path(),
            r#"{ "kernel": { "source_url": "https://downstream.example/linux-9.9.9.tar.xz" } }"#,
        );
        let baseline = resolve_pins(None).expect("baseline resolves");
        let merged = resolve_pins(Some(&overlay)).expect("overlay resolves");

        assert_eq!(
            merged.get("kernel_source_url").map(String::as_str),
            Some("https://downstream.example/linux-9.9.9.tar.xz"),
            "the overridden key must take the overlay's value"
        );
        // The siblings inside the same namespace survive — key-level, not document-level, merge.
        assert_eq!(
            merged.get("kernel_microvm_config"),
            baseline.get("kernel_microvm_config"),
            "a namespace-replacement merge would drop the baseline's microvm_config"
        );
        assert_eq!(
            merged.get("kernel_source_sha256"),
            baseline.get("kernel_source_sha256"),
            "a namespace-replacement merge would drop the baseline's source_sha256"
        );
    }

    // GATE (delta 1) — FALLS BACK TO THE BASELINE. Every key the overlay does not mention resolves
    // from the committed baseline, and a NEW entry inside a known namespace is legal (that is the
    // whole point: extend the registry without forking pins.json). Red-on-inverse: a resolver that
    // returns only the overlay's own keys drops `rootfs_image`/the baseline labels.
    #[test]
    fn pins_overlay_falls_back_to_baseline_and_admits_new_registry_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = write_overlay(
            tmp.path(),
            r#"{ "kernels": { "9.9.9": { "source_url": "https://d.example/l.tar.xz",
                 "source_sha256": "beef" } } }"#,
        );
        let baseline = resolve_pins(None).expect("baseline resolves");
        let merged = resolve_pins(Some(&overlay)).expect("overlay resolves");

        // Untouched namespaces fall back verbatim.
        assert_eq!(
            merged.get("rootfs_image"),
            baseline.get("rootfs_image"),
            "an unmentioned namespace must resolve from the baseline"
        );
        // The baseline's own labels survive alongside the added one.
        assert!(
            baseline.contains_key("kernel_6.12.94_source_url"),
            "fixture premise: the committed baseline carries the 6.12.94 label"
        );
        assert_eq!(
            merged.get("kernel_6.12.94_source_url"),
            baseline.get("kernel_6.12.94_source_url"),
            "an added registry entry must not evict the baseline's entries"
        );
        assert_eq!(
            merged.get("kernel_9.9.9_source_url").map(String::as_str),
            Some("https://d.example/l.tar.xz")
        );
        // …and the added label is enumerable by the roster `vmcell build-kernels` builds, so a
        // downstream label is not merely resolvable but buildable (the gate-blindness this closes).
        let labels = resolve_kernel_labels(Some(&overlay)).expect("labels resolve");
        assert!(
            labels.contains(&"9.9.9".to_string()) && labels.contains(&"6.12.94".to_string()),
            "the label roster must be the MERGED registry, got {labels:?}"
        );
        assert_eq!(
            labels,
            {
                let mut sorted = labels.clone();
                sorted.sort();
                sorted
            },
            "the roster must be sorted so the build order is deterministic"
        );
    }

    // GATE (delta 1) — a MISSPELLED top-level override is REJECTED, naming the key. This is the
    // whole reason the overlay parser is stricter than the baseline's: `kerne1` (the `1`-for-`l`
    // slip, the same shape as the `source_ur1` example in the schema doc) would otherwise
    // parse fine, contribute nothing, and let the entire `kernel` namespace resolve from the
    // baseline — a green build of the wrong kernel. Red-on-inverse: drop the `pins_namespace_shape`
    // key check (i.e. reuse the baseline's ignore-unknown parse) and this returns Ok.
    #[test]
    fn pins_overlay_rejects_misspelled_top_level_key_naming_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = write_overlay(
            tmp.path(),
            r#"{ "kerne1": { "source_url": "https://d.example/l.tar.xz" } }"#,
        );
        let res = resolve_pins(Some(&overlay));
        let Err(crate::error::Error::Artifact(msg)) = res else {
            panic!("a misspelled overlay namespace must be a hard error, got {res:?}");
        };
        assert!(
            msg.contains("kerne1"),
            "the rejection must NAME the offending key, got {msg}"
        );
        // A correctly-spelled key is the positive control: the same shape must be accepted.
        let ok = write_overlay(
            tmp.path(),
            r#"{ "kernel": { "source_url": "https://d.example/l.tar.xz" } }"#,
        );
        resolve_pins(Some(&ok)).expect("the correctly-spelled namespace must be accepted");
    }

    // GATE (delta 1) — a REFERENCED-BUT-ABSENT overlay fails loud NAMING THE PATH. `$VMCELL_PINS`
    // (or `--pins`) pointing at nothing is a configuration error, never "no overlay".
    // Red-on-inverse: `read_to_string(...).unwrap_or_default()` (or `.ok()`) silently resolves the
    // baseline and this `Err` match goes red.
    #[test]
    fn pins_overlay_referenced_but_absent_fails_loud_naming_the_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("no-such-overlay.json");
        let res = resolve_pins(Some(&missing));
        let Err(crate::error::Error::Artifact(msg)) = res else {
            panic!("an absent overlay must be a hard error, got {res:?}");
        };
        assert!(
            msg.contains("no-such-overlay.json"),
            "the failure must name the missing overlay, got {msg}"
        );
    }

    // A non-object overlay (`[...]`, `"str"`, `null`) has no top-level namespaces to check, so the
    // key check alone would wave it through and every override would silently vanish.
    // Red-on-inverse: drop the `as_object()` guard and this returns Ok.
    #[test]
    fn pins_overlay_rejects_non_object_document() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = write_overlay(tmp.path(), r#"["kernel"]"#);
        let res = resolve_pins(Some(&overlay));
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "a non-object overlay must be a hard error, got {res:?}"
        );
    }

    // The BASELINE keeps its ignore-unknown semantics — it is vmcell-committed, not caller input
    // (§10.2). This pins the asymmetry so a later "tidy-up" that makes one strict parser for both
    // cannot land silently. Red-on-inverse: route the baseline through `parse_pins_overlay` and the
    // unknown key becomes an error here.
    #[test]
    fn pins_baseline_keeps_ignore_unknown_semantics() {
        let map =
            parse_pins_json(r#"{ "kerne1": { "source_url": "x" }, "rootfs": { "image": "i" } }"#)
                .expect("the baseline parser must ignore an unknown top-level key");
        assert_eq!(map.get("rootfs_image").map(String::as_str), Some("i"));
        assert!(!map.contains_key("kernel_source_url"));
    }

    // One law, one predicate: the human-readable roster in the rejection message must agree with
    // the authority (`flatten_pins_namespace`'s dispatch), and the authority must cover every
    // namespace vmcell's own committed pins.json uses plus the `builder_base` pair
    // `resolve_builder_base` consumes. Red-on-inverse: drop an arm from the dispatch (or add a name
    // to the roster that the dispatch does not know) and this goes red.
    #[test]
    fn known_pins_namespace_roster_matches_the_flatten_dispatch() {
        for name in KNOWN_PINS_NAMESPACES {
            assert!(
                pins_namespace_shape(name).is_some(),
                "`{name}` is advertised in the rejection message but the flatten dispatch rejects it"
            );
        }
        let committed: serde_json::Value =
            serde_json::from_str(COMMITTED_PINS).expect("committed pins.json is valid JSON");
        for (name, value) in committed.as_object().expect("pins.json is an object") {
            let shape = pins_namespace_shape(name).unwrap_or_else(|| {
                panic!("the committed pins.json uses `{name}`, which an overlay could not override")
            });
            // The committed baseline must itself satisfy the shape the overlay is held to —
            // otherwise the strict parser would reject an overlay that merely restates a baseline
            // namespace, and the two documents would answer to different schemas.
            assert!(
                shape.matches(value),
                "the committed pins.json gives `{name}` a value the overlay parser would reject \
                 (expected {})",
                shape.describe()
            );
        }
        assert!(pins_namespace_shape("kerne1").is_none());
    }

    // GATE (delta 1 fix) — DISPATCH ⊆ ROSTER, the direction the roster test above cannot see. The
    // roster is only the rejection message's human-readable list, so an arm added to
    // `flatten_pins_namespace` without a roster entry leaves the error advertising an INCOMPLETE
    // "known namespaces" list — a downstream is then told its perfectly valid key is unknown. There
    // is no way to enumerate a `match`'s arms at runtime, so this scans the dispatch's own source
    // text (the fn is in this file). Red-on-inverse: add an arm (`"gremlin" => …`) to the dispatch
    // without adding it to `KNOWN_PINS_NAMESPACES` and this goes red naming `gremlin`.
    #[test]
    fn flatten_dispatch_arms_are_all_advertised_in_the_roster() {
        const SOURCE: &str = include_str!("mod.rs");
        let body = SOURCE
            .split_once("fn flatten_pins_namespace(")
            .expect("the dispatch is defined in this file")
            .1
            .split_once("match name {")
            .expect("the dispatch matches on `name`")
            .1;
        let mut arms: Vec<String> = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            // The catch-all closes the dispatch; everything after it is other code.
            if line.starts_with("_ =>") {
                break;
            }
            // An arm line is `"name" => {` or `"a" | "b" => {`; bodies and comments never start
            // with a quote.
            if !line.starts_with('"') {
                continue;
            }
            let Some((patterns, _)) = line.split_once("=>") else {
                continue;
            };
            for pat in patterns.split('|') {
                arms.push(pat.trim().trim_matches('"').to_string());
            }
        }
        // The scan itself must be able to fail: if it silently matched nothing, every assert below
        // would be vacuous.
        assert_eq!(
            arms.len(),
            KNOWN_PINS_NAMESPACES.len(),
            "the source scan found dispatch arms {arms:?} against roster {KNOWN_PINS_NAMESPACES:?}"
        );
        for name in &arms {
            assert!(
                KNOWN_PINS_NAMESPACES.contains(&name.as_str()),
                "the dispatch handles `{name}` but the rejection message does not advertise it, so \
                 a downstream using it would be told the roster is {KNOWN_PINS_NAMESPACES:?}"
            );
        }
    }

    // GATE (delta 1 fix) — ACCEPT-THEN-IGNORE ON A SCALAR NAMESPACE. `cloud_hypervisor` and
    // `virtiofsd` are bare strings, while every namespace the committed pins.json actually carries
    // (`kernel`, `kernels`, `kernel_prebuilt`, `rootfs`, `kernel_fragments`) is an object — so
    // `{"cloud_hypervisor": {"version": "46.0"}}` is the shape a downstream will guess. Before the
    // shape check that document was ACCEPTED and flattened to nothing: the CH build identity
    // silently vanished from the snapshot cache key (M-ART-7 stale-snapshot), with no
    // referenced-but-absent backstop because `snapshot.rs` folds the pin with `unwrap_or_default`.
    // Red-on-inverse: drop the `shape.matches(value)` check in `parse_pins_overlay` and the object
    // form is accepted again with `cloud_hypervisor` resolving to None.
    #[test]
    fn pins_overlay_rejects_wrong_shaped_scalar_namespace() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for ns in ["cloud_hypervisor", "virtiofsd"] {
            let overlay = write_overlay(
                tmp.path(),
                &format!(r#"{{ "{ns}": {{ "version": "46.0" }} }}"#),
            );
            let res = resolve_pins(Some(&overlay));
            let Err(crate::error::Error::Artifact(msg)) = res else {
                panic!(
                    "an object on the scalar namespace `{ns}` must be a hard error, got {res:?}"
                );
            };
            assert!(
                msg.contains(ns) && msg.contains("JSON string"),
                "the rejection must name the key and the expected shape, got {msg}"
            );
        }
        // Positive control: the RIGHT shape is accepted and actually resolves the pin, so the check
        // rejects the shape and not the namespace.
        let ok = write_overlay(tmp.path(), r#"{ "cloud_hypervisor": "46.0" }"#);
        let merged = resolve_pins(Some(&ok)).expect("a scalar override must be accepted");
        assert_eq!(
            merged.get("cloud_hypervisor").map(String::as_str),
            Some("46.0"),
            "the accepted shape must reach the pin map — otherwise the check moved the silence"
        );
    }

    // GATE (delta 1 fix) — THE WHOLE-NAMESPACE WIPE. `merge_pins_documents`' replace-outright arm
    // makes a scalar on an object namespace replace the namespace, dropping every baseline sibling
    // (`{"kernel": "https://…"}` wipes microvm_config AND source_sha256). It is unreachable only
    // because the shape check runs first — this pins that, plus the invariant it protects.
    // Red-on-inverse: drop the shape check and the document is accepted, `Missing
    // kernel_microvm_config pin` surfacing much later instead of here.
    #[test]
    fn pins_overlay_rejects_scalar_on_an_object_namespace() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = write_overlay(tmp.path(), r#"{ "kernel": "https://d.example/l.tar.xz" }"#);
        let res = resolve_pins(Some(&overlay));
        let Err(crate::error::Error::Artifact(msg)) = res else {
            panic!("a scalar on the object namespace `kernel` must be a hard error, got {res:?}");
        };
        assert!(
            msg.contains("kernel") && msg.contains("JSON object"),
            "the rejection must name the key and the expected shape, got {msg}"
        );
        // The baseline siblings the wipe would have dropped are still resolvable — the positive
        // control that the rejection protected something real.
        let baseline = resolve_pins(None).expect("baseline resolves");
        assert!(baseline.contains_key("kernel_microvm_config"));
        assert!(baseline.contains_key("kernel_source_sha256"));
    }

    // The `builder_base` namespace closes a consumed-but-unproducible hole: `resolve_builder_base`
    // prefers `builder_base_image`/`_digest` over the `rootfs_*` pair, but nothing emitted them.
    // Red-on-inverse: remove the `builder_base` arm and both the flatten and the
    // `resolve_builder_base` preference go red.
    #[cfg(feature = "pipeline")]
    #[test]
    fn pins_builder_base_namespace_feeds_resolve_builder_base() {
        let map = parse_pins_json(
            r#"{ "rootfs": { "image": "docker.io/library/debian", "digest": "sha256:aa" },
                 "builder_base": { "image": "docker.io/library/ubuntu", "digest": "sha256:bb" } }"#,
        )
        .expect("valid pins JSON");
        assert_eq!(
            map.get("builder_base_image").map(String::as_str),
            Some("docker.io/library/ubuntu")
        );
        let (img, dig) = crate::artifact::rootfs::resolve_builder_base(&map).expect("resolves");
        assert_eq!(
            (img.as_str(), dig.as_str()),
            ("docker.io/library/ubuntu", "sha256:bb")
        );
    }

    // GATE (delta 1) — the ONE pins fold, which `ResolvePinsStage::cache_key` AND
    // `fast_artifacts_fingerprint` (the `.build.stamp` short-circuit) both route through. Testing it
    // directly is how the fingerprint half gets coverage at all: that fn needs the whole workspace
    // source closure and the proxy CA, and reads `$VMCELL_PINS` from the process env.
    // Red-on-inverse: (a) drop the overlay branch and v1/v2/absent collapse onto one digest — an
    // overlay edit would leave a warm `.build.stamp` fresh and the pipeline skipped; (b) swap the
    // absent marker for `unwrap_or_default()`'s empty string and the empty-file case aliases it;
    // (c) make the unreadable case fold a marker instead of erroring and the `Err` assert goes red.
    #[test]
    fn fold_pins_identity_separates_absent_content_and_unreadable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = tmp.path().join("overlay.json");
        let fold = |path: Option<&Path>| -> Result<blake3::Hash> {
            let mut h = blake3::Hasher::new();
            fold_pins_identity(&mut h, path)?;
            Ok(h.finalize())
        };

        // A referenced-but-absent overlay is a hard error naming the path — never a silent fold.
        let err = fold(Some(&overlay)).expect_err("an absent overlay must fail loud");
        assert!(
            format!("{err}").contains("overlay.json"),
            "the fold error must name the overlay, got {err}"
        );

        let absent = fold(None).expect("no overlay folds");
        std::fs::write(&overlay, "").expect("write empty");
        let empty = fold(Some(&overlay)).expect("empty overlay folds");
        assert_ne!(
            absent, empty,
            "an empty overlay file must not alias the no-overlay marker"
        );

        std::fs::write(&overlay, r#"{ "rootfs": { "image": "v1" } }"#).expect("write v1");
        let v1 = fold(Some(&overlay)).expect("v1 folds");
        std::fs::write(&overlay, r#"{ "rootfs": { "image": "v2" } }"#).expect("write v2");
        let v2 = fold(Some(&overlay)).expect("v2 folds");
        assert_ne!(v1, v2, "editing the overlay must move the fold");
        assert_ne!(absent, v1, "an overlay must move the fold off the baseline");
        assert_eq!(v1, {
            std::fs::write(&overlay, r#"{ "rootfs": { "image": "v1" } }"#).expect("rewrite v1");
            fold(Some(&overlay)).expect("v1 folds")
        });
    }

    // GATE (delta 1) — GATE BLINDNESS #1: the `.build.stamp` short-circuit. `ensure_test_artifacts`
    // skips the ENTIRE fast pipeline when the stamp matches this fingerprint, so an overlay that
    // does not move the fingerprint is silently ignored in any warm workspace — accept-then-ignore
    // on the very surface the overlay exists to provide. Red-on-inverse: drop the
    // `fold_pins_identity` call from `fast_artifacts_fingerprint_with` and the two fingerprints
    // below become equal.
    #[cfg(feature = "pipeline")]
    #[test]
    fn fast_artifacts_fingerprint_moves_with_the_pins_overlay() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = tmp.path().join("overlay.json");
        std::fs::write(&overlay, r#"{ "rootfs": { "image": "downstream/base" } }"#).expect("write");

        let without = fast_artifacts_fingerprint_with(None).expect("fingerprint");
        let with = fast_artifacts_fingerprint_with(Some(&overlay)).expect("fingerprint");
        assert_ne!(
            without, with,
            "an overlay must move the fingerprint, or `.build.stamp` stays fresh and the pipeline \
             is skipped"
        );
        assert_eq!(
            with,
            fast_artifacts_fingerprint_with(Some(&overlay)).expect("fingerprint"),
            "the fingerprint must be stable for identical inputs"
        );
        // A referenced-but-absent overlay is a hard error here too, never a skipped fold.
        assert!(fast_artifacts_fingerprint_with(Some(&tmp.path().join("nope.json"))).is_err());
    }

    // GATE (delta 1) — AN OVERLAY EDIT INVALIDATES THE STAGE KEY. Four distinct states must yield
    // four distinct keys: no overlay, overlay v1, overlay v2 (edited), and a referenced-but-absent
    // overlay. Red-on-inverse: (a) drop the overlay fold from `cache_key` and v1/v2/absent all
    // collapse onto the no-overlay key — a warm workspace would serve pre-overlay artifacts;
    // (b) fold `unwrap_or_default()` instead of the distinct markers and the empty-overlay case
    // aliases the no-overlay case (asserted last).
    #[test]
    fn resolve_pins_stage_key_folds_the_overlay() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = tmp.path().join("overlay.json");
        let inputs = StageInputs::default();

        let none_key = ResolvePinsStage { overlay_file: None }.cache_key(&inputs);

        // A referenced-but-absent overlay is its own state, never the no-overlay state.
        let absent_key = ResolvePinsStage {
            overlay_file: Some(overlay.clone()),
        }
        .cache_key(&inputs);
        assert_ne!(
            none_key, absent_key,
            "an unreadable overlay must not hash as `no overlay`"
        );

        std::fs::write(
            &overlay,
            r#"{ "kernel": { "source_url": "https://d.example/v1" } }"#,
        )
        .expect("write v1");
        let v1 = ResolvePinsStage {
            overlay_file: Some(overlay.clone()),
        }
        .cache_key(&inputs);
        assert_ne!(none_key, v1, "an overlay must change the stage key");
        assert_ne!(absent_key, v1, "content must not hash as a read error");

        std::fs::write(
            &overlay,
            r#"{ "kernel": { "source_url": "https://d.example/v2" } }"#,
        )
        .expect("write v2");
        let v2 = ResolvePinsStage {
            overlay_file: Some(overlay.clone()),
        }
        .cache_key(&inputs);
        assert_ne!(v1, v2, "EDITING the overlay must re-resolve the stage");

        // Same bytes → same key (the fold is pure, cache-key rule 1/4).
        std::fs::write(
            &overlay,
            r#"{ "kernel": { "source_url": "https://d.example/v1" } }"#,
        )
        .expect("rewrite v1");
        assert_eq!(
            v1,
            ResolvePinsStage {
                overlay_file: Some(overlay.clone())
            }
            .cache_key(&inputs)
        );

        // An EMPTY overlay file is a fourth distinct state, not an alias of "no overlay".
        std::fs::write(&overlay, "").expect("write empty");
        let empty = ResolvePinsStage {
            overlay_file: Some(overlay),
        }
        .cache_key(&inputs);
        assert_ne!(
            none_key, empty,
            "an empty overlay file must not alias the no-overlay marker"
        );
    }
}
