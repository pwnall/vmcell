//! The **Unix-domain-socket transport** the daemon serves alongside its TCP bind (design §17, Open
//! gaps and future capabilities: "A UDS transport under `XDG_RUNTIME_DIR` (alongside the HTTP
//! bind)").
//!
//! Same router, same handlers, same auth: [`crate::server::serve_uds`] serves the value
//! [`crate::server::build_router`] returns, exactly as the TCP [`crate::server::serve`] does. What
//! this module owns is the *socket*: where it may live, what permissions guard it, what to do about
//! one that is already there, and removing it on the way out.
//!
//! # Where the socket lives
//!
//! Under `$XDG_RUNTIME_DIR` — a per-user, `0700`, tmpfs-backed directory the kernel cleans up at
//! logout — in a `vmcell/` subdirectory, never bare `/tmp` (AGENTS.md: runtime files under
//! `XDG_RUNTIME_DIR`, never bare `/tmp` on shared hosts; a socket in a world-writable sticky
//! directory can be pre-created or replaced by any local user). With `XDG_RUNTIME_DIR` unset there
//! is **no fallback**: [`uds_path_under_runtime_dir`] fails loud and names `--uds-path`, because
//! every candidate fallback is either world-writable or a guess about the operator's host.
//!
//! # Authentication: the API key is required here too
//!
//! **Stated as a decision, not an omission.** A UDS is guarded by filesystem permissions, and this
//! module makes those permissions real (a `0700` directory, a `0600` socket, both verified rather
//! than assumed). That is a genuine boundary — and it is not the same boundary the bearer key is:
//!
//! * The filesystem authenticates a **uid**, not a client. Every process running as the daemon's
//!   user inherits it: a browser extension, a build script, a compromised editor plugin. The key
//!   distinguishes "the operator's own tooling" from "anything at all running as the operator".
//! * Auth in this daemon is a property of the **router**, not of a transport (§11.6, Authentication
//!   — a bearer API key: one middleware over every route but two, so a new route is authenticated by
//!   default). A transport that dropped it would make the invariant per-transport — the shape law
//!   P5's parity gate exists to prevent — and the *route table* would no longer say who can reach a
//!   route.
//! * `--allow-unauthenticated` stays the single explicit opt-out, and it warns on **every** request
//!   on both transports. An operator who wants keyless local access says so and sees it in the log.
//!
//! So the socket permissions are defence in depth *under* the key, never a replacement for it.
//! `the_uds_transport_serves_the_same_authenticated_router` in [`crate::server`] is the gate.

use crate::error::DaemonError;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// The subdirectory of `$XDG_RUNTIME_DIR` the daemon's runtime files live in.
pub const UDS_DIR_NAME: &str = "vmcell";

/// The socket's file name inside [`UDS_DIR_NAME`].
pub const UDS_SOCKET_NAME: &str = "vmcelld.sock";

/// The mode the socket's parent directory must have: owner-only, no group or other bits.
///
/// One const, read by both the create and the verify path, so a directory this daemon makes and one
/// it finds are held to the same rule.
pub const UDS_DIR_MODE: u32 = 0o700;

/// The mode the socket itself is given after `bind`.
///
/// The directory is the real boundary (a socket cannot be reached without traversing it), but the
/// socket is narrowed too: a later `chmod` of the directory by an operator must not silently widen
/// what is inside it.
pub const UDS_SOCKET_MODE: u32 = 0o600;

/// The default socket path under `runtime_dir`: `<runtime_dir>/vmcell/vmcelld.sock`.
///
/// Takes the directory as a **parameter** rather than reading the environment, so the law is a pure
/// function the gates drive directly; the one environment read lives at the `vmcelld` call site.
///
/// # Errors
/// [`DaemonError::BadRequest`] when `runtime_dir` is absent or not absolute — with no `/tmp`
/// fallback, because a socket in a world-writable directory can be pre-created or replaced by any
/// local user, and a guessed path is worse than an explicit `--uds-path`.
pub fn uds_path_under_runtime_dir(runtime_dir: Option<PathBuf>) -> Result<PathBuf, DaemonError> {
    let Some(dir) = runtime_dir else {
        return Err(DaemonError::BadRequest(
            "XDG_RUNTIME_DIR is not set, so there is no per-user runtime directory to put the \
             control socket in. Pass --uds-path <path> explicitly (in a directory only you can \
             reach); vmcelld will not fall back to /tmp, where any local user could pre-create or \
             replace the socket."
                .to_string(),
        ));
    };
    if !dir.is_absolute() {
        return Err(DaemonError::BadRequest(format!(
            "XDG_RUNTIME_DIR is {dir:?}, which is not an absolute path; refusing to resolve the \
             control socket against a relative directory"
        )));
    }
    Ok(dir.join(UDS_DIR_NAME).join(UDS_SOCKET_NAME))
}

/// Removes the socket file when the daemon stops serving it — teardown is ownership, and a socket
/// left behind is what makes the *next* start-up have to reason about a stale one.
///
/// Best-effort by construction (the process may be exiting under a signal), but **logged**, never a
/// discarded `Result`.
#[derive(Debug)]
pub struct UdsPathGuard {
    path: PathBuf,
}

impl UdsPathGuard {
    /// The socket path this guard will remove.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UdsPathGuard {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                tracing::debug!(socket = %self.path.display(), "vmcelld: control socket removed")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                socket = %self.path.display(),
                error = %e,
                "vmcelld: could not remove the control socket; the next start-up will have to \
                 reclaim it as stale"
            ),
        }
    }
}

/// A bound control socket: the listener plus the guard that unlinks its path.
///
/// Deliberately **not** `Drop` itself, so [`crate::server::serve_uds`] can destructure it — the
/// listener has to move into `axum::serve` while the guard stays alive beside it for the whole
/// serve.
#[derive(Debug)]
pub struct UdsBinding {
    /// The bound listener.
    pub listener: tokio::net::UnixListener,
    /// The unlink-on-drop guard for the socket path.
    pub guard: UdsPathGuard,
}

/// Binds the control socket at `path`, creating and permission-checking its parent directory and
/// reclaiming a **stale** socket left by a hard-killed daemon.
///
/// The order is the whole point:
///
/// 1. **The directory first.** It is the boundary that matters — a socket is unreachable without
///    traversing its parent — so it is created `0700` (or verified `0700`) *before* anything is
///    bound. Verified, not assumed: a directory an operator widened to `0755` is refused with the
///    `chmod` that fixes it, exactly as the API-key file is (law P4).
/// 2. **A socket already at the path is asked, never assumed.** Connecting to it is the only honest
///    liveness test: a successful connect means another daemon is serving and this one refuses
///    (unlinking would silently steal a live daemon's socket); `ECONNREFUSED` means the file
///    outlived its process and is reclaimed, with a log line saying so. A path holding something
///    that is **not** a socket is refused outright — this function never unlinks a regular file.
/// 3. **Bind, then narrow.** `bind` creates the node under the process umask, so the mode is set
///    immediately afterwards; between the two, the `0700` directory is already the barrier.
///
/// # Panics
/// Must be called from inside a tokio runtime — `tokio::net::UnixListener::bind` registers the
/// socket with the reactor.
///
/// # Errors
/// [`DaemonError::AlreadyExists`] when a live daemon is serving there; [`DaemonError::BadRequest`]
/// for a path with no parent, a non-socket in the way, or a directory whose permissions are wider
/// than [`UDS_DIR_MODE`]; [`DaemonError::Internal`] for an I/O failure.
pub fn bind_uds(path: &Path) -> Result<UdsBinding, DaemonError> {
    let parent = path.parent().ok_or_else(|| {
        DaemonError::BadRequest(format!(
            "control socket path {path:?} has no parent directory"
        ))
    })?;
    ensure_private_dir(parent)?;
    reclaim_or_refuse_existing(path)?;

    let listener = tokio::net::UnixListener::bind(path).map_err(|e| {
        DaemonError::Internal(format!("cannot bind the control socket at {path:?}: {e}"))
    })?;
    // Narrow the node the bind created under whatever umask this process has.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(UDS_SOCKET_MODE)).map_err(
        |e| DaemonError::Internal(format!("cannot restrict the control socket {path:?}: {e}")),
    )?;
    Ok(UdsBinding {
        listener,
        guard: UdsPathGuard {
            path: path.to_path_buf(),
        },
    })
}

/// Creates `dir` mode [`UDS_DIR_MODE`], or verifies an existing one is no wider.
///
/// `create_dir_all` then `set_permissions` rather than a mode-carrying create: the parents above the
/// last component (`$XDG_RUNTIME_DIR` itself) are not ours to re-mode, and only the leaf we own is
/// narrowed.
fn ensure_private_dir(dir: &Path) -> Result<(), DaemonError> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| {
            DaemonError::Internal(format!(
                "cannot create the control-socket directory {dir:?}: {e}"
            ))
        })?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(UDS_DIR_MODE)).map_err(
            |e| {
                DaemonError::Internal(format!(
                    "cannot restrict the control-socket directory {dir:?}: {e}"
                ))
            },
        )?;
        return Ok(());
    }
    let meta = std::fs::metadata(dir).map_err(|e| {
        DaemonError::Internal(format!(
            "cannot read the control-socket directory {dir:?}: {e}"
        ))
    })?;
    if !meta.is_dir() {
        return Err(DaemonError::BadRequest(format!(
            "the control socket's parent {dir:?} is not a directory"
        )));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & !UDS_DIR_MODE != 0 {
        return Err(DaemonError::BadRequest(format!(
            "the control-socket directory {dir:?} is mode {mode:04o}; anyone who can traverse it \
             can reach the socket. Run `chmod {UDS_DIR_MODE:o} {}` (or pass --uds-path pointing \
             somewhere only you can reach).",
            dir.display()
        )));
    }
    Ok(())
}

/// Decides what to do about a path that is already occupied: refuse a live daemon's socket, reclaim
/// a stale one, refuse anything that is not a socket at all.
fn reclaim_or_refuse_existing(path: &Path) -> Result<(), DaemonError> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(()); // Nothing there — the common case.
    };
    if !meta.file_type().is_socket() {
        return Err(DaemonError::BadRequest(format!(
            "{path:?} exists and is not a socket; vmcelld will not remove it. Choose another \
             --uds-path or delete it yourself."
        )));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_live) => Err(DaemonError::AlreadyExists(format!(
            "another daemon is already serving on {path:?}; stop it, or pass a different --uds-path"
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            tracing::info!(
                socket = %path.display(),
                "vmcelld: reclaiming a stale control socket (nothing is listening on it)"
            );
            std::fs::remove_file(path).map_err(|e| {
                DaemonError::Internal(format!(
                    "cannot remove the stale control socket {path:?}: {e}"
                ))
            })
        }
        // Any other errno — EACCES, ENOTCONN, a path we cannot even ask about — is "I could not
        // tell", and unlinking on "I could not tell" is how a live daemon loses its socket.
        Err(e) => Err(DaemonError::BadRequest(format!(
            "a socket already exists at {path:?} and its liveness could not be determined ({e}); \
             refusing to remove it"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The path law: the socket lives under `$XDG_RUNTIME_DIR/vmcell/`, and an absent or relative
    // runtime dir is a LOUD refusal naming the flag — never a silent `/tmp` fallback, which is the
    // one thing AGENTS.md forbids by name for runtime files on a shared host.
    //
    // RED on the inverse: give the `None` arm a `/tmp/vmcell` default and the second leg's
    // `expect_err` fails.
    #[test]
    fn the_socket_path_is_under_the_runtime_dir_and_never_falls_back_to_tmp() {
        let path = uds_path_under_runtime_dir(Some(PathBuf::from("/run/user/1000")))
            .expect("an absolute runtime dir resolves");
        assert_eq!(path, Path::new("/run/user/1000/vmcell/vmcelld.sock"));

        let err = uds_path_under_runtime_dir(None).expect_err("no runtime dir, no default");
        let msg = err.message();
        assert!(
            msg.contains("XDG_RUNTIME_DIR") && msg.contains("--uds-path") && msg.contains("/tmp"),
            "the refusal must name the variable, the flag, and why /tmp is not it: {msg}"
        );

        assert!(
            uds_path_under_runtime_dir(Some(PathBuf::from("relative/dir"))).is_err(),
            "a relative runtime dir is refused"
        );
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    // The permissions law, asserted on the filesystem the bind actually touched: the directory is
    // created 0700 and the socket lands 0600.
    //
    // The **control** is what keeps it non-vacuous: a bare `UnixListener::bind` in the same
    // directory, under this process's own umask, must NOT already be 0600 — otherwise the umask,
    // not the code, is producing the mode and the assertion below would pass on a `bind_uds` with no
    // `set_permissions` at all. The control asserts that condition rather than assuming it, so a
    // hostile umask (0177) reddens the gate instead of hollowing it.
    //
    // RED on the inverse: drop the `set_permissions` after `bind` in `bind_uds`.
    #[tokio::test]
    async fn binding_creates_a_private_directory_and_a_private_socket() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let control_path = tmp.path().join("control.sock");
        let control = std::os::unix::net::UnixListener::bind(&control_path).expect("control bind");
        assert_ne!(
            mode_of(&control_path),
            UDS_SOCKET_MODE,
            "this process's umask already yields {UDS_SOCKET_MODE:04o} for a bare bind, so the              assertion below cannot tell the chmod from the umask — the gate is vacuous under this              umask, not passing"
        );
        drop(control);

        let path = tmp.path().join("vmcell").join("vmcelld.sock");
        let binding = bind_uds(&path).expect("bind");

        assert_eq!(mode_of(&path), UDS_SOCKET_MODE, "the socket is owner-only");
        assert_eq!(
            mode_of(path.parent().expect("parent")),
            UDS_DIR_MODE,
            "the directory that guards it is owner-only"
        );
        assert!(path.exists());

        // Teardown is ownership: dropping the binding unlinks the socket.
        drop(binding);
        assert!(
            !path.exists(),
            "the socket must be removed when the daemon stops serving it"
        );
    }

    // A parent directory anyone can traverse is REFUSED with the chmod that fixes it, and the
    // positive control is the same bind after that chmod — so the refusal is about the mode, not
    // about the path.
    //
    // RED on the inverse: drop the `mode & !UDS_DIR_MODE` check and the first leg binds happily
    // inside a world-traversable directory.
    #[tokio::test]
    async fn a_world_traversable_directory_is_refused_and_the_same_path_binds_once_narrowed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("vmcell");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
        let path = dir.join("vmcelld.sock");

        let err = bind_uds(&path).expect_err("a 0755 directory is refused");
        let msg = err.message();
        assert!(
            msg.contains("0755") && msg.contains("chmod"),
            "the refusal names the mode it found and the fix: {msg}"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod 700");
        let binding = bind_uds(&path).expect("the positive control binds");
        drop(binding);
    }

    // The occupied-path law, both answers in one gate. A socket with a LIVE listener is refused
    // (unlinking it would steal a running daemon's transport); a socket whose process is gone is
    // reclaimed. The two differ only in whether the first listener is still alive, which is what
    // makes this a positive control for the reclaim rather than two unrelated legs.
    //
    // RED on the inverse: unlink unconditionally before binding, and the first leg succeeds — the
    // second daemon steals the socket out from under the first.
    #[tokio::test]
    async fn a_live_socket_is_refused_and_a_stale_one_is_reclaimed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("vmcell").join("vmcelld.sock");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::set_permissions(
            path.parent().expect("parent"),
            std::fs::Permissions::from_mode(UDS_DIR_MODE),
        )
        .expect("chmod");

        let live = std::os::unix::net::UnixListener::bind(&path).expect("first listener");
        let err = bind_uds(&path).expect_err("a live socket is not stolen");
        assert!(matches!(err, DaemonError::AlreadyExists(_)), "{err}");

        // The listener goes away without unlinking — a hard-killed daemon's residue.
        drop(live);
        assert!(path.exists(), "the stale socket file outlives its listener");
        let binding = bind_uds(&path).expect("the stale socket is reclaimed");
        drop(binding);
    }

    // A regular file in the way is refused, never unlinked: `--uds-path` is operator input, and a
    // typo pointing at a real file must not delete it.
    //
    // RED on the inverse: replace the `is_socket` check with an unconditional remove.
    #[tokio::test]
    async fn a_regular_file_in_the_way_is_refused_and_left_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("vmcell");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(UDS_DIR_MODE))
            .expect("chmod");
        let path = dir.join("precious.txt");
        std::fs::write(&path, b"not a socket").expect("write");

        assert!(bind_uds(&path).is_err(), "a non-socket is refused");
        assert_eq!(
            std::fs::read(&path).expect("still there"),
            b"not a socket",
            "and is left exactly as it was"
        );
    }
}
