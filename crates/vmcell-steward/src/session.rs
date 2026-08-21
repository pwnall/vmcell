//! Interactive sessions: PTY and pipe, stdin routing, window resize, and per-session teardown.
//!
//! Placement-blind (design §3.5). PTY sessions depend on `/dev/pts`, which the `Pid1` assembly
//! mounts best-effort; under `Service` the guest's own init owns that mount, and an absent
//! `/dev/pts` fails the session loud with `SessionExit(127)` exactly as it does under `Pid1`.

use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use vmcell_protocol::{self as protocol, Message, SessionId, SessionSpec};

use crate::exec::build_command;
use crate::serve::{Sessions, Writer, join_pump, poll_timeout, send_msg, send_msg_best_effort};
use crate::{ReaperCoordinator, ServeContext};

// ===========================================================================
// Interactive sessions (§3, The control plane: vsock, the host clients, and the steward): PTY / pipe sessions, streaming stdin,
// window resize, and multiplexed concurrent execs over one connection.
// ===========================================================================

/// Where a session's streamed stdin is delivered (§3, The control plane: vsock, the host clients, and the steward). A pipe session
/// writes to the child's stdin pipe (dropping it on `StdinEof` closes it → the
/// child reads EOF); a PTY session writes to the pseudo-terminal master (bytes
/// arrive as terminal input). The PTY master `Arc<OwnedFd>` is shared with
/// [`SessionHandle::pty_master`] so `Stdin` and `Winsize` use the same fd. Owned
/// solely by the session's stdin writer thread (M6).
pub(crate) enum StdinSink {
    /// A pipe session's child-stdin write end (the `ChildStdin` taken as its raw
    /// [`OwnedFd`], so both arms write through the one fd path below).
    Pipe(OwnedFd),
    /// A PTY session's pseudo-terminal master.
    Pty(Arc<OwnedFd>),
}

impl StdinSink {
    /// The fd this sink writes to. One accessor so `poll`+`write` always agree on
    /// the target (one law, one predicate).
    fn fd(&self) -> BorrowedFd<'_> {
        match self {
            StdinSink::Pipe(fd) => fd.as_fd(),
            StdinSink::Pty(fd) => fd.as_fd(),
        }
    }
}

/// A queued host→guest stdin item for one session's writer thread (M6). `Eof`
/// travels through the SAME queue as the bytes, so it closes the pipe only after
/// everything queued ahead of it has been written — an out-of-band close would
/// truncate the child's input.
pub(crate) enum StdinItem {
    /// Bytes from a `Stdin` frame.
    Data(Vec<u8>),
    /// The host's `StdinEof`, for a **pipe** session only. A PTY session never
    /// enqueues one: [`route_stdin_eof`] refuses it at the routing boundary
    /// ([`SessionHandle::accepts_stdin_eof`]).
    Eof,
}

/// How long a session's stdin writer thread waits for its sink to accept bytes
/// before re-checking [`SessionHandle::stdin_closing`] (M6). Long enough that a
/// healthy stream costs one `poll` per chunk, short enough that connection
/// teardown's join is bounded even when the child never drains its stdin.
pub(crate) const STDIN_POLL_SLICE: Duration = Duration::from_millis(100);

/// Per-`write(2)` cap on a session's stdin (M6). `PIPE_BUF`: the kernel reports a
/// pipe writable only once a whole free page is available, so a chunk this size
/// cannot block after `poll` said go, and a PTY master's terminal input queue is
/// the same 4096 bytes.
pub(crate) const STDIN_CHUNK_BYTES: usize = 4096;

/// The live state of one interactive session, keyed by [`SessionId`] in the
/// per-connection [`Sessions`] table.
#[derive(Debug)]
pub(crate) struct SessionHandle {
    /// The queue feeding this session's stdin writer thread (M6). Unbounded and
    /// fed only by the *trusted host's own* sessions (design §3, recorded trade
    /// §17); `send` never blocks, so the dispatch loop can no longer be wedged by
    /// a child that stopped reading its stdin.
    pub(crate) stdin_tx: std::sync::mpsc::Sender<StdinItem>,
    /// Set by [`SessionHandle::shutdown_stdin`] so a writer thread parked on a
    /// full pipe or terminal gives up within one [`STDIN_POLL_SLICE`], making the
    /// teardown join bounded.
    pub(crate) stdin_closing: Arc<AtomicBool>,
    /// The stdin writer thread, joined by teardown so no thread outlives the
    /// connection that opened the session.
    pub(crate) stdin_writer: JoinHandle<()>,
    /// The PTY master for `Winsize`, or `None` for a pipe session.
    pub(crate) pty_master: Option<Arc<OwnedFd>>,
    /// The child's process-group id (== its pid: `setsid` for a PTY session,
    /// `process_group(0)` for a pipe session), used by `CloseSession`/timeout/
    /// connection-teardown to `kill(-pgid)` the whole group.
    pub(crate) pid: u32,
}

impl SessionHandle {
    /// Builds a session's handle, spawning the stdin writer thread that owns
    /// `stdin` (M6). The one place a handle is constructed, so both the pipe and
    /// the PTY path get the same stdin discipline.
    pub(crate) fn new(
        session: SessionId,
        stdin: Option<StdinSink>,
        pty_master: Option<Arc<OwnedFd>>,
        pid: u32,
    ) -> Self {
        let (stdin_tx, stdin_rx) = std::sync::mpsc::channel();
        let stdin_closing = Arc::new(AtomicBool::new(false));
        let stdin_writer = spawn_stdin_writer(session, stdin, stdin_rx, Arc::clone(&stdin_closing));
        Self {
            stdin_tx,
            stdin_closing,
            stdin_writer,
            pty_master,
            pid,
        }
    }

    /// Whether this session's stdin can be **half-closed** — the guest-side half of
    /// the one stdin-half-close law (§17, Open gaps and future capabilities).
    ///
    /// True for a pipe session: dropping the child's stdin write end is a real
    /// half-close, and the child reads EOF. False for a PTY session: a
    /// pseudo-terminal has no write-side half-close at all. The only thing that
    /// even resembles one is the line discipline's `VEOF` character, and it is not
    /// a half-close — it means end-of-input only to a reader that happens to be in
    /// canonical mode *at that instant*, and is delivered as a literal byte to any
    /// other (a raw-mode reader would receive `0x04` as data). The mode can change
    /// between the check and the write, so even a mode-discriminating variant
    /// could not be made correct. The facility is absent, so it is refused rather
    /// than approximated (§7.2, The fail-loud capability contract and HostCapabilities).
    ///
    /// This is the ONE place pty-ness answers that question in the guest;
    /// [`session_stdin_route`] is its one call site, so `route_stdin_eof` cannot
    /// re-derive it. The host end refuses the same operation *before the wire*
    /// (`vmcell::steward::session::Session::supports_stdin_close`), so a
    /// conforming client never sends a PTY `StdinEof` at all — what reaches here
    /// is a non-conforming client, and it is refused loud rather than discarded.
    pub(crate) fn accepts_stdin_eof(&self) -> bool {
        self.pty_master.is_none()
    }

    /// Stops this session's stdin writer thread and joins it (M6) — the one place
    /// that sequence lives. Flag it closing (a writer parked on a full pipe or
    /// terminal gives up within one [`STDIN_POLL_SLICE`]), drop the queue's last
    /// sender (so a drained writer's `recv` ends), then join so no thread leaks.
    /// Callers `kill_group` first, which is what makes the pending write fail
    /// immediately in the common case.
    pub(crate) fn shutdown_stdin(self) {
        self.stdin_closing.store(true, Ordering::Relaxed);
        drop(self.stdin_tx);
        if self.stdin_writer.join().is_err() {
            // Not `unwrap`: a panicked writer thread must not take PID 1 with it.
            tracing::warn!("vmcell-steward: session stdin writer thread panicked");
        }
    }
}

/// Runs one session's stdin writer thread (M6): drains the queue and performs the
/// blocking writes **off** the connection's dispatch loop. Pre-fix these writes
/// were inline, so a child that stopped reading a full 64 KiB pipe blocked the
/// whole connection — `CloseSession` was never dispatched and, on host
/// disconnect, `serve_loop` never returned, so [`teardown_sessions`] (the
/// connection-owns-its-sessions law, §13) never ran and the child outlived its
/// connection.
///
/// Ends on a write failure (the child is gone), on `closing`, or when the last
/// sender is dropped — never on a decode/lookup path, so it cannot panic PID 1.
pub(crate) fn spawn_stdin_writer(
    session: SessionId,
    mut sink: Option<StdinSink>,
    rx: std::sync::mpsc::Receiver<StdinItem>,
    closing: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while let Ok(item) = rx.recv() {
            match item {
                StdinItem::Data(data) => {
                    let Some(current) = sink.as_ref() else {
                        // Stdin already closed by an earlier `StdinEof`: drop the
                        // bytes, exactly as the pre-M6 `guard.as_mut()` no-op did.
                        continue;
                    };
                    if let Err(e) = write_stdin_sink(current, &data, &closing) {
                        tracing::debug!(
                            "vmcell-steward: stdin write to session {:?} failed: {}",
                            session,
                            e
                        );
                        break;
                    }
                }
                // Pipe: drop the write end → the child reads EOF, but only now
                // that every byte queued ahead of this item has been written.
                //
                // The PTY arm is belt-and-braces, not a second copy of the law:
                // `route_stdin_eof` refuses a PTY session's `StdinEof` at the
                // routing boundary (`SessionHandle::accepts_stdin_eof`), so one
                // cannot reach this queue. If a future edit let one through,
                // dropping the master here would silently swallow every LATER
                // `Stdin` byte for that session (the `sink.as_ref()` arm above
                // treats a taken sink as already closed) — so keep the terminal
                // and say so loud instead.
                StdinItem::Eof => match sink.take() {
                    None | Some(StdinSink::Pipe(_)) => {}
                    Some(pty @ StdinSink::Pty(_)) => {
                        tracing::warn!(
                            "vmcell-steward: StdinEof reached PTY session {:?}'s writer thread; a pseudo-terminal has no stdin half-close, keeping the terminal open",
                            session
                        );
                        sink = Some(pty);
                    }
                },
            }
        }
        // Dropping `sink` closes a pipe session's write end (the child reads EOF)
        // and releases this thread's PTY-master `Arc` clone.
    })
}

/// Maps a `rows`×`cols` window into the kernel [`Winsize`](rustix::termios::Winsize)
/// the guest installs via `TIOCSWINSZ`.
///
/// Split out as a pure function so the field mapping (`rows`→`ws_row`,
/// `cols`→`ws_col`) is unit-tested: a swapped assignment reddens
/// `winsize_from_maps_rows_and_cols` without a live PTY (mirrors
/// [`resync_timespec`]).
pub(crate) fn winsize_from(rows: u16, cols: u16) -> rustix::termios::Winsize {
    rustix::termios::Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// `SIGKILL`s a process group by its leader pid (`kill(-pgid)`), the shared
/// group-kill law used by the one-shot timeout, session `CloseSession`/timeout,
/// and connection teardown (§13, Cross-cutting invariants). A non-existent group is a silent no-op.
pub(crate) fn kill_group(pid: u32) {
    use rustix::process::{Pid, Signal, kill_process_group};
    if let Some(p) = Pid::from_raw(pid.cast_signed()) {
        // This IS the one shared group-kill law, so the discard lives here and nowhere else. A
        // failure is `ESRCH` (the group is already gone — the outcome wanted) or `EPERM`; neither
        // is actionable, and every caller is on a teardown path with no channel to report on.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the one shared group-kill law: ESRCH is the wanted outcome and no caller has a channel to report on"
        )]
        let _ = kill_process_group(p, Signal::KILL);
    }
}

/// Reports a session that could not be opened (bad argv, spawn or PTY-allocation
/// failure) the same way the one-shot path reports a spawn failure — one
/// terminal-frame convention (§13, Cross-cutting invariants): `SessionStderr{msg}` then
/// `SessionExit{127}`.
pub(crate) fn open_failed(writer: &Writer, session: SessionId, msg: &str) {
    tracing::warn!("vmcell-steward: session {:?} open failed: {}", session, msg);
    send_msg_best_effort(
        writer,
        &Message::SessionStderr {
            session,
            data: msg.as_bytes().to_vec(),
        },
    );
    send_msg_best_effort(writer, &Message::SessionExit { session, code: 127 });
}

/// Registers a session's handle in the per-connection table, **rejecting** a
/// duplicate of a still-live id: the new handle comes back in the `Err` so the
/// caller can abandon the session it just opened.
///
/// The host is authoritative and monotonic, so a repeated id is a protocol
/// violation, not a normal event. The pre-fix insert *displaced* the live entry,
/// which is the worse of the two failures: the displaced session's own waiter
/// thread later removes `id` from the table — now the **new** session's entry — so
/// its `Stdin`/`Winsize`/`CloseSession` all silently stop resolving while its
/// child keeps running. Refusing the duplicate leaves the live session
/// untouched, and the caller reports the refusal through the one terminal-frame
/// convention ([`open_failed`]).
pub(crate) fn register_session(
    sessions: &Sessions,
    id: SessionId,
    handle: SessionHandle,
) -> Result<(), SessionHandle> {
    use std::collections::hash_map::Entry;
    let mut table = sessions.lock().unwrap_or_else(|e| e.into_inner());
    match table.entry(id) {
        Entry::Occupied(_) => {
            tracing::warn!(
                "vmcell-steward: session id {:?} is already live; refusing the duplicate",
                id
            );
            Err(handle)
        }
        Entry::Vacant(slot) => {
            slot.insert(handle);
            Ok(())
        }
    }
}

/// Abandons a session whose child has already been spawned: kill its process
/// group, release the reaper reservation that spawn took, and report the failure
/// through the one terminal-frame convention ([`open_failed`]).
///
/// **One helper for every post-spawn failure path**, so none of them can forget
/// the reservation: `reserve` records an entry that only a `wait_for` consumes,
/// and these paths spawn no waiter — the un-pruned reservation map would grow one
/// entry per failure and leave a stale epoch on a pid the kernel later reuses.
pub(crate) fn abandon_spawned_session(
    writer: &Writer,
    session: SessionId,
    reaper: &Arc<ReaperCoordinator>,
    pid: u32,
    msg: &str,
) {
    kill_group(pid);
    reaper.cancel_reservation(pid);
    open_failed(writer, session, msg);
}

/// Spawns a reader thread that pumps a child stream to the host, wrapping each
/// chunk into the session-tagged [`Message`] `wrap` produces and emitting it
/// through the single [`Writer`] (§13, Cross-cutting invariants). Ends on EOF, any read error (a PTY
/// master returns `EIO` once the child closes its slave — end of stream), or a
/// write failure (the connection died).
pub(crate) fn spawn_pump<R, F>(mut reader: R, writer: Writer, wrap: F) -> JoinHandle<()>
where
    R: Read + Send + 'static,
    F: Fn(Vec<u8>) -> Message + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // `read` guarantees n <= buf.len(); `get(..n)` is the non-panicking
                    // spelling of that (indexing_slicing is denied in PID-1 code).
                    let chunk = buf.get(..n).unwrap_or_default().to_vec();
                    if send_msg(&writer, &wrap(chunk)).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

/// Arms an optional kill thread for a session: if `timeout` is `Some`, `SIGKILL`
/// the process group after it elapses unless the child already exited. `None`
/// leaves the session **persistent** (§3.3, Interactive-session wire semantics) — bounded instead by
/// `CloseSession`, the child exiting, or connection teardown (§13, Cross-cutting invariants).
pub(crate) fn arm_session_timeout(
    timeout: Option<Duration>,
    pid: u32,
    has_exited: Arc<AtomicBool>,
) {
    let Some(t) = timeout else {
        return;
    };
    std::thread::spawn(move || {
        std::thread::sleep(t);
        if !has_exited.load(Ordering::Relaxed) {
            kill_group(pid);
        }
    });
}

/// Spawns the waiter thread that claims a session's exit code from the shared
/// reaper, then — after **joining the pump(s)** so all output precedes the exit
/// (§13, Cross-cutting invariants) — emits the terminal `SessionExit` and removes the session from the
/// table. No `child.wait()` here, so the reaper's status cannot be stolen (the
/// false-127 race).
pub(crate) fn spawn_session_waiter(
    reaper: &Arc<ReaperCoordinator>,
    pid: u32,
    has_exited: Arc<AtomicBool>,
    pumps: Vec<JoinHandle<()>>,
    writer: Writer,
    session: SessionId,
    sessions: Sessions,
) {
    let reaper = Arc::clone(reaper);
    std::thread::spawn(move || {
        let code = reaper.wait_for(pid);
        has_exited.store(true, Ordering::Relaxed);
        for pump in pumps {
            join_pump(pump);
        }
        send_msg_best_effort(&writer, &Message::SessionExit { session, code });
        sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session);
    });
}

/// Opens an interactive session (§3, The control plane: vsock, the host clients, and the steward): builds the command, then
/// dispatches to the PTY or pipe path per `spec.pty`.
pub(crate) fn run_session(
    session: SessionId,
    spec: SessionSpec,
    writer: &Writer,
    sessions: &Sessions,
    ctx: &Arc<ServeContext>,
) {
    let Some(cmd) = build_command(&spec.command, &ctx.tools_dir) else {
        open_failed(writer, session, "empty argv");
        return;
    };
    let timeout = spec.command.timeout;
    match spec.pty {
        Some(pty) => run_pty_session(session, cmd, pty, timeout, writer, sessions, ctx),
        None => run_pipe_session(session, cmd, timeout, writer, sessions, ctx),
    }
}

/// Runs a pipe (non-PTY) session: piped stdin/stdout/stderr, streamable stdin,
/// separate `SessionStdout`/`SessionStderr` channels.
pub(crate) fn run_pipe_session(
    session: SessionId,
    mut cmd: Command,
    timeout: Option<Duration>,
    writer: &Writer,
    sessions: &Sessions,
    ctx: &Arc<ServeContext>,
) {
    let reaper = &ctx.reaper;
    cmd.process_group(0);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let epoch = reaper.pre_spawn_epoch();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            open_failed(writer, session, &format!("failed to spawn command: {e}"));
            return;
        }
    };
    let stdin = child.stdin.take();
    let pid = child.id();
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        abandon_spawned_session(
            writer,
            session,
            reaper,
            pid,
            "failed to capture child stdio",
        );
        return;
    };
    reaper.reserve(pid, epoch);

    if let Err(rejected) = register_session(
        sessions,
        session,
        // The `ChildStdin` becomes a bare `OwnedFd` owned by the session's stdin
        // writer thread (M6) — one fd write path for both sink kinds.
        SessionHandle::new(session, stdin.map(|s| StdinSink::Pipe(s.into())), None, pid),
    ) {
        abandon_spawned_session(writer, session, reaper, pid, "session id is already in use");
        rejected.shutdown_stdin();
        return;
    }

    let out = spawn_pump(stdout, Arc::clone(writer), move |data| {
        Message::SessionStdout { session, data }
    });
    let err = spawn_pump(stderr, Arc::clone(writer), move |data| {
        Message::SessionStderr { session, data }
    });
    let has_exited = Arc::new(AtomicBool::new(false));
    arm_session_timeout(timeout, pid, Arc::clone(&has_exited));
    spawn_session_waiter(
        reaper,
        pid,
        has_exited,
        vec![out, err],
        Arc::clone(writer),
        session,
        Arc::clone(sessions),
    );
}

/// Allocates a pseudo-terminal pair: the `CLOEXEC` master (kept by the steward) and
/// the slave path from `ptsname` (opened by the caller for the child). `grantpt`
/// is a Linux no-op but is called for POSIX faithfulness; `unlockpt` is required.
pub(crate) fn open_pty() -> rustix::io::Result<(OwnedFd, std::ffi::CString)> {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let slave_path = ptsname(&master, Vec::new())?;
    Ok((master, slave_path))
}

/// The `login_tty` sequence, run in the child's `pre_exec` (§3, The control plane: vsock, the host clients, and the steward): make
/// the child a session leader (`setsid`, so its pgid == its pid and it has no
/// controlling terminal), adopt the pty slave as its controlling terminal
/// (`TIOCSCTTY`), and wire the slave onto stdin/stdout/stderr. Every call is an
/// async-signal-safe raw syscall via `rustix`; the slave is `CLOEXEC`, so after
/// these `dup2`s it closes at `execve`, leaving only fds 0/1/2 on the terminal.
pub(crate) fn login_tty(slave_fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `slave_fd` is the pty slave fd, opened by the parent and inherited
    // into this child across the `fork` that `Command::spawn` performed; it is a
    // live, valid fd here. We only borrow it non-owningly for the syscalls below
    // (no close), so no aliasing OwnedFd exists.
    let slave = unsafe { BorrowedFd::borrow_raw(slave_fd) };
    rustix::process::setsid()?;
    rustix::process::ioctl_tiocsctty(slave)?;
    rustix::stdio::dup2_stdin(slave)?;
    rustix::stdio::dup2_stdout(slave)?;
    rustix::stdio::dup2_stderr(slave)?;
    Ok(())
}

/// Runs a PTY session: allocate a controlling-terminal pseudo-terminal, run the
/// command as a session leader on it (`isatty()` true, resizable), and pump the
/// single merged master stream back as `SessionStdout` (§13, Cross-cutting invariants).
pub(crate) fn run_pty_session(
    session: SessionId,
    mut cmd: Command,
    pty: protocol::PtyConfig,
    timeout: Option<Duration>,
    writer: &Writer,
    sessions: &Sessions,
    ctx: &Arc<ServeContext>,
) {
    use rustix::fs::{Mode, OFlags};

    let reaper = &ctx.reaper;
    let (master, slave_path) = match open_pty() {
        Ok(v) => v,
        Err(e) => {
            open_failed(writer, session, &format!("pty allocation failed: {e}"));
            return;
        }
    };
    // Open the slave CLOEXEC: it is inherited into the child by the fork (CLOEXEC
    // does not affect fork), used by `login_tty` in `pre_exec`, then closed at
    // `execve` — so the exec'd program keeps only fds 0/1/2 on the terminal.
    let slave = match rustix::fs::open(
        slave_path.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(s) => s,
        Err(e) => {
            open_failed(writer, session, &format!("pty slave open failed: {e}"));
            return;
        }
    };
    // Best-effort initial window size before the child starts.
    if let Err(e) = rustix::termios::tcsetwinsize(&master, winsize_from(pty.rows, pty.cols)) {
        tracing::debug!("vmcell-steward: initial winsize failed: {}", e);
    }

    // No `process_group(0)`: `setsid` in `login_tty` creates the new session and
    // process group (a would-be group leader cannot `setsid`, so the two are
    // mutually exclusive). The pgid still ends == the child pid.
    let slave_raw = slave.as_raw_fd();
    // SAFETY: the pre_exec closure runs only `login_tty`, which performs solely
    // async-signal-safe syscalls (setsid/TIOCSCTTY/dup2) on the inherited slave
    // fd and allocates nothing — the async-signal-safety obligation of `pre_exec`.
    unsafe {
        cmd.pre_exec(move || login_tty(slave_raw));
    }

    let epoch = reaper.pre_spawn_epoch();
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            open_failed(writer, session, &format!("failed to spawn command: {e}"));
            return;
        }
    };
    // The parent must drop its slave so the master EOFs (Linux: `EIO`) once the
    // child — the last slave holder — exits, letting the pump end (§13, Cross-cutting invariants).
    drop(slave);

    let pid = child.id();
    reaper.reserve(pid, epoch);

    // One master fd read by the pump; a shared `Arc<OwnedFd>` for stdin writes +
    // winsize. `try_clone` is `F_DUPFD_CLOEXEC`, so the pump's copy is CLOEXEC too.
    let master_read = match master.try_clone() {
        Ok(m) => std::fs::File::from(m),
        Err(e) => {
            // The child is already spawned and reserved: abandon it through the one
            // helper so the reservation is released with it (nothing else ever
            // would — this path spawns no waiter).
            abandon_spawned_session(
                writer,
                session,
                reaper,
                pid,
                &format!("pty master clone failed: {e}"),
            );
            return;
        }
    };
    let master_arc = Arc::new(master);
    if let Err(rejected) = register_session(
        sessions,
        session,
        SessionHandle::new(
            session,
            Some(StdinSink::Pty(Arc::clone(&master_arc))),
            Some(Arc::clone(&master_arc)),
            pid,
        ),
    ) {
        abandon_spawned_session(writer, session, reaper, pid, "session id is already in use");
        rejected.shutdown_stdin();
        return;
    }

    let pump = spawn_pump(master_read, Arc::clone(writer), move |data| {
        Message::SessionStdout { session, data }
    });
    let has_exited = Arc::new(AtomicBool::new(false));
    arm_session_timeout(timeout, pid, Arc::clone(&has_exited));
    spawn_session_waiter(
        reaper,
        pid,
        has_exited,
        vec![pump],
        Arc::clone(writer),
        session,
        Arc::clone(sessions),
    );
}

/// Waits (bounded by [`STDIN_POLL_SLICE`]) for a stdin sink to accept bytes.
/// `Ok(false)` is "not yet" — the caller loops and re-checks its `closing` flag.
/// Any `revents` at all is a go-ahead: `POLLOUT` means room, and
/// `POLLERR`/`POLLHUP` (the reader is gone) means the `write(2)` below fails loud
/// with the real errno instead of spinning here.
pub(crate) fn stdin_sink_ready(fd: BorrowedFd<'_>) -> std::io::Result<bool> {
    use rustix::event::{PollFd, PollFlags};

    let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
    let timeout = poll_timeout(STDIN_POLL_SLICE);
    match rustix::event::poll(&mut fds, Some(&timeout)) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::INTR) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Writes all of `data` to a session's stdin sink from that session's own writer
/// thread (M6), never blocking indefinitely: each pass re-checks `closing`, waits
/// for the sink to accept bytes, then writes at most [`STDIN_CHUNK_BYTES`].
/// Partial writes are looped and `EINTR`/`EAGAIN` retried (B10: counts are
/// handled). Fails once the sink is gone (`EPIPE` on a pipe whose child died,
/// `EIO` on a PTY master whose slave closed) or the session is tearing down, so
/// the writer thread ends instead of pinning a dead fd.
///
/// Poll-and-chunk rather than `O_NONBLOCK`: a PTY session's output pump reads a
/// `try_clone` of the same master, which shares the open file description — so
/// setting `O_NONBLOCK` here would turn every pump read into `EAGAIN` and
/// silently kill the session's output. Polling gives the same bounded wait
/// without touching the fd's status flags.
pub(crate) fn write_stdin_sink(
    sink: &StdinSink,
    mut data: &[u8],
    closing: &AtomicBool,
) -> std::io::Result<()> {
    let fd = sink.fd();
    while !data.is_empty() {
        if closing.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "session stdin closing",
            ));
        }
        if !stdin_sink_ready(fd)? {
            continue;
        }
        let chunk = data
            .get(..data.len().min(STDIN_CHUNK_BYTES))
            .unwrap_or_default();
        match rustix::io::write(fd, chunk) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => data = data.get(n..).unwrap_or_default(),
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Everything a host→guest stdin frame needs from a live session's handle (M6),
/// read out under ONE table lock so a `Stdin` and a `StdinEof` for the same
/// session can never disagree about what that session is.
pub(crate) struct StdinRoute {
    /// The queue feeding that session's stdin writer thread.
    pub(crate) tx: std::sync::mpsc::Sender<StdinItem>,
    /// [`SessionHandle::accepts_stdin_eof`] for this session, evaluated at the one
    /// site that evaluates it: `true` for a pipe session, `false` for a PTY.
    pub(crate) accepts_eof: bool,
}

/// Looks up a session's stdin route, releasing the table lock before returning it
/// (M6). A frame for an unknown/closed session is dropped at debug — the session
/// simply already ended.
pub(crate) fn session_stdin_route(sessions: &Sessions, session: SessionId) -> Option<StdinRoute> {
    let table = sessions.lock().unwrap_or_else(|e| e.into_inner());
    match table.get(&session) {
        Some(h) => Some(StdinRoute {
            tx: h.stdin_tx.clone(),
            accepts_eof: h.accepts_stdin_eof(),
        }),
        None => {
            tracing::debug!(
                "vmcell-steward: stdin frame for unknown/closed session {:?}; dropping",
                session
            );
            None
        }
    }
}

/// Routes a `Stdin` frame to its session (§3, The control plane: vsock, the host clients, and the steward). ENQUEUES the bytes on
/// the session's stdin queue and returns immediately (M6): the blocking write
/// happens on that session's writer thread, so a child that stopped reading its
/// stdin can no longer stall the dispatch loop — and with it `CloseSession` and
/// the connection-owns-its-sessions teardown (§13).
pub(crate) fn route_stdin(sessions: &Sessions, session: SessionId, data: Vec<u8>) {
    let Some(route) = session_stdin_route(sessions, session) else {
        return;
    };
    // Never a silent drop: the only failure is a writer thread that has already
    // ended (its sink died), which is the same condition the pre-M6 inline write
    // reported at debug.
    if route.tx.send(StdinItem::Data(data)).is_err() {
        tracing::debug!(
            "vmcell-steward: stdin queue for session {:?} is closed; dropping",
            session
        );
    }
}

/// Routes a `StdinEof` frame (§3, The control plane: vsock, the host clients, and the steward): closes a **pipe** session's stdin
/// (dropping the write end → the child reads EOF), sequenced through the SAME
/// queue as the bytes (M6), so the pipe closes only after everything already
/// queued has been written — an out-of-band close would truncate the child's
/// input.
///
/// **A PTY session's `StdinEof` is REFUSED here, loud** (§17, Open gaps and future capabilities):
/// a pseudo-terminal has no stdin half-close, so there is nothing to honor —
/// see [`SessionHandle::accepts_stdin_eof`] for why an approximation (the
/// termios `VEOF` byte) would be worse than the refusal. The refusal is a `warn`
/// because the guest has no per-frame error reply: the wire protocol's only
/// guest→host session frames are `SessionStdout`/`SessionStderr`/`SessionExit`,
/// and reporting in-band would inject steward prose into the caller's terminal
/// stream. It costs nothing in practice — the host end refuses this operation
/// *before* the wire, so only a non-conforming client can produce the frame this
/// arm logs. What it must never be is what it was: enqueued, then silently
/// discarded by the writer thread (an accepted input that was neither honored
/// nor rejected).
pub(crate) fn route_stdin_eof(sessions: &Sessions, session: SessionId) {
    let Some(route) = session_stdin_route(sessions, session) else {
        return;
    };
    if !route.accepts_eof {
        tracing::warn!(
            "vmcell-steward: refusing StdinEof for PTY session {:?}: a pseudo-terminal has no stdin half-close (end input in-band or CloseSession)",
            session
        );
        return;
    }
    if route.tx.send(StdinItem::Eof).is_err() {
        tracing::debug!(
            "vmcell-steward: stdin queue for session {:?} is closed; EOF is already implied",
            session
        );
    }
}

/// Routes a `Winsize` frame (§3, The control plane: vsock, the host clients, and the steward): installs the new window on a PTY
/// session's master (`TIOCSWINSZ`, delivering `SIGWINCH`); a debug no-op for a
/// pipe session.
pub(crate) fn route_winsize(sessions: &Sessions, session: SessionId, rows: u16, cols: u16) {
    let master = {
        let table = sessions.lock().unwrap_or_else(|e| e.into_inner());
        match table.get(&session) {
            Some(h) => h.pty_master.clone(),
            None => return,
        }
    };
    match master {
        Some(master) => {
            if let Err(e) = rustix::termios::tcsetwinsize(&*master, winsize_from(rows, cols)) {
                tracing::debug!(
                    "vmcell-steward: winsize for session {:?} failed: {}",
                    session,
                    e
                );
            }
        }
        None => tracing::debug!(
            "vmcell-steward: winsize for non-pty session {:?}; ignoring",
            session
        ),
    }
}

/// Routes a `CloseSession` frame (§3, The control plane: vsock, the host clients, and the steward): `SIGKILL`s the session's
/// process group. The waiter observes the resulting exit, emits `SessionExit`,
/// and removes the entry — so no double-remove here.
pub(crate) fn close_session(sessions: &Sessions, session: SessionId) {
    let pid = {
        let table = sessions.lock().unwrap_or_else(|e| e.into_inner());
        match table.get(&session) {
            Some(h) => h.pid,
            None => return,
        }
    };
    kill_group(pid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    /// A fresh one-entry session table over `sink`, with `pty_master` set exactly
    /// as the production PTY path sets it — the field
    /// [`SessionHandle::accepts_stdin_eof`] reads. `pid` is 0: these tests never
    /// take the kill/teardown path, so no signal is ever sent.
    fn table_with(sink: StdinSink, pty_master: Option<Arc<OwnedFd>>) -> (Sessions, SessionId) {
        let id = SessionId(0);
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        sessions
            .lock()
            .expect("a fresh table's lock is never poisoned")
            .insert(id, SessionHandle::new(id, Some(sink), pty_master, 0));
        (sessions, id)
    }

    /// Reads whatever the pty slave has, waiting until `deadline` for the writer
    /// thread to deliver it. The slave is `O_NONBLOCK`, so `EAGAIN` is "nothing
    /// yet" — the bound is on the WHOLE wait, not on the gaps between polls.
    fn read_slave_until(slave: BorrowedFd<'_>, deadline: Instant) -> Vec<u8> {
        let mut buf = [0u8; 256];
        loop {
            match rustix::io::read(slave, &mut buf) {
                Ok(0) => panic!("the pty slave saw EOF: nothing may close this terminal"),
                Ok(n) => return buf.get(..n).unwrap_or_default().to_vec(),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    assert!(
                        Instant::now() < deadline,
                        "the pty slave never received the routed stdin bytes"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("pty slave read failed: {e}"),
            }
        }
    }

    // §17 (Open gaps and future capabilities), the PTY half-close law, guest end: a
    // `StdinEof` for a PTY session is REFUSED — nothing is written to the terminal
    // and the terminal stays open. Data-plane on a REAL pty (rubric A10): the
    // assertion is on the bytes the slave (the "child") actually reads, not on a
    // queue or a log line.
    //
    // RED on both inverses:
    //  * option (a), "send the termios VEOF": the slave's canonical line discipline
    //    turns that byte into an end-of-input, so the read returns Ok(0) and
    //    `read_slave_until`'s EOF panic fires — and the post-EOF leg below could
    //    never run.
    //  * the shipped-before-this-change behavior (enqueue, then discard in the
    //    writer thread) is what the third leg pins: with the `sink.take()` arm made
    //    unconditional, the master sink is dropped, every LATER byte is discarded as
    //    "stdin already closed", and the final `read_slave_until` times out.
    #[test]
    fn pty_stdin_eof_is_refused_and_the_terminal_stays_open() {
        use rustix::fs::{Mode, OFlags};

        let (master, slave_path) = open_pty().expect("a pty pair (needs /dev/ptmx)");
        let slave = rustix::fs::open(
            slave_path.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect("open the pty slave");
        let master = Arc::new(master);
        let (sessions, id) = table_with(
            StdinSink::Pty(Arc::clone(&master)),
            Some(Arc::clone(&master)),
        );

        // (1) Terminal input works: the routed line reaches the slave.
        route_stdin(&sessions, id, b"before\n".to_vec());
        assert_eq!(
            read_slave_until(slave.as_fd(), Instant::now() + Duration::from_secs(5)),
            b"before\n".to_vec(),
            "a PTY session's routed stdin must reach the terminal"
        );

        // (2) The refusal: no byte at all is delivered for the `StdinEof` — in
        // particular not a `VEOF` (0x04), which this terminal's canonical line
        // discipline would turn into an end-of-input for the reader.
        route_stdin_eof(&sessions, id);
        std::thread::sleep(Duration::from_millis(300));
        let mut buf = [0u8; 256];
        match rustix::io::read(slave.as_fd(), &mut buf) {
            Err(rustix::io::Errno::AGAIN) => {}
            Ok(0) => panic!("StdinEof must not end the terminal's input: the slave read EOF"),
            Ok(n) => panic!(
                "StdinEof must deliver NO bytes to a PTY; got {:?}",
                buf.get(..n).unwrap_or_default()
            ),
            Err(e) => panic!("pty slave read failed: {e}"),
        }

        // (3) The positive control for the refusal: the session is untouched, so a
        // LATER byte still reaches the terminal. This is the leg the pre-change
        // "enqueue it and let the writer thread discard it" shape could break.
        route_stdin(&sessions, id, b"after\n".to_vec());
        assert_eq!(
            read_slave_until(slave.as_fd(), Instant::now() + Duration::from_secs(5)),
            b"after\n".to_vec(),
            "a refused StdinEof must leave the session's stdin fully usable"
        );
    }

    // The POSITIVE CONTROL for the leg above, and the pipe half of the same law: a
    // pipe session's `StdinEof` IS honored — the child's stdin write end closes and
    // the reader sees EOF, after every queued byte. RED if the refusal were widened
    // to every session (the read would block past the deadline and never EOF).
    #[test]
    fn pipe_stdin_eof_is_honored_and_the_child_reads_eof() {
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let (sessions, id) = table_with(StdinSink::Pipe(writer.into()), None);

        route_stdin(&sessions, id, b"payload".to_vec());
        route_stdin_eof(&sessions, id);
        // Drop the table so the handle's last queue sender goes with it; the writer
        // thread ends once drained, exactly as it does when a session's waiter
        // removes its own entry.
        drop(sessions);

        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("read to EOF");
        assert_eq!(
            got,
            b"payload".to_vec(),
            "a pipe session's StdinEof must close the write end AFTER every queued byte"
        );
    }

    // The CALL-SITE half of the guest-end law (§13, Cross-cutting invariants): the
    // legs above pin the behavior, and this pins that the behavior cannot be
    // re-derived somewhere else. `accepts_stdin_eof` is the one predicate and
    // `session_stdin_route` its one call site, so a future `route_stdin_eof` cannot
    // grow its own pty test that drifts from it; and `StdinItem::Eof` may enter the
    // queue only AFTER that guard. Source-scanning, KVM-free: it reads this file,
    // stopping at the test module so these tests' own text cannot satisfy it.
    //
    // RED on the inverse: move the `accepts_eof` check below the `route.tx.send`
    // (the ordering assert), or add a second `.accepts_stdin_eof()` call site / a
    // second `StdinItem::Eof` enqueue (the count asserts).
    #[test]
    fn stdin_eof_is_enqueued_only_through_the_one_pty_refusing_predicate() {
        let src = include_str!("session.rs");
        let cut = src
            .find("\n#[cfg(test)]\n")
            .expect("the test module marks the end of the production source");
        let prod = src.get(..cut).unwrap_or_default();

        let calls = prod.matches(".accepts_stdin_eof()").count();
        assert_eq!(
            calls, 1,
            "`accepts_stdin_eof` is the ONE guest-side answer to \"does this session have a stdin \
             half-close?\"; found {calls} call sites"
        );
        let route_at = prod
            .find("pub(crate) fn session_stdin_route(")
            .expect("`session_stdin_route` is the one lookup");
        assert!(
            prod.get(route_at..)
                .unwrap_or_default()
                .contains(".accepts_stdin_eof()"),
            "the one call site must be inside `session_stdin_route`, read under the table lock"
        );

        let eof_at = route_at
            + prod
                .get(route_at..)
                .unwrap_or_default()
                .find("fn route_stdin_eof(")
                .expect("`route_stdin_eof` must follow the lookup it uses");
        let body = prod.get(eof_at..).unwrap_or_default();
        let guard = body
            .find("if !route.accepts_eof")
            .expect("`route_stdin_eof` must guard on the predicate's answer");
        let enqueue = body
            .find("send(StdinItem::Eof)")
            .expect("`route_stdin_eof` is the one place an Eof is enqueued");
        assert!(
            guard < enqueue,
            "the PTY refusal must come BEFORE the enqueue, or a PTY's Eof reaches the queue again"
        );
        assert_eq!(
            prod.matches("send(StdinItem::Eof)").count(),
            1,
            "exactly one site may enqueue a StdinEof — the one that refuses a PTY first"
        );
    }
}
