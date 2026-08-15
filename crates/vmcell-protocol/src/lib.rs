//! Framed postcard wire protocol shared by the vmcell host and the guest agent.
//!
//! This is the *only* code the host (`vmcell::agent::AgentClient`) and the guest
//! PID-1 agent (`vmcell-guest-agent`) share — extracting it into its own crate is
//! what lets the guest agent be a standalone, host-stack-free workspace member
//! (§8.1, Workspace layout). It defines the messages exchanged over the vsock connection and
//! the framing bound both ends must agree on.
//!
//! It carries one non-wire item for the same reason: [`GUEST_TOOLS_APPLETS`], the
//! host↔guest **agreement** on the multicall applet roster. `vmcell-guest-tools` links
//! this crate for that const alone; it speaks no protocol.
#![forbid(unsafe_code)]
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        // B10: production guest/network-derived values narrow with `try_from`, never `as` (wire
        // crate). Test vectors may still build byte patterns with `as` — the repo's lenient-in-tests
        // idiom (clippy.toml allow-*-in-tests, AGENTS.md; see docs/implementation-notes.md).
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use serde::{Deserialize, Serialize};

/// Maximum length, in bytes, of a single framed control-plane message.
///
/// Both ends of the vsock protocol must agree on this bound: the host
/// `AgentClient` configures its `LengthDelimitedCodec` with it (its 8 MiB
/// default would otherwise reject a frame the guest is willing to send) and the
/// guest agent's hand-rolled framing rejects anything larger. Keeping the two in
/// one constant prevents the asymmetric-cap class where one side silently drops
/// a frame the other accepts.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// How much of a value's `{:?}` render a log line may carry.
///
/// Every desync diagnostic on this control plane quotes a **frame**, and a frame is
/// bounded only by [`MAX_FRAME_BYTES`] (16 MiB) with a payload the peer chooses. The
/// guest agent's own logs land on the *persisted* serial-console artifact, so an
/// uncapped `{other:?}` there lets a peer write 16 MiB — rendered as `[1, 2, 3, …]`
/// decimal, several times that again — into an artifact every later run reads; the
/// host sites have the same shape at a smaller blast radius. 256 bytes still shows
/// the variant name, the session id, and the head of the payload — enough to
/// identify the frame in a desync report — while staying ~65 000× below the frame
/// cap.
///
/// It lives here, beside `MAX_FRAME_BYTES`, because the cap on what a frame may
/// carry and the cap on what a log may quote from one are a single law: the guest
/// agent and both host clients share this one const and [`capped_debug`], never a
/// per-site copy (docs/78 §6, `uncapped-frame-debug-renders`).
pub const MAX_DEBUG_RENDER_BYTES: usize = 256;

/// What [`capped_debug`] appends when the cap stopped the formatter, so a truncated
/// render is never mistaken for a whole value — and so a caller's *test* can assert
/// truncation against the same string the renderer emits, rather than a second copy
/// of the literal.
pub const DEBUG_TRUNCATED_MARKER: &str = "…<truncated>";

/// `{value:?}`, truncated at [`MAX_DEBUG_RENDER_BYTES`] and marked as truncated so a
/// reader never mistakes a capped render for the whole value.
///
/// The formatter is **stopped** at the cap rather than the value being rendered in
/// full and then trimmed: [`core::fmt::Write`] returning `Err` aborts the formatting,
/// so the tail is never rendered at all, not merely never kept. That bounds the CPU
/// as well as the allocation a peer-chosen 16 MiB frame can cost a log line — the
/// guest agent is PID 1, and a diagnostic must not become a work amplifier for
/// whatever the peer sends.
///
/// The trade-off that buys: the *total* render length is unknowable without
/// rendering it, so the output carries [`DEBUG_TRUNCATED_MARKER`] rather than a
/// total, and every call site — each of which holds the encoded frame — quotes the
/// frame's true byte count beside the render. That is the more useful number anyway
/// (wire bytes, not decimal-`Debug` bytes).
#[must_use]
pub fn capped_debug(value: &dyn core::fmt::Debug) -> String {
    use core::fmt::Write as _;

    struct CappedSink {
        out: String,
    }
    impl core::fmt::Write for CappedSink {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let room = MAX_DEBUG_RENDER_BYTES.saturating_sub(self.out.len());
            if room == 0 {
                return Err(core::fmt::Error);
            }
            if s.len() <= room {
                self.out.push_str(s);
                Ok(())
            } else {
                // Truncate on a char boundary, then stop the whole format.
                let mut end = room;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                self.out.push_str(s.get(..end).unwrap_or_default());
                Err(core::fmt::Error)
            }
        }
    }

    let mut sink = CappedSink { out: String::new() };
    // The cap stopping the formatter is the expected outcome, not a failure: it is
    // reported to the reader as the marker rather than swallowed. A `Debug` impl of
    // its own that errors lands here too, and the same marker is the honest answer —
    // the render is incomplete either way.
    if write!(sink, "{value:?}").is_err() {
        sink.out.push_str(DEBUG_TRUNCATED_MARKER);
    }
    sink.out
}

/// Default per-exec timeout applied when an [`ExecRequest`] does not set one.
///
/// The host applies this as its own wait bound and propagates it into the
/// request before sending, so the guest always installs a kill thread. Without
/// this, a `None` timeout would let a runaway guest child outlive the host's
/// abandoned wait and leak.
pub const DEFAULT_EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The **one** guest-tools multicall applet roster: every exec-PATH name the
/// `vmcell-guest-tools` binary dispatches, in injection order.
///
/// Design §4.4 requires the guest binary's dispatch table and the host's
/// `vmcell::artifact::rootfs` injection manifest to agree. They were independent literals,
/// so a one-sided edit stayed green: a `/vmcell-tools/<name>` symlink with no dispatch arm
/// prints a usage error and exits 2 — and because `echo-server` is also used as a custom
/// `init=` target, an exit-2 PID 1 is an immediate guest kernel panic. That regression
/// shipped twice (docs/81 m22), so the roster lives here, in the one crate both sides link,
/// and **both sides derive from it**:
///
/// * `vmcell-guest-tools` sizes its dispatch table to `GUEST_TOOLS_APPLETS.len()` and
///   `const`-asserts the names element-wise, so a one-sided edit is a *compile* error.
/// * `vmcell`'s `rootfs_injection_manifest` emits exactly one `/vmcell-tools/<name>`
///   symlink per entry — there is no name literal on that side to edit at all.
///
/// Order is the injection order and the dispatch-table order; it carries no other meaning.
/// Names must be unique (the dispatch lookup is first-match) — pinned by
/// `guest_tools_applet_roster_is_unique_and_non_empty`.
pub const GUEST_TOOLS_APPLETS: &[&str] = &["ip", "curl", "kvm-ok", "echo-server"];

/// IPv4 reconfiguration the guest applies to `eth0` during a post-restore resync
/// (H-VMM-1 — "rotate everything").
///
/// A snapshot is a *zygote*: one suspended VM is resumed into many concurrent
/// children, each of which must have a **distinct** network identity (its own
/// netns/tap/`/30`/MAC/IP) so they don't collide on the host. The restore path
/// therefore rotates the vmid — but the guest resumes with the *frozen* `ip=`
/// address of the original vmid, which no longer matches its rotated host-side
/// tap/`/30` wiring. This message re-points the guest's `eth0` address and default
/// route to the rotated identity, exactly as the `mac` field re-points the
/// hardware address. Octets are carried verbatim (endianness-free on the wire).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Reconfig {
    /// The guest's new `eth0` address (e.g. `10.200.<m>.2`).
    pub addr: [u8; 4],
    /// The subnet prefix length (`30` for the point-to-point `/30`).
    pub prefix_len: u8,
    /// The new default-route gateway — the host side of the `/30`
    /// (e.g. `10.200.<m>.1`).
    pub gateway: [u8; 4],
}

/// A stable identity for one interactive session on a host↔guest connection
/// (§3.3, Interactive-session wire semantics).
///
/// The host is authoritative for the ids on its own connection: `SessionMux`
/// hands out monotonically increasing values, and every session data/control
/// frame carries the id so the guest and host can multiplex many concurrent
/// sessions over one vsock connection. `Copy`/`Ord`/`Hash` so it keys the
/// per-connection session tables on both ends.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u64);

/// The initial window size of a PTY session's pseudo-terminal (§3.3, Interactive-session wire semantics).
///
/// Carried in [`SessionSpec::pty`] as the terminal's `rows`×`cols` at open time;
/// the host can change it mid-session with [`Message::Winsize`]. `u16` matches the
/// kernel `struct winsize` (`ws_row`/`ws_col`) the guest installs via `TIOCSWINSZ`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtyConfig {
    /// Number of character rows.
    pub rows: u16,
    /// Number of character columns.
    pub cols: u16,
}

/// What to run in an interactive session, and how (§3.3, Interactive-session wire semantics).
///
/// Reuses [`ExecRequest`] for the command line, environment, working directory,
/// and optional kill deadline — one shape for "what to run", not a second copy.
/// `pty: Some(_)` allocates a controlling-terminal pseudo-terminal (merged
/// stdout+stderr, `isatty()` true in-guest, resizable); `pty: None` uses pipes
/// (separate stdout/stderr, streamable stdin).
///
/// The embedded [`ExecRequest::timeout`] keeps its uniform meaning — *an optional
/// kill deadline; `None` = no deadline* (§3.3, Interactive-session wire semantics). Unlike the one-shot `exec()`
/// path (which fills `None → DEFAULT_EXEC_TIMEOUT` before sending so a runaway
/// child cannot outlive an abandoned host wait), the session path leaves `None`
/// as `None`: an interactive session is *persistent* and is bounded instead by
/// [`Message::CloseSession`], the child exiting, or connection teardown.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionSpec {
    /// The command to run (argv/env/cwd/optional kill deadline).
    pub command: ExecRequest,
    /// `Some` allocates a PTY with this initial window size; `None` uses pipes.
    pub pty: Option<PtyConfig>,
}

impl SessionSpec {
    /// Creates a pipe (non-PTY) session spec for the given command.
    #[must_use]
    pub fn new(command: ExecRequest) -> Self {
        Self { command, pty: None }
    }

    /// Turns this into a PTY session with the given initial window size.
    #[must_use]
    pub fn with_pty(mut self, rows: u16, cols: u16) -> Self {
        self.pty = Some(PtyConfig { rows, cols });
        self
    }
}

/// A message exchanged between the host and the guest agent.
///
/// **Append-only.** `postcard` encodes each variant by its zero-based
/// declaration index, so the variant order is part of the wire protocol: new
/// variants must be *appended* and existing ones never reordered or removed, or
/// the host and guest would disagree on the discriminant. `#[non_exhaustive]`
/// keeps out-of-crate matches from silently breaking when a variant is appended.
/// The one-shot exec path (`Exec`/`Stdout`/`Stderr`/`Exit`, indices 1–4) is
/// distinct from the channelized interactive-session path (`OpenSession`…
/// `SessionExit`, indices 8–15, §3.3, Interactive-session wire semantics): the former carries no
/// [`SessionId`] and runs one exchange per connection; the latter multiplexes
/// many concurrent sessions, each frame keyed by its id.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// Agent is ready to accept commands.
    Ready,
    /// Request to execute a command.
    Exec(ExecRequest),
    /// Standard output data from a command.
    Stdout(Vec<u8>),
    /// Standard error data from a command.
    Stderr(Vec<u8>),
    /// Exit code of a completed command.
    Exit(i32),
    /// Request to place a file at a destination path.
    PutFile {
        /// Destination path in the guest.
        dst: String,
        /// File contents.
        bytes: Vec<u8>,
    },
    /// Host→guest one-shot post-restore resync request (§8.2, Restore correctness: a restored VM is not a fresh VM).
    ///
    /// A snapshot resumes at the frozen instant, so the host drives one native
    /// in-agent resync — replacing the three post-restore subprocess execs
    /// (`date` / `head -c 32 /dev/hwrng` / `ip link set`). It carries the host
    /// wall-clock instant the guest must set `CLOCK_REALTIME` to and an optional
    /// new `eth0` MAC to install; one request elicits exactly one
    /// [`Message::ResyncAck`].
    Resync {
        /// Whole seconds since the Unix epoch for the guest `CLOCK_REALTIME` set.
        unix_secs: u64,
        /// Sub-second nanoseconds component of the target realtime clock.
        unix_nanos: u32,
        /// Optional new `eth0` hardware address to install via `SIOCSIFHWADDR`;
        /// `None` skips the MAC rotation.
        mac: Option<[u8; 6]>,
        /// Optional new `eth0` IPv4 address + default route to install (H-VMM-1);
        /// `None` skips the IP rotation. The restore/zygote path rotates the vmid
        /// so the guest's frozen `ip=` address no longer matches its rotated
        /// host-side tap/`/30` wiring — this re-points it, exactly as `mac`
        /// re-points the hardware address. Appended after `mac` (per-variant
        /// field order is part of the postcard wire encoding).
        ipv4: Option<Ipv4Reconfig>,
    },
    /// Guest→host acknowledgement of a [`Message::Resync`], reporting each step's
    /// outcome (§8.2, Restore correctness: a restored VM is not a fresh VM).
    ///
    /// The clock set is mandatory: `clock_error` is `Some(msg)` iff it failed
    /// (the host treats that as a hard, retryable failure and does not clear its
    /// restored flag). The CSPRNG reseed and MAC rotation are best-effort, with
    /// `reseed_applied` / `mac_applied` reporting whether each took effect.
    ResyncAck {
        /// `Some(err)` iff the mandatory `CLOCK_REALTIME` set failed; `None` on
        /// success.
        clock_error: Option<String>,
        /// Whether the best-effort `/dev/hwrng`→`/dev/urandom` reseed applied.
        reseed_applied: bool,
        /// Whether the best-effort `eth0` MAC rotation applied.
        mac_applied: bool,
        /// Whether the best-effort `eth0` IPv4 address + default-route rotation
        /// applied (H-VMM-1). Appended after `mac_applied`.
        ip_applied: bool,
    },
    /// Host→guest: open a new interactive session (§3.3, Interactive-session wire semantics). The guest
    /// spawns the command per `spec` (PTY or pipes), registers it under
    /// `session`, and streams `SessionStdout`/`SessionStderr` then a terminal
    /// `SessionExit`, all keyed by `session`. A failed open is reported as
    /// `SessionStderr` + `SessionExit(127)` (the one-shot spawn-failure
    /// convention); there is no separate open-ack, so the host may send `Stdin`/
    /// `Winsize` for `session` immediately after (the single ordered stream
    /// guarantees this frame is processed first).
    OpenSession {
        /// The host-chosen id for the new session.
        session: SessionId,
        /// What to run, and whether on a PTY.
        spec: SessionSpec,
    },
    /// Host→guest: feed stdin bytes to a running session (§3.3, Interactive-session wire semantics). For a
    /// pipe session the bytes go to the child's stdin; for a PTY session they go
    /// to the master (arriving as terminal input). Bounded by `MAX_FRAME_BYTES`.
    Stdin {
        /// The target session.
        session: SessionId,
        /// The stdin bytes to deliver.
        data: Vec<u8>,
    },
    /// Host→guest: close a session's stdin (§3.3, Interactive-session wire semantics). For a pipe session
    /// the child's stdin write end is dropped, so the child reads EOF; for a PTY
    /// session this is a no-op (closing the master would tear down output — a PTY
    /// caller ends input with an in-band EOT or `CloseSession`).
    StdinEof {
        /// The target session.
        session: SessionId,
    },
    /// Host→guest: resize a PTY session's window (§3.3, Interactive-session wire semantics). Installs the
    /// new `rows`×`cols` via `TIOCSWINSZ`, delivering `SIGWINCH` to the session's
    /// foreground process group. A no-op for a pipe session.
    Winsize {
        /// The target session.
        session: SessionId,
        /// New number of character rows.
        rows: u16,
        /// New number of character columns.
        cols: u16,
    },
    /// Host→guest: terminate a session (§3.3, Interactive-session wire semantics). The guest `SIGKILL`s the
    /// session's process group; the resulting exit is reported as the session's
    /// terminal `SessionExit`.
    CloseSession {
        /// The target session.
        session: SessionId,
    },
    /// Guest→host: standard output (or merged PTY output) from a session
    /// (§3.3, Interactive-session wire semantics).
    SessionStdout {
        /// The originating session.
        session: SessionId,
        /// The output bytes.
        data: Vec<u8>,
    },
    /// Guest→host: standard error from a *pipe* session (§3.3, Interactive-session wire semantics). A PTY
    /// session merges stderr into `SessionStdout`, so it never emits this.
    SessionStderr {
        /// The originating session.
        session: SessionId,
        /// The error-stream bytes.
        data: Vec<u8>,
    },
    /// Guest→host: a session's exit code — its **terminal** frame (§3.3,
    /// Interactive-session wire semantics). Exactly one is sent per opened session, after all output, and no
    /// further frame carries that `session`.
    SessionExit {
        /// The session that exited.
        session: SessionId,
        /// The process exit code (`128 + signal` for a signal-terminated child,
        /// `127` for a failed spawn/PTY-allocation).
        code: i32,
    },
}

/// A request to execute a command inside the guest VM.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecRequest {
    /// The command line arguments (e.g., `["ls", "-l"]`).
    pub argv: Vec<String>,
    /// Environment variables to set.
    pub env: Vec<(String, String)>,
    /// Optional working directory.
    pub cwd: Option<String>,
    /// Per-exec timeout. If None, a sane default is used.
    pub timeout: Option<std::time::Duration>,
}

impl ExecRequest {
    /// Creates a new `ExecRequest` with the given arguments.
    #[must_use]
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            env: vec![],
            cwd: None,
            timeout: None,
        }
    }

    /// Sets the environment variables.
    #[must_use]
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets the timeout for the request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// The result of executing a command inside the guest VM.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecOutcome {
    /// The exit code of the process.
    pub code: i32,
    /// Standard output of the process.
    pub stdout: Vec<u8>,
    /// Standard error of the process.
    pub stderr: Vec<u8>,
}

impl ExecOutcome {
    /// Creates an outcome with the given exit `code` and captured streams.
    ///
    /// A constructor is provided because [`ExecOutcome`] is `#[non_exhaustive]`:
    /// callers in other crates (the orchestrator, test doubles) cannot use a
    /// struct literal, so this keeps their call sites stable as fields grow.
    #[must_use]
    pub fn new(code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            code,
            stdout,
            stderr,
        }
    }
}

impl Default for ExecOutcome {
    /// Creates an outcome with code `-1` — a sentinel for "no exit code was
    /// observed yet", deliberately outside the `0..=255` range any real process
    /// exit status occupies, so a defaulted outcome that is never overwritten
    /// (e.g. a stream that ended before an `Exit` frame) is distinguishable from
    /// a genuine exit.
    fn default() -> Self {
        Self {
            code: -1,
            stdout: vec![],
            stderr: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The roster both sides derive from must be a usable lookup key set. Both consumers do a
    // first-match lookup (`vmcell-guest-tools`' dispatch, `is_reserved_injection_path`'s
    // membership scan) and the manifest emits one symlink per entry, so a duplicate name
    // would make the second copy permanently unreachable AND emit a duplicate symlink into
    // the packer's node map. An empty roster would silently un-bake every applet.
    // RED on the inverse: add a second `"ip"` (the dedup assert fires naming it); empty the
    // const (the non-empty assert fires).
    #[test]
    fn guest_tools_applet_roster_is_unique_and_non_empty() {
        assert!(
            !GUEST_TOOLS_APPLETS.is_empty(),
            "an empty roster un-bakes every guest-tools applet"
        );
        let mut seen: Vec<&str> = Vec::new();
        for name in GUEST_TOOLS_APPLETS {
            assert!(
                !name.is_empty() && !name.contains('/'),
                "{name:?} is not a usable exec-PATH file name"
            );
            assert!(
                !seen.contains(name),
                "duplicate applet name {name:?}: the second copy is unreachable"
            );
            seen.push(name);
        }
    }

    // docs/78 §6 (`uncapped-frame-debug-renders`): the ONE renderer every desync log
    // site on this plane goes through. A frame is peer-chosen and `MAX_FRAME_BYTES`
    // (16 MiB) big, and the guest agent's log lines are PERSISTED on the serial
    // artifact — so this pins both halves of the law: an over-cap value renders to a
    // bounded, visibly-truncated string, and an under-cap one renders verbatim (a
    // "cap" that mangled ordinary frames would just be traded for silent log loss).
    //
    // RED on the inverse in three distinct ways: a plain `format!("{value:?}")`
    // fails the length bound and the marker assert; a render-then-truncate
    // implementation passes the length bound but fails `render_calls` (the tail was
    // handed to the sink, which is the CPU half of the defect); a cap that also
    // clipped short values fails the verbatim assert.
    #[test]
    fn capped_debug_truncates_over_cap_values_and_leaves_short_ones_verbatim() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // The real shape at the sites: a session frame whose payload alone is far
        // over the cap (each byte renders as up to 5 chars of `[7, 7, …]` decimal).
        let frame = Message::SessionStdout {
            session: SessionId(42),
            data: vec![7u8; 64 * 1024],
        };
        let rendered = capped_debug(&frame);
        assert!(
            rendered.len() <= MAX_DEBUG_RENDER_BYTES + DEBUG_TRUNCATED_MARKER.len(),
            "a 64 KiB frame must render to a capped diagnostic, got {} bytes",
            rendered.len()
        );
        assert!(
            rendered.starts_with("SessionStdout { session: SessionId(42), data: [7, 7,"),
            "the cap must keep the identifying prefix — variant, id, payload head — got {rendered:?}"
        );
        assert!(
            rendered.ends_with(DEBUG_TRUNCATED_MARKER),
            "a truncated render must say so, got {rendered:?}"
        );

        // The formatter is STOPPED, not just trimmed: a value whose `Debug` counts
        // its own writes proves the tail is never rendered. The counter is a LOCAL
        // borrowed by the value (not a `static`): a module-global would trip the B6
        // global-state ban, and nothing here needs to outlive the test.
        struct Counted<'a>(&'a AtomicUsize);
        let calls = AtomicUsize::new(0);
        impl std::fmt::Debug for Counted<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for _ in 0..10_000 {
                    self.0.fetch_add(1, Ordering::Relaxed);
                    write!(f, "0123456789")?;
                }
                Ok(())
            }
        }
        let counted = capped_debug(&Counted(&calls));
        let render_calls = calls.load(Ordering::Relaxed);
        assert!(
            counted.chars().count()
                <= MAX_DEBUG_RENDER_BYTES + DEBUG_TRUNCATED_MARKER.chars().count(),
            "capped output, got {} chars",
            counted.chars().count()
        );
        assert!(
            render_calls < 100,
            "formatting must ABORT at the cap, not render all 10 000 chunks — {render_calls} ran"
        );

        // A value that fits is byte-identical to the uncapped render: no marker, no
        // truncation, nothing lost from an ordinary desync report.
        let small = Message::SessionExit {
            session: SessionId(1),
            code: 7,
        };
        assert_eq!(capped_debug(&small), format!("{small:?}"));
        assert!(!capped_debug(&small).contains(DEBUG_TRUNCATED_MARKER));
    }

    // The cap is a *byte* cap applied to a UTF-8 `String`: a multi-byte char
    // straddling the boundary must be dropped whole, never split into invalid UTF-8
    // (which is not even representable) or silently rounded UP past the cap. RED on
    // a `end -= 1` boundary walk removed: the push panics on a non-boundary index.
    #[test]
    fn capped_debug_truncates_on_a_char_boundary() {
        // 4-byte chars, so the cap lands mid-char for at least one of these lengths.
        for pad in 0..4usize {
            let value = format!("{}{}", "a".repeat(pad), "🐟".repeat(1024));
            let rendered = capped_debug(&value);
            assert!(
                rendered.len() <= MAX_DEBUG_RENDER_BYTES + DEBUG_TRUNCATED_MARKER.len(),
                "pad {pad}: {} bytes",
                rendered.len()
            );
            assert!(rendered.ends_with(DEBUG_TRUNCATED_MARKER), "pad {pad}");
        }
    }

    #[test]
    fn test_serialization() {
        let msg = Message::Exec(ExecRequest {
            argv: vec!["ls".to_string(), "-l".to_string()],
            env: vec![("PATH".to_string(), "/bin".to_string())],
            cwd: Some("/root".to_string()),
            timeout: None,
        });

        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();

        match decoded {
            Message::Exec(req) => {
                assert_eq!(req.argv, vec!["ls", "-l"]);
                assert_eq!(req.cwd, Some("/root".to_string()));
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_serialization_all_variants() {
        let msgs = vec![
            Message::Ready,
            Message::Stdout(vec![1, 2, 3]),
            Message::Stderr(vec![4, 5, 6]),
            Message::Exit(42),
            Message::PutFile {
                dst: "/tmp/test".to_string(),
                bytes: vec![7, 8, 9],
            },
            // Resync/ResyncAck round-trip: a dropped/reordered field or a
            // secs↔nanos swap reddens the `assert_eq!(msg, decoded)` below.
            Message::Resync {
                unix_secs: 1_700_000_000,
                unix_nanos: 123_456_789,
                mac: Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x05]),
                ipv4: Some(Ipv4Reconfig {
                    addr: [10, 200, 5, 2],
                    prefix_len: 30,
                    gateway: [10, 200, 5, 1],
                }),
            },
            Message::Resync {
                unix_secs: 0,
                unix_nanos: 0,
                mac: None,
                ipv4: None,
            },
            Message::ResyncAck {
                clock_error: Some("clock_settime: EPERM".to_string()),
                reseed_applied: true,
                mac_applied: false,
                ip_applied: false,
            },
            Message::ResyncAck {
                clock_error: None,
                reseed_applied: false,
                mac_applied: true,
                ip_applied: true,
            },
            // Interactive-session variants (§3.3, Interactive-session wire semantics). A dropped/reordered
            // field or a rows↔cols swap reddens the `assert_eq!` below.
            Message::OpenSession {
                session: SessionId(7),
                spec: SessionSpec::new(
                    ExecRequest::new(vec!["cat".to_string()])
                        .with_env(vec![("TERM".to_string(), "xterm".to_string())]),
                )
                .with_pty(40, 100),
            },
            Message::OpenSession {
                session: SessionId(0),
                spec: SessionSpec::new(ExecRequest::new(vec!["sh".to_string()])),
            },
            Message::Stdin {
                session: SessionId(3),
                data: vec![0x68, 0x69, 0x0a],
            },
            Message::StdinEof {
                session: SessionId(3),
            },
            Message::Winsize {
                session: SessionId(3),
                rows: 50,
                cols: 120,
            },
            Message::CloseSession {
                session: SessionId(9),
            },
            Message::SessionStdout {
                session: SessionId(1),
                data: vec![1, 2, 3],
            },
            Message::SessionStderr {
                session: SessionId(2),
                data: vec![4, 5, 6],
            },
            Message::SessionExit {
                session: SessionId(1),
                code: 137,
            },
        ];

        for msg in msgs {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    // Append-only wire discipline (§3.1, The wire protocol / §3.3, Interactive-session wire semantics): postcard encodes an enum
    // variant as a LEB128 varint of its zero-based declaration index, which for
    // 0..=15 is a single leading byte equal to the index. This pins each variant to
    // its discriminant, so reordering or removing a variant — which would silently
    // desync the host and guest — reddens here, KVM-free. RED on any reorder.
    #[test]
    fn variant_discriminants_are_append_only_stable() {
        fn tag(msg: &Message) -> u8 {
            postcard::to_stdvec(msg).unwrap()[0]
        }
        // Indices 0–7: the original one-shot + resync path — must never move.
        assert_eq!(tag(&Message::Ready), 0);
        assert_eq!(tag(&Message::Exec(ExecRequest::new(vec![]))), 1);
        assert_eq!(tag(&Message::Stdout(vec![])), 2);
        assert_eq!(tag(&Message::Stderr(vec![])), 3);
        assert_eq!(tag(&Message::Exit(0)), 4);
        assert_eq!(
            tag(&Message::PutFile {
                dst: String::new(),
                bytes: vec![],
            }),
            5
        );
        assert_eq!(
            tag(&Message::Resync {
                unix_secs: 0,
                unix_nanos: 0,
                mac: None,
                ipv4: None,
            }),
            6
        );
        assert_eq!(
            tag(&Message::ResyncAck {
                clock_error: None,
                reseed_applied: false,
                mac_applied: false,
                ip_applied: false,
            }),
            7
        );
        // Indices 8–15: the appended interactive-session variants (§3.3, Interactive-session wire semantics).
        let sid = SessionId(1);
        assert_eq!(
            tag(&Message::OpenSession {
                session: sid,
                spec: SessionSpec::new(ExecRequest::new(vec![])),
            }),
            8
        );
        assert_eq!(
            tag(&Message::Stdin {
                session: sid,
                data: vec![],
            }),
            9
        );
        assert_eq!(tag(&Message::StdinEof { session: sid }), 10);
        assert_eq!(
            tag(&Message::Winsize {
                session: sid,
                rows: 0,
                cols: 0,
            }),
            11
        );
        assert_eq!(tag(&Message::CloseSession { session: sid }), 12);
        assert_eq!(
            tag(&Message::SessionStdout {
                session: sid,
                data: vec![],
            }),
            13
        );
        assert_eq!(
            tag(&Message::SessionStderr {
                session: sid,
                data: vec![],
            }),
            14
        );
        assert_eq!(
            tag(&Message::SessionExit {
                session: sid,
                code: 0,
            }),
            15
        );
    }

    #[test]
    fn test_framing_multiple_messages() {
        let msg1 = Message::Ready;
        let msg2 = Message::Exit(1);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&postcard::to_stdvec(&msg1).unwrap());
        bytes.extend_from_slice(&postcard::to_stdvec(&msg2).unwrap());

        let (decoded1, rest) = postcard::take_from_bytes::<Message>(&bytes).unwrap();
        assert_eq!(decoded1, Message::Ready);
        let (decoded2, rest2) = postcard::take_from_bytes::<Message>(rest).unwrap();
        assert_eq!(decoded2, Message::Exit(1));
        assert!(rest2.is_empty());
    }

    use proptest::prelude::*;

    fn arb_message() -> impl Strategy<Value = Message> {
        prop_oneof![
            Just(Message::Ready),
            any::<Vec<u8>>().prop_map(Message::Stdout),
            any::<Vec<u8>>().prop_map(Message::Stderr),
            any::<i32>().prop_map(Message::Exit),
            (any::<String>(), any::<Vec<u8>>())
                .prop_map(|(dst, bytes)| Message::PutFile { dst, bytes }),
            (
                any::<Vec<String>>(),
                any::<Vec<(String, String)>>(),
                any::<Option<String>>(),
                any::<Option<std::time::Duration>>()
            )
                .prop_map(|(argv, env, cwd, timeout)| {
                    Message::Exec(ExecRequest {
                        argv,
                        env,
                        cwd,
                        timeout,
                    })
                }),
            (
                any::<u64>(),
                any::<u32>(),
                any::<Option<[u8; 6]>>(),
                prop::option::of((any::<[u8; 4]>(), any::<u8>(), any::<[u8; 4]>()).prop_map(
                    |(addr, prefix_len, gateway)| Ipv4Reconfig {
                        addr,
                        prefix_len,
                        gateway,
                    },
                ),),
            )
                .prop_map(|(unix_secs, unix_nanos, mac, ipv4)| Message::Resync {
                    unix_secs,
                    unix_nanos,
                    mac,
                    ipv4,
                }),
            (
                any::<Option<String>>(),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(|(clock_error, reseed_applied, mac_applied, ip_applied)| {
                    Message::ResyncAck {
                        clock_error,
                        reseed_applied,
                        mac_applied,
                        ip_applied,
                    }
                }),
            // Interactive-session variants (§3.3, Interactive-session wire semantics).
            (
                any::<u64>(),
                any::<Vec<String>>(),
                any::<Vec<(String, String)>>(),
                any::<Option<String>>(),
                prop::option::of((any::<u16>(), any::<u16>())),
            )
                .prop_map(|(id, argv, env, cwd, pty)| Message::OpenSession {
                    session: SessionId(id),
                    spec: SessionSpec {
                        command: ExecRequest {
                            argv,
                            env,
                            cwd,
                            timeout: None,
                        },
                        pty: pty.map(|(rows, cols)| PtyConfig { rows, cols }),
                    },
                }),
            (any::<u64>(), any::<Vec<u8>>()).prop_map(|(id, data)| Message::Stdin {
                session: SessionId(id),
                data,
            }),
            any::<u64>().prop_map(|id| Message::StdinEof {
                session: SessionId(id),
            }),
            (any::<u64>(), any::<u16>(), any::<u16>()).prop_map(|(id, rows, cols)| {
                Message::Winsize {
                    session: SessionId(id),
                    rows,
                    cols,
                }
            }),
            any::<u64>().prop_map(|id| Message::CloseSession {
                session: SessionId(id),
            }),
            (any::<u64>(), any::<Vec<u8>>()).prop_map(|(id, data)| Message::SessionStdout {
                session: SessionId(id),
                data,
            }),
            (any::<u64>(), any::<Vec<u8>>()).prop_map(|(id, data)| Message::SessionStderr {
                session: SessionId(id),
                data,
            }),
            (any::<u64>(), any::<i32>()).prop_map(|(id, code)| Message::SessionExit {
                session: SessionId(id),
                code,
            }),
        ]
    }

    proptest! {
        #[test]
        fn test_message_roundtrip(msg in arb_message()) {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(msg, decoded);
        }
    }
}
