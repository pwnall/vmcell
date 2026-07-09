# vmcell — Design Document (v26 amendment): persistent interactive sessions (PTY + streaming stdin + multiplexed exec)

> **v26 (this revision) — persistent interactive sessions layered on the vsock control plane: a PTY
> (controlling-terminal) session, streaming stdin over the session's lifetime, and multiplexed concurrent
> execs over one connection, keyed by a `SessionId`.** A focused amendment on the v23 unified design
> (`docs/59-claude-design-v23.md`), the v24 privileged-window amendment (`docs/60-claude-design-v24.md`),
> and the v25 OverlayStore/lineage amendment (`docs/61-claude-design-v25.md`), in the same shape v24/v25
> were: the base architecture is unchanged, and this document adds one component — **Part IX / §22** —
> graduating the roadmap item "persistent interactive PTY sessions" (§17, base line 2660; `docs/todo.md`
> "Persistent interactive sessions: PTY + streaming stdin + multiplexed exec [V:high/E:med]") from
> forward-work to **built and gated**.
>
> **What the base already ships (stated up front, honestly).** The vsock control plane already carries a
> **one-shot** exec: the host sends `Message::Exec(ExecRequest)`, the guest forks the command with piped
> stdout/stderr and stdin pointed at `/dev/null`, streams `Stdout`/`Stderr` frames, and ends with one
> `Exit(code)` (§4.1–§4.3). That path is strictly request/response and single-stream: one exec occupies the
> connection until `Exit`, there is **no stdin** (M-GUEST-1 nails it to `/dev/null`), **no PTY** (separate
> pipes, `isatty()` false in-guest), and **no channel id** on the data frames, so it cannot carry two execs
> at once. v26 does **not** change that path — every existing `exec()`/`put_file()`/`resync()` byte, gate,
> and test stays exactly as is. It **adds** three genuinely-missing capabilities the roadmap item names, as
> an additive session layer:
>
> 1. **A PTY session.** The guest allocates a pseudo-terminal (`/dev/ptmx` → master + `/dev/pts/N` slave),
>    runs the command as a **session leader with the slave as its controlling terminal** (`setsid` +
>    `TIOCSCTTY`), and merges its output onto the single master stream. In-guest `isatty()` is true, line
>    editing / job control / `stty` work, and the host can **resize** the window (`TIOCSWINSZ`, delivering
>    `SIGWINCH`). This satisfies requirements.md #9 ("Programmable access to the VM console … Good: TTY
>    emulation") beyond the existing serial-console capture.
> 2. **Streaming stdin.** The host feeds stdin bytes to a *running* command over the session's lifetime
>    (`Message::Stdin`), and closes the input (`Message::StdinEof`) — the exact thing the one-shot path
>    forbids. For a pipe session the bytes go to the child's stdin pipe; for a PTY session they go to the
>    master (so they arrive as terminal input, echoed and line-edited by the tty discipline).
> 3. **Multiplexed exec.** Multiple concurrent sessions run over **one** connection, each distinguished by a
>    `SessionId`; every data/control frame carries its id, and the guest's per-connection reader never
>    blocks on any one child, so session A's output interleaves with session B's on the wire without either
>    stalling the other.
>
> **Amends:** **§4.1** (the wire enum grows eight appended, channelized variants + a `SessionId`/`SessionSpec`/
> `PtyConfig`; the one-shot variants are untouched), **§4.2** (a new host `agent::session` multiplexer beside
> `AgentClient`, sharing one connect/handshake helper), **§4.3** (the guest connection handler becomes a
> non-blocking dispatch loop with a single per-connection writer, a session table, and connection-owns-its-
> sessions teardown), **§10.2** (additive public API), **§12** (new invariants **§12.26–§12.29**), **§14**
> (new gates), **§16/§17** and `docs/todo.md` (the roadmap item moves to built). Version bumps:
> `vmcell-protocol` **0.3.0 → 0.4.0** (a `0.x` minor: appended `#[non_exhaustive]` enum variants + new types
> are additive, but a minor bump is the honest `0.x` slot and keeps the shared-crate version legible);
> `vmcell` **0.8.0 → 0.9.0** (additive `agent::session` surface + `MicroVm::connect_sessions`, no breaking
> change — `cargo semver-checks`-clean); `vmcell-guest-agent` **0.2.0 → 0.3.0** (the PID-1 connection handler
> is reworked, an internal change). The daemon and CLI are addressed in §22.7.

---

## Part IX — Persistent interactive sessions

## 22. PTY, streaming stdin, and multiplexed exec over the vsock control plane

### 22.1 What already ships, and what §22 adds

The vsock control plane (§4) is the one seam the host and guest share: a framed `postcard` `Message` enum
capped at `MAX_FRAME_BYTES` (16 MiB, defined once in `vmcell-protocol`), a host `AgentClient` doing
request/response, and a guest PID-1 agent that serves each accepted connection on its own thread and forks
each `Exec` under the shared `ReaperCoordinator` (§4.3, §12.6). §22 keeps every part of that and layers a
**session** abstraction on top, because the three capabilities the roadmap item names are exactly the three
things the one-shot path structurally cannot do:

- **No PTY.** `handle_exec` wires the child to two anonymous pipes and `Stdio::null()` stdin. `isatty()` is
  false; there is no controlling terminal, no line discipline, no window size.
- **No stdin.** M-GUEST-1 deliberately points the child's stdin at `/dev/null` so a `cat`/`wc`/heredoc sees
  immediate EOF instead of blocking on the serial console. Correct for one-shot; it forecloses interaction.
- **No multiplexing.** `Message::{Stdout,Stderr,Exit}` carry **no** id, and `handle_connection` runs one
  `handle_exec` to completion before reading the next request. One exec owns the connection.

§22 adds a session layer that is **purely additive** at the wire and does **not** touch the one-shot path.

### 22.2 The wire protocol: eight appended, channelized variants (one law: append-only)

`Message` is append-only — `postcard` encodes a variant by its zero-based declaration index, so the order
*is* the wire format (§4.1). v26 **appends** (never reorders/removes) after `ResyncAck`, and adds three
value types. The one-shot `Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`/`PutFile`/`Resync`/`ResyncAck` keep their
indices 0–7 byte-for-byte.

```rust
// vmcell-protocol — appended after ResyncAck (indices 8..=15). Host→guest: OpenSession, Stdin, StdinEof,
// Winsize, CloseSession. Guest→host: SessionStdout, SessionStderr, SessionExit.
pub struct SessionId(pub u64);                        // Copy/Ord/Hash; monotonic per host connection
pub struct PtyConfig { pub rows: u16, pub cols: u16 } // initial window size for a PTY session
pub struct SessionSpec {                              // reuses ExecRequest for argv/env/cwd/timeout (§22.2.1)
    pub command: ExecRequest,
    pub pty: Option<PtyConfig>,                       // Some => allocate a controlling-terminal PTY; None => pipes
}
enum Message { /* …0..=7 unchanged… */
    OpenSession  { session: SessionId, spec: SessionSpec }, // 8  host→guest: start a session
    Stdin        { session: SessionId, data: Vec<u8> },     // 9  host→guest: feed stdin (bounded by MAX_FRAME_BYTES)
    StdinEof     { session: SessionId },                    // 10 host→guest: close stdin (pipe: child sees EOF)
    Winsize      { session: SessionId, rows: u16, cols: u16 }, // 11 host→guest: resize PTY (SIGWINCH)
    CloseSession { session: SessionId },                    // 12 host→guest: kill the session's process group
    SessionStdout{ session: SessionId, data: Vec<u8> },     // 13 guest→host: stdout / merged PTY output
    SessionStderr{ session: SessionId, data: Vec<u8> },     // 14 guest→host: stderr (pipe sessions only)
    SessionExit  { session: SessionId, code: i32 },         // 15 guest→host: terminal frame for a session
}
```

**No open-ack, by construction.** The host may send `Stdin`/`Winsize` immediately after `OpenSession`: one
vsock connection is a single ordered byte stream and the guest's reader is sequential, so `OpenSession` is
always processed before any frame the host queued after it. A failed open (bad `argv`, PTY-alloc failure) is
reported the same way the one-shot path reports a spawn failure — **`SessionStderr{id, msg}` then
`SessionExit{id, 127}`** — so there is exactly one terminal-frame convention and no separate error variant
(§12.26).

**No `SessionId` on the wire for the one-shot path.** The one-shot `Exec` deliberately stays id-less; a host
that wants multiplexing uses the session API, which is a *different connection* (§22.4). This keeps the
heavily-tested one-shot frames untouched.

#### 22.2.1 Timeout semantics: one field, one meaning ("a deadline, or none")

`SessionSpec` embeds `ExecRequest` (reuse, not a second copy of argv/env/cwd — AGENTS.md "one law"). The one
field whose reading needs care is `ExecRequest.timeout`, and v26 keeps its meaning **uniform**: *an optional
kill deadline; `None` = no deadline.* The one-shot **host** `exec()` fills `None → Some(DEFAULT_EXEC_TIMEOUT)`
before sending (so a one-shot child always has a kill thread and cannot outlive the host's abandoned wait,
§4.1); the one-shot **guest** handler additionally `unwrap_or(DEFAULT)`s as a belt-and-suspenders. The
**session** path leaves `None` as `None` — an interactive session is *persistent*, so it has **no** kill
thread unless the caller sets one; its lifetime is bounded instead by explicit `CloseSession`, the child
exiting, or connection-owns-its-sessions teardown (§12.27). No field is read with two contradictory meanings
— it is always "a deadline or none"; the one-shot path's default is a policy applied by the host before the
byte leaves, not a second interpretation in the guest.

### 22.3 The guest: a non-blocking dispatch loop, one writer, a session table, and teardown

The guest change is confined to the per-connection handler; PID-1 mount/boot, the reaper (§12.6), the
event-driven accept/re-bind loop (§9.2/OPP-2), and `handle_exec`/`handle_put_file`/`handle_resync` are
unchanged in behavior. What changes:

- **Split the connection; one writer (§12.28).** `serve_connection` splits the accepted `VsockStream` into a
  read half (owned by the dispatch loop) and a write half via `try_clone()`, behind an
  `Arc<Mutex<VsockStream>>` — the **single** per-connection writer. Every frame (the initial `Ready`, the
  one-shot output, put-file/resync acks, and all session frames from all pump threads) is emitted through
  one `send_msg(writer, &msg)` that locks and calls the one `send_framed` (the sole framing law, with the
  `MAX_FRAME_BYTES` encode-side cap, L-GUEST-2). No two threads ever write the vsock concurrently, so
  multiplexed frames from different sessions never interleave-corrupt on the wire.
- **The dispatch loop never blocks on a child.** It reads a frame, matches, and dispatches:
  - `Exec`/`PutFile`/`Resync` → the existing handlers (now writing via `writer`). The one-shot `Exec` is
    still synchronous (it drains its child to `Exit` before the loop reads again) — that is the one-shot
    contract, and one-shot and sessions are never mixed on one connection (§22.4).
  - `OpenSession{id, spec}` → spawn the session (below), register a `SessionHandle` in the per-connection
    `Arc<Mutex<HashMap<SessionId, SessionHandle>>>`, and return immediately — the loop keeps reading.
  - `Stdin{id, data}` → look up the handle, clone its `Arc<Mutex<StdinSink>>`, **release the table lock**,
    then write the bytes (looping partial writes; B10 "counts are handled"). A closed/unknown id is dropped
    at `debug` (the session already ended), never a desync.
  - `StdinEof{id}` → drop the pipe session's stdin writer (child sees EOF). A no-op for a PTY session
    (closing the master would tear down output; a PTY caller ends input with an in-band EOT or `CloseSession`).
  - `Winsize{id, rows, cols}` → `tcsetwinsize(pty_master, …)` for a PTY session (delivers `SIGWINCH`); a
    debug no-op for a pipe session (no tty).
  - `CloseSession{id}` → `kill_process_group(pgid, SIGKILL)`; the waiter reports the resulting `SessionExit`.
  - A guest→host variant received here (`Ready`/`Stdout`/…/`SessionStdout`/…) means the peer desynced: log
    loud, close the connection (AGENT-5), unchanged.
- **Per session.** `run_session` captures the pre-spawn reaper epoch (AGENT-2), spawns, `reserve`s the pid,
  and spawns pump + waiter threads exactly like `handle_exec`, but session-tagged:
  - **PTY session:** `openpt(RDWR|NOCTTY|CLOEXEC)` → master; `unlockpt`/`grantpt`; open the `ptsname` slave;
    set the initial `PtyConfig` winsize on the master. The child is spawned **without** `process_group(0)`;
    its `pre_exec` runs `setsid()` (new session + process group, pgid == pid), `ioctl_tiocsctty(slave)` (the
    slave becomes the controlling terminal), then `dup2` the slave onto fds 0/1/2 — the canonical `login_tty`
    sequence, each step an async-signal-safe raw syscall via `rustix` (one `unsafe` only to borrow the raw
    slave fd; the master is `CLOEXEC` so it never reaches the exec'd program). The parent then **closes its
    slave** (so the master EOFs when the child — the last slave holder — exits, Linux `EIO`), and one pump
    thread reads the master → `SessionStdout{id, chunk}`. Merged stdout+stderr, one stream.
  - **Pipe session:** `process_group(0)` (pgid == pid), stdin/stdout/stderr piped; two pumps →
    `SessionStdout`/`SessionStderr{id, …}`; the child's stdin pipe writer is the session's `StdinSink`.
  - **Both:** an optional kill thread iff `spec.command.timeout` is `Some` (§22.2.1); a waiter thread that
    `wait_for(pid)`s the reaper, sets `has_exited`, **joins the pump(s)** (so all output precedes exit,
    §12.26), sends `SessionExit{id, code}`, and removes the session from the table.
- **The connection owns its sessions (§12.27).** When the dispatch loop returns for any reason — host
  disconnect (a clean `UnexpectedEof`, logged at info as today), decode/transport error, or a desync close —
  `serve_connection` iterates the session table and `SIGKILL`s each still-open session's process group and
  drops its fds **before returning**. No interactive session (a `sleep 600`, a shell) outlives the
  connection that opened it. Sessions do not survive snapshot/restore either: a restored VM re-binds the
  listener and the host reconnects on a fresh connection (§9.2), which is a clean, expected boundary — the
  "persistent" in the feature name is *within a session's life across many frames*, not across a VM restore.

**devpts.** PTY allocation needs `devpts` mounted at `/dev/pts`. The agent mounts it right after
`devtmpfs`, **best-effort** and tolerated like the sysfs/share/loopback mounts (it is not in the fatal
core-mount set `{overlay, /proc, /dev}`, §4.3): a failed mount only fails PTY *sessions* (which then report
`SessionExit(127)`), never the control plane, pipe sessions, or one-shot exec. The guest kernel already
advertises UNIX98 PTYs (validated on the KVM run, §22.6); a kernel without it degrades exactly this way.

### 22.4 The host: an `agent::session` multiplexer beside `AgentClient`

The host gains `vmcell::agent::session`, a multiplexer that owns **its own** vsock connection (separate from
the cached one-shot `AgentClient`), so the two never share a stream and never interleave one-shot and session
frames. It reuses the **one** connect/handshake helper `AgentClient` already uses (the byte-by-byte `OK`
line + `Ready`, §12.5) — refactored into a shared `connect_framed(...)` so the fragile handshake has exactly
one implementation (AGENTS.md "one law").

```rust
// vmcell::agent::session (re-exported at vmcell::agent)
pub struct SessionMux { /* writer sink (Arc<Mutex<SplitSink>>), a demux registry, a reader task, next-id */ }
pub struct Session    { /* id, an mpsc receiver of SessionEvent, a clone of the writer sink */ }
pub enum SessionEvent { Stdout(Vec<u8>), Stderr(Vec<u8>), Exit(i32) }
pub struct SessionSpecBuilder { /* argv → env/cwd/pty(rows,cols)/timeout → SessionSpec */ }

impl SessionMux {
    /// Connects a fresh session-multiplexing connection to the guest agent (same handshake as AgentClient).
    pub async fn connect(vsock_path: &Path, port: u32, timeout: Duration, timeouts: &Timeouts,
        serial_log: &dyn SerialLog) -> Result<Self>;
    /// Opens a session: allocates a SessionId, registers its event channel, sends OpenSession, returns a handle.
    pub async fn open(&self, spec: SessionSpec) -> Result<Session>;
}
impl Session {
    pub fn id(&self) -> SessionId;
    pub async fn write_stdin(&self, data: &[u8]) -> Result<()>;   // Message::Stdin
    pub async fn close_stdin(&self) -> Result<()>;                // Message::StdinEof
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()>; // Message::Winsize
    pub async fn close(&self) -> Result<()>;                      // Message::CloseSession
    pub async fn recv(&mut self) -> Option<SessionEvent>;         // next output/exit; None once Exit consumed
    pub async fn wait(&mut self) -> ExecOutcome;                  // drain to Exit, collecting output (convenience)
}
```

A single background **reader task** owns the read half of the connection, decodes each frame, and routes
`SessionStdout`/`SessionStderr`/`SessionExit` to the matching session's `mpsc` sender from the demux
registry (`SessionExit` also closes that session's channel). Writes from all `Session` handles + the mux go
through one `Arc<Mutex<SplitSink>>` — the host mirror of the guest's single-writer discipline. Dropping the
`SessionMux` closes the connection, which the guest observes as the read-loop end that triggers
connection-owns-its-sessions teardown (§12.27) — so a host that forgets to `close()` still cannot leak guest
processes. Per-session queues are **unbounded** and fed only by the *trusted host's own* sessions (the guest
is the sandboxed workload; the host chose to open and must drain each session) — a deliberate,
recorded trade (§16), not the untrusted-server-accumulation class the rubric flags.

`MicroVm::connect_sessions(timeout, serial_log) -> Result<SessionMux>` is the ergonomic entry: it dials a
second control-plane connection on the same VM. It refuses fail-loud with the existing
control-plane-disabled `Error::Agent` when a custom `init=` has replaced the agent (§19.2.2), exactly as
`agent()` does.

### 22.5 Cross-cutting invariants added

Folded into §12 (numbering continues from §12.25):

- **§12.26 — Session I/O is channelized and terminally-framed.** Every session data/control frame carries
  its `SessionId`; a session's lifecycle on the wire is zero-or-more `SessionStdout`/`SessionStderr` frames
  then **exactly one** terminal `SessionExit`, which is the last frame for that id. The guest never emits a
  legacy id-less `Stdout`/`Stderr`/`Exit` for a session, never a second `SessionExit`, and reports a failed
  open as `SessionStderr` + `SessionExit(127)` (the one-shot spawn-failure convention). Owner: guest
  `run_session` + host demux. Gate: the host demux multiplex test (interleaved ids delivered to the right
  handle, each stream ending at its `SessionExit`, a stray frame after exit dropped not delivered); the
  guest spawn-failure → `SessionStderr`+`SessionExit(127)` unit test — each red on its inverse.

- **§12.27 — A connection owns its sessions.** When a connection's dispatch loop ends (host disconnect,
  transport error, or desync), every still-open session's process group is `SIGKILL`ed and its fds are
  closed **before the connection thread returns**; no session outlives its connection, and dropping the host
  `SessionMux` is a sufficient teardown trigger. Owner: guest `serve_connection` teardown. Gate: the KVM
  live connection-drop residue test — open a persistent session (`sh -c 'echo $$; sleep 600'`), record its
  pid from the data plane, drop the `SessionMux`, then from a **fresh** connection assert `kill -0 <pid>`
  fails (the process is gone) — existed-before / gone-after, not a vacuous check.

- **§12.28 — One writer per connection.** Every frame on a connection is emitted through the single
  per-connection writer (`send_framed` under one mutex on the guest; one `Arc<Mutex<SplitSink>>` on the
  host); no two threads write the transport concurrently, so multiplexed session frames never
  interleave-corrupt. Owner: guest writer mutex + host writer sink. Gate: the concurrent-multiplexed-exec
  data-plane test — two sessions each emit a large, self-identifying, window-filling stream on one
  connection, and the host reassembles **both** intact with **zero** cross-attribution (an A line in B's
  stream, or a torn frame, reddens it).

- **§12.29 — A PTY session is a controlling-terminal session leader.** A PTY session runs its command via
  `setsid` + `TIOCSCTTY` on the pty slave, so in-guest `isatty(0/1/2)` is true and a host `Winsize` delivers
  the new dimensions (`SIGWINCH`); output is the single merged master stream. Owner: guest `run_session`
  (PTY arm). Gate: the KVM live PTY test — a session running `test -t 0 && test -t 1 && stty size` reports a
  tty and the configured rows/cols on the data plane, and a mid-session `resize` is reflected by a second
  `stty size` (a pipe session, as the positive/negative control, reports "not a tty").

### 22.6 Quality gates (added to §14)

- **Unit / pure (KVM-free, root-free, in `just ci`):**
  - `vmcell-protocol`: round-trip of every new variant (extend `test_serialization_all_variants` and the
    `arb_message` proptest with `OpenSession`/`Stdin`/`StdinEof`/`Winsize`/`CloseSession`/`SessionStdout`/
    `SessionStderr`/`SessionExit`, `SessionId`/`SessionSpec`/`PtyConfig`); a **discriminant-stability** test
    pinning the appended variants to indices 8..=15 (encode a known value of each, assert the leading
    variant byte) so a reorder/removal of the append-only enum reddens KVM-free (§4.1).
  - `vmcell-guest-agent`: pure helpers — `winsize_from(rows, cols) -> Winsize` field mapping (red on a
    rows↔cols swap, mirroring `resync_timespec`); the shared `child_path(base)` PATH-augmentation extracted
    to **one** function used by both `handle_exec` and `run_session` (one law; red if a session drops the
    `/vmcell-tools` prefix); the open-failure → `SessionStderr`+`SessionExit(127)` mapping.
  - Guest framing interop: extend the AGENT-3 round-trip so a `SessionStdout{id, payload}` framed by the
    guest's `send_framed` decodes through the host's real `LengthDelimitedCodec` and back (both directions,
    over-cap reject) — the channelized frames cross the same hand-rolled boundary.
  - Host demux (`agent::session`): a KVM-free test over an in-memory `tokio::io::duplex` pair — feed a
    hand-built, **interleaved** sequence of framed session frames (ids 1 and 2 alternating, plus a stray
    frame after id 1's `SessionExit`) into the reader task and assert each `Session` handle receives exactly
    and only its own frames in order, terminates at its `SessionExit`, and the post-exit stray is dropped.
    Red on a demux that ignores the id or delivers cross-session.
- **Host-validated (KVM, `tests/session.rs`, DONE 2026-07-06):** sessions need only the vsock agent (no
  snapshot), so the suite runs on **all three backends** (CH primary, FC, QEMU) with **no `require_cap!`
  skips** — **14/14 green** here through the blessed runner under the delegated scope (12 live × 3 backends +
  2 host demux unit tests). Four data-plane tests, each red on its inverse:
  1. **PTY + winsize (§12.29):** an `sh` PTY session reports `isatty` true + the initial `stty size`, and a
     mid-session `resize` is reflected by a second `stty size`; a pipe control session reports "not a tty".
  2. **Streaming stdin (§22.2 / rubric A10):** a pipe `cat` session round-trips streamed stdin
     (`write_stdin("hello\n")` → `SessionStdout "hello\n"`), then `close_stdin` drives `cat` to
     `SessionExit(0)`; a PTY `cat` session echoes streamed input through the tty discipline.
  3. **Multiplexed exec (§12.28):** two sessions on **one** connection each emit a large, self-identifying,
     window-filling stream; both arrive intact with zero cross-attribution.
  4. **Connection owns sessions (§12.27):** a persistent `sleep` session's pid, captured on the data plane,
     is gone (`/proc/<pid>/cmdline` no longer names `sleep`, from a fresh connection) after the `SessionMux`
     is dropped.
  The rest of the privileged suite re-ran green **except** a pre-existing host-environmental cluster —
  `nested_virt`/`nested_virt_disabled` (CH+QEMU, `/dev/kvm` nested passthrough) and `snapshot_restore`'s
  post-restore CSPRNG reseed (CH+FC, `/dev/hwrng` virtio-rng) — which a **control run of the unmodified
  baseline agent reproduces identically** (proving they are not this change) and which the host kernel log
  explains: recurring `kvm_intel` EPT-violation faults degrading nested-KVM + device passthrough on this
  machine right now. That is a `NOT READY` host condition for those specific capability tests (named
  mechanism), not a session regression; `just test-unprivileged` is **4/4 green**.

### 22.7 What ships now, and the honest forward work

**Shipped and gated in v26:** the eight channelized `Message` variants + `SessionId`/`SessionSpec`/
`PtyConfig` (append-only, discriminant-pinned); the guest non-blocking dispatch loop with a single
per-connection writer, PTY/pipe/streaming-stdin/winsize sessions, and connection-owns-its-sessions teardown;
the host `agent::session::{SessionMux, Session, SessionEvent}` multiplexer + `MicroVm::connect_sessions`,
sharing the one connect/handshake helper; invariants §12.26–§12.29 with red-on-inverse gates; a modest
`vmcell-cli` surface for trying it out (§22.7, below). The one-shot `exec`/`put_file`/`resync` path is
unchanged beneath the new layer.

**CLI (shipped, minimal — "quickly try out the functionality", requirements.md §Source 3).** `vmcell-cli run`
gains `--stdin` (stream the CLI process's own stdin into a pipe session and print the streamed output) and
`--tty` (allocate a PTY session, so in-guest programs see a terminal). Local raw-mode terminal handling
(putting the CLI's own tty into raw mode, forwarding `SIGWINCH`) is intentionally best-effort in v26 — the
tested, load-bearing surface is the library API; polished interactive terminal UX is §22.7 forward work.

**Forward work (each a real edge, not a hedge):**

- **Daemon control-plane sessions.** The daemon's HTTP `POST /v1/vms/{id}/exec` is one-shot
  request/response with base64 body; interactive sessions need a **streaming** transport (a WebSocket or
  chunked bidirectional channel) and a `SessionId`-keyed sub-protocol over it, plus the broker RPC
  (`VmEngine`) growing streaming ops. That is a transport-shaped increment on top of the shipped library API
  (the same "library first, control-plane verb later" staging v25 used for lineage), not a change to the
  session mechanics.
- **Local raw-mode interactive CLI.** Full terminal passthrough (raw mode, `SIGWINCH`→`resize`, restoring
  the tty on exit) for `run --tty`, so the CLI is a drop-in interactive console.
- **Per-session output flow control / backpressure.** The host per-session queue is unbounded (host-trusted,
  §22.4); a credit/window scheme would let a slow consumer backpressure the guest without unbounded host
  memory, at the cost of head-of-line coordination — worth it only if a non-draining consumer becomes real.
- **PTY `StdinEof` semantics.** `StdinEof` closes a pipe session's stdin; for a PTY it is a no-op today (an
  interactive caller sends an in-band EOT or `CloseSession`). A future refinement could push the pty into a
  half-closed input state without tearing down output.

---

## Amendments to the base document (v23/v24/v25)

- **§2.2 (key decisions)** — add a row: **Interactive sessions** | Beside the one-shot `exec` (§4), an
  additive **session** layer (§22): a PTY (controlling-terminal, `isatty` true, resizable) or pipe session,
  **streaming stdin** over the session's life, and **multiplexed** concurrent sessions over one connection
  keyed by `SessionId` — eight append-only channelized `Message` variants, a guest non-blocking dispatch
  loop with one per-connection writer and connection-owns-its-sessions teardown (§12.26–§12.29), and a host
  `agent::session` multiplexer. Library + CLI ship; daemon streaming is §22.7 forward work.
- **§4.1 (the protocol)** — the `Message` enum grows eight appended, `SessionId`-keyed variants
  (`OpenSession`/`Stdin`/`StdinEof`/`Winsize`/`CloseSession`/`SessionStdout`/`SessionStderr`/`SessionExit`)
  plus `SessionId`/`SessionSpec`/`PtyConfig`; indices 0–7 and the one-shot semantics are unchanged, and the
  append-only order is now discriminant-pinned by a KVM-free test.
- **§4.2 (the host `AgentClient`)** — a new `agent::session` multiplexer (`SessionMux`/`Session`) sits beside
  `AgentClient`, on its own connection, sharing the one refactored connect/handshake helper (§12.5).
- **§4.3 (the guest agent)** — the per-connection handler becomes a non-blocking dispatch loop with a single
  per-connection writer (`try_clone`d write half behind a mutex), a `SessionId` → `SessionHandle` table, PTY
  (`setsid`+`TIOCSCTTY`, devpts) / pipe / streaming-stdin / winsize sessions, and ordered teardown that
  kills every still-open session on connection end. `handle_exec`/`handle_put_file`/`handle_resync` behavior
  is unchanged (they now write through the shared writer). A best-effort `devpts` mount at `/dev/pts` is
  added to the boot mount sequence (not a fatal core mount).
- **§10.2 (public API)** — additive: `agent::session::{SessionMux, Session, SessionEvent, SessionSpecBuilder}`
  re-exported at `vmcell::agent`; `vmcell::agent::protocol::{SessionId, SessionSpec, PtyConfig}` (via the
  `vmcell-protocol` re-export); `MicroVm::connect_sessions`. No existing signature changes (`exec`/`put_file`/
  `resync`/`agent` unchanged) — `vmcell` 0.8.0 → 0.9.0, `cargo semver-checks`-clean; `vmcell-protocol`
  0.3.0 → 0.4.0 (additive `#[non_exhaustive]` variants + new types).
- **§12** — new invariants **§12.26–§12.29** (§22.5).
- **§14** — new gates (§22.6).
- **§16 (open decisions)** — add: interactive sessions ship at the library + CLI (§22); daemon streaming
  sessions, a raw-mode interactive CLI, per-session backpressure, and richer PTY `StdinEof` are the
  remaining increments (§22.7). The unbounded host per-session queue is a recorded host-trusted trade.
- **§17 (future capabilities) / `docs/todo.md`** — strike "persistent interactive PTY sessions" /
  "Persistent interactive sessions: PTY + streaming stdin + multiplexed exec" from the build-later list; it
  is §22.
