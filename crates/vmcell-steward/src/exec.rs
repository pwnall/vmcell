//! One-shot `exec`, `put_file`, and the post-restore `resync` handler.
//!
//! Placement-blind (design §3.5): the reservation/epoch machinery is pid-reuse correctness for
//! children the steward spawned *itself*, and it carries into service mode intact. The one seam
//! v33 added is the tools directory — hardcoded `/vmcell-tools` before, now
//! [`crate::StewardOptions::tools_dir`], because §10.5 makes the handler an artifact whose mount
//! point is a property of the cell rather than of this source file.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use std::os::unix::process::CommandExt;

use vmcell_protocol::{self as protocol, ExecRequest, Message};

use crate::ServeContext;
use crate::netif;
use crate::serve::{Writer, join_pump, send_msg};
use crate::session::kill_group;

/// Publishes one output/terminal frame on the one-shot exec's collector channel, best-effort.
///
/// WHY DISCARDING IS CORRECT, once, instead of at four call sites (AGENTS.md "Fail loud" plus its
/// Suppressions rule): the receiver is the `for msg in rx` loop below, which **breaks on
/// `Message::Exit`** and then drops `rx`. Every send that fails is therefore a chunk produced after
/// the exec already reported its exit — a stdout pump still draining a pipe, or the timeout thread
/// firing against a child that exited first. There is no consumer left, and creating one would mean
/// holding the connection open past the answer it already gave.
///
/// Traced rather than dropped in silence, so a pump that kept producing after `Exit` is visible.
/// The steward runs as PID 1 under the `Pid1` placement, so this path must not panic.
fn publish_chunk(tx: &std::sync::mpsc::Sender<Message>, msg: Message) {
    if tx.send(msg).is_err() {
        tracing::debug!(
            "vmcell-steward: exec output produced after the collector closed; dropping the frame"
        );
    }
}

pub(crate) fn handle_put_file(
    dst: &str,
    bytes: &[u8],
    writer: &Writer,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = std::path::Path::new(dst).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dst, bytes)?;
        Ok(())
    })();

    let code = if result.is_ok() { 0 } else { 1 };
    send_msg(writer, &Message::Exit(code))?;
    Ok(())
}

/// Maps a host `(unix_secs, unix_nanos)` instant to the `rustix` [`Timespec`] the
/// mandatory post-restore clock set consumes.
///
/// Split out as a pure function so the field mapping (`unix_secs`→`tv_sec`,
/// `unix_nanos`→`tv_nsec`) is unit-tested: a swapped or truncated assignment
/// reddens `resync_timespec_maps_fields` without a live guest / a privileged
/// `clock_settime`.
///
/// [`Timespec`]: rustix::time::Timespec
pub(crate) fn resync_timespec(unix_secs: u64, unix_nanos: u32) -> rustix::time::Timespec {
    rustix::time::Timespec {
        tv_sec: i64::try_from(unix_secs).unwrap_or(i64::MAX),
        tv_nsec: i64::from(unix_nanos),
    }
}

/// Copies 32 bytes of `/dev/hwrng` into `/dev/urandom` (best-effort CSPRNG
/// reseed), byte-identical to the `head -c 32 /dev/hwrng > /dev/urandom` redirect
/// the exec-based restore path used: writing to `/dev/urandom` mixes the bytes
/// into the pool without crediting entropy.
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if `/dev/hwrng` is missing/unreadable
/// or `/dev/urandom` cannot be written. The caller treats any error as
/// "reseed not applied" and never fails the resync on it.
pub(crate) fn reseed_urandom_from_hwrng() -> std::io::Result<()> {
    let mut hwrng = std::fs::File::open("/dev/hwrng")?;
    let mut buf = [0u8; 32];
    hwrng.read_exact(&mut buf)?;
    let mut urandom = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/urandom")?;
    urandom.write_all(&buf)?;
    Ok(())
}

/// Handles a [`Message::Resync`] post-restore resync natively — replacing the
/// three subprocess execs (`date` / `head -c 32 /dev/hwrng` / `ip link set`) —
/// and always replies with a [`Message::ResyncAck`] carrying each step's outcome
/// (§8.2, Restore correctness: a restored VM is not a fresh VM).
///
/// The clock set is **mandatory** (§8.2, Restore correctness: a restored VM is not a fresh VM): a failure is reported via `clock_error`
/// but NEVER propagated with `?` or a panic — the ack must always be sent so the
/// host gets a definitive answer and decides (it treats a `Some(clock_error)` as a
/// hard, retryable failure). The CSPRNG reseed and MAC rotation are best-effort
/// and reported via the two bool flags; neither failing aborts the ack.
pub(crate) fn handle_resync(
    unix_secs: u64,
    unix_nanos: u32,
    mac: Option<[u8; 6]>,
    ipv4: Option<protocol::Ipv4Reconfig>,
    writer: &Writer,
) -> std::io::Result<()> {
    // 1. Clock (MANDATORY): set CLOCK_REALTIME to the host instant. Never `?` — a
    //    failure is reported in the ack, not propagated.
    let clock_error = match rustix::time::clock_settime(
        rustix::time::ClockId::Realtime,
        resync_timespec(unix_secs, unix_nanos),
    ) {
        Ok(()) => None,
        Err(e) => Some(e.to_string()),
    };

    // 2. RNG reseed (best-effort): a missing/unreadable hwrng yields false, never
    //    an error. Log the underlying cause (L-GUEST-6) rather than collapsing it
    //    to a bare bool — debugging `reseed_applied=false` otherwise means guessing
    //    between a missing `/dev/hwrng`, a short read, and an unwritable pool.
    let reseed_applied = match reseed_urandom_from_hwrng() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                "vmcell-steward: resync hwrng reseed failed: {}; continuing (best-effort)",
                e
            );
            false
        }
    };

    // 3+4. MAC and IPv4 rotation (best-effort): installed in-process via
    //      SIOCSIFHWADDR / SIOCSIFADDR + the route ioctls (no in-guest netlink).
    //      Both arms go through ONE call because the default route is a property of
    //      the resync as a whole (d1): the MAC arm bounces eth0 and the kernel tears
    //      the default route's nexthop down with it, so whoever bounces the link
    //      owes the route back — `netif::apply_resync_net` decides that once, for
    //      every arm, and logs each arm's io::Error cause (L-GUEST-6) rather than
    //      collapsing it to a bare bool.
    let net = match netif::resync_net(
        "eth0",
        mac,
        ipv4.map(|cfg| netif::Ipv4Args {
            addr: cfg.addr,
            prefix_len: cfg.prefix_len,
            gateway: cfg.gateway,
        }),
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::warn!(
                "vmcell-steward: resync could not open the config socket: {}; no interface arm applied",
                e
            );
            netif::ResyncNetOutcome::default()
        }
    };

    let ack = Message::ResyncAck {
        clock_error,
        reseed_applied,
        mac_applied: net.mac_applied,
        ip_applied: net.ip_applied,
    };
    send_msg(writer, &ack)?;
    Ok(())
}

/// Augments a base PATH with the guest-helper dir (`/vmcell-tools` by default, or whatever
/// [`crate::StewardOptions::tools_dir`] declares — §10.5 makes the handler an artifact) ahead of
/// the request-provided or inherited PATH — the **one** PATH law shared by the one-shot
/// [`handle_exec`] and interactive [`crate::session::run_session`] paths (AGENTS.md "one law, one
/// predicate"). The steward may inherit a minimal/empty PATH, so an empty base falls back to the
/// standard system dirs.
pub(crate) fn child_path(tools_dir: &Path, req_path: Option<String>) -> String {
    let tools = tools_dir.display();
    let base_path = req_path
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    if base_path.is_empty() {
        format!("{tools}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    } else {
        format!("{tools}:{base_path}")
    }
}

/// Builds the child [`Command`] from an [`ExecRequest`] — program + args, cwd, and
/// the environment with the tools-dir-augmented PATH ([`child_path`]) — the
/// shared command-construction law for both the one-shot and session paths.
/// Returns `None` for an empty argv (the non-panicking split; `indexing_slicing`
/// is denied in PID-1 code). Does **not** set stdio or the process group — those
/// are path-specific (pipes vs PTY) and set by the caller.
pub(crate) fn build_command(req: &ExecRequest, tools_dir: &Path) -> Option<Command> {
    let (program, args) = req.argv.split_first()?;
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    let mut req_path: Option<String> = None;
    for (k, v) in &req.env {
        if k.as_str() == "PATH" {
            req_path = Some(v.clone());
        }
        cmd.env(k, v);
    }
    cmd.env("PATH", child_path(tools_dir, req_path));
    Some(cmd)
}

/// Runs one **one-shot** `exec` to completion: spawns the child in its own process group, streams
/// its output through the single [`Writer`], and returns once the terminal `Exit` frame is sent.
///
/// `execs` is the connection's live-child table (§13, law C3). The child is published there for as
/// long as this call runs, so the two things that outlive this stack frame can reach it: a
/// service-mode shutdown sweep, and the connection's own teardown.
pub(crate) fn handle_exec(
    req: ExecRequest,
    writer: &Writer,
    ctx: &Arc<ServeContext>,
    execs: &crate::serve::OneShotExecs,
) -> Result<(), Box<dyn std::error::Error>> {
    let reaper = &ctx.reaper;
    let Some(mut cmd) = build_command(&req, &ctx.tools_dir) else {
        send_msg(writer, &Message::Exit(1))?;
        return Ok(());
    };
    // Run the child as its own process-group leader so the timeout path can
    // signal the whole group (`kill(-pgid)`), tearing down any subprocesses it
    // spawned rather than only the leader.
    cmd.process_group(0);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Point the child's stdin at /dev/null (M-GUEST-1). PID 1's own fd 0 is the
    // serial console (`/dev/console`), from which no input ever arrives, so a
    // command that reads stdin (`cat`, `wc`, a `sh` heredoc) would block on the
    // console and run out its timeout instead of seeing EOF immediately. (The
    // interactive-session path, §3, The control plane: vsock, the host clients, and the steward, is where streamed stdin lives.)
    cmd.stdin(Stdio::null());

    // AGENT-2: capture the reservation epoch BEFORE the spawn. An instant child
    // can exit and be drained by the PID-1 reaper before this thread reaches
    // `reserve` (on one vcpu the child often runs to completion first); the
    // pre-spawn epoch lets `reserve` recognize that already-recorded status as
    // the child's own (recorded after the epoch) instead of wiping it as a stale
    // previous occupant's — which stranded the waiter forever and surfaced on
    // the host as a sporadic "Steward exec timed out" for a command that had
    // already succeeded.
    let pre_spawn_epoch = reaper.pre_spawn_epoch();
    match cmd.spawn() {
        Ok(mut child) => {
            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| std::io::Error::other("failed to get stdout"))?;
            let mut stderr = child
                .stderr
                .take()
                .ok_or_else(|| std::io::Error::other("failed to get stderr"))?;

            let (tx, rx) = std::sync::mpsc::channel();
            let tx_out = tx.clone();
            let tx_err = tx.clone();
            let out_handle = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            // `read` guarantees n <= buf.len(); `get(..n)` is the non-panicking
                            // spelling of that (indexing_slicing is denied in PID-1 code).
                            let chunk = buf.get(..n).unwrap_or_default().to_vec();
                            publish_chunk(&tx_out, Message::Stdout(chunk));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            });

            let err_handle = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stderr.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let chunk = buf.get(..n).unwrap_or_default().to_vec();
                            publish_chunk(&tx_err, Message::Stderr(chunk));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            });

            let pid = child.id();
            // Reserve this pid in the shared reaper with the PRE-SPAWN epoch, so
            // a re-parented grandchild that previously held this (now reused) pid
            // cannot have its lingering, unclaimed exit status mis-delivered to
            // this child as a false result: `reserve` clears a status recorded at
            // or before the epoch, and the waiter's `wait_for(pid)` below only
            // accepts one recorded strictly after it (§3.4, The guest: vmcell-steward as PID 1; the PID-1 reaper-vs-waiter
            // contract). A status recorded after the epoch — this child's own,
            // when it exited and was drained before this line ran — survives the
            // reservation and is delivered immediately (AGENT-2).
            reaper.reserve(pid, pre_spawn_epoch);
            let has_exited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            // Publish the child on the connection's live one-shot table (§13, law C3). Until this
            // existed, a one-shot child's pgid was known ONLY to this stack frame: a service-mode
            // shutdown swept sessions and left `sleep 600` running under the real init, and a
            // connection thread that panicked or failed a `send_msg` mid-output left it running
            // with nobody at all to kill it. The ticket covers every way out of this frame.
            let _live_child = crate::serve::OneShotTicket::register(
                execs,
                pid,
                std::sync::Arc::clone(&has_exited),
            );
            let has_exited_clone = std::sync::Arc::clone(&has_exited);
            let tx_timeout = tx.clone();

            // Always arm a kill thread, even when the host omits a timeout: the
            // host now resets its connection on timeout, so an unbounded child
            // would otherwise leak forever. Default to the host's
            // `DEFAULT_EXEC_TIMEOUT` (10s). On expiry, kill the child's entire
            // process group rather than just the leader.
            let timeout = req.timeout.unwrap_or(protocol::DEFAULT_EXEC_TIMEOUT);
            std::thread::spawn(move || {
                std::thread::sleep(timeout);
                if !has_exited_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    kill_group(pid);
                    publish_chunk(
                        &tx_timeout,
                        Message::Stderr(b"Command timed out\n".to_vec()),
                    );
                }
            });

            let waiter_reaper = Arc::clone(reaper);
            std::thread::spawn(move || {
                // Claim this pid's exit code from the single shared reaper; no
                // `child.wait()` here, so the reaper cannot have its status
                // stolen (the false-127 race).
                let code = waiter_reaper.wait_for(pid);
                has_exited.store(true, std::sync::atomic::Ordering::Relaxed);
                join_pump(out_handle);
                join_pump(err_handle);
                publish_chunk(&tx, Message::Exit(code));
            });

            for msg in rx {
                send_msg(writer, &msg)?;
                if let Message::Exit(_) = msg {
                    break;
                }
            }
        }
        Err(e) => {
            let err_msg = format!("Failed to spawn command: {e}");
            send_msg(writer, &Message::Stderr(err_msg.into_bytes()))?;
            send_msg(writer, &Message::Exit(127))?;
        }
    }

    Ok(())
}
