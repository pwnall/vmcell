//! Guest agent running as PID 1 inside the microvm.
//!
//! No crate-level `forbid(unsafe_code)`: PID-1 setup issues raw mount/syscall FFI. The unsafe
//! surface is audited via `undocumented_unsafe_blocks` + `unsafe_op_in_unsafe_fn`. The
//! `unwrap_used`/`panic` bans are load-bearing here — a PID-1 panic aborts the whole guest.
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
use rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_change, unmount,
};
use rustix::process::{WaitOptions, pivot_root, wait};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use vmcell_guest_agent::{ReaperCoordinator, exit_code_from_termination, netif};
use vmcell_protocol::{self as protocol, ExecRequest, MAX_FRAME_BYTES, Message};
use vsock::{VsockAddr, VsockListener, VsockStream};

/// Reaps every currently-exited child with `WNOHANG`, recording each status in
/// the shared [`ReaperCoordinator`] so the matching per-exec waiter can claim
/// it.
///
/// Invoked on each `SIGCHLD` wake. Because `SIGCHLD` coalesces, this drains
/// *all* reapable children in one pass so none is missed; statuses for
/// re-parented grandchildren that no waiter claims are pruned by the
/// coordinator, keeping the map bounded.
fn drain_zombies(reaper: &ReaperCoordinator) {
    // The `waitpid(WNOHANG)` reap and the status record run under one lock (via
    // `drain_reaped`) so a fork that reuses a just-freed pid cannot `reserve` it
    // *between* the reap and the record — closing the residual PID-reuse race
    // where a stale grandchild status is stamped past the reservation epoch and
    // mis-delivered as the reused child's exit (AGENT-1, §4.3).
    reaper.drain_reaped(|| match wait(WaitOptions::NOHANG) {
        Ok(Some((pid, status))) => {
            let pid = pid.as_raw_nonzero().get().cast_unsigned();
            let code = exit_code_from_termination(
                status.terminating_signal().map(|s| s.cast_signed()),
                status.exit_status().map(|c| c.cast_signed()),
            );
            Some((pid, code))
        }
        // `Ok(None)` = no more reapable children; `Err` (e.g. ECHILD) = stop.
        _ => None,
    });
}

/// A virtio-fs share the guest must mount, decoded from one `vmcell_share=` token.
struct ShareMount {
    /// virtio-fs mount tag.
    tag: String,
    /// Absolute in-guest mount point (the host's `Share::guest_path`, default `/<tag>`).
    mount_point: String,
    /// Whether to mount read-only (the host declared `ro`).
    read_only: bool,
}

/// Parses `vmcell_share=<tag>:<guest_path>:<ro|rw>` tokens out of the kernel
/// command line.
///
/// The host emits one token per configured share (`config::push_share_args`), and
/// the guest mounts each `tag` at its `guest_path`. A token is skipped — never
/// trusted — when it is malformed (fewer than three `:`-separated fields, an empty
/// tag or mount point, or an access mode other than `ro`/`rw`), so a corrupt boot
/// line cannot silently mount read-write a share the host declared read-only.
fn parse_share_mounts(cmdline: &str) -> Vec<ShareMount> {
    cmdline
        .split_ascii_whitespace()
        .filter_map(|tok| tok.strip_prefix("vmcell_share="))
        .filter_map(|spec| {
            let mut fields = spec.splitn(3, ':');
            let tag = fields.next()?;
            let mount_point = fields.next()?;
            let access = fields.next()?;
            if tag.is_empty() || mount_point.is_empty() {
                return None;
            }
            let read_only = match access {
                "ro" => true,
                "rw" => false,
                _ => return None,
            };
            Some(ShareMount {
                tag: tag.to_string(),
                mount_point: mount_point.to_string(),
                read_only,
            })
        })
        .collect()
}

/// Parses a whole-millisecond timeout token out of the (UNTRUSTED) kernel command
/// line, clamped into the inclusive `[floor_ms, ceil_ms]` window.
///
/// Scans the whitespace-split tokens for the first that `strip_prefix(key)` and
/// then parses as a `u64`, and clamps the result into `[floor_ms, ceil_ms]` — so a
/// hostile or fat-fingered boot line cannot drive a guest timeout to a busy-spin
/// (`0`) or an unbounded stall. An absent, non-numeric, or overflowing token falls
/// back to `default_ms` (assumed already in range). `/proc/cmdline` is
/// host-controlled but treated as untrusted here, exactly like
/// [`parse_share_mounts`].
fn parse_ms(
    cmdline: &str,
    key: &str,
    default_ms: u64,
    floor_ms: u64,
    ceil_ms: u64,
) -> std::time::Duration {
    let ms = cmdline
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix(key)?.parse::<u64>().ok())
        .map_or(default_ms, |v| v.clamp(floor_ms, ceil_ms));
    std::time::Duration::from_millis(ms)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("vmcell-guest-agent: starting");

    // Mount setup. `/sys` is NOT in the fatal core-mount set ({overlay, /proc,
    // /dev}, §4.3): its *mount* failure is tolerated below (:127-138), so its
    // mount-point creation must be tolerated too — a fatal `?` here would
    // kernel-panic PID 1 ("Attempted to kill init") on a policy the agent
    // otherwise treats as best-effort (AGENT-6).
    if let Err(e) = std::fs::create_dir_all("/sys") {
        tracing::warn!(
            "vmcell-guest-agent: could not create /sys mount point: {}; continuing (sysfs is not a fatal core mount)",
            e
        );
    }
    std::fs::create_dir_all("/proc")?;
    std::fs::create_dir_all("/mnt")?;

    if let Err(e) = mount("tmpfs", "/mnt", "tmpfs", MountFlags::empty(), "") {
        // Fatal core mount (§4.3): failure returns Err and kernel-panics PID 1, so
        // log it at error — louder than the tolerated best-effort failures (sysfs,
        // shares, loopback) that log at warn (N-GUEST-1: the levels were inverted).
        tracing::error!("vmcell-guest-agent: mount tmpfs failed: {}", e);
        return Err(e.into());
    }
    std::fs::create_dir_all("/mnt/upper")?;
    std::fs::create_dir_all("/mnt/work")?;
    std::fs::create_dir_all("/mnt/rootfs")?;

    if let Err(e) = mount(
        "overlay",
        "/mnt/rootfs",
        "overlay",
        MountFlags::empty(),
        "lowerdir=/,upperdir=/mnt/upper,workdir=/mnt/work",
    ) {
        // Fatal core mount (§4.3): error level (N-GUEST-1).
        tracing::error!("vmcell-guest-agent: overlay failed: {}", e);
        return Err(e.into());
    }

    if let Err(e) = std::env::set_current_dir("/mnt/rootfs") {
        tracing::error!("vmcell-guest-agent: failed to chdir to /mnt/rootfs: {}", e);
        return Err(e.into());
    }
    std::fs::create_dir_all("oldroot")?;

    if let Err(e) = pivot_root(".", "oldroot") {
        // Fatal core mount (§4.3): error level (N-GUEST-1).
        tracing::error!("vmcell-guest-agent: pivot_root failed: {}", e);
        return Err(e.into());
    }
    // The `else` is unnecessary after the early `return Err` above (N-GUEST-1):
    // the success path continues here.
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )?;
    unmount("oldroot", UnmountFlags::DETACH)?;
    std::fs::remove_dir_all("oldroot")?;

    // /sys is NOT part of the fatal core-mount set — that set is EXACTLY
    // {overlay, /proc, /dev} (§4.3). The vsock control plane, the
    // overlay/pivot_root sequence, and restore-path MAC rotation (ioctls) do not
    // require sysfs, so a failed sysfs mount is logged and tolerated like the
    // share-mount / loopback paths below. Returning Err from PID 1's main would
    // kernel-panic the guest ("Attempted to kill init").
    if let Err(e) = mount("sysfs", "/sys", "sysfs", MountFlags::empty(), "") {
        tracing::warn!(
            "vmcell-guest-agent: sysfs mount failed: {}; continuing without /sys",
            e
        );
    }
    if let Err(e) = mount("proc", "/proc", "proc", MountFlags::empty(), "") {
        // Fatal core mount (§4.3): error level (N-GUEST-1).
        tracing::error!("vmcell-guest-agent: proc failed: {}", e);
        return Err(e.into());
    }
    if let Err(e) = mount("devtmpfs", "/dev", "devtmpfs", MountFlags::empty(), "") {
        // Fatal core mount (§4.3): error level (N-GUEST-1).
        tracing::error!("vmcell-guest-agent: devtmpfs failed: {}", e);
        return Err(e.into());
    }

    // Mount the virtio-fs shares the host configured, decoded from the kernel
    // command line (`vmcell_share=<tag>:<guest_path>:<ro|rw>` tokens emitted by
    // `config::push_share_args`). Tags are caller-defined, not built into the
    // agent (§5.2): the agent honours whatever `VmConfig.shares` specified rather
    // than a hardcoded `imp-*` list. A share is optional — a config may attach
    // none (the benchmark / exec-only paths do), and virtiofsd may not be attached
    // for a declared tag, so a failed mount is logged and skipped, never
    // propagated: returning Err from PID 1's main kernel-panics the guest
    // ("Attempted to kill init").
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    for ShareMount {
        tag,
        mount_point,
        read_only,
    } in parse_share_mounts(&cmdline)
    {
        if let Err(e) = std::fs::create_dir_all(&mount_point) {
            tracing::warn!(
                "vmcell-guest-agent: could not create mount point {}: {}; skipping share",
                mount_point,
                e
            );
            continue;
        }

        let flags = if read_only {
            MountFlags::RDONLY
        } else {
            MountFlags::empty()
        };
        if let Err(e) = mount(tag.as_str(), &mount_point as &str, "virtiofs", flags, "") {
            tracing::warn!(
                "vmcell-guest-agent: optional virtiofs share {} not attached: {}; continuing",
                tag,
                e
            );
        } else {
            tracing::info!(
                "vmcell-guest-agent: mounted virtiofs {} at {} ({})",
                tag,
                mount_point,
                if read_only { "ro" } else { "rw" }
            );
        }
    }

    // Bring up loopback without shelling out to `ip`, via the audited 40-byte
    // `IfReq` helper (C-GUEST-1/M-GUEST-5). The prior inline path here declared an
    // 18-byte `ifreq` and passed it to `SIOCG/SIOCSIFFLAGS`, which `copy_to_user`
    // the kernel's 40-byte `struct ifreq` — a 22-byte OOB write on PID 1's stack.
    // Best-effort: loopback is not required for the vsock control plane, so a
    // failure is logged and tolerated (returning `Err` from PID 1 would panic).
    if let Err(e) = netif::set_loopback_up() {
        tracing::warn!(
            "vmcell-guest-agent: loopback bring-up failed: {}; continuing without lo",
            e
        );
    }

    // Boot-time control-plane self-check, run BEFORE binding the listener so a
    // missing transport yields a clear diagnostic instead of an opaque bind
    // failure. Probe AF_VSOCK by actually opening a socket; the host-side
    // `/dev/vhost-vsock` device is irrelevant inside the guest, so it is not
    // consulted.
    // SAFETY: `socket(2)` is invoked with constant, valid arguments (AF_VSOCK/SOCK_STREAM, protocol
    // 0); the returned fd is checked and closed below before any other use.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    let vsock_ok = if fd >= 0 {
        // SAFETY: `fd` is a live socket fd just returned by `socket(2)` above; closed exactly once
        // here and never used afterwards.
        unsafe { libc::close(fd) };
        true
    } else {
        false
    };
    if vsock_ok {
        tracing::info!("vmcell-guest-agent: boot self-check: AF_VSOCK transport available");
    } else {
        tracing::error!(
            "vmcell-guest-agent: boot self-check: AF_VSOCK unavailable ({}); the vsock control plane will not come up",
            std::io::Error::last_os_error()
        );
    }

    let virtiofs_supported = std::fs::read_to_string("/proc/filesystems")
        .is_ok_and(|contents| contents.contains("virtiofs"));
    if virtiofs_supported {
        tracing::info!("vmcell-guest-agent: boot self-check: virtiofs filesystem supported");
    } else {
        tracing::warn!(
            "vmcell-guest-agent: boot self-check: virtiofs not advertised in /proc/filesystems"
        );
    }

    // Shared reaper/exec coordination: a single WNOHANG reaper (this thread)
    // records every child's exit code; each per-exec waiter blocks until its
    // pid's status is recorded, then claims it. No `child.wait()` races the
    // reaper (the false-127 bug it avoids), and unclaimed grandchild statuses
    // are pruned so the status map stays bounded.
    let reaper = Arc::new(ReaperCoordinator::new());

    // Per-VM guest timeout tuning from the (untrusted) kernel cmdline (§8.3): the
    // host emits `vmcell_accept_poll_ms=` / `vmcell_rebind_idle_ms=` from
    // `cfg.timeouts` so the bind-retry / re-bind cadence is tunable without a
    // rootfs rebuild. Absent/garbage tokens fall back to the compiled defaults
    // (`ACCEPT_POLL` / `REBIND_IDLE`); each is clamped to a correctness floor so a
    // `0` cannot busy-spin PID 1.
    let accept_poll = parse_ms(
        &cmdline,
        "vmcell_accept_poll_ms=",
        u64::try_from(ACCEPT_POLL.as_millis()).unwrap_or(u64::MAX),
        1,
        10_000,
    );
    let rebind_idle = parse_ms(
        &cmdline,
        "vmcell_rebind_idle_ms=",
        u64::try_from(REBIND_IDLE.as_millis()).unwrap_or(u64::MAX),
        20,
        60_000,
    );

    // Install the SIGCHLD/SIGTERM handler BEFORE spawning the vsock listener
    // thread (L-GUEST-11). The listener spawns exec children on accepted
    // connections; a child that exits in the window before the handler is
    // installed would deliver its SIGCHLD to the default disposition and be
    // recorded only on the *next* SIGCHLD — delaying (or, absent any later
    // signal, stranding) that exit. Registering first closes the window; the
    // pre-spawn drain below still catches anything that exited before this point.
    let signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGCHLD,
        signal_hook::consts::SIGTERM,
    ]);

    // Spawn vsock listener thread (recoverable across snapshot/restore).
    let listener_reaper = Arc::clone(&reaper);
    std::thread::spawn(move || serve_vsock(&listener_reaper, accept_poll, rebind_idle));

    // Main thread is the PID 1 zombie reaper. It is woken by SIGCHLD rather
    // than polling, so an exec's exit is observed immediately instead of up to
    // ~100 ms late. SIGCHLD coalesces, so each wake drains *all* reapable
    // children.
    drain_zombies(&reaper); // catch anything that exited before registration
    match signals {
        Ok(mut signals) => {
            for signal in signals.forever() {
                drain_zombies(&reaper);
                if signal == signal_hook::consts::SIGTERM {
                    break;
                }
            }
        }
        Err(e) => {
            // Degraded fallback: the signalfd/handler could not be installed, so
            // reap on a timer instead of leaving zombies unreaped. PID 1 must
            // never exit on a recoverable condition.
            tracing::error!(
                "vmcell-guest-agent: SIGCHLD registration failed: {}; falling back to a polling reaper",
                e
            );
            let term = Arc::new(AtomicBool::new(false));
            let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term));
            while !term.load(std::sync::atomic::Ordering::Relaxed) {
                drain_zombies(&reaper);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // Either reaper loop only exits on SIGTERM. PID 1 must NOT return here: a
    // returning init kernel-panics the guest ("Attempted to kill init"), which
    // the host then flags via `contains_panic()`. On SIGTERM (normal teardown
    // signals the guest before force-killing the VMM group) perform an orderly
    // power-off instead of falling out of `main` (AGENT-2, §4.3).
    power_off_never_returns()
}

/// Powers the guest off in response to SIGTERM and never returns.
///
/// PID 1 returning from `main` panics the kernel, so this diverges: it flushes
/// filesystem buffers and issues `reboot(RB_POWER_OFF)`, which only returns on
/// failure (e.g. a missing `CAP_SYS_BOOT`); in that case it parks forever so
/// PID 1 still never exits.
fn power_off_never_returns() -> ! {
    tracing::info!("vmcell-guest-agent: received SIGTERM; powering off");
    // SAFETY: `sync(2)` takes no arguments and no pointers — flush filesystem buffers before reboot.
    unsafe {
        libc::sync();
    }
    // SAFETY: `reboot(2)` is called with the constant `RB_POWER_OFF` and no pointers; it returns only
    // on error, after which we park forever below so PID 1 never returns to the kernel.
    unsafe {
        libc::reboot(libc::RB_POWER_OFF);
    }
    tracing::error!(
        "vmcell-guest-agent: power-off failed ({}); parking so PID 1 never exits",
        std::io::Error::last_os_error()
    );
    loop {
        std::thread::park();
    }
}

/// vsock control-plane port the host's `AgentClient` connects to.
const VSOCK_PORT: u32 = 5000;
/// Compiled **default** retry cadence for a *failed vsock `bind`*, used when the
/// host does not emit `vmcell_accept_poll_ms=` on the cmdline (§8.3).
///
/// **Semantic change (OPP-2):** the accept path itself is now event-driven — a
/// blocking `poll(2)` on the listener fd wakes sub-millisecond on connection
/// arrival — so this cadence no longer bounds connect latency. It governs only
/// how often [`serve_vsock`] retries after `bind_vsock_listener` fails. The
/// `parse_ms` floor clamp (1 ms) stays load-bearing on that path: a hostile
/// `vmcell_accept_poll_ms=0` must not turn the bind-retry loop into a busy-spin.
const ACCEPT_POLL: std::time::Duration = std::time::Duration::from_millis(20);
/// Compiled **default** re-bind idle window, used when the host does not emit
/// `vmcell_rebind_idle_ms=` on the cmdline (§8.3): re-bind the listener after this
/// much idle time with no new connection. Bounds the post-restore "deaf listener"
/// window (§9.2): on CH `--restore` the pre-snapshot listener stops yielding
/// accepts, and the guest only re-attaches to the re-created vhost-vsock device by
/// re-binding. Re-binding is harmless during normal operation (accepted
/// connections keep their own fds), so a shorter idle only tightens the worst-case
/// reconnect without new risk.
const REBIND_IDLE: std::time::Duration = std::time::Duration::from_millis(250);

/// Binds the `CID_ANY:VSOCK_PORT` listener in non-blocking mode.
///
/// Returns `None` on failure so the caller can retry — PID 1 must never give up
/// the control plane.
fn bind_vsock_listener() -> Option<VsockListener> {
    let addr = VsockAddr::new(0xFFFFFFFF, VSOCK_PORT); // VMADDR_CID_ANY
    match VsockListener::bind(&addr) {
        Ok(listener) => {
            if let Err(e) = listener.set_nonblocking(true) {
                tracing::warn!(
                    "vmcell-guest-agent: vsock set_nonblocking failed: {}; cannot poll for re-bind",
                    e
                );
            }
            Some(listener)
        }
        Err(e) => {
            tracing::error!("vmcell-guest-agent: failed to bind vsock: {}", e);
            None
        }
    }
}

/// One iteration's outcome in the accept loop, as seen by the re-bind deadline
/// policy ([`next_deadline`]).
#[derive(Clone, Copy, Debug)]
enum AcceptOutcome {
    /// `accept()` returned a live connection.
    Accepted,
    /// `poll(2)` reported `POLLIN` but `accept()` said `WouldBlock` — a spurious
    /// wakeup.
    SpuriousReadable,
    /// `poll(2)` returned `EINTR` (PID 1 takes `SIGCHLD`; `poll` is never
    /// auto-restarted by `SA_RESTART`).
    Interrupted,
}

/// The re-bind deadline policy for one accept-loop iteration: only a **real**
/// accept restarts the idle window; a spurious wakeup or `EINTR` leaves the
/// deadline untouched.
///
/// The untouched-deadline half is the load-bearing part (§9.2/§12.4): a
/// post-restore *deaf* listener never delivers a real accept, but `poll` can
/// still wake (signals, stray revents). If those wakes extended the deadline,
/// the idle window would never elapse and the listener would never re-bind.
fn next_deadline(
    deadline: Instant,
    now: Instant,
    rebind_idle: Duration,
    outcome: AcceptOutcome,
) -> Instant {
    match outcome {
        AcceptOutcome::Accepted => now + rebind_idle,
        AcceptOutcome::SpuriousReadable | AcceptOutcome::Interrupted => deadline,
    }
}

/// Remaining time in the re-bind idle window, or `None` once the deadline has
/// been reached — the caller must then re-bind, not poll again.
///
/// Saturating: a `now` past the deadline yields `None`, never an underflow
/// panic. Exactly-at-deadline is `None`, not `Some(ZERO)` — a zero remainder
/// fed to [`poll_timeout_ms`] would be floored back up to 1 ms and the deaf
/// listener would keep polling forever instead of re-binding.
fn remaining_idle(deadline: Instant, now: Instant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(now);
    (remaining > Duration::ZERO).then_some(remaining)
}

/// Clamps a remaining idle window into the whole-millisecond timeout `poll(2)`
/// takes: floored at 1 ms and otherwise truncated so it never overshoots the
/// remaining window by a full tick.
///
/// The 1 ms floor is a correctness floor, like the `parse_ms` clamp: a
/// sub-millisecond remainder truncated to `0` means "return immediately", which
/// busy-spins PID 1 until the deadline check catches up. Overshooting a sub-ms
/// remainder by <1 ms is harmless — the deadline itself is enforced on
/// [`Instant`]s by [`remaining_idle`], not by the poll timeout.
fn poll_timeout_ms(remaining: Duration) -> i32 {
    // Cap at i32::MAX (an over-long remainder), floor at 1 ms; both are correctness bounds, not a
    // truncating `as` — `try_from` saturates instead of wrapping. Equivalent to the old clamp+cast.
    i32::try_from(remaining.as_millis())
        .unwrap_or(i32::MAX)
        .max(1)
}

/// Serves the vsock control plane, re-binding the listener across snapshot
/// restores.
///
/// After a CH/Firecracker `--restore` the vhost-vsock device is re-created and
/// the listener bound before the snapshot goes deaf — it never yields the host's
/// post-restore reconnect (and the stale connection may never EOF), so a
/// bound-once listener wedges the warm-restore path forever. We therefore
/// re-`bind` whenever the listener has been idle for `rebind_idle`, which
/// re-attaches it to the *current* device. Re-binding is harmless during normal
/// operation: already-accepted connections keep their own fds, and the fresh
/// listener re-binds the same `CID_ANY:VSOCK_PORT` on the live device. Each
/// accepted connection is served on its own thread so a parked stale connection
/// never blocks new accepts.
///
/// The wait is event-driven (OPP-2): instead of `accept` → `WouldBlock` →
/// `sleep(accept_poll)` (a mean ~half-interval of added latency on *every*
/// connect), the loop blocks in `poll(2)` on the listener fd for `POLLIN` with
/// the **remaining re-bind window** as the timeout, so a host connection wakes
/// the agent sub-millisecond while the idle window still elapses exactly as
/// before. The deadline is `Instant`-based ([`remaining_idle`]) and only a real
/// accept restarts it ([`next_deadline`]); `EINTR` and spurious wakeups re-poll
/// with the recomputed remainder. `accept_poll` now paces only the bind-failure
/// retry (see [`ACCEPT_POLL`]). Any poll-level listener failure
/// (`POLLERR`/`POLLHUP`/`POLLNVAL`, or an errno other than `EINTR`) is logged
/// and treated like the deaf-listener case — re-bind, never exit: PID 1 must
/// never give up the control plane.
fn serve_vsock(reaper: &Arc<ReaperCoordinator>, accept_poll: Duration, rebind_idle: Duration) {
    use rustix::event::{PollFd, PollFlags};

    loop {
        let Some(listener) = bind_vsock_listener() else {
            // Bind-failure retry cadence: the one remaining consumer of
            // `accept_poll`, still floor-clamped by `parse_ms` so a cmdline `0`
            // cannot busy-spin PID 1.
            std::thread::sleep(accept_poll);
            continue;
        };
        tracing::info!("vmcell-guest-agent: listening on vsock port {}", VSOCK_PORT);

        // Idle window starts at the (re)bind; only a successful accept restarts
        // it. Once it elapses with no accepted connection — or an arm below
        // `break`s on a listener-level failure — fall out, drop this listener,
        // and re-bind on the current device (§9.2).
        let mut deadline = Instant::now() + rebind_idle;
        while let Some(remaining) = remaining_idle(deadline, Instant::now()) {
            let mut fds = [PollFd::new(&listener, PollFlags::IN)];
            match rustix::event::poll(&mut fds, poll_timeout_ms(remaining)) {
                // Timed out: loop back — the recomputed remainder hits zero (or
                // re-polls a sub-ms tail once) and triggers the re-bind.
                Ok(0) => {}
                Ok(_) => {
                    let revents = fds[0].revents();
                    if revents.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
                        tracing::warn!(
                            "vmcell-guest-agent: vsock listener poll revents {:?}; re-binding",
                            revents
                        );
                        break;
                    }
                    // POLLIN: the (still non-blocking) listener should have a
                    // connection ready.
                    match listener.accept() {
                        Ok((mut s, _)) => {
                            deadline = next_deadline(
                                deadline,
                                Instant::now(),
                                rebind_idle,
                                AcceptOutcome::Accepted,
                            );
                            tracing::info!("vmcell-guest-agent: accepted connection");
                            let conn_reaper = Arc::clone(reaper);
                            std::thread::spawn(move || {
                                if let Err(e) = handle_connection(&mut s, &conn_reaper) {
                                    // A clean host disconnect surfaces as
                                    // `read_framed`'s `UnexpectedEof` (the length
                                    // prefix's `read_exact` hits EOF between
                                    // requests): that is the normal end of a
                                    // connection, not a fault, so log it at info.
                                    // Reserve error level for genuine
                                    // protocol/transport failures (L-GUEST-10).
                                    let clean_eof =
                                        e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                                            io.kind() == std::io::ErrorKind::UnexpectedEof
                                        });
                                    if clean_eof {
                                        tracing::info!(
                                            "vmcell-guest-agent: host closed the connection"
                                        );
                                    } else {
                                        tracing::error!(
                                            "vmcell-guest-agent: handle_connection error: {}",
                                            e
                                        );
                                    }
                                }
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Spurious wakeup: re-poll with the recomputed
                            // remainder. MUST NOT restart the idle window — a
                            // deaf listener has to run out the clock and re-bind.
                            deadline = next_deadline(
                                deadline,
                                Instant::now(),
                                rebind_idle,
                                AcceptOutcome::SpuriousReadable,
                            );
                        }
                        Err(e) => {
                            tracing::info!("vmcell-guest-agent: accept error: {}; re-binding", e);
                            // L-GUEST-4: back off before the outer loop re-binds.
                            // A persistent accept error (e.g. EMFILE) would
                            // otherwise spin: break → immediate re-bind → poll →
                            // accept error → … with no pause. The bind-failure
                            // path already sleeps `accept_poll`; mirror it here so
                            // every recover-by-rebind path is rate-limited.
                            std::thread::sleep(accept_poll);
                            break;
                        }
                    }
                }
                Err(rustix::io::Errno::INTR) => {
                    // PID 1 takes SIGCHLD and poll(2) is never auto-restarted:
                    // re-poll with the recomputed remainder, deadline untouched.
                    deadline = next_deadline(
                        deadline,
                        Instant::now(),
                        rebind_idle,
                        AcceptOutcome::Interrupted,
                    );
                }
                Err(e) => {
                    // Fail loud, then recover: any other poll failure is treated
                    // like the deaf-listener case — re-bind rather than exit.
                    tracing::warn!(
                        "vmcell-guest-agent: vsock listener poll failed: {}; re-binding",
                        e
                    );
                    // L-GUEST-4: back off before re-binding so a persistent poll
                    // failure cannot spin the bind→poll→error loop.
                    std::thread::sleep(accept_poll);
                    break;
                }
            }
        }
    }
}

fn handle_connection(
    stream: &mut VsockStream,
    reaper: &Arc<ReaperCoordinator>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ready_msg = postcard::to_stdvec(&Message::Ready)?;
    send_framed(stream, &ready_msg)?;

    loop {
        let req_bytes = read_framed(stream)?;
        let msg: Message = postcard::from_bytes(&req_bytes)?;

        match msg {
            Message::Exec(req) => handle_exec(req, stream, reaper)?,
            Message::PutFile { dst, bytes } => handle_put_file(&dst, &bytes, stream)?,
            Message::Resync {
                unix_secs,
                unix_nanos,
                mac,
                ipv4,
            } => handle_resync(unix_secs, unix_nanos, mac, ipv4, stream)?,
            // Ready/Stdout/Stderr/Exit are guest→host frames; receiving one (or
            // any future variant) means the peer desynced. Log it loudly and
            // close the connection so the host reconnects on a fresh stream,
            // rather than silently swallowing it and looping on a skewed stream
            // (AGENT-5).
            other => {
                tracing::warn!(
                    "vmcell-guest-agent: unexpected control-plane message {:?}; closing connection to resync",
                    other
                );
                return Ok(());
            }
        }
    }
}

// Generic over `Write`/`Read` (not just `VsockStream`) so the hand-rolled
// framing — the load-bearing interop with the host's `tokio_util`
// `LengthDelimitedCodec` — can be round-tripped against the real codec in a
// KVM-free unit test (AGENT-3); `VsockStream` satisfies both bounds.
fn send_framed<W: Write>(stream: &mut W, data: &[u8]) -> std::io::Result<()> {
    // Enforce the shared cap on the ENCODE side too (L-GUEST-2), mirroring the
    // host codec and the guest decode path. Without this, a `data.len()` above
    // `u32::MAX` would silently truncate through `as u32` and the host would
    // decode a wrong length; even below that, sending an over-cap frame the host
    // rejects only wastes a round-trip. Fail loud at the source instead.
    if data.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    // `data.len() <= MAX_FRAME_BYTES` (checked just above) < u32::MAX, so this never truncates; the
    // saturating fallback is dead but keeps the narrowing honest (a bogus over-cap length would be
    // sent as u32::MAX, which the host rejects — never a silently-wrong small length).
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}

fn read_framed<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Shared cap with the host codec (see `MAX_FRAME_BYTES`); both ends agree so
    // neither silently drops a frame the other was willing to send.
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}

fn handle_put_file(
    dst: &str,
    bytes: &[u8],
    stream: &mut VsockStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = std::path::Path::new(dst).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dst, bytes)?;
        Ok(())
    })();

    let code = if result.is_ok() { 0 } else { 1 };
    let exit_msg = postcard::to_stdvec(&Message::Exit(code))?;
    send_framed(stream, &exit_msg)?;
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
fn resync_timespec(unix_secs: u64, unix_nanos: u32) -> rustix::time::Timespec {
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
fn reseed_urandom_from_hwrng() -> std::io::Result<()> {
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
/// (design 44 §5).
///
/// The clock set is **mandatory** (§9.2): a failure is reported via `clock_error`
/// but NEVER propagated with `?` or a panic — the ack must always be sent so the
/// host gets a definitive answer and decides (it treats a `Some(clock_error)` as a
/// hard, retryable failure). The CSPRNG reseed and MAC rotation are best-effort
/// and reported via the two bool flags; neither failing aborts the ack.
fn handle_resync(
    unix_secs: u64,
    unix_nanos: u32,
    mac: Option<[u8; 6]>,
    ipv4: Option<protocol::Ipv4Reconfig>,
    stream: &mut VsockStream,
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
                "vmcell-guest-agent: resync hwrng reseed failed: {}; continuing (best-effort)",
                e
            );
            false
        }
    };

    // 3. MAC rotation (best-effort): install the new eth0 hwaddr in-process via
    //    SIOCSIFHWADDR (no in-guest netlink). Absent MAC → not applied. Log the
    //    io::Error cause on failure (L-GUEST-6) instead of discarding it via
    //    `.is_ok()`.
    let mac_applied = match mac {
        None => false,
        Some(m) => match netif::set_mac_bytes("eth0", m) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    "vmcell-guest-agent: resync MAC rotation failed: {}; continuing (best-effort)",
                    e
                );
                false
            }
        },
    };

    // 4. IPv4 rotation (best-effort, H-VMM-1): the restore/zygote path rotates the
    //    vmid, so the guest resumes with the frozen `ip=` address of the original
    //    vmid — re-point `eth0` + the default route to the rotated `/30`, in-process
    //    via SIOCSIFADDR/route ioctls (no in-guest netlink), exactly as the MAC
    //    rotation above. Absent config → not applied. Log the cause on failure.
    let ip_applied = match ipv4 {
        None => false,
        Some(cfg) => match netif::set_ipv4("eth0", cfg.addr, cfg.prefix_len, cfg.gateway) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    "vmcell-guest-agent: resync IP rotation failed: {}; continuing (best-effort)",
                    e
                );
                false
            }
        },
    };

    let ack = Message::ResyncAck {
        clock_error,
        reseed_applied,
        mac_applied,
        ip_applied,
    };
    let bytes = postcard::to_stdvec(&ack).map_err(std::io::Error::other)?;
    send_framed(stream, &bytes)?;
    Ok(())
}

fn handle_exec(
    req: ExecRequest,
    stream: &mut VsockStream,
    reaper: &Arc<ReaperCoordinator>,
) -> Result<(), Box<dyn std::error::Error>> {
    // `split_first` is the non-panicking form of the "argv[0] is the program, argv[1..] the
    // args" split, and folds in the empty-argv guard (indexing_slicing is denied in PID-1 code).
    let Some((program, args)) = req.argv.split_first() else {
        let exit_msg = postcard::to_stdvec(&Message::Exit(1))?;
        send_framed(stream, &exit_msg)?;
        return Ok(());
    };

    let mut cmd = Command::new(program);
    cmd.args(args);
    // Run the child as its own process-group leader so the timeout path can
    // signal the whole group (`kill(-pgid)`), tearing down any subprocesses it
    // spawned rather than only the leader.
    cmd.process_group(0);

    if let Some(cwd) = req.cwd {
        cmd.current_dir(cwd);
    }

    let mut req_path: Option<String> = None;
    for (k, v) in req.env {
        if k == "PATH" {
            req_path = Some(v.clone());
        }
        cmd.env(k, v);
    }

    // Surface the `/vmcell-tools` guest-helper dir (ip/curl/kvm-ok, baked into the
    // rootfs) on the child's PATH, ahead of the request-provided or inherited
    // PATH. PID 1 may inherit a minimal/empty PATH, so fall back to the standard
    // system directories.
    let base_path = req_path
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    let child_path = if base_path.is_empty() {
        "/vmcell-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
    } else {
        format!("/vmcell-tools:{base_path}")
    };
    cmd.env("PATH", child_path);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Point the child's stdin at /dev/null (M-GUEST-1). PID 1's own fd 0 is the
    // serial console (`/dev/console`), from which no input ever arrives, so a
    // command that reads stdin (`cat`, `wc`, a `sh` heredoc) would block on the
    // console and run out its timeout instead of seeing EOF immediately.
    cmd.stdin(Stdio::null());

    // AGENT-2: capture the reservation epoch BEFORE the spawn. An instant child
    // can exit and be drained by the PID-1 reaper before this thread reaches
    // `reserve` (on one vcpu the child often runs to completion first); the
    // pre-spawn epoch lets `reserve` recognize that already-recorded status as
    // the child's own (recorded after the epoch) instead of wiping it as a stale
    // previous occupant's — which stranded the waiter forever and surfaced on
    // the host as a sporadic "Agent exec timed out" for a command that had
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
                            let _ = tx_out.send(Message::Stdout(chunk));
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
                            let _ = tx_err.send(Message::Stderr(chunk));
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
            // accepts one recorded strictly after it (§4.3 PID-1 reaper-vs-waiter
            // contract). A status recorded after the epoch — this child's own,
            // when it exited and was drained before this line ran — survives the
            // reservation and is delivered immediately (AGENT-2).
            reaper.reserve(pid, pre_spawn_epoch);
            let has_exited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
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
                    use rustix::process::{Pid, Signal, kill_process_group};
                    if let Some(p) = Pid::from_raw(pid.cast_signed()) {
                        let _ = kill_process_group(p, Signal::Kill);
                    }
                    let _ = tx_timeout.send(Message::Stderr(b"Command timed out\n".to_vec()));
                }
            });

            let waiter_reaper = Arc::clone(reaper);
            std::thread::spawn(move || {
                // Claim this pid's exit code from the single shared reaper; no
                // `child.wait()` here, so the reaper cannot have its status
                // stolen (the false-127 race).
                let code = waiter_reaper.wait_for(pid);
                has_exited.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = out_handle.join();
                let _ = err_handle.join();
                let _ = tx.send(Message::Exit(code));
            });

            for msg in rx {
                let bytes = postcard::to_stdvec(&msg)?;
                send_framed(stream, &bytes)?;
                if let Message::Exit(_) = msg {
                    break;
                }
            }
        }
        Err(e) => {
            let err_msg = format!("Failed to spawn command: {e}");
            let msg = postcard::to_stdvec(&Message::Stderr(err_msg.into_bytes()))?;
            send_framed(stream, &msg)?;

            let exit_msg = postcard::to_stdvec(&Message::Exit(127))?;
            send_framed(stream, &exit_msg)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards the boot mount-plan decode (`<tag>:<guest_path>:<ro|rw>`). Buggy impls
    // this catches: ignoring the access mode (mounting a declared-`ro` share `rw` —
    // a real isolation break), and ignoring the guest_path (always mounting at
    // `/<tag>` instead of the host-chosen mount point).
    #[test]
    fn parse_share_mounts_decodes_tag_path_and_access() {
        let cmdline = "console=ttyS0 vmcell_share=data-in:/data-in:ro vmcell_vmid=7 vmcell_share=out:/srv/out:rw";
        let mounts = parse_share_mounts(cmdline);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].tag, "data-in");
        assert_eq!(mounts[0].mount_point, "/data-in");
        assert!(mounts[0].read_only, "ro share must mount read-only");
        assert_eq!(mounts[1].tag, "out");
        assert_eq!(
            mounts[1].mount_point, "/srv/out",
            "the custom guest_path must be honoured, not derived from the tag"
        );
        assert!(!mounts[1].read_only, "rw share must mount read-write");
    }

    // Too few fields, an unknown access mode, and an empty tag/mount point are each
    // dropped, not mounted — a corrupt boot line must not synthesize a share.
    #[test]
    fn parse_share_mounts_skips_malformed_tokens() {
        let cmdline = "vmcell_share=notag vmcell_share=t:/m:xx vmcell_share=:/m:ro \
                       vmcell_share=t::ro vmcell_share=ok:/ok:ro";
        let mounts = parse_share_mounts(cmdline);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].tag, "ok");
        assert_eq!(mounts[0].mount_point, "/ok");
        assert!(mounts[0].read_only);
    }

    #[test]
    fn parse_share_mounts_empty_when_no_tokens() {
        assert!(parse_share_mounts("console=ttyS0 root=/dev/vda ro").is_empty());
        assert!(parse_share_mounts("").is_empty());
    }

    // §8.3: the guest-tuning cmdline tokens are UNTRUSTED and must be clamped into
    // `[floor, ceil]`, falling back to the compiled default when absent/garbage.
    // The clamp is load-bearing: an un-clamped parse would let
    // `vmcell_accept_poll_ms=0` busy-spin PID 1's bind-retry loop (0ms sleep; since
    // OPP-2 this token paces only the bind-failure retry — the accept wait itself
    // is event-driven).
    #[test]
    fn parse_ms_clamps_and_defaults() {
        use std::time::Duration;
        let key = "vmcell_accept_poll_ms=";
        // Absent → the compiled default.
        assert_eq!(
            parse_ms("console=ttyS0 ro", key, 20, 1, 10_000),
            Duration::from_millis(20)
        );
        // An in-range value is honored verbatim.
        assert_eq!(
            parse_ms("vmcell_accept_poll_ms=7 ro", key, 20, 1, 10_000),
            Duration::from_millis(7)
        );
        // 0 is clamped UP to the floor (1) — the busy-spin guard. RED on an
        // un-clamped parse that would return 0.
        assert_eq!(
            parse_ms("vmcell_accept_poll_ms=0", key, 20, 1, 10_000),
            Duration::from_millis(1),
            "0 must clamp to the floor so it cannot busy-spin PID 1"
        );
        // Above the ceiling is clamped DOWN.
        assert_eq!(
            parse_ms("vmcell_accept_poll_ms=999999", key, 20, 1, 10_000),
            Duration::from_millis(10_000)
        );
        // Non-numeric garbage → the default (not a partial/zero parse).
        assert_eq!(
            parse_ms("vmcell_accept_poll_ms=abc", key, 20, 1, 10_000),
            Duration::from_millis(20)
        );
        // Overflowing `u64` → the default (parse fails, not saturates).
        assert_eq!(
            parse_ms(
                "vmcell_accept_poll_ms=99999999999999999999999999",
                key,
                20,
                1,
                10_000
            ),
            Duration::from_millis(20)
        );
        // The FIRST parseable token wins (matches the strip_prefix+parse contract).
        assert_eq!(
            parse_ms(
                "vmcell_accept_poll_ms=x vmcell_accept_poll_ms=9",
                key,
                20,
                1,
                10_000
            ),
            Duration::from_millis(9)
        );
    }

    // OPP-2: the pure deadline policy behind the event-driven accept loop. Only a
    // REAL accept restarts the re-bind idle window; a spurious POLLIN→WouldBlock
    // wakeup or an EINTR'd poll leaves the deadline exactly where it was. RED on
    // an impl that resets the deadline on either (`SpuriousReadable => now +
    // rebind_idle`): a post-restore deaf listener never yields a real accept but
    // its poll can still wake, so a resetting policy re-arms the window forever
    // and the §9.2 re-bind never fires.
    #[test]
    fn spurious_wakeup_and_eintr_do_not_reset_the_deadline() {
        let start = Instant::now();
        let idle = Duration::from_millis(250);
        let deadline = start + idle;
        // 200 ms into the window, so a buggy reset would move the deadline.
        let now = start + Duration::from_millis(200);
        assert_eq!(
            next_deadline(deadline, now, idle, AcceptOutcome::SpuriousReadable),
            deadline,
            "a spurious POLLIN→WouldBlock wakeup must not extend the re-bind deadline"
        );
        assert_eq!(
            next_deadline(deadline, now, idle, AcceptOutcome::Interrupted),
            deadline,
            "an EINTR'd poll (PID 1 takes SIGCHLD) must not extend the re-bind deadline"
        );
        // Only a successful accept restarts the idle window — anchored at `now`,
        // not at the old deadline.
        assert_eq!(
            next_deadline(deadline, now, idle, AcceptOutcome::Accepted),
            now + idle,
            "a real accept must restart the idle window from now"
        );
    }

    // The remaining-window math the poll timeout is derived from. RED on an impl
    // returning `Some(ZERO)` at the deadline (fed through the 1 ms poll-timeout
    // floor, the deaf listener would re-poll forever instead of re-binding) or one
    // that underflows/panics once `now` passes the deadline.
    #[test]
    fn remaining_idle_counts_down_and_expires_exactly_at_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(250);
        // Mid-window: the exact Instant-based remainder, no cadence quantization.
        assert_eq!(
            remaining_idle(deadline, now),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            remaining_idle(deadline, now + Duration::from_millis(100)),
            Some(Duration::from_millis(150))
        );
        // Exactly at the deadline the window is expired — None (re-bind), not
        // Some(ZERO) (another poll).
        assert_eq!(remaining_idle(deadline, deadline), None);
        // Past the deadline: saturating, still None.
        assert_eq!(
            remaining_idle(deadline, deadline + Duration::from_millis(40)),
            None
        );
    }

    // The poll(2) timeout clamp. RED if the 1 ms floor is dropped: a sub-ms
    // remainder truncates to 0 = "return immediately" and PID 1 busy-spins until
    // the deadline check catches up.
    #[test]
    fn poll_timeout_ms_floors_at_one_ms_and_never_exceeds_remaining() {
        assert_eq!(
            poll_timeout_ms(Duration::from_micros(300)),
            1,
            "a sub-millisecond remainder must floor to 1 ms, not truncate to 0"
        );
        assert_eq!(poll_timeout_ms(Duration::from_millis(1)), 1);
        // Whole-ms truncation: never over the remaining window by a full tick.
        assert_eq!(poll_timeout_ms(Duration::from_micros(2500)), 2);
        assert_eq!(poll_timeout_ms(Duration::from_millis(250)), 250);
        // Absurdly large windows saturate at i32::MAX instead of wrapping negative
        // (a negative poll timeout means "block forever" — the re-bind would die).
        assert_eq!(poll_timeout_ms(Duration::from_secs(u64::MAX)), i32::MAX);
    }

    // The (secs, nanos) → Timespec mapping the mandatory post-restore clock set
    // consumes. RED on a units swap (secs↔nanos) or a truncating nanos cast.
    #[test]
    fn resync_timespec_maps_fields() {
        let ts = resync_timespec(1_700_000_000, 123_456_789);
        assert_eq!(ts.tv_sec, 1_700_000_000, "unix_secs must map to tv_sec");
        assert_eq!(ts.tv_nsec, 123_456_789, "unix_nanos must map to tv_nsec");
        assert_ne!(
            ts.tv_sec, 123_456_789,
            "a secs↔nanos swap must not put the nanos in tv_sec"
        );
        // The full u32 nanos range maps without overflow/truncation.
        let ts_max = resync_timespec(0, u32::MAX);
        assert_eq!(ts_max.tv_sec, 0);
        assert_eq!(ts_max.tv_nsec, u32::MAX as i64);
    }

    // AGENT-3: the guest's hand-rolled framing is the load-bearing interop with
    // the host's `tokio_util::codec::LengthDelimitedCodec`, but the default suite
    // otherwise only ever runs the codec on both ends. These KVM-free tests pin
    // the two directions against the REAL codec plus the shared `MAX_FRAME_BYTES`
    // cap, so a wrong endianness, an off-by-the-prefix, or a cap mismatch reddens
    // here instead of only on a KVM host.
    use bytes::{Bytes, BytesMut};
    use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

    #[test]
    fn send_framed_is_decoded_by_real_length_delimited_codec() {
        // Frame with the guest and decode with the host's codec. RED on a
        // little-endian prefix, an off-by-one prefix, or a length that excludes
        // the header: the codec mis-reads the length and returns None/wrong bytes.
        let payload = b"hello framing interop \x00\x01\xfe\xff world".to_vec();
        let mut wire = Vec::new();
        send_framed(&mut wire, &payload).expect("send_framed");

        // Exact wire contract: 4-byte big-endian length prefix, then the payload.
        assert_eq!(&wire[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(&wire[4..], &payload[..]);

        let mut codec = LengthDelimitedCodec::new();
        let mut src = BytesMut::from(&wire[..]);
        let frame = codec
            .decode(&mut src)
            .expect("codec decode")
            .expect("a complete frame");
        assert_eq!(&frame[..], &payload[..]);
        assert!(src.is_empty(), "codec must consume exactly one guest frame");
    }

    #[test]
    fn read_framed_decodes_a_real_length_delimited_codec_frame() {
        // Encode with the host's codec and decode with the guest. RED on the same
        // inverses in the read direction (LE prefix / off-by-one / wrong cap).
        let payload = b"round trip the other way \xde\xad\xbe\xef".to_vec();
        let mut codec = LengthDelimitedCodec::new();
        let mut encoded = BytesMut::new();
        codec
            .encode(Bytes::from(payload.clone()), &mut encoded)
            .expect("codec encode");

        let mut cursor = std::io::Cursor::new(encoded.to_vec());
        let decoded = read_framed(&mut cursor).expect("read_framed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn send_framed_rejects_frame_over_max_frame_bytes() {
        // L-GUEST-2: the encode side enforces the shared cap too, so an over-cap
        // frame is rejected at the source rather than sent with a truncated (or,
        // above u32::MAX, wrapped) length prefix the host then mis-decodes. RED if
        // the encode-side check is dropped: `send_framed` would return Ok and write
        // the frame, leaving the sink non-empty.
        let data = vec![0u8; MAX_FRAME_BYTES + 1];
        let mut sink = Vec::new();
        let err = send_framed(&mut sink, &data).expect_err("over-cap frame must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            sink.is_empty(),
            "an over-cap frame must be rejected before any byte is written"
        );
    }

    #[test]
    fn send_framed_accepts_frame_at_exactly_max_frame_bytes() {
        // The boundary is allowed (`>` cap, not `>=`), symmetric with the decode
        // path. A frame at exactly the cap is framed with the 4-byte length prefix
        // + payload. RED if the encode cap is tightened off-by-one (it would then
        // reject the boundary as InvalidData).
        let data = vec![0xA5u8; MAX_FRAME_BYTES];
        let mut sink = Vec::new();
        send_framed(&mut sink, &data).expect("a frame at exactly the cap must be accepted");
        assert_eq!(sink.len(), 4 + MAX_FRAME_BYTES);
        assert_eq!(&sink[..4], &(MAX_FRAME_BYTES as u32).to_be_bytes());
    }

    #[test]
    fn read_framed_rejects_frame_over_max_frame_bytes() {
        // A header declaring more than the shared cap is rejected as InvalidData
        // *before* the body is read. RED if the cap check is dropped or loosened
        // (it would then try to allocate/read an over-cap body instead).
        let over = MAX_FRAME_BYTES as u32 + 1;
        let mut wire = Vec::new();
        wire.extend_from_slice(&over.to_be_bytes());
        // Body deliberately absent: the cap must trip on the header alone.
        let mut cursor = std::io::Cursor::new(wire);
        let err = read_framed(&mut cursor).expect_err("over-cap frame must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_framed_accepts_frame_at_exactly_max_frame_bytes() {
        // The boundary itself is allowed (`>` cap, not `>=`). With the header at
        // exactly MAX and no body, read_framed passes the cap check and then fails
        // on the missing body (UnexpectedEof) — NOT InvalidData. RED if the cap is
        // tightened off-by-one (it would reject the boundary as InvalidData) or
        // wired to a smaller constant.
        let mut wire = Vec::new();
        wire.extend_from_slice(&(MAX_FRAME_BYTES as u32).to_be_bytes());
        let mut cursor = std::io::Cursor::new(wire);
        let err = read_framed(&mut cursor).expect_err("short body must error");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::UnexpectedEof,
            "a frame at exactly the cap must pass the cap check, not be rejected as too large"
        );
    }
}
