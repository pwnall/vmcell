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
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use vmcell_guest_agent::{ReaperCoordinator, exit_code_from_termination, netif};
use vmcell_protocol::{
    self as protocol, ExecRequest, MAX_FRAME_BYTES, Message, SessionId, SessionSpec,
};
use vsock::{VsockAddr, VsockListener, VsockStream};

/// The single per-connection writer (§13, Cross-cutting invariants): every frame — the initial `Ready`,
/// one-shot exec/put-file/resync output, and all interactive-session frames from
/// every pump/waiter thread — is emitted through this one `send_framed` under one
/// lock, so no two threads write the vsock concurrently and multiplexed session
/// frames never interleave-corrupt on the wire. The write half is a `try_clone`d
/// handle sharing the socket with the read half the dispatch loop owns.
type Writer = Arc<Mutex<VsockStream>>;

/// The per-connection session table: `SessionId` → its live [`SessionHandle`]
/// (§3, The control plane: vsock, the host clients, and the guest agent). The dispatch loop inserts on `OpenSession` and looks up on
/// `Stdin`/`Winsize`/`CloseSession`; each session's waiter thread removes its own
/// entry on exit; connection teardown drains and kills whatever is left (§13, Cross-cutting invariants).
type Sessions = Arc<Mutex<HashMap<SessionId, SessionHandle>>>;

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
    // mis-delivered as the reused child's exit (AGENT-1, §3.4, The guest: vmcell-guest-agent as PID 1).
    reaper.drain_reaped(|| match wait(WaitOptions::NOHANG) {
        Ok(Some((pid, status))) => {
            let pid = pid.as_raw_nonzero().get().cast_unsigned();
            let code = exit_code_from_termination(
                // rustix 1.x `WaitStatus` signal/exit accessors already return
                // `Option<i32>` (they were `Option<u32>` on 0.38), so no cast is needed.
                status.terminating_signal(),
                status.exit_status(),
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
    // /dev}, §3.4, The guest: vmcell-guest-agent as PID 1): its *mount* failure is tolerated below (:127-138), so its
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

    if let Err(e) = mount(
        "tmpfs",
        "/mnt",
        "tmpfs",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-guest-agent as PID 1): failure returns Err and kernel-panics PID 1, so
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
        Some(c"lowerdir=/,upperdir=/mnt/upper,workdir=/mnt/work"),
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-guest-agent as PID 1): error level (N-GUEST-1).
        tracing::error!("vmcell-guest-agent: overlay failed: {}", e);
        return Err(e.into());
    }

    if let Err(e) = std::env::set_current_dir("/mnt/rootfs") {
        tracing::error!("vmcell-guest-agent: failed to chdir to /mnt/rootfs: {}", e);
        return Err(e.into());
    }
    std::fs::create_dir_all("oldroot")?;

    if let Err(e) = pivot_root(".", "oldroot") {
        // Fatal core mount (§3.4, The guest: vmcell-guest-agent as PID 1): error level (N-GUEST-1).
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
    // {overlay, /proc, /dev} (§3.4, The guest: vmcell-guest-agent as PID 1). The vsock control plane, the
    // overlay/pivot_root sequence, and restore-path MAC rotation (ioctls) do not
    // require sysfs, so a failed sysfs mount is logged and tolerated like the
    // share-mount / loopback paths below. Returning Err from PID 1's main would
    // kernel-panic the guest ("Attempted to kill init").
    if let Err(e) = mount(
        "sysfs",
        "/sys",
        "sysfs",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        tracing::warn!(
            "vmcell-guest-agent: sysfs mount failed: {}; continuing without /sys",
            e
        );
    }
    if let Err(e) = mount(
        "proc",
        "/proc",
        "proc",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-guest-agent as PID 1): error level (N-GUEST-1).
        tracing::error!("vmcell-guest-agent: proc failed: {}", e);
        return Err(e.into());
    }
    if let Err(e) = mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-guest-agent as PID 1): error level (N-GUEST-1).
        tracing::error!("vmcell-guest-agent: devtmpfs failed: {}", e);
        return Err(e.into());
    }

    // devpts at /dev/pts powers interactive PTY sessions (§3, The control plane: vsock, the host clients, and the guest agent):
    // `/dev/ptmx` allocates a master and `ptsname` resolves the slave under
    // /dev/pts. Best-effort and NOT in the fatal core-mount set {overlay, /proc,
    // /dev} (§3.4, The guest: vmcell-guest-agent as PID 1) — only PTY *sessions* need it (they fail loud with
    // `SessionExit(127)` if it is absent); one-shot exec, pipe sessions, and the
    // vsock control plane do not. So a failure is logged and tolerated like the
    // sysfs/share/loopback mounts (returning Err from PID 1 kernel-panics the
    // guest). `newinstance` is legacy/ignored on modern kernels; the standard
    // `gid=5,mode=620,ptmxmode=666` gives the usual /dev/pts semantics.
    if let Err(e) = std::fs::create_dir_all("/dev/pts") {
        tracing::warn!(
            "vmcell-guest-agent: could not create /dev/pts mount point: {}; PTY sessions unavailable",
            e
        );
    } else if let Err(e) = mount(
        "devpts",
        "/dev/pts",
        "devpts",
        MountFlags::empty(),
        Some(c"gid=5,mode=620,ptmxmode=666"),
    ) {
        tracing::warn!(
            "vmcell-guest-agent: devpts mount failed: {}; PTY sessions unavailable (pipe sessions and exec unaffected)",
            e
        );
    }

    // Mount the virtio-fs shares the host configured, decoded from the kernel
    // command line (`vmcell_share=<tag>:<guest_path>:<ro|rw>` tokens emitted by
    // `config::push_share_args`). Tags are caller-defined, not built into the
    // agent (§4.5, Shared directories (virtio-fs)): the agent honours whatever `VmConfig.shares` specified rather
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
        if let Err(e) = mount(
            tag.as_str(),
            &mount_point as &str,
            "virtiofs",
            flags,
            None::<&core::ffi::CStr>,
        ) {
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

    // Per-VM guest timeout tuning from the (untrusted) kernel cmdline (§5.3, The kernel command line): the
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
            if let Err(e) =
                signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))
            {
                // Doubly degraded: even the SIGTERM flag could not be installed, so the
                // poll loop below will never observe SIGTERM. Log it — teardown
                // force-kills the VMM group anyway, so PID 1 must not exit on this.
                tracing::warn!(
                    "vmcell-guest-agent: SIGTERM flag registration failed in degraded reaper: {}; relying on teardown force-kill",
                    e
                );
            }
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
    // power-off instead of falling out of `main` (AGENT-2, §3.4, The guest: vmcell-guest-agent as PID 1).
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
/// host does not emit `vmcell_accept_poll_ms=` on the cmdline (§5.3, The kernel command line).
///
/// **Semantic change (OPP-2):** the accept path itself is now event-driven — a
/// blocking `poll(2)` on the listener fd wakes sub-millisecond on connection
/// arrival — so this cadence no longer bounds connect latency. It governs only
/// how often [`serve_vsock`] retries after `bind_vsock_listener` fails. The
/// `parse_ms` floor clamp (1 ms) stays load-bearing on that path: a hostile
/// `vmcell_accept_poll_ms=0` must not turn the bind-retry loop into a busy-spin.
const ACCEPT_POLL: std::time::Duration = std::time::Duration::from_millis(20);
/// Compiled **default** re-bind idle window, used when the host does not emit
/// `vmcell_rebind_idle_ms=` on the cmdline (§5.3, The kernel command line): re-bind the listener after this
/// much idle time with no new connection. Bounds the post-restore "deaf listener"
/// window (§8.2, Restore correctness: a restored VM is not a fresh VM): on CH `--restore` the pre-snapshot listener stops yielding
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
/// The untouched-deadline half is the load-bearing part (§8.2, Restore correctness: a restored VM is not a fresh VM / §13, Cross-cutting invariants): a
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
fn poll_timeout(remaining: Duration) -> rustix::time::Timespec {
    // Whole-millisecond clamp, floored at 1 ms — both are correctness bounds (see the doc above),
    // now expressed as the `Timespec` that rustix 1.x `poll(2)` takes (it was a raw `i32` ms count
    // on 0.38). `try_from` saturates the millisecond count at `i64::MAX` instead of wrapping, and
    // the 1 ms floor keeps a sub-ms remainder from truncating to 0 (which would busy-spin PID 1).
    let ms = i64::try_from(remaining.as_millis())
        .unwrap_or(i64::MAX)
        .max(1);
    rustix::time::Timespec {
        tv_sec: ms / 1_000,
        tv_nsec: (ms % 1_000) * 1_000_000,
    }
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
        // and re-bind on the current device (§8.2, Restore correctness: a restored VM is not a fresh VM).
        let mut deadline = Instant::now() + rebind_idle;
        while let Some(remaining) = remaining_idle(deadline, Instant::now()) {
            let mut fds = [PollFd::new(&listener, PollFlags::IN)];
            // rustix 1.x `poll` takes `Option<&Timespec>`; `Some(&ts)` preserves the finite
            // timeout — `None` would block forever and defeat the idle-rebind deadline.
            let timeout = poll_timeout(remaining);
            match rustix::event::poll(&mut fds, Some(&timeout)) {
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
                        Ok((s, _)) => {
                            deadline = next_deadline(
                                deadline,
                                Instant::now(),
                                rebind_idle,
                                AcceptOutcome::Accepted,
                            );
                            tracing::info!("vmcell-guest-agent: accepted connection");
                            let conn_reaper = Arc::clone(reaper);
                            std::thread::spawn(move || {
                                if let Err(e) = serve_connection(s, &conn_reaper) {
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

/// Postcard-encodes and frames one [`Message`] through the single per-connection
/// [`Writer`] (§13, Cross-cutting invariants). Locking mirrors the reaper's poison policy (recover the
/// guard rather than propagate a poison panic through PID 1).
fn send_msg(writer: &Writer, msg: &Message) -> std::io::Result<()> {
    let bytes = postcard::to_stdvec(msg).map_err(std::io::Error::other)?;
    let mut stream = writer.lock().unwrap_or_else(|e| e.into_inner());
    send_framed(&mut *stream, &bytes)
}

/// Serves one accepted connection: sends `Ready`, runs the dispatch loop, and —
/// however the loop ends — tears down every session it left open (§13, Cross-cutting invariants).
///
/// The stream is split into a read half (owned by [`serve_loop`]) and a
/// `try_clone`d write half behind the single [`Writer`], so a session pump can
/// emit output while the loop is blocked reading the next frame, without two
/// threads ever writing the socket at once (§13, Cross-cutting invariants).
fn serve_connection(
    stream: VsockStream,
    reaper: &Arc<ReaperCoordinator>,
) -> Result<(), Box<dyn std::error::Error>> {
    let writer: Writer = Arc::new(Mutex::new(stream.try_clone()?));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let mut read_stream = stream;

    send_msg(&writer, &Message::Ready)?;
    let result = serve_loop(&mut read_stream, &writer, &sessions, reaper);
    // Connection owns its sessions (§13, Cross-cutting invariants): before returning, kill every
    // still-open session's process group so no interactive session outlives the
    // connection that opened it. Draining the table also drops each handle,
    // closing its stdin pipe / PTY master fds.
    teardown_sessions(&sessions);
    result
}

/// The per-connection dispatch loop: reads one framed [`Message`] at a time and
/// routes it. It never blocks on a running child — one-shot `Exec` is still
/// synchronous (drains to `Exit` before the next read, the one-shot contract),
/// while `OpenSession` spawns a session and returns immediately so many sessions
/// multiplex over the one connection (§3, The control plane: vsock, the host clients, and the guest agent).
fn serve_loop(
    read_stream: &mut VsockStream,
    writer: &Writer,
    sessions: &Sessions,
    reaper: &Arc<ReaperCoordinator>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let req_bytes = read_framed(read_stream)?;
        let msg: Message = postcard::from_bytes(&req_bytes)?;

        match msg {
            Message::Exec(req) => handle_exec(req, writer, reaper)?,
            Message::PutFile { dst, bytes } => handle_put_file(&dst, &bytes, writer)?,
            Message::Resync {
                unix_secs,
                unix_nanos,
                mac,
                ipv4,
            } => handle_resync(unix_secs, unix_nanos, mac, ipv4, writer)?,
            // Interactive-session control (§3, The control plane: vsock, the host clients, and the guest agent). These never fail the
            // connection: a bad open reports `SessionExit(127)` to the host, and a
            // frame for an unknown/closed session is dropped at debug — the session
            // simply already ended.
            Message::OpenSession { session, spec } => {
                run_session(session, spec, writer, sessions, reaper);
            }
            Message::Stdin { session, data } => route_stdin(sessions, session, data),
            Message::StdinEof { session } => route_stdin_eof(sessions, session),
            Message::Winsize {
                session,
                rows,
                cols,
            } => route_winsize(sessions, session, rows, cols),
            Message::CloseSession { session } => close_session(sessions, session),
            // Ready/Stdout/Stderr/Exit and the guest→host session frames are
            // guest→host only; receiving one means the peer desynced. Log it loudly
            // and close the connection so the host reconnects on a fresh stream,
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

/// Kills every still-open session's process group and drops its fds (§13, Cross-cutting invariants),
/// invoked once the connection's dispatch loop has ended for any reason.
fn teardown_sessions(sessions: &Sessions) {
    // Drain under the lock, then kill and join OUTSIDE it: joining a stdin writer
    // thread while holding the table lock would block every still-running waiter
    // thread's own removal (M6).
    let drained: Vec<(SessionId, SessionHandle)> = {
        let mut table = sessions.lock().unwrap_or_else(|e| e.into_inner());
        table.drain().collect()
    };
    for (id, handle) in drained {
        tracing::info!(
            "vmcell-guest-agent: connection ending; killing session {:?} (pid {})",
            id,
            handle.pid
        );
        // Kill first: the dead child releases the pipe read end / PTY slave, so a
        // writer thread parked on a full stdin fails immediately (EPIPE/EIO) and
        // the join below is prompt; `closing` bounds the residual case (M6).
        kill_group(handle.pid);
        handle.shutdown_stdin();
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
/// (§8.2, Restore correctness: a restored VM is not a fresh VM).
///
/// The clock set is **mandatory** (§8.2, Restore correctness: a restored VM is not a fresh VM): a failure is reported via `clock_error`
/// but NEVER propagated with `?` or a panic — the ack must always be sent so the
/// host gets a definitive answer and decides (it treats a `Some(clock_error)` as a
/// hard, retryable failure). The CSPRNG reseed and MAC rotation are best-effort
/// and reported via the two bool flags; neither failing aborts the ack.
fn handle_resync(
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
    send_msg(writer, &ack)?;
    Ok(())
}

/// Augments a base PATH with the `/vmcell-tools` guest-helper dir (ip/curl/kvm-ok,
/// baked into the rootfs) ahead of the request-provided or inherited PATH — the
/// **one** PATH law shared by the one-shot [`handle_exec`] and interactive
/// [`run_session`] paths (AGENTS.md "one law, one predicate"). PID 1 may inherit a
/// minimal/empty PATH, so an empty base falls back to the standard system dirs.
fn child_path(req_path: Option<String>) -> String {
    let base_path = req_path
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    if base_path.is_empty() {
        "/vmcell-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
    } else {
        format!("/vmcell-tools:{base_path}")
    }
}

/// Builds the child [`Command`] from an [`ExecRequest`] — program + args, cwd, and
/// the environment with the `/vmcell-tools`-augmented PATH ([`child_path`]) — the
/// shared command-construction law for both the one-shot and session paths.
/// Returns `None` for an empty argv (the non-panicking split; `indexing_slicing`
/// is denied in PID-1 code). Does **not** set stdio or the process group — those
/// are path-specific (pipes vs PTY) and set by the caller.
fn build_command(req: &ExecRequest) -> Option<Command> {
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
    cmd.env("PATH", child_path(req_path));
    Some(cmd)
}

fn handle_exec(
    req: ExecRequest,
    writer: &Writer,
    reaper: &Arc<ReaperCoordinator>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut cmd) = build_command(&req) else {
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
    // interactive-session path, §3, The control plane: vsock, the host clients, and the guest agent, is where streamed stdin lives.)
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
            // accepts one recorded strictly after it (§3.4, The guest: vmcell-guest-agent as PID 1; the PID-1 reaper-vs-waiter
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
                    kill_group(pid);
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

// ===========================================================================
// Interactive sessions (§3, The control plane: vsock, the host clients, and the guest agent): PTY / pipe sessions, streaming stdin,
// window resize, and multiplexed concurrent execs over one connection.
// ===========================================================================

/// Where a session's streamed stdin is delivered (§3, The control plane: vsock, the host clients, and the guest agent). A pipe session
/// writes to the child's stdin pipe (dropping it on `StdinEof` closes it → the
/// child reads EOF); a PTY session writes to the pseudo-terminal master (bytes
/// arrive as terminal input). The PTY master `Arc<OwnedFd>` is shared with
/// [`SessionHandle::pty_master`] so `Stdin` and `Winsize` use the same fd. Owned
/// solely by the session's stdin writer thread (M6).
enum StdinSink {
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
enum StdinItem {
    /// Bytes from a `Stdin` frame.
    Data(Vec<u8>),
    /// The host's `StdinEof`.
    Eof,
}

/// How long a session's stdin writer thread waits for its sink to accept bytes
/// before re-checking [`SessionHandle::stdin_closing`] (M6). Long enough that a
/// healthy stream costs one `poll` per chunk, short enough that connection
/// teardown's join is bounded even when the child never drains its stdin.
const STDIN_POLL_SLICE: Duration = Duration::from_millis(100);

/// Per-`write(2)` cap on a session's stdin (M6). `PIPE_BUF`: the kernel reports a
/// pipe writable only once a whole free page is available, so a chunk this size
/// cannot block after `poll` said go, and a PTY master's terminal input queue is
/// the same 4096 bytes.
const STDIN_CHUNK_BYTES: usize = 4096;

/// The live state of one interactive session, keyed by [`SessionId`] in the
/// per-connection [`Sessions`] table.
struct SessionHandle {
    /// The queue feeding this session's stdin writer thread (M6). Unbounded and
    /// fed only by the *trusted host's own* sessions (design §3, recorded trade
    /// §17); `send` never blocks, so the dispatch loop can no longer be wedged by
    /// a child that stopped reading its stdin.
    stdin_tx: std::sync::mpsc::Sender<StdinItem>,
    /// Set by [`SessionHandle::shutdown_stdin`] so a writer thread parked on a
    /// full pipe or terminal gives up within one [`STDIN_POLL_SLICE`], making the
    /// teardown join bounded.
    stdin_closing: Arc<AtomicBool>,
    /// The stdin writer thread, joined by teardown so no thread outlives the
    /// connection that opened the session.
    stdin_writer: JoinHandle<()>,
    /// The PTY master for `Winsize`, or `None` for a pipe session.
    pty_master: Option<Arc<OwnedFd>>,
    /// The child's process-group id (== its pid: `setsid` for a PTY session,
    /// `process_group(0)` for a pipe session), used by `CloseSession`/timeout/
    /// connection-teardown to `kill(-pgid)` the whole group.
    pid: u32,
}

impl SessionHandle {
    /// Builds a session's handle, spawning the stdin writer thread that owns
    /// `stdin` (M6). The one place a handle is constructed, so both the pipe and
    /// the PTY path get the same stdin discipline.
    fn new(
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

    /// Stops this session's stdin writer thread and joins it (M6) — the one place
    /// that sequence lives. Flag it closing (a writer parked on a full pipe or
    /// terminal gives up within one [`STDIN_POLL_SLICE`]), drop the queue's last
    /// sender (so a drained writer's `recv` ends), then join so no thread leaks.
    /// Callers `kill_group` first, which is what makes the pending write fail
    /// immediately in the common case.
    fn shutdown_stdin(self) {
        self.stdin_closing.store(true, Ordering::Relaxed);
        drop(self.stdin_tx);
        if self.stdin_writer.join().is_err() {
            // Not `unwrap`: a panicked writer thread must not take PID 1 with it.
            tracing::warn!("vmcell-guest-agent: session stdin writer thread panicked");
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
fn spawn_stdin_writer(
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
                            "vmcell-guest-agent: stdin write to session {:?} failed: {}",
                            session,
                            e
                        );
                        break;
                    }
                }
                // Pipe: drop the write end → the child reads EOF, but only now
                // that every byte queued ahead of this item has been written. PTY:
                // a no-op (closing the master would tear down output — a PTY
                // caller ends input in-band).
                StdinItem::Eof => {
                    if matches!(sink, Some(StdinSink::Pipe(_))) {
                        sink = None;
                    }
                }
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
fn winsize_from(rows: u16, cols: u16) -> rustix::termios::Winsize {
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
fn kill_group(pid: u32) {
    use rustix::process::{Pid, Signal, kill_process_group};
    if let Some(p) = Pid::from_raw(pid.cast_signed()) {
        let _ = kill_process_group(p, Signal::KILL);
    }
}

/// Reports a session that could not be opened (bad argv, spawn or PTY-allocation
/// failure) the same way the one-shot path reports a spawn failure — one
/// terminal-frame convention (§13, Cross-cutting invariants): `SessionStderr{msg}` then
/// `SessionExit{127}`.
fn open_failed(writer: &Writer, session: SessionId, msg: &str) {
    tracing::warn!(
        "vmcell-guest-agent: session {:?} open failed: {}",
        session,
        msg
    );
    let _ = send_msg(
        writer,
        &Message::SessionStderr {
            session,
            data: msg.as_bytes().to_vec(),
        },
    );
    let _ = send_msg(writer, &Message::SessionExit { session, code: 127 });
}

/// Registers a session's handle in the per-connection table. A reused id (the
/// host is authoritative and monotonic, so this should not happen) kills the
/// displaced session rather than leaking it.
fn register_session(sessions: &Sessions, id: SessionId, handle: SessionHandle) {
    // Insert under the lock; kill + join the displaced session's stdin writer
    // outside it, the same order teardown uses (M6).
    let displaced = {
        let mut table = sessions.lock().unwrap_or_else(|e| e.into_inner());
        table.insert(id, handle)
    };
    if let Some(old) = displaced {
        tracing::warn!(
            "vmcell-guest-agent: session id {:?} reused; killing the displaced session",
            id
        );
        kill_group(old.pid);
        old.shutdown_stdin();
    }
}

/// Spawns a reader thread that pumps a child stream to the host, wrapping each
/// chunk into the session-tagged [`Message`] `wrap` produces and emitting it
/// through the single [`Writer`] (§13, Cross-cutting invariants). Ends on EOF, any read error (a PTY
/// master returns `EIO` once the child closes its slave — end of stream), or a
/// write failure (the connection died).
fn spawn_pump<R, F>(mut reader: R, writer: Writer, wrap: F) -> JoinHandle<()>
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
fn arm_session_timeout(timeout: Option<Duration>, pid: u32, has_exited: Arc<AtomicBool>) {
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
fn spawn_session_waiter(
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
            let _ = pump.join();
        }
        let _ = send_msg(&writer, &Message::SessionExit { session, code });
        sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session);
    });
}

/// Opens an interactive session (§3, The control plane: vsock, the host clients, and the guest agent): builds the command, then
/// dispatches to the PTY or pipe path per `spec.pty`.
fn run_session(
    session: SessionId,
    spec: SessionSpec,
    writer: &Writer,
    sessions: &Sessions,
    reaper: &Arc<ReaperCoordinator>,
) {
    let Some(cmd) = build_command(&spec.command) else {
        open_failed(writer, session, "empty argv");
        return;
    };
    let timeout = spec.command.timeout;
    match spec.pty {
        Some(pty) => run_pty_session(session, cmd, pty, timeout, writer, sessions, reaper),
        None => run_pipe_session(session, cmd, timeout, writer, sessions, reaper),
    }
}

/// Runs a pipe (non-PTY) session: piped stdin/stdout/stderr, streamable stdin,
/// separate `SessionStdout`/`SessionStderr` channels.
fn run_pipe_session(
    session: SessionId,
    mut cmd: Command,
    timeout: Option<Duration>,
    writer: &Writer,
    sessions: &Sessions,
    reaper: &Arc<ReaperCoordinator>,
) {
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
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        open_failed(writer, session, "failed to capture child stdio");
        kill_group(child.id());
        return;
    };
    let pid = child.id();
    reaper.reserve(pid, epoch);

    register_session(
        sessions,
        session,
        // The `ChildStdin` becomes a bare `OwnedFd` owned by the session's stdin
        // writer thread (M6) — one fd write path for both sink kinds.
        SessionHandle::new(session, stdin.map(|s| StdinSink::Pipe(s.into())), None, pid),
    );

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

/// Allocates a pseudo-terminal pair: the `CLOEXEC` master (kept by the agent) and
/// the slave path from `ptsname` (opened by the caller for the child). `grantpt`
/// is a Linux no-op but is called for POSIX faithfulness; `unlockpt` is required.
fn open_pty() -> rustix::io::Result<(OwnedFd, std::ffi::CString)> {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let slave_path = ptsname(&master, Vec::new())?;
    Ok((master, slave_path))
}

/// The `login_tty` sequence, run in the child's `pre_exec` (§3, The control plane: vsock, the host clients, and the guest agent): make
/// the child a session leader (`setsid`, so its pgid == its pid and it has no
/// controlling terminal), adopt the pty slave as its controlling terminal
/// (`TIOCSCTTY`), and wire the slave onto stdin/stdout/stderr. Every call is an
/// async-signal-safe raw syscall via `rustix`; the slave is `CLOEXEC`, so after
/// these `dup2`s it closes at `execve`, leaving only fds 0/1/2 on the terminal.
fn login_tty(slave_fd: RawFd) -> std::io::Result<()> {
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
fn run_pty_session(
    session: SessionId,
    mut cmd: Command,
    pty: protocol::PtyConfig,
    timeout: Option<Duration>,
    writer: &Writer,
    sessions: &Sessions,
    reaper: &Arc<ReaperCoordinator>,
) {
    use rustix::fs::{Mode, OFlags};

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
        tracing::debug!("vmcell-guest-agent: initial winsize failed: {}", e);
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
            open_failed(writer, session, &format!("pty master clone failed: {e}"));
            kill_group(pid);
            return;
        }
    };
    let master_arc = Arc::new(master);
    register_session(
        sessions,
        session,
        SessionHandle::new(
            session,
            Some(StdinSink::Pty(Arc::clone(&master_arc))),
            Some(Arc::clone(&master_arc)),
            pid,
        ),
    );

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
fn stdin_sink_ready(fd: BorrowedFd<'_>) -> std::io::Result<bool> {
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
fn write_stdin_sink(
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

/// Looks up a session's stdin queue, releasing the table lock before returning it
/// (M6). A frame for an unknown/closed session is dropped at debug — the session
/// simply already ended.
fn session_stdin_queue(
    sessions: &Sessions,
    session: SessionId,
) -> Option<std::sync::mpsc::Sender<StdinItem>> {
    let table = sessions.lock().unwrap_or_else(|e| e.into_inner());
    match table.get(&session) {
        Some(h) => Some(h.stdin_tx.clone()),
        None => {
            tracing::debug!(
                "vmcell-guest-agent: stdin frame for unknown/closed session {:?}; dropping",
                session
            );
            None
        }
    }
}

/// Routes a `Stdin` frame to its session (§3, The control plane: vsock, the host clients, and the guest agent). ENQUEUES the bytes on
/// the session's stdin queue and returns immediately (M6): the blocking write
/// happens on that session's writer thread, so a child that stopped reading its
/// stdin can no longer stall the dispatch loop — and with it `CloseSession` and
/// the connection-owns-its-sessions teardown (§13).
fn route_stdin(sessions: &Sessions, session: SessionId, data: Vec<u8>) {
    let Some(tx) = session_stdin_queue(sessions, session) else {
        return;
    };
    // Never a silent drop: the only failure is a writer thread that has already
    // ended (its sink died), which is the same condition the pre-M6 inline write
    // reported at debug.
    if tx.send(StdinItem::Data(data)).is_err() {
        tracing::debug!(
            "vmcell-guest-agent: stdin queue for session {:?} is closed; dropping",
            session
        );
    }
}

/// Routes a `StdinEof` frame (§3, The control plane: vsock, the host clients, and the guest agent): closes a **pipe** session's stdin
/// (dropping the write end → the child reads EOF); a no-op for a PTY session
/// (closing the master would tear down output — a PTY caller ends input in-band).
/// Sequenced through the SAME queue as the bytes (M6), so the pipe closes only
/// after everything already queued has been written — an out-of-band close would
/// truncate the child's input.
fn route_stdin_eof(sessions: &Sessions, session: SessionId) {
    let Some(tx) = session_stdin_queue(sessions, session) else {
        return;
    };
    if tx.send(StdinItem::Eof).is_err() {
        tracing::debug!(
            "vmcell-guest-agent: stdin queue for session {:?} is closed; EOF is already implied",
            session
        );
    }
}

/// Routes a `Winsize` frame (§3, The control plane: vsock, the host clients, and the guest agent): installs the new window on a PTY
/// session's master (`TIOCSWINSZ`, delivering `SIGWINCH`); a debug no-op for a
/// pipe session.
fn route_winsize(sessions: &Sessions, session: SessionId, rows: u16, cols: u16) {
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
                    "vmcell-guest-agent: winsize for session {:?} failed: {}",
                    session,
                    e
                );
            }
        }
        None => tracing::debug!(
            "vmcell-guest-agent: winsize for non-pty session {:?}; ignoring",
            session
        ),
    }
}

/// Routes a `CloseSession` frame (§3, The control plane: vsock, the host clients, and the guest agent): `SIGKILL`s the session's
/// process group. The waiter observes the resulting exit, emits `SessionExit`,
/// and removes the entry — so no double-remove here.
fn close_session(sessions: &Sessions, session: SessionId) {
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

    // §5.3 (The kernel command line): the guest-tuning cmdline tokens are UNTRUSTED and must be clamped into
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
    // and the §8.2 (Restore correctness: a restored VM is not a fresh VM) re-bind never fires.
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
    fn poll_timeout_floors_at_one_ms_and_never_exceeds_remaining() {
        // A sub-millisecond remainder floors to 1 ms (tv_nsec = 1_000_000), never 0.
        let ts = poll_timeout(Duration::from_micros(300));
        assert_eq!(
            (ts.tv_sec, ts.tv_nsec),
            (0, 1_000_000),
            "a sub-millisecond remainder must floor to 1 ms, not truncate to 0"
        );
        assert_eq!(poll_timeout(Duration::from_millis(1)).tv_nsec, 1_000_000);
        // Whole-ms truncation: never over the remaining window by a full tick.
        assert_eq!(poll_timeout(Duration::from_micros(2500)).tv_nsec, 2_000_000);
        let ts = poll_timeout(Duration::from_millis(250));
        assert_eq!((ts.tv_sec, ts.tv_nsec), (0, 250_000_000));
        // Absurdly large windows saturate instead of wrapping negative (a negative
        // timeout would mean "block forever" and the re-bind would never fire).
        let ts = poll_timeout(Duration::from_secs(u64::MAX));
        assert_eq!(ts.tv_sec, i64::MAX / 1_000);
        assert_eq!(ts.tv_nsec, (i64::MAX % 1_000) * 1_000_000);
        assert!(ts.tv_sec > 0 && ts.tv_nsec >= 0, "must not wrap negative");
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

    // §3 (The control plane: vsock, the host clients, and the guest agent) / §3.3 (Interactive-session wire semantics): the rows→ws_row, cols→ws_col field mapping the PTY
    // winsize install consumes. RED on a rows↔cols swap (mirrors
    // `resync_timespec_maps_fields`), without a live PTY.
    #[test]
    fn winsize_from_maps_rows_and_cols() {
        let ws = winsize_from(40, 100);
        assert_eq!(ws.ws_row, 40, "rows must map to ws_row");
        assert_eq!(ws.ws_col, 100, "cols must map to ws_col");
        assert_ne!(
            ws.ws_row, 100,
            "a rows↔cols swap must not put cols in ws_row"
        );
        // Pixel dims are unset (character-cell terminal).
        assert_eq!(ws.ws_xpixel, 0);
        assert_eq!(ws.ws_ypixel, 0);
    }

    // §3.3 (Interactive-session wire semantics): `child_path` is the ONE PATH law shared by handle_exec and
    // run_session — it must prepend `/vmcell-tools` so the guest-helper shims
    // (ip/curl/kvm-ok) resolve. RED if a session path dropped the prefix.
    #[test]
    fn child_path_prepends_vmcell_tools() {
        // A request-provided PATH is honored, with /vmcell-tools ahead of it.
        assert_eq!(
            child_path(Some("/usr/bin:/bin".to_string())),
            "/vmcell-tools:/usr/bin:/bin"
        );
        // An empty base falls back to the standard system dirs, still /vmcell-tools first.
        assert_eq!(
            child_path(Some(String::new())),
            "/vmcell-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        );
        assert!(
            child_path(Some("/opt/bin".to_string())).starts_with("/vmcell-tools:"),
            "the guest-tools dir must be first on PATH"
        );
    }

    // AGENT-3 extended to the channelized session frames (§3.3, Interactive-session wire semantics): a
    // guest-encoded `SessionStdout{id, payload}` frames through `send_framed`,
    // decodes through the host's REAL LengthDelimitedCodec, and postcard-decodes
    // back to the same Message — proving the id-keyed frames cross the hand-rolled
    // framing boundary intact. RED on a framing/endianness/cap regression.
    #[test]
    fn session_frame_round_trips_through_real_codec() {
        let msg = Message::SessionStdout {
            session: SessionId(7),
            data: b"multiplexed \x00\x01\xfe\xff output".to_vec(),
        };
        let encoded = postcard::to_stdvec(&msg).expect("postcard encode");
        let mut wire = Vec::new();
        send_framed(&mut wire, &encoded).expect("send_framed");

        let mut codec = LengthDelimitedCodec::new();
        let mut src = BytesMut::from(&wire[..]);
        let frame = codec
            .decode(&mut src)
            .expect("codec decode")
            .expect("a complete frame");
        let decoded: Message = postcard::from_bytes(&frame).expect("postcard decode");
        assert_eq!(
            decoded, msg,
            "session frame must round-trip through the codec"
        );
        assert!(src.is_empty(), "codec must consume exactly one guest frame");
    }

    /// Registers a live session handle over `sink` in a fresh table, for the M6
    /// stdin-queue gates. `pid` is 0 — these tests never take the kill/teardown
    /// path, so no signal is ever sent.
    fn stdin_test_session(sink: StdinSink) -> (Sessions, SessionId) {
        let id = SessionId(0);
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        sessions
            .lock()
            .unwrap()
            .insert(id, SessionHandle::new(id, Some(sink), None, 0));
        (sessions, id)
    }

    // M6 (`guest-dispatch-blocking-stdin-wedge`), KVM-free half of the gate: the
    // DISPATCH side of a session's stdin must never block, and `StdinEof` must be
    // sequenced through the same queue as the bytes.
    //
    // (1) 128 KiB — twice a full pipe — is routed at a child that is not reading;
    //     `route_stdin`/`route_stdin_eof` must still return promptly. RED on the
    //     pre-fix inline `write_all`: the routing thread parks on the full pipe,
    //     the 5 s wait elapses and the assert fires (the live legs in
    //     crates/vmcell/tests/session.rs cover the consequences — an undispatched
    //     `CloseSession` and the skipped C3 teardown).
    // (2) Only THEN is the pipe drained: every queued byte must arrive, in order,
    //     before EOF. RED if `StdinEof` closed the sink out of band (a short read)
    //     or if a post-EOF write were still delivered (a long read).
    #[test]
    fn route_stdin_does_not_block_on_a_full_pipe_and_eof_follows_every_byte() {
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let (sessions, id) = stdin_test_session(StdinSink::Pipe(writer.into()));

        const N: usize = 128 * 1024;
        let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let routed = std::thread::spawn(move || {
            route_stdin(&sessions, id, payload);
            route_stdin_eof(&sessions, id);
            // A write after EOF: the writer drops it (stdin is closed) — it must
            // never reach the child, and must not panic the thread.
            route_stdin(&sessions, id, b"AFTER-EOF".to_vec());
            // Drop the table (and with it the handle's queue sender) so the writer
            // thread ends once drained; the JoinHandle inside it is detached here,
            // exactly as it is when a session's waiter removes its own entry.
            done_tx.send(()).expect("signal");
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("routing a full pipe's worth of stdin must NOT block the dispatch loop (M6)");
        routed.join().expect("routing thread");

        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("read to EOF");
        assert_eq!(
            got.len(),
            N,
            "every queued byte must be written before StdinEof closes the pipe, and no post-EOF byte after it"
        );
        assert_eq!(got, expected, "the streamed bytes must arrive verbatim");
    }

    // M6: a stdin writer parked on a full pipe must give up once its session is
    // flagged closing, so `SessionHandle::shutdown_stdin`'s join — run by
    // `teardown_sessions` for every still-open session — is BOUNDED. RED on the
    // inverse (drop the `closing` check in `write_stdin_sink`): the thread stays
    // parked on the pipe forever and the `is_finished` assert fires (5 s), instead
    // of hanging teardown. `_reader` stays alive throughout: dropping it would
    // EPIPE the write and make the gate vacuous.
    #[test]
    fn stdin_writer_gives_up_on_closing_so_teardown_join_is_bounded() {
        let (_reader, writer) = std::io::pipe().expect("pipe");
        let (tx, rx) = std::sync::mpsc::channel();
        let closing = Arc::new(AtomicBool::new(false));
        let thread = spawn_stdin_writer(
            SessionId(3),
            Some(StdinSink::Pipe(writer.into())),
            rx,
            Arc::clone(&closing),
        );

        // 512 KiB at a reader that never reads: the writer parks on the full pipe.
        tx.send(StdinItem::Data(vec![7u8; 512 * 1024]))
            .expect("queue stdin");
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !thread.is_finished(),
            "the writer must actually be parked on the full pipe, or this gate is vacuous"
        );

        // The teardown sequence, minus the blocking join (so a regression reddens
        // rather than hangs): flag closing, drop the last queue sender.
        closing.store(true, Ordering::Relaxed);
        drop(tx);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            thread.is_finished(),
            "a writer parked on a full stdin must give up within one STDIN_POLL_SLICE of `closing`"
        );
        thread.join().expect("writer thread");
    }
}
