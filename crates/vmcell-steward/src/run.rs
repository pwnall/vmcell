//! `run` — the steward's one entry point, and the per-placement policy it applies.
//!
//! The binary is a wrapper around this function (design §3.5): it selects the placement from
//! `getpid()`, installs the subscriber, and calls [`run`]. Every per-mode difference below is a
//! **parameter**, never a fork of the code — filesystem assembly, `PR_SET_CHILD_SUBREAPER`, and
//! the SIGTERM policy. What does not vary: the wire protocol, the credential posture (this crate
//! makes no uid/gid syscall), the single-writer discipline (C4), and the tools-dir `PATH` prepend.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::process::{WaitOptions, wait};

use crate::assembly;
use crate::options::{SigtermPolicy, StewardOptions, TracingSetup};
use crate::serve::{ConnectionRegistry, serve_vsock};
use crate::{ReaperCoordinator, ServeContext, exit_code_from_termination};

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
    // mis-delivered as the reused child's exit (AGENT-1, §3.4, The guest: vmcell-steward as PID 1).
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

/// Reads the kernel command line, tolerating its absence.
///
/// Under `Pid1` this is only meaningful **after** [`assembly::assemble_core_mounts`] has mounted
/// `/proc`; calling it earlier silently yields the empty string. That ordering is the reason the
/// read lives here rather than in the binary (see [`crate::options`]).
fn read_proc_cmdline() -> String {
    std::fs::read_to_string("/proc/cmdline").unwrap_or_default()
}

/// Boot-time self-checks, logged for the serial-log classifier.
///
/// Placement-blind: the classifier keys on these exact lines
/// (`vmcell-artifact-validator`'s `classify`), so their text is a contract with the validator and
/// must not drift silently.
fn boot_self_checks() {
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
        tracing::info!("vmcell-steward: boot self-check: AF_VSOCK transport available");
    } else {
        tracing::error!(
            "vmcell-steward: boot self-check: AF_VSOCK unavailable ({}); the vsock control plane will not come up",
            std::io::Error::last_os_error()
        );
    }

    let virtiofs_supported = std::fs::read_to_string("/proc/filesystems")
        .is_ok_and(|contents| contents.contains("virtiofs"));
    if virtiofs_supported {
        tracing::info!("vmcell-steward: boot self-check: virtiofs filesystem supported");
    } else {
        tracing::warn!(
            "vmcell-steward: boot self-check: virtiofs not advertised in /proc/filesystems"
        );
    }
}

/// Powers the guest off in response to SIGTERM and never returns.
///
/// PID 1 returning from `main` panics the kernel, so this diverges: it flushes
/// filesystem buffers and issues `reboot(RB_POWER_OFF)`, which only returns on
/// failure (e.g. a missing `CAP_SYS_BOOT`); in that case it parks forever so
/// PID 1 still never exits.
fn power_off_never_returns() -> ! {
    tracing::info!("vmcell-steward: received SIGTERM; powering off");
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
        "vmcell-steward: power-off failed ({}); parking so PID 1 never exits",
        std::io::Error::last_os_error()
    );
    loop {
        std::thread::park();
    }
}

/// Runs the steward to completion under `opts`.
///
/// # Errors
///
/// Returns `Err` only for a failure of the `Pid1` filesystem assembly's fatal set. Under
/// [`crate::GuestPlacement::Pid1`] this function does not return on the success path at all: SIGTERM
/// powers the guest off, because a returning PID 1 kernel-panics the guest. Under
/// [`crate::GuestPlacement::Service`] SIGTERM returns `Ok(())` after law C3's teardown — an exit that is
/// legal precisely because this steward is not pid 1.
pub fn run(opts: StewardOptions) -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = opts;
    if matches!(opts.tracing, TracingSetup::Install) {
        tracing_subscriber::fmt::init();
    }
    tracing::info!("vmcell-steward: starting (placement {:?})", opts.placement);

    // The assembly runs FIRST under `Pid1`, because everything after it — including the
    // `/proc/cmdline` read below — depends on the root it builds. Under `Service` it does not run
    // at all: somebody else assembled the filesystem and re-running `pivot_root` would be
    // destructive, not merely redundant.
    if opts.placement.assembles_the_filesystem() {
        assembly::assemble_guest_root()?;
    }

    let cmdline = read_proc_cmdline();
    opts.apply_cmdline(&cmdline);

    // PR_SET_CHILD_SUBREAPER, under `Service` only (§3.5). As pid 1 every orphan reparents to the
    // steward by definition; as a service, a double-forking payload would reparent to the REAL
    // init, which reaps it, and `ReaperCoordinator::wait_for` would block on a status that is never
    // recorded — a hung `exec`, not an error. `set_child_subreaper` takes the prctl arg2 as an
    // `Option<Pid>`, and a non-zero arg2 is what ENABLES the attribute; `Pid::INIT` is the
    // canonical spelling of the `1` the man page names. Failure is fatal-loud rather than warned:
    // a service steward without the bit answers `exec` by hanging, which is strictly worse than
    // refusing to start (AGENTS.md: a privilege/posture reduction that fails is never discarded).
    if opts.placement.needs_child_subreaper() {
        rustix::process::set_child_subreaper(Some(rustix::process::Pid::INIT))?;
        tracing::info!("vmcell-steward: PR_SET_CHILD_SUBREAPER set (service placement)");
    }

    boot_self_checks();

    // Shared reaper/exec coordination: a single WNOHANG reaper (this thread)
    // records every child's exit code; each per-exec waiter blocks until its
    // pid's status is recorded, then claims it. No `child.wait()` races the
    // reaper (the false-127 bug it avoids), and unclaimed grandchild statuses
    // are pruned so the status map stays bounded.
    let reaper = Arc::new(ReaperCoordinator::with_max_statuses(
        opts.max_reaped_statuses,
    ));
    let ctx = Arc::new(ServeContext {
        reaper: Arc::clone(&reaper),
        tools_dir: opts.tools_dir.clone(),
        connections: Arc::new(ConnectionRegistry::new()),
        shutdown: Arc::new(AtomicBool::new(false)),
    });

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

    // Spawn vsock listener thread (recoverable across snapshot/restore). The handle is RETAINED
    // now: under `Service` the shutdown path joins it, so "stop accepting" is an observed fact
    // rather than a hope. Under `Pid1` nothing joins it, exactly as before.
    let listener_ctx = Arc::clone(&ctx);
    let tuning = opts.tuning;
    let port = opts.vsock_port;
    let listener = std::thread::spawn(move || serve_vsock(&listener_ctx, port, tuning));

    // Main thread is the zombie reaper. It is woken by SIGCHLD rather
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
            // reap on a timer instead of leaving zombies unreaped. The steward must
            // never exit on a recoverable condition.
            tracing::error!(
                "vmcell-steward: SIGCHLD registration failed: {}; falling back to a polling reaper",
                e
            );
            let term = Arc::new(AtomicBool::new(false));
            if let Err(e) =
                signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))
            {
                // Doubly degraded: even the SIGTERM flag could not be installed, so the
                // poll loop below will never observe SIGTERM. Log it — teardown
                // force-kills the VMM group anyway, so the steward must not exit on this.
                tracing::warn!(
                    "vmcell-steward: SIGTERM flag registration failed in degraded reaper: {}; relying on teardown force-kill",
                    e
                );
            }
            while !term.load(Ordering::Relaxed) {
                drain_zombies(&reaper);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // BOTH reaper loops converge here, and BOTH obey the placement's policy. Covering only the
    // primary arm would leave a `Service` steward powering the machine off whenever handler
    // registration happened to fail — the degraded path is not a rare path, it is the path a
    // constrained guest takes.
    match opts.on_sigterm {
        // The `Pid1` contract, unchanged: a returning init kernel-panics the guest
        // ("Attempted to kill init"), which the host then flags via `contains_panic()`.
        SigtermPolicy::PowerOff => power_off_never_returns(),
        SigtermPolicy::Shutdown => {
            tracing::info!("vmcell-steward: received SIGTERM; shutting down (service placement)");
            // Order matters. Stop accepting first, so a connection cannot be registered after the
            // teardown sweep and outlive it; then honor law C3 on every connection that is still
            // live — its interactive sessions *and* the one-shot `exec` children it has in flight,
            // which are the ones that would otherwise reparent to the real init and keep running;
            // then return, letting the init that started us restart us.
            ctx.shutdown.store(true, Ordering::SeqCst);
            if listener.join().is_err() {
                tracing::warn!(
                    "vmcell-steward: the vsock listener thread panicked during shutdown"
                );
            }
            let torn_down = ctx.connections.teardown_all();
            tracing::info!(
                "vmcell-steward: shutdown complete; tore down {} live connection(s)",
                torn_down
            );
            Ok(())
        }
    }
}
