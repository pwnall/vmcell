//! Guest agent running as PID 1 inside the microvm.
#![deny(missing_docs)]
#![deny(clippy::missing_errors_doc)]
use rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_change, unmount,
};
use rustix::process::{WaitOptions, pivot_root, wait};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use vmcell::agent::protocol::{self, ExecRequest, Message};
use vmcell::agent::{MAX_FRAME_BYTES, ReaperCoordinator, exit_code_from_termination};
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
    // Stops on `Ok(None)` (no more reapable children) or `Err` (e.g. ECHILD).
    while let Ok(Some((pid, status))) = wait(WaitOptions::NOHANG) {
        let pid = pid.as_raw_nonzero().get() as u32;
        let code = exit_code_from_termination(
            status.terminating_signal().map(|s| s as i32),
            status.exit_status().map(|c| c as i32),
        );
        reaper.record_exit(pid, code);
    }
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("vmcell-guest-agent: starting");

    // Mount setup
    std::fs::create_dir_all("/sys")?;
    std::fs::create_dir_all("/proc")?;
    std::fs::create_dir_all("/mnt")?;

    if let Err(e) = mount("tmpfs", "/mnt", "tmpfs", MountFlags::empty(), "") {
        tracing::info!("vmcell-guest-agent: mount tmpfs failed: {}", e);
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
        tracing::info!("vmcell-guest-agent: overlay failed: {}", e);
        return Err(e.into());
    }

    if let Err(e) = std::env::set_current_dir("/mnt/rootfs") {
        tracing::error!("vmcell-guest-agent: failed to chdir to /mnt/rootfs: {}", e);
        return Err(e.into());
    }
    std::fs::create_dir_all("oldroot")?;

    if let Err(e) = pivot_root(".", "oldroot") {
        tracing::info!("vmcell-guest-agent: pivot_root failed: {}", e);
        return Err(e.into());
    } else {
        mount_change(
            "/",
            MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        )?;
        unmount("oldroot", UnmountFlags::DETACH)?;
        std::fs::remove_dir_all("oldroot")?;
    }

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
        tracing::info!("vmcell-guest-agent: proc failed: {}", e);
        return Err(e.into());
    }
    if let Err(e) = mount("devtmpfs", "/dev", "devtmpfs", MountFlags::empty(), "") {
        tracing::info!("vmcell-guest-agent: devtmpfs failed: {}", e);
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

    // Bring up loopback interface without shelling out to `ip`
    #[repr(C)]
    struct ifreq {
        ifr_name: [std::os::raw::c_char; 16],
        ifr_flags: std::os::raw::c_short,
    }
    let socket = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        None,
    );
    if let Ok(fd) = socket {
        use std::os::fd::AsRawFd;
        let mut ifr = ifreq {
            ifr_name: [0; 16],
            ifr_flags: 0,
        };
        ifr.ifr_name[0] = b'l' as std::os::raw::c_char;
        ifr.ifr_name[1] = b'o' as std::os::raw::c_char;
        // SAFETY: `ifr` is a correctly-sized, zero-initialized `ifreq`; both
        // ioctls operate solely on that struct through a valid `AF_INET`
        // socket fd. Loopback bring-up is best-effort and not required for the
        // vsock control plane, so a failure is logged and tolerated — returning
        // `Err` from PID 1's `main` would kernel-panic the guest.
        unsafe {
            let siocgifflags = 0x8913; // SIOCGIFFLAGS
            let siocsifflags = 0x8914; // SIOCSIFFLAGS
            if libc::ioctl(fd.as_raw_fd(), siocgifflags, &mut ifr) >= 0 {
                ifr.ifr_flags |= 0x1 | 0x40; // IFF_UP | IFF_RUNNING
                if libc::ioctl(fd.as_raw_fd(), siocsifflags, &ifr) < 0 {
                    tracing::warn!(
                        "vmcell-guest-agent: loopback bring-up (SIOCSIFFLAGS) failed: {}; continuing without lo",
                        std::io::Error::last_os_error()
                    );
                }
            } else {
                tracing::warn!(
                    "vmcell-guest-agent: loopback query (SIOCGIFFLAGS) failed: {}; continuing without lo",
                    std::io::Error::last_os_error()
                );
            }
        }
    } else {
        tracing::warn!(
            "vmcell-guest-agent: could not open AF_INET socket for loopback bring-up; continuing without lo"
        );
    }

    // Boot-time control-plane self-check, run BEFORE binding the listener so a
    // missing transport yields a clear diagnostic instead of an opaque bind
    // failure. Probe AF_VSOCK by actually opening a socket; the host-side
    // `/dev/vhost-vsock` device is irrelevant inside the guest, so it is not
    // consulted.
    // SAFETY: `socket(2)`/`close(2)` are invoked with constant, valid
    // arguments; the returned fd (when non-negative) is closed immediately and
    // never otherwise used.
    let vsock_ok = unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd >= 0 {
            libc::close(fd);
            true
        } else {
            false
        }
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

    // Spawn vsock listener thread (recoverable across snapshot/restore).
    let listener_reaper = Arc::clone(&reaper);
    std::thread::spawn(move || serve_vsock(&listener_reaper));

    // Main thread is the PID 1 zombie reaper. It is woken by SIGCHLD rather
    // than polling, so an exec's exit is observed immediately instead of up to
    // ~100 ms late. SIGCHLD coalesces, so each wake drains *all* reapable
    // children.
    drain_zombies(&reaper); // catch anything that exited before registration
    match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGCHLD,
        signal_hook::consts::SIGTERM,
    ]) {
        Ok(mut signals) => {
            for signal in signals.forever() {
                drain_zombies(&reaper);
                if signal == signal_hook::consts::SIGTERM {
                    tracing::info!("vmcell-guest-agent: received SIGTERM, exiting");
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
            tracing::info!("vmcell-guest-agent: received SIGTERM, exiting");
        }
    }

    Ok(())
}

/// vsock control-plane port the host's `AgentClient` connects to.
const VSOCK_PORT: u32 = 5000;
/// Poll cadence for the non-blocking accept loop.
const ACCEPT_POLL: std::time::Duration = std::time::Duration::from_millis(100);
/// Re-bind the listener after this much idle time with no new connection.
const REBIND_IDLE: std::time::Duration = std::time::Duration::from_secs(1);

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

/// Serves the vsock control plane, re-binding the listener across snapshot
/// restores.
///
/// After a CH/Firecracker `--restore` the vhost-vsock device is re-created and
/// the listener bound before the snapshot goes deaf — it never yields the host's
/// post-restore reconnect (and the stale connection may never EOF), so a
/// bound-once listener wedges the warm-restore path forever. We therefore run a
/// non-blocking accept loop and re-`bind` whenever the listener has been idle for
/// `REBIND_IDLE`, which re-attaches it to the *current* device. Re-binding is
/// harmless during normal operation: already-accepted connections keep their own
/// fds, and the fresh listener re-binds the same `CID_ANY:VSOCK_PORT` on the live
/// device. Each accepted connection is served on its own thread so a parked stale
/// connection never blocks new accepts.
fn serve_vsock(reaper: &Arc<ReaperCoordinator>) {
    loop {
        let Some(listener) = bind_vsock_listener() else {
            std::thread::sleep(ACCEPT_POLL);
            continue;
        };
        tracing::info!("vmcell-guest-agent: listening on vsock port {}", VSOCK_PORT);

        let mut idle = std::time::Duration::ZERO;
        loop {
            match listener.accept() {
                Ok((mut s, _)) => {
                    idle = std::time::Duration::ZERO;
                    tracing::info!("vmcell-guest-agent: accepted connection");
                    let conn_reaper = Arc::clone(reaper);
                    std::thread::spawn(move || {
                        if let Err(e) = handle_connection(&mut s, &conn_reaper) {
                            tracing::error!("vmcell-guest-agent: handle_connection error: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                    idle += ACCEPT_POLL;
                    if idle >= REBIND_IDLE {
                        // Drop this listener and re-bind on the current device.
                        break;
                    }
                }
                Err(e) => {
                    tracing::info!("vmcell-guest-agent: accept error: {}; re-binding", e);
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

        if let Message::Exec(req) = msg {
            handle_exec(req, stream, reaper)?;
        } else if let Message::PutFile { dst, bytes } = msg {
            handle_put_file(&dst, &bytes, stream)?;
        }
    }
}

fn send_framed(stream: &mut VsockStream, data: &[u8]) -> std::io::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}

fn read_framed(stream: &mut VsockStream) -> std::io::Result<Vec<u8>> {
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

fn handle_exec(
    req: ExecRequest,
    stream: &mut VsockStream,
    reaper: &Arc<ReaperCoordinator>,
) -> Result<(), Box<dyn std::error::Error>> {
    if req.argv.is_empty() {
        let exit_msg = postcard::to_stdvec(&Message::Exit(1))?;
        send_framed(stream, &exit_msg)?;
        return Ok(());
    }

    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..]);
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
                            let _ = tx_out.send(Message::Stdout(buf[..n].to_vec()));
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
                            let _ = tx_err.send(Message::Stderr(buf[..n].to_vec()));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            });

            let pid = child.id();
            // Reserve this pid in the shared reaper *immediately* after spawn, so
            // a re-parented grandchild that previously held this (now reused) pid
            // cannot have its lingering, unclaimed exit status mis-delivered to
            // this child as a false result. `reserve` clears any pre-existing
            // status for the pid and captures the generation epoch; the waiter's
            // `wait_for(pid)` below then only accepts a status reaped at or after
            // this point (§4.3 PID-1 reaper-vs-waiter contract).
            reaper.reserve(pid);
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
                    if let Some(p) = Pid::from_raw(pid as i32) {
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
            let err_msg = format!("Failed to spawn command: {}", e);
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
}
