//! Small privileged-networking syscall helpers that require `unsafe` and therefore
//! cannot live under `net`, which is `#![forbid(unsafe_code)]`.

use std::io;
use std::os::fd::RawFd;

/// Moves the **calling thread** into the network namespace referenced by `fd`
/// (`setns(fd, CLONE_NEWNET)`).
///
/// A socket's network namespace is fixed at `socket()` time, so the only way to create a socket
/// inside a segment's namespace is to move a thread there first ([`crate::net::NetSegment::dial_tcp`],
/// §6.5). `CLONE_NEWNET` scopes the move to this one thread; every other thread in the process keeps
/// its namespace. The caller must therefore run this on a **dedicated** thread it owns — never a
/// pooled runtime worker.
///
/// # Errors
/// Returns the OS error if the syscall fails (e.g. `EPERM` without `CAP_SYS_ADMIN`, `EBADF`).
pub(crate) fn setns_net(fd: RawFd) -> io::Result<()> {
    // SAFETY: `setns(2)` on `fd`, which the caller keeps open (borrowed from a live `File`) for the
    // duration of this call; the kernel retains no reference past it. `CLONE_NEWNET` is the correct
    // nstype for a `/proc/<pid>/ns/net` or `/var/run/netns/<name>` fd, and the return is checked.
    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Makes a tun/tap interface persistent via `TUNSETPERSIST`, so it survives after
/// its creating fd is closed.
///
/// The orchestrator creates the tap to configure it, then drops its fd so the VMM
/// can open the interface — a non-multi-queue tap allows only a single opener, so
/// without persistence the interface would either vanish (fd closed) or refuse the
/// VMM's open with `EBUSY` (fd held).
///
/// # Errors
/// Returns the OS error if the ioctl fails.
pub(crate) fn set_tun_persist(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid, open tun/tap fd owned by the caller for the duration
    // of this call; `libc::TUNSETPERSIST` (`_IOW('T', 203, int)`) takes an `int` by
    // value (1 = persist) and the kernel retains no pointer past the syscall.
    let rc = unsafe { libc::ioctl(fd, libc::TUNSETPERSIST, 1 as libc::c_int) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
