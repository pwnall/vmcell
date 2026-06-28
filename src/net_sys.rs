//! Small privileged-networking syscall helpers that require `unsafe` and therefore
//! cannot live under `net`, which is `#![forbid(unsafe_code)]`.

use std::io;
use std::os::fd::RawFd;

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
    // TUNSETPERSIST = _IOW('T', 203, int).
    const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
    // SAFETY: `fd` is a valid, open tun/tap fd owned by the caller for the duration
    // of this call; `TUNSETPERSIST` takes an `int` by value (1 = persist) and the
    // kernel retains no pointer past the syscall.
    let rc = unsafe { libc::ioctl(fd, TUNSETPERSIST, 1 as libc::c_int) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
