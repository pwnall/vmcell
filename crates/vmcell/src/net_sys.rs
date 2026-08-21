//! Small privileged-networking syscall helpers that require `unsafe` and therefore
//! cannot live under `net`, which is `#![forbid(unsafe_code)]`.

use std::io;
use std::os::fd::RawFd;

/// The tun/tap control device. Opening it is what binds a tap to a network namespace — see
/// [`create_tap_in_current_netns`].
const TUN_DEVICE: &str = "/dev/net/tun";

/// `IFF_TAP | IFF_NO_PI`, narrowed to the `c_short` the `ifr_flags` union arm carries.
///
/// `IFF_NO_PI` is not decoration: without it the kernel prepends a 4-byte `tun_pi` header to every
/// frame, which every VMM that opens this tap would then have to strip. Both halves are fixed ABI
/// constants (`0x0002`, `0x1000`), so the OR is `0x1002` and the narrowing to the 16-bit union arm
/// is lossless — `tunsetiff_abi_is_pinned_to_the_kernel` asserts that round trip rather than
/// trusting it, the same shape `vmcell_steward::netif`'s `IFF_UP` narrowing carries.
///
/// Deliberately **not** `IFF_MULTI_QUEUE`: no backend asks for a multi-queue tap
/// (`ChNet` has no `num_queues`, QEMU's `-netdev tap` passes no `queues=`), and the kernel rejects
/// a queue-flag mismatch with `EINVAL` when the VMM re-attaches. Adding `queues=N` anywhere
/// downstream means adding the flag here in the same change.
#[expect(
    clippy::cast_possible_truncation,
    reason = "IFF_TAP|IFF_NO_PI is the constant 0x1002 — it fits the ifr_flags c_short losslessly; pinned by tunsetiff_abi_is_pinned_to_the_kernel"
)]
const TAP_NO_PI_FLAGS: libc::c_short = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;

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

/// Builds the zeroed `ifreq` that [`create_tap_in_current_netns`] submits to `TUNSETIFF`: `name` in
/// `ifr_name`, [`TAP_NO_PI_FLAGS`] in the `ifr_flags` union arm.
///
/// Split out so the name law is drivable without `/dev/net/tun` and without `CAP_NET_ADMIN`.
///
/// **The name is rejected, never truncated.** `tun-tap`'s C shim — what this replaced — did
/// `strncpy(ifr.ifr_name, name, IFNAMSIZ - 1)`, so an over-long name brought the tap up under a
/// name nobody composed and the failure surfaced one step later at the `rtnetlink` index lookup,
/// far from the composer that overflowed. [`crate::naming`] bounds every name it composes, but this
/// is the boundary that has to *hold* that bound rather than assume it.
///
/// Only the two facts needed to build the struct are checked here — the length that must leave room
/// for the NUL, and the absence of an interior NUL that would silently shorten the name. Everything
/// else the kernel may object to (`dev_valid_name`'s rejects, or a `%d` pattern it would *expand*)
/// is caught loudly by the caller's read-back comparison, so this is not a second, partial copy of
/// the kernel's name rules.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] naming the offending value if `name` is empty, is `IFNAMSIZ`
/// bytes or longer, or contains an interior NUL.
fn tap_ifreq(name: &str) -> io::Result<libc::ifreq> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "tap name must be 1..{} bytes (IFNAMSIZ leaves room for the NUL), got {} in {name:?}",
                libc::IFNAMSIZ,
                bytes.len()
            ),
        ));
    }
    if bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tap name must not contain an interior NUL: {name:?}"),
        ));
    }
    // SAFETY: `libc::ifreq` is `#[repr(C)]` over an integer array and a union of integers, raw
    // pointers and `sockaddr`s — every field is valid at all-zero, and none is a reference,
    // `NonNull` or enum. Zeroing rather than initializing field-by-field is REQUIRED, not hygiene:
    // `TUNSETIFF` `copy_from_user`s all `size_of::<ifreq>()` bytes, so any byte left uninitialized
    // is a byte the kernel reads.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, &b) in ifr.ifr_name.iter_mut().zip(bytes) {
        // `c_char` is `i8` on x86-64 and `u8` on aarch64; `from_ne_bytes` is the one spelling that
        // is a no-op on both, so this loop is not silently x86-only.
        *slot = libc::c_char::from_ne_bytes([b]);
    }
    // Writing a union field is safe (no drop glue on a `c_short`); only reading one is `unsafe`.
    ifr.ifr_ifru.ifru_flags = TAP_NO_PI_FLAGS;
    Ok(ifr)
}

/// The NUL-terminated name the kernel left in `ifr_name`.
///
/// `ifr_name` is a plain array, not a union arm, so this needs no `unsafe`.
fn ifreq_name(ifr: &libc::ifreq) -> Vec<u8> {
    ifr.ifr_name
        .iter()
        .map(|&c| c.to_ne_bytes()[0])
        .take_while(|&b| b != 0)
        .collect()
}

/// Creates the TAP interface `name` **in the calling thread's current network namespace**
/// (`TUNSETIFF` with `IFF_TAP | IFF_NO_PI` on `/dev/net/tun`), returning the fd that owns it.
///
/// The one `TUNSETIFF` in this crate — the whole of what the unmaintained `tun-tap` crate, and the
/// `tokio 0.1` subtree behind it, used to supply.
///
/// **The open and the ioctl are one function because the namespace is captured at `open()`, not at
/// `ioctl()`.** `tun_chr_open` stores the opener's netns on the `tun_file`'s socket and
/// `__tun_chr_ioctl` reads it back from *there*, never from `current` — so hoisting the
/// `/dev/net/tun` open out of the caller's [`crate::net::tap`] `in_netns` closure (the natural
/// tidy-up once the open and the ioctl are two visible statements instead of one opaque call)
/// creates every tap in the **host** namespace. That failure is silent: the tap comes up, this
/// returns `Ok`, and it surfaces one step later at an in-namespace `rtnetlink` lookup. Keeping both
/// halves here makes the hoist unrepresentable without splitting this function, and
/// `tap_lands_in_the_target_netns_and_not_the_host` is the live gate that reddens if anyone does.
///
/// The fd is opened through [`std::fs::OpenOptions`], which unconditionally sets `O_CLOEXEC`, and
/// that is load-bearing rather than boilerplate: `vmcelld` fork/execs VMMs and forks the broker
/// concurrently with this call, and a leaked `/dev/net/tun` fd is an *attached tap queue* — the
/// VMM's own `TUNSETIFF` on the same tap then fails `EBUSY`, which is verbatim the
/// "Open tap device failed: Device or resource busy" the caller's persist-then-drop dance exists to
/// prevent. A raw `libc::open` here would reintroduce that.
///
/// The kernel copies the interface's real name back into the `ifreq`, so this compares it against
/// what was asked for and fails loud on a mismatch — free coverage for the silent-truncation and
/// `%d`-expansion classes.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] if `name` cannot be encoded (see [`tap_ifreq`]); the OS error if
/// `/dev/net/tun` cannot be opened or the ioctl fails (`EPERM` without `CAP_NET_ADMIN` in the
/// namespace's user namespace, `EBUSY` when an interface of that name is already open by someone
/// else, `EINVAL` when the name is taken by a non-tun device); and
/// [`io::ErrorKind::InvalidData`] if the kernel reports a name other than the one requested.
pub(crate) fn create_tap_in_current_netns(name: &str) -> io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;

    let mut ifr = tap_ifreq(name)?;
    let tun = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_DEVICE)?;
    // SAFETY: `TUNSETIFF` reads and writes exactly one `struct ifreq` through its pointer argument.
    // `ifr` is a live, fully initialized `libc::ifreq` — the kernel's own definition of that struct,
    // so it is exactly the 40 bytes `copy_{from,to}_user` move — and `addr_of_mut!` hands over a
    // unique pointer to it which the kernel retains no reference to past the call. `tun` is an open
    // `/dev/net/tun` fd owned here for the whole call. Handing over a *shared* reference, or any
    // struct smaller than the kernel's, is the out-of-bounds-write class recorded against the
    // 18-byte `ifreq` in `vmcell_steward::netif`.
    let rc = unsafe {
        libc::ioctl(
            tun.as_raw_fd(),
            libc::TUNSETIFF,
            std::ptr::addr_of_mut!(ifr),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let assigned = ifreq_name(&ifr);
    if assigned != name.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "kernel named the tap {:?}, not the requested {name:?}",
                String::from_utf8_lossy(&assigned)
            ),
        ));
    }
    Ok(tun)
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

#[cfg(test)]
mod tests {
    use super::{TAP_NO_PI_FLAGS, TUN_DEVICE, ifreq_name, tap_ifreq};

    // The divergence guard for the `TUNSETIFF` submission, and the reason this crate needs NO third
    // `#[repr(C)] struct IfReq` beside the two recorded guest-side copies: the struct submitted here
    // IS `libc::ifreq`, so there is no layout to drift. What CAN drift is everything around it — the
    // request number, the flag word, and the narrowing into the 16-bit `ifr_flags` union arm — and a
    // wrong one of those is silent at compile time and wrong at the kernel boundary.
    //
    // RED on: dropping `IFF_NO_PI` so every frame gains a 4-byte header; swapping `IFF_TAP` for
    // `IFF_TUN` so the interface comes up layer-3; a `libc` that renumbers any of the three; or a
    // flag word widened past what the `c_short` arm can hold. All four proven by mutation.
    //
    // What this canNOT see, stated so the claim does not age into fiction: a *call-site* typo —
    // `create_tap_in_current_netns` issuing `TUNSETPERSIST` where it means `TUNSETIFF`. This test
    // pins the constants, not which one the ioctl names. `tap_create.rs`'s live legs are that gate.
    #[test]
    fn tunsetiff_abi_is_pinned_to_the_kernel() {
        use std::mem::{offset_of, size_of};

        assert_eq!(libc::TUNSETIFF, 0x4004_54ca, "_IOW('T', 202, int)");
        assert_eq!(libc::TUNSETPERSIST, 0x4004_54cb, "_IOW('T', 203, int)");
        assert_ne!(
            libc::TUNSETIFF,
            libc::TUNSETPERSIST,
            "the two requests this module issues are adjacent numbers; a typo must not alias"
        );
        assert_eq!(libc::IFF_TAP, 0x0002);
        assert_eq!(libc::IFF_NO_PI, 0x1000);
        assert_eq!(TAP_NO_PI_FLAGS, 0x1002);
        assert_eq!(
            libc::c_int::from(TAP_NO_PI_FLAGS),
            libc::IFF_TAP | libc::IFF_NO_PI,
            "the flag word must survive the narrowing to the ifr_flags c_short"
        );

        // The struct we hand the kernel is the kernel's own, so these assert that `libc` still
        // describes the ABI the ioctl moves: 40 bytes, name first, union at IFNAMSIZ.
        assert_eq!(size_of::<libc::ifreq>(), 40);
        assert_eq!(offset_of!(libc::ifreq, ifr_name), 0);
        assert_eq!(offset_of!(libc::ifreq, ifr_ifru), libc::IFNAMSIZ);
        assert_eq!(libc::IFNAMSIZ, 16);
    }

    // The name law (`tap-name-truncated-not-rejected`): `tun-tap`'s shim silently `strncpy`'d an
    // over-long name to 15 bytes, so the tap came up under a name nobody composed. The replacement
    // refuses instead.
    //
    // RED on: restoring the truncating copy (`zip` alone truncates — this is what proves the length
    // check in front of it is load-bearing), or dropping either bound.
    #[test]
    fn an_over_long_or_unencodable_tap_name_is_refused_not_truncated() {
        // The longest name that fits with its NUL is accepted, and lands byte-for-byte.
        let longest = "a".repeat(libc::IFNAMSIZ - 1);
        let ifr = tap_ifreq(&longest).expect("IFNAMSIZ-1 bytes must be accepted");
        assert_eq!(
            ifreq_name(&ifr),
            longest.as_bytes(),
            "the accepted name must reach ifr_name whole"
        );

        for (name, why) in [
            (
                &*"a".repeat(libc::IFNAMSIZ),
                "IFNAMSIZ leaves no room for the NUL",
            ),
            (&*"a".repeat(64), "far over-long"),
            ("", "empty"),
            ("vmcell\0-tap-1", "interior NUL"),
        ] {
            let err = tap_ifreq(name).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "{why}: must be refused typed, not truncated"
            );
        }
    }

    // `ifreq_name` is what turns the kernel's read-back into a loud mismatch, so it must stop at the
    // NUL rather than dragging the rest of the array along.
    //
    // RED on: dropping the `take_while`, or reading the array as a fixed 16-byte name.
    #[test]
    fn ifreq_name_reads_back_to_the_nul_only() {
        let ifr = tap_ifreq("vmcell-tap-7").expect("valid name");
        assert_eq!(ifreq_name(&ifr), b"vmcell-tap-7");
        assert_eq!(
            ifreq_name(&ifr).len(),
            "vmcell-tap-7".len(),
            "the trailing NUL padding must not become part of the name"
        );
    }

    #[test]
    fn the_tun_control_device_is_the_kernel_path() {
        assert_eq!(TUN_DEVICE, "/dev/net/tun");
    }
}
