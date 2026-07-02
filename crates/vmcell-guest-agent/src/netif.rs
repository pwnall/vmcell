//! Minimal interface-configuration helpers for the guest agent's native
//! post-restore resync (design 44 §5).
//!
//! Just enough of the `SIOCSIFHWADDR` MAC-set path to rotate `eth0`'s hardware
//! address in-process on restore, so PID 1 no longer spawns the multi-MB
//! `ip`/guest-tools binary for it. The ioctl sequence mirrors the guest-tools
//! `set_mac` helper — bring the link down (some drivers require it to change the
//! address), write `ARPHRD_ETHER` + the six MAC bytes into `ifr_hwaddr`, issue
//! `SIOCSIFHWADDR`, then bring the link back up — but depends only on `libc`, so
//! the lean-agent dependency assertion (`cargo tree -e no-dev` sees no
//! tokio/hyper/rtnetlink/reqwest) stays green.

use std::os::raw::c_char;

const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const SIOCSIFHWADDR: libc::c_ulong = 0x8924;
const ARPHRD_ETHER: u16 = 1;
const IFF_UP: i16 = 0x1;

/// Offset of the `ifr_hwaddr` sockaddr's `sa_family` within the `ifru` union.
const HWADDR_FAMILY_OFFSET: usize = 0;
/// Offset of the MAC bytes (the sockaddr's `sa_data`) within the `ifru` union:
/// a `u16` family precedes them.
const HWADDR_MAC_OFFSET: usize = 2;

/// A `struct ifreq` (40 bytes on 64-bit Linux): the 16-byte interface name
/// followed by the `ifr_ifru` union, which we access as raw bytes for the two
/// shapes we use — `ifr_flags` (a `short` at offset 0) and `ifr_hwaddr` (a
/// `sockaddr`: `sa_family` then `sa_data`, at offset 0).
#[repr(C)]
struct IfReq {
    name: [c_char; libc::IFNAMSIZ],
    ifru: [u8; 24],
}

impl IfReq {
    fn new(dev: &str) -> std::io::Result<Self> {
        let bytes = dev.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("device name too long: {dev}"),
            ));
        }
        let mut name = [0 as c_char; libc::IFNAMSIZ];
        for (slot, &b) in name.iter_mut().zip(bytes) {
            *slot = b as c_char;
        }
        Ok(IfReq {
            name,
            ifru: [0u8; 24],
        })
    }
}

/// Builds the `ifreq` submitted to `SIOCSIFHWADDR` for `dev`+`mac`: the interface
/// name, `ARPHRD_ETHER` in the sockaddr family, then the six MAC bytes. Split out
/// so the byte layout is unit-testable without a live interface.
fn hwaddr_ifreq(dev: &str, mac: [u8; 6]) -> std::io::Result<IfReq> {
    let mut ifr = IfReq::new(dev)?;
    // ifr_hwaddr: sa_family (host-order u16) then sa_data; first 6 data bytes
    // are the MAC.
    ifr.ifru[HWADDR_FAMILY_OFFSET..HWADDR_FAMILY_OFFSET + 2]
        .copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
    ifr.ifru[HWADDR_MAC_OFFSET..HWADDR_MAC_OFFSET + 6].copy_from_slice(&mac);
    Ok(ifr)
}

fn open_inet_socket() -> std::io::Result<libc::c_int> {
    // SAFETY: a constant, valid `socket(2)` call; the returned fd is checked
    // before use and closed by the caller.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn set_link_up(fd: libc::c_int, dev: &str, up: bool) -> std::io::Result<()> {
    let mut ifr = IfReq::new(dev)?;
    // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCGIFFLAGS reads the
    // name and writes `ifr_flags` into the `ifru` union bytes. `fd` is a valid
    // AF_INET socket.
    if unsafe { libc::ioctl(fd, SIOCGIFFLAGS, &mut ifr) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut flags = i16::from_ne_bytes([ifr.ifru[0], ifr.ifru[1]]);
    if up {
        flags |= IFF_UP;
    } else {
        flags &= !IFF_UP;
    }
    ifr.ifru[0..2].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: same struct; SIOCSIFFLAGS consumes the name + `ifr_flags`.
    if unsafe { libc::ioctl(fd, SIOCSIFFLAGS, &mut ifr) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Sets `dev`'s hardware (MAC) address to `mac` via `SIOCSIFHWADDR`.
///
/// Mirrors the guest-tools `set_mac` sequence: opens an `AF_INET` datagram
/// socket, brings the link down (best effort — some drivers reject a hwaddr
/// change while up), issues `SIOCSIFHWADDR` with `ARPHRD_ETHER` + the six MAC
/// bytes, then brings the link back up. Used by the native post-restore resync
/// so PID 1 never spawns the `ip` binary.
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the socket cannot be opened, the
/// device name is too long, or the `SIOCSIFHWADDR` / link-up ioctl fails. The
/// caller treats any error as "MAC not applied" and never fails the resync on it.
pub fn set_mac_bytes(dev: &str, mac: [u8; 6]) -> std::io::Result<()> {
    let fd = open_inet_socket()?;
    let res = (|| -> std::io::Result<()> {
        // Best effort: some drivers require the link down to change its hwaddr.
        let _ = set_link_up(fd, dev, false);
        let mut ifr = hwaddr_ifreq(dev, mac)?;
        // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCSIFHWADDR reads
        // the name and the `ifr_hwaddr` sockaddr from the `ifru` bytes. `fd` is a
        // valid AF_INET socket opened above.
        if unsafe { libc::ioctl(fd, SIOCSIFHWADDR, &mut ifr) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        set_link_up(fd, dev, true)?;
        Ok(())
    })();
    // SAFETY: `fd` is the socket we opened above and no longer use.
    unsafe {
        libc::close(fd);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pins the `ifreq` byte layout `SIOCSIFHWADDR` consumes, so a field-offset or
    // family regression reddens without a netns / privileged ioctl. RED on a
    // wrong hwaddr offset (e.g. writing the MAC at 0) or a wrong/byte-swapped
    // `sa_family`.
    #[test]
    fn set_mac_ifreq_layout() {
        let mac = [0x02, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let ifr = hwaddr_ifreq("eth0", mac).expect("ifreq");

        // The interface name occupies the leading bytes, NUL-terminated.
        assert_eq!(
            &ifr.name[..4],
            &[
                b'e' as c_char,
                b't' as c_char,
                b'h' as c_char,
                b'0' as c_char
            ],
            "ifr_name must be the device"
        );
        assert_eq!(ifr.name[4], 0, "ifr_name must be NUL-terminated");

        // sa_family == ARPHRD_ETHER (0x0001), host-order (little-endian on the
        // guest's x86-64) at bytes 0..2 of the hwaddr sockaddr.
        assert_eq!(
            &ifr.ifru[0..2],
            &[0x01, 0x00],
            "sa_family must be ARPHRD_ETHER, little-endian"
        );
        assert_eq!(
            u16::from_ne_bytes([ifr.ifru[0], ifr.ifru[1]]),
            ARPHRD_ETHER,
            "sa_family must decode to ARPHRD_ETHER"
        );

        // The MAC bytes live at offset 2..8 (after the u16 family), verbatim.
        assert_eq!(
            &ifr.ifru[2..8],
            &mac,
            "MAC must be at the hwaddr data offset"
        );
    }
}
