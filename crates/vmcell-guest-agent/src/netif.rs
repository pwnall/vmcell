//! Minimal interface-configuration helpers for the guest agent's native
//! post-restore resync (§8.2, Restore correctness: a restored VM is not a fresh VM).
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
// IPv4 address / netmask / route ioctls (H-VMM-1 guest-IP rotation).
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891c;
const SIOCADDRT: libc::c_ulong = 0x890b;
const SIOCDELRT: libc::c_ulong = 0x890c;
const RTF_UP: u16 = 0x0001;
const RTF_GATEWAY: u16 = 0x0002;
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
            *slot = b.cast_signed();
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

/// Brings the loopback interface (`lo`) administratively up via `SIOCSIFFLAGS`,
/// without spawning `ip`.
///
/// Reuses the audited 40-byte `IfReq` and `set_link_up` path
/// (C-GUEST-1/M-GUEST-5): the previous inline loopback bring-up in `main` declared
/// its own **18-byte** `ifreq`, but `SIOCG/SIOCSIFFLAGS` `copy_{from,to}_user` the
/// kernel's **40-byte** `struct ifreq` — a 22-byte out-of-bounds read/write onto
/// PID 1's stack on every boot. Routing through this helper eliminates that class.
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the socket cannot be opened or the
/// ioctl fails. Loopback is best-effort (not required for the vsock control
/// plane), so the caller logs and tolerates a failure rather than panicking PID 1.
pub fn set_loopback_up() -> std::io::Result<()> {
    let fd = open_inet_socket()?;
    let res = set_link_up(fd, "lo", true);
    // SAFETY: `fd` is the socket we opened above and no longer use.
    unsafe {
        libc::close(fd);
    }
    res
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
            let err = std::io::Error::last_os_error();
            // M-GUEST-2: the link was brought down above; re-raise it even on this
            // failure path so a failed (best-effort) MAC rotation never leaves the
            // restored guest's eth0 administratively DOWN with no one to re-raise
            // it. The re-up is itself best-effort — the original error is returned.
            let _ = set_link_up(fd, dev, true);
            return Err(err);
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

/// The four netmask octets (network order) for a `/prefix_len` prefix, e.g.
/// `30 -> [255, 255, 255, 252]`, `0 -> [0, 0, 0, 0]`, `>=32 -> [255; 4]`. Pure so
/// the `/30` math is unit-testable without a live interface.
fn netmask_octets(prefix_len: u8) -> [u8; 4] {
    let mask: u32 = match prefix_len {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => !((1u32 << (32 - p)) - 1),
    };
    mask.to_be_bytes()
}

/// Parses the gateway octets of every default route (destination `0.0.0.0`) out of
/// `/proc/net/route` contents. Both `Destination` and `Gateway` are printed as a
/// little-endian hex `u32`, so a gateway `10.200.2.1` (network bytes
/// `0a c8 02 01`) appears as `0102C80A` and decodes back via `to_le_bytes()`. Pure
/// (takes the file contents) so the hex/endianness handling is unit-testable.
fn parse_default_gateways(proc_net_route: &str) -> Vec<[u8; 4]> {
    proc_net_route
        .lines()
        .skip(1) // header row
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let _iface = f.next()?;
            let dest = f.next()?;
            let gw = f.next()?;
            if dest != "00000000" {
                return None;
            }
            let v = u32::from_str_radix(gw, 16).ok()?;
            Some(v.to_le_bytes())
        })
        .collect()
}

/// `AF_INET` (`c_int`) narrowed to `sa_family_t` once, behind one reasoned `expect`. `AF_INET` is the
/// constant 2, so the narrowing is lossless; centralizing it keeps the single `as` cast (which the
/// wire-crate B10 lints otherwise forbid) in one place — `try_from` cannot fail for a fixed constant.
#[expect(
    clippy::cast_possible_truncation,
    reason = "AF_INET is the constant 2 — fits sa_family_t (u16) losslessly"
)]
const AF_INET_FAMILY: libc::sa_family_t = libc::AF_INET as libc::sa_family_t;

/// Builds a `libc::sockaddr` holding an `AF_INET` `sockaddr_in` for `addr` (port 0).
/// `sin_addr.s_addr` is network byte order — the octets are laid out verbatim, so
/// `from_ne_bytes` (an identity on the byte pattern) is correct.
fn sockaddr_in_v4(addr: [u8; 4]) -> libc::sockaddr {
    // SAFETY: `sockaddr` is a C POD whose all-zero bit pattern is a valid, fully initialized value.
    let mut sa: libc::sockaddr = unsafe { std::mem::zeroed() };
    let sin = std::ptr::addr_of_mut!(sa) as *mut libc::sockaddr_in;
    // `sockaddr` and `sockaddr_in` share the `sa_family`-prefixed layout, and `sin` points at the
    // stack-owned `sa` (valid, correctly aligned, no larger than `sockaddr`); every write below goes
    // through that pointer to an initialized scalar field, never reading uninitialized memory.
    // SAFETY: valid, aligned `sin` (see above) — set the address family.
    unsafe {
        (*sin).sin_family = AF_INET_FAMILY;
    }
    // SAFETY: valid, aligned `sin` (see above) — zero the port.
    unsafe {
        (*sin).sin_port = 0;
    }
    // SAFETY: valid, aligned `sin` (see above) — set the address (octets verbatim; `from_ne_bytes`
    // is the identity on the network-order byte pattern).
    unsafe {
        (*sin).sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(addr),
        };
    }
    sa
}

/// Writes an `AF_INET` `sockaddr_in` for `addr` into an `ifreq`'s `ifru` bytes
/// (`ifr_addr` / `ifr_netmask`): family at offset 0, addr at offset 4 (a `u16`
/// port sits between them). Pure over the byte buffer for unit testing.
fn write_ifru_sockaddr(ifru: &mut [u8; 24], addr: [u8; 4]) {
    ifru.fill(0);
    ifru[0..2].copy_from_slice(&AF_INET_FAMILY.to_ne_bytes());
    // ifru[2..4] is the (zero) sin_port.
    ifru[4..8].copy_from_slice(&addr);
}

/// Replaces the guest's default route with one via `gateway`, using only route
/// ioctls (no netlink). Every existing default route is read from
/// `/proc/net/route` and deleted (matching its exact old gateway), then the new
/// default is added — so a rotated `/30` gateway from the old vmid does not linger
/// as a dead route alongside the new one.
fn replace_default_route(fd: libc::c_int, gateway: [u8; 4]) -> std::io::Result<()> {
    let existing = std::fs::read_to_string("/proc/net/route")
        .map(|s| parse_default_gateways(&s))
        .unwrap_or_default();
    for old_gw in existing {
        // SAFETY: `rtentry` is a C POD struct whose all-zero bit pattern is a valid, fully
        // initialized value; every field is overwritten below before the ioctl reads it.
        let mut del: libc::rtentry = unsafe { std::mem::zeroed() };
        del.rt_dst = sockaddr_in_v4([0, 0, 0, 0]);
        del.rt_genmask = sockaddr_in_v4([0, 0, 0, 0]);
        del.rt_gateway = sockaddr_in_v4(old_gw);
        del.rt_flags = RTF_UP | RTF_GATEWAY;
        // SAFETY: `del` is a fully-initialized `rtentry`; a delete of a
        // non-existent route just returns `ESRCH`, which we ignore.
        unsafe {
            libc::ioctl(fd, SIOCDELRT, &del);
        }
    }
    // SAFETY: `rtentry` is a C POD struct whose all-zero bit pattern is a valid, fully
    // initialized value; every field is overwritten below before the ioctl reads it.
    let mut add: libc::rtentry = unsafe { std::mem::zeroed() };
    add.rt_dst = sockaddr_in_v4([0, 0, 0, 0]);
    add.rt_genmask = sockaddr_in_v4([0, 0, 0, 0]);
    add.rt_gateway = sockaddr_in_v4(gateway);
    add.rt_flags = RTF_UP | RTF_GATEWAY;
    // SAFETY: `add` is a fully-initialized `rtentry` describing a default route
    // via `gateway`; `fd` is a valid `AF_INET` socket.
    if unsafe { libc::ioctl(fd, SIOCADDRT, &add) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Rotates the guest's `eth0` IPv4 identity post-restore (H-VMM-1): sets the new
/// address + `/prefix_len` netmask, brings the link up, and re-points the default
/// route at the new `gateway`.
///
/// The restore/zygote path rotates the vmid, so the guest resumes with the frozen
/// `ip=` address of the *original* vmid, which no longer matches its rotated
/// host-side tap/`/30` wiring — this re-points it, exactly as [`set_mac_bytes`]
/// re-points the hardware address. Uses only `SIOCSIFADDR`/`SIOCSIFNETMASK` and
/// the route ioctls (no netlink), preserving the zero-netlink-in-PID-1 contract.
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the socket cannot be opened or any
/// ioctl fails. The caller treats any error as "IP not applied" and never fails
/// the resync on it.
pub fn set_ipv4(dev: &str, addr: [u8; 4], prefix_len: u8, gateway: [u8; 4]) -> std::io::Result<()> {
    let fd = open_inet_socket()?;
    let res = (|| -> std::io::Result<()> {
        let mut ifr = IfReq::new(dev)?;
        write_ifru_sockaddr(&mut ifr.ifru, addr);
        // SAFETY: `ifr` is a correctly-sized `ifreq` whose `ifru` holds an
        // `AF_INET` `sockaddr_in`; `fd` is a valid `AF_INET` socket.
        if unsafe { libc::ioctl(fd, SIOCSIFADDR, &mut ifr) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ifr = IfReq::new(dev)?;
        write_ifru_sockaddr(&mut ifr.ifru, netmask_octets(prefix_len));
        // SAFETY: same shape as above; `SIOCSIFNETMASK` consumes `ifr_netmask`.
        if unsafe { libc::ioctl(fd, SIOCSIFNETMASK, &mut ifr) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        set_link_up(fd, dev, true)?;
        replace_default_route(fd, gateway)?;
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

    // H-VMM-1: the `/30` netmask math. RED on an off-by-one prefix or a byte-swap.
    #[test]
    fn netmask_octets_maps_prefix() {
        assert_eq!(netmask_octets(30), [255, 255, 255, 252]);
        assert_eq!(netmask_octets(24), [255, 255, 255, 0]);
        assert_eq!(netmask_octets(0), [0, 0, 0, 0]);
        assert_eq!(netmask_octets(32), [255, 255, 255, 255]);
    }

    // H-VMM-1: `/proc/net/route` prints the gateway as a little-endian hex u32, so
    // `10.200.2.1` (network bytes 0a c8 02 01) is `0102C80A`. RED on a wrong
    // endianness (`to_be_bytes`) or on failing to skip non-default routes.
    #[test]
    fn parse_default_gateways_decodes_le_hex() {
        let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t00000000\t0102C80A\t0003\t0\t0\t0\t00000000\n\
                     eth0\t00C80A00\t00000000\t0001\t0\t0\t0\t00FCFFFF\n";
        assert_eq!(parse_default_gateways(route), vec![[10, 200, 2, 1]]);
        // No default route -> empty.
        let none = "Iface\tDestination\tGateway\n\
                    eth0\t00C80A00\t00000000\n";
        assert!(parse_default_gateways(none).is_empty());
    }

    // H-VMM-1: the `ifr_addr` byte layout `SIOCSIFADDR`/`SIOCSIFNETMASK` consume —
    // `AF_INET` family at 0, the address at offset 4 (after the u16 port). RED on a
    // wrong offset or a byte-swapped family.
    #[test]
    fn write_ifru_sockaddr_layout() {
        let mut ifru = [0xEEu8; 24];
        write_ifru_sockaddr(&mut ifru, [10, 200, 5, 2]);
        assert_eq!(
            u16::from_ne_bytes([ifru[0], ifru[1]]),
            libc::AF_INET as u16,
            "sa_family must be AF_INET"
        );
        assert_eq!(&ifru[2..4], &[0, 0], "sin_port must be zero");
        assert_eq!(&ifru[4..8], &[10, 200, 5, 2], "sin_addr at offset 4");
    }

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

        // L-GUEST-8 / C-GUEST-1 class guard: pin the TOTAL size to the kernel's
        // `struct ifreq`. Shrinking `ifru` (e.g. to `[u8; 20]`) would pass every
        // offset assert above while recreating the out-of-bounds `copy_to_user`
        // the ioctls do — this catches that whole class.
        assert_eq!(
            std::mem::size_of::<IfReq>(),
            std::mem::size_of::<libc::ifreq>(),
            "IfReq must match the kernel `struct ifreq` size (40 bytes on x86-64)"
        );
    }
}
