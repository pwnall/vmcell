//! Minimal interface-configuration helpers for the steward's native
//! post-restore resync (§8.2, Restore correctness: a restored VM is not a fresh VM).
//!
//! Just enough of the `SIOCSIFHWADDR` / `SIOCSIFADDR` / route-ioctl paths to
//! re-point `eth0`'s hardware and IPv4 identity in-process on restore, so PID 1
//! no longer spawns the multi-MB `ip`/guest-tools binary for it. The ioctl
//! sequences mirror the guest-tools helpers but depend only on `libc`, so the
//! lean-steward dependency assertion (`cargo tree -e no-dev` sees no
//! tokio/hyper/rtnetlink/reqwest) stays green.
//!
//! The module is two halves. `KernelNet` is the thin ioctl layer — one syscall
//! per method, no ordering. `apply_resync_net` is the *composition*: which arm
//! bounces the link, in what order, and — the law d1 exists for — who re-installs
//! the default route the bounce destroyed. The composition runs against the
//! `NetOps` trait, so it is unit-testable against a recording fake without a
//! live interface.

use std::os::raw::c_char;

// Kernel ABI values, taken from `libc` rather than re-spelled locally (m25): this
// module is the SECOND copy of the guest-tools `ifreq` stack
// (`ifreq-stack-duplicated-guest-tools`, docs/78 §6), and the recorded deviation's
// promise is that "a copy that drifts from the ABI reddens in its own crate".
// Hardcoded literals cannot do that — they are a second local spelling of a kernel
// constant, which is exactly what the guest-tools half already refuses to write.
// `ioctl_requests_and_flags_are_pinned_to_the_kernel_abi` below pins every one of
// them to its number, so a `libc` renumbering reddens here too.
const SIOCGIFFLAGS: libc::c_ulong = libc::SIOCGIFFLAGS;
const SIOCSIFFLAGS: libc::c_ulong = libc::SIOCSIFFLAGS;
const SIOCSIFHWADDR: libc::c_ulong = libc::SIOCSIFHWADDR;
// IPv4 address / netmask / route ioctls (H-VMM-1 guest-IP rotation).
const SIOCSIFADDR: libc::c_ulong = libc::SIOCSIFADDR;
const SIOCSIFNETMASK: libc::c_ulong = libc::SIOCSIFNETMASK;
const SIOCADDRT: libc::c_ulong = libc::SIOCADDRT;
const SIOCDELRT: libc::c_ulong = libc::SIOCDELRT;
const RTF_UP: u16 = libc::RTF_UP;
const RTF_GATEWAY: u16 = libc::RTF_GATEWAY;
const ARPHRD_ETHER: u16 = libc::ARPHRD_ETHER;
/// `libc::IFF_UP` narrowed to the `short` the `ifr_flags` union arm carries. A fixed
/// ABI constant (1), so the narrowing is lossless — and the pin below asserts the
/// round trip rather than trusting that.
#[expect(
    clippy::cast_possible_truncation,
    reason = "IFF_UP is the constant 1 — fits the ifr_flags short losslessly; pinned by ioctl_requests_and_flags_are_pinned_to_the_kernel_abi"
)]
const IFF_UP: i16 = libc::IFF_UP as i16;

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

/// Sets `dev`'s hardware (MAC) address to `mac` via `SIOCSIFHWADDR` — the ioctl
/// alone. Bringing the link down around it (some drivers reject a hwaddr change
/// while up) and back up is the *caller's* sequencing, which lives in
/// [`apply_resync_net`] so the whole-resync route law can see it.
fn set_hwaddr(fd: libc::c_int, dev: &str, mac: [u8; 6]) -> std::io::Result<()> {
    let mut ifr = hwaddr_ifreq(dev, mac)?;
    // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCSIFHWADDR reads
    // the name and the `ifr_hwaddr` sockaddr from the `ifru` bytes. `fd` is a
    // valid AF_INET socket opened by the caller.
    if unsafe { libc::ioctl(fd, SIOCSIFHWADDR, &mut ifr) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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

/// Maps the result of reading `/proc/net/route` to the default gateways to delete,
/// **propagating** a read error rather than swallowing it. Swallowing it into an
/// empty vec skips the stale-route deletion, so the new default is added alongside
/// the old vmid's lingering `/30` default — intermittently blackholing post-restore
/// egress. Pure over the read `Result` so the propagation is unit-testable.
fn default_gateways_to_delete(read: std::io::Result<String>) -> std::io::Result<Vec<[u8; 4]>> {
    read.map(|s| parse_default_gateways(&s))
}

/// Replaces the guest's default route with one via `gateway`, using only route
/// ioctls (no netlink). Every existing default route is read from
/// `/proc/net/route` and deleted (matching its exact old gateway), then the new
/// default is added — so a rotated `/30` gateway from the old vmid does not linger
/// as a dead route alongside the new one. A `/proc/net/route` read failure is
/// propagated (via [`default_gateways_to_delete`]), never swallowed into an empty
/// list: skipping the deletion would leave a stale default route blackholing egress.
fn replace_default_route(fd: libc::c_int, gateway: [u8; 4]) -> std::io::Result<()> {
    let existing = default_gateways_to_delete(std::fs::read_to_string("/proc/net/route"))?;
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

/// Installs `dev`'s IPv4 address and its `/prefix_len` netmask
/// (`SIOCSIFADDR`/`SIOCSIFNETMASK`) — the two ioctls alone. Bringing the link up
/// and re-pointing the default route is the caller's sequencing
/// ([`apply_resync_net`]).
fn set_inet_addr(fd: libc::c_int, dev: &str, addr: [u8; 4], prefix_len: u8) -> std::io::Result<()> {
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
    Ok(())
}

/// The kernel-facing steps a post-restore resync performs on one interface.
///
/// The trait exists so the **composition** — which arm bounces the link, and
/// therefore which resync has to re-install the default route
/// ([`resync_restores_route`]) — is unit-testable against a recording fake, while
/// the ioctl half stays the thin, unfakeable [`KernelNet`] below. The fake is
/// kernel-blind by construction: the live `snapshot_restore` egress assertion
/// remains the only proof that `KernelNet`'s ioctls are right.
trait NetOps {
    /// Every default route's gateway, in `/proc/net/route` order.
    fn default_gateways(&self) -> std::io::Result<Vec<[u8; 4]>>;
    /// Brings the interface administratively up (`true`) or down (`false`).
    fn set_link_up(&self, up: bool) -> std::io::Result<()>;
    /// Installs the hardware address (`SIOCSIFHWADDR`).
    fn set_mac(&self, mac: [u8; 6]) -> std::io::Result<()>;
    /// Installs the IPv4 address and its `/prefix_len` netmask.
    fn set_addr(&self, addr: [u8; 4], prefix_len: u8) -> std::io::Result<()>;
    /// Deletes every existing default route and installs one via `gateway`.
    fn replace_default_route(&self, gateway: [u8; 4]) -> std::io::Result<()>;
}

/// [`NetOps`] over a live `AF_INET` socket and one interface name — the real
/// ioctls, and nothing else: no ordering, no policy.
struct KernelNet<'a> {
    fd: libc::c_int,
    dev: &'a str,
}

impl NetOps for KernelNet<'_> {
    fn default_gateways(&self) -> std::io::Result<Vec<[u8; 4]>> {
        default_gateways_to_delete(std::fs::read_to_string("/proc/net/route"))
    }

    fn set_link_up(&self, up: bool) -> std::io::Result<()> {
        set_link_up(self.fd, self.dev, up)
    }

    fn set_mac(&self, mac: [u8; 6]) -> std::io::Result<()> {
        set_hwaddr(self.fd, self.dev, mac)
    }

    fn set_addr(&self, addr: [u8; 4], prefix_len: u8) -> std::io::Result<()> {
        set_inet_addr(self.fd, self.dev, addr, prefix_len)
    }

    fn replace_default_route(&self, gateway: [u8; 4]) -> std::io::Result<()> {
        replace_default_route(self.fd, gateway)
    }
}

/// The IPv4 identity a resync installs on the guest's interface (H-VMM-1).
///
/// A local type rather than the wire `Ipv4Reconfig` so this module stays
/// protocol-free — the dispatch converts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Args {
    /// The rotated `/30` address.
    pub addr: [u8; 4],
    /// Its prefix length (30 on the NAT and tap datapaths).
    pub prefix_len: u8,
    /// The default gateway to route through.
    pub gateway: [u8; 4],
}

/// Which arms of one resync took effect, reported back on the wire as
/// `ResyncAck`'s `mac_applied`/`ip_applied`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResyncNetOutcome {
    /// The hardware address was rotated.
    pub mac_applied: bool,
    /// The IPv4 address, netmask, and default route were re-pointed.
    pub ip_applied: bool,
    /// The pre-bounce default route was re-installed because no other arm
    /// installed one (the `resync_restores_route` law). Diagnostic: the host does
    /// not carry this on the wire, but a fake-driven test asserts on it.
    pub route_restored: bool,
}

/// **The resync route law (d1): a resync that bounces the link owns the default
/// route.**
///
/// Downing an interface tears its routes down with it — the kernel's
/// `NETDEV_DOWN` handler runs `fib_disable_ip`, which marks the default route's
/// nexthop dead. The MAC arm bounces `eth0` (drivers may reject a hwaddr change
/// while up), so a `Resync` carrying `mac` **alone** — which the wire type and
/// the design present as an independent option — used to leave the restored guest
/// with no default route at all. The IPv4 arm installs its own default route and
/// therefore covers itself; nothing else does.
///
/// One predicate over the resync as a whole, consulted once by
/// [`apply_resync_net`], so a future third link-bouncing arm inherits the
/// restoration instead of re-discovering the defect.
#[must_use]
fn resync_restores_route(bounced_link: bool, ipv4_installed_route: bool) -> bool {
    bounced_link && !ipv4_installed_route
}

/// Rotates the hardware address with the link bounced around it, re-raising the
/// link on **both** exits (M-GUEST-2): a failed, best-effort MAC rotation must
/// never strand the restored guest's interface administratively DOWN.
fn rotate_mac<O: NetOps>(ops: &O, mac: [u8; 6]) -> std::io::Result<()> {
    // Best effort: a driver that refuses the down-transition may still accept the
    // hwaddr change, and the `set_mac` below is what decides the outcome.
    if let Err(e) = ops.set_link_up(false) {
        tracing::debug!(
            "vmcell-steward: resync link-down before the MAC rotation failed: {}; continuing",
            e
        );
    }
    match ops.set_mac(mac) {
        Ok(()) => ops.set_link_up(true),
        Err(e) => {
            if let Err(up) = ops.set_link_up(true) {
                tracing::warn!(
                    "vmcell-steward: resync could not re-raise the link after a failed MAC rotation: {}",
                    up
                );
            }
            Err(e)
        }
    }
}

/// Re-points the interface's IPv4 identity: address + netmask, link up, then the
/// new default route (H-VMM-1).
fn install_ipv4<O: NetOps>(ops: &O, cfg: Ipv4Args) -> std::io::Result<()> {
    ops.set_addr(cfg.addr, cfg.prefix_len)?;
    ops.set_link_up(true)?;
    ops.replace_default_route(cfg.gateway)
}

/// Applies one resync's network arms in order and reports which took effect.
///
/// Both arms are best-effort — a failure is logged with its cause (L-GUEST-6) and
/// reported as "not applied", never propagated, because the ack must always be
/// sent. The default route is handled for the resync **as a whole**: the
/// pre-bounce gateway is captured before any arm runs and re-installed afterwards
/// exactly when [`resync_restores_route`] says the resync owes it (d1).
fn apply_resync_net<O: NetOps>(
    ops: &O,
    mac: Option<[u8; 6]>,
    ipv4: Option<Ipv4Args>,
) -> ResyncNetOutcome {
    let mut out = ResyncNetOutcome::default();
    if mac.is_none() && ipv4.is_none() {
        return out;
    }

    // Capture BEFORE the bounce: once the link goes down the kernel has already
    // torn the default route's nexthop down, so `/proc/net/route` no longer holds
    // the gateway we would have to restore.
    let mut saved_gateway: Option<[u8; 4]> = None;
    if mac.is_some() {
        match ops.default_gateways() {
            Ok(gateways) => saved_gateway = gateways.first().copied(),
            Err(e) if ipv4.is_none() => {
                // Nothing else will install a route, and we cannot read the one we
                // are about to destroy: refuse the bounce rather than perform an
                // irreversible teardown blind. Reported as "MAC not applied".
                tracing::warn!(
                    "vmcell-steward: resync cannot read the default route ({}); skipping the MAC rotation so the guest keeps its route",
                    e
                );
                return out;
            }
            Err(e) => {
                tracing::warn!(
                    "vmcell-steward: resync cannot read the default route ({}); the IPv4 arm installs its own, so the link bounce is still safe",
                    e
                );
            }
        }
    }

    if let Some(m) = mac {
        out.mac_applied = match rotate_mac(ops, m) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    "vmcell-steward: resync MAC rotation failed: {}; continuing (best-effort)",
                    e
                );
                false
            }
        };
    }

    if let Some(cfg) = ipv4 {
        out.ip_applied = match install_ipv4(ops, cfg) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    "vmcell-steward: resync IP rotation failed: {}; continuing (best-effort)",
                    e
                );
                false
            }
        };
    }

    if resync_restores_route(mac.is_some(), out.ip_applied)
        && let Some(gateway) = saved_gateway
    {
        match ops.replace_default_route(gateway) {
            Ok(()) => out.route_restored = true,
            Err(e) => tracing::warn!(
                "vmcell-steward: resync could not restore the default route after the link bounce: {}",
                e
            ),
        }
    }
    out
}

/// Applies one post-restore resync's network arms to `dev` (H-VMM-1, §8.2).
///
/// The restore/zygote path rotates the vmid, so the guest resumes with the frozen
/// MAC and `ip=` address of the *original* vmid, neither of which matches its
/// rotated host-side tap/`/30` wiring. This re-points both, in-process, using only
/// `SIOCSIFHWADDR`/`SIOCSIFADDR`/`SIOCSIFNETMASK` and the route ioctls — no
/// netlink, no spawned `ip` binary (C1/C6).
///
/// # Errors
/// Returns the underlying [`std::io::Error`] only if the `AF_INET` socket cannot
/// be opened, which is the one failure that leaves *nothing* attempted. Per-arm
/// failures are logged and reported through [`ResyncNetOutcome`]'s flags so the
/// caller can always send its ack.
pub fn resync_net(
    dev: &str,
    mac: Option<[u8; 6]>,
    ipv4: Option<Ipv4Args>,
) -> std::io::Result<ResyncNetOutcome> {
    let fd = open_inet_socket()?;
    let out = apply_resync_net(&KernelNet { fd, dev }, mac, ipv4);
    // SAFETY: `fd` is the socket we opened above and no longer use.
    unsafe {
        libc::close(fd);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// One recorded [`NetOps`] call, in the order the composition made it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NetCall {
        ReadGateways,
        LinkUp(bool),
        SetMac([u8; 6]),
        SetAddr([u8; 4], u8),
        ReplaceRoute([u8; 4]),
    }

    /// A recording [`NetOps`] fake: it sees the composition's *order*, which is
    /// where the d1 law lives. It is kernel-blind — the live `snapshot_restore`
    /// egress assertion is what covers `KernelNet`'s ioctls.
    struct FakeNet {
        calls: RefCell<Vec<NetCall>>,
        gateways: Option<Vec<[u8; 4]>>,
        fail_set_mac: bool,
    }

    impl FakeNet {
        fn with_gateways(gateways: &[[u8; 4]]) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                gateways: Some(gateways.to_vec()),
                fail_set_mac: false,
            }
        }
        /// `/proc/net/route` unreadable.
        fn unreadable_routes() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                gateways: None,
                fail_set_mac: false,
            }
        }
        fn calls(&self) -> Vec<NetCall> {
            self.calls.borrow().clone()
        }
    }

    impl NetOps for FakeNet {
        fn default_gateways(&self) -> std::io::Result<Vec<[u8; 4]>> {
            self.calls.borrow_mut().push(NetCall::ReadGateways);
            self.gateways
                .clone()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }
        fn set_link_up(&self, up: bool) -> std::io::Result<()> {
            self.calls.borrow_mut().push(NetCall::LinkUp(up));
            Ok(())
        }
        fn set_mac(&self, mac: [u8; 6]) -> std::io::Result<()> {
            self.calls.borrow_mut().push(NetCall::SetMac(mac));
            if self.fail_set_mac {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            Ok(())
        }
        fn set_addr(&self, addr: [u8; 4], prefix_len: u8) -> std::io::Result<()> {
            self.calls
                .borrow_mut()
                .push(NetCall::SetAddr(addr, prefix_len));
            Ok(())
        }
        fn replace_default_route(&self, gateway: [u8; 4]) -> std::io::Result<()> {
            self.calls.borrow_mut().push(NetCall::ReplaceRoute(gateway));
            Ok(())
        }
    }

    const MAC: [u8; 6] = [0x02, 0x00, 0x0a, 0xc8, 0x02, 0x02];
    const OLD_GW: [u8; 4] = [10, 200, 2, 1];
    const NEW_IPV4: Ipv4Args = Ipv4Args {
        addr: [10, 200, 5, 2],
        prefix_len: 30,
        gateway: [10, 200, 5, 1],
    };

    // d1: a `Resync` carrying ONLY `mac` bounces the link, and `NETDEV_DOWN` →
    // `fib_disable_ip` marks the default route's nexthop dead — so the resync as a
    // whole owes the route back. RED on the inverse (drop the
    // `resync_restores_route` step, i.e. the pre-fix code where only `set_ipv4`
    // ever touched the route table): the trailing `ReplaceRoute(OLD_GW)` is absent
    // and the guest is left with no default route.
    #[test]
    fn mac_only_resync_restores_the_default_route_it_bounced_away() {
        let ops = FakeNet::with_gateways(&[OLD_GW]);
        let out = apply_resync_net(&ops, Some(MAC), None);

        assert_eq!(
            ops.calls(),
            vec![
                // Captured BEFORE the bounce — afterwards the route is already gone.
                NetCall::ReadGateways,
                NetCall::LinkUp(false),
                NetCall::SetMac(MAC),
                NetCall::LinkUp(true),
                NetCall::ReplaceRoute(OLD_GW),
            ],
            "a mac-only resync must re-install the default route it bounced away"
        );
        assert!(out.mac_applied);
        assert!(!out.ip_applied);
        assert!(out.route_restored, "the route restoration must be reported");
    }

    // The IPv4 arm installs its own default route, so the resync does NOT owe a
    // second one: exactly one route op, carrying the NEW gateway. RED if the
    // restoration were made unconditional on the bounce (the old gateway would be
    // re-installed after the new one, blackholing the rotated `/30`).
    #[test]
    fn mac_and_ipv4_resync_ends_on_the_new_gateway_only() {
        let ops = FakeNet::with_gateways(&[OLD_GW]);
        let out = apply_resync_net(&ops, Some(MAC), Some(NEW_IPV4));

        assert_eq!(
            ops.calls(),
            vec![
                NetCall::ReadGateways,
                NetCall::LinkUp(false),
                NetCall::SetMac(MAC),
                NetCall::LinkUp(true),
                NetCall::SetAddr(NEW_IPV4.addr, NEW_IPV4.prefix_len),
                NetCall::LinkUp(true),
                NetCall::ReplaceRoute(NEW_IPV4.gateway),
            ],
            "the IPv4 arm owns the route; the stale gateway must not be re-added after it"
        );
        assert!(out.mac_applied && out.ip_applied);
        assert!(
            !out.route_restored,
            "the IPv4 arm covers itself — no restoration is owed"
        );
    }

    // An ipv4-only resync never downs the link, so it owes nothing extra and must
    // not even read the route table for a restoration it will not perform.
    #[test]
    fn ipv4_only_resync_does_not_bounce_the_link() {
        let ops = FakeNet::with_gateways(&[OLD_GW]);
        let out = apply_resync_net(&ops, None, Some(NEW_IPV4));

        assert_eq!(
            ops.calls(),
            vec![
                NetCall::SetAddr(NEW_IPV4.addr, NEW_IPV4.prefix_len),
                NetCall::LinkUp(true),
                NetCall::ReplaceRoute(NEW_IPV4.gateway),
            ]
        );
        assert!(!out.mac_applied && out.ip_applied && !out.route_restored);
    }

    // M-GUEST-2 + d1 on the failure path: a MAC rotation that fails still re-raises
    // the link AND still owes the route back — the link was downed either way.
    #[test]
    fn failed_mac_rotation_still_raises_the_link_and_restores_the_route() {
        let mut ops = FakeNet::with_gateways(&[OLD_GW]);
        ops.fail_set_mac = true;
        let out = apply_resync_net(&ops, Some(MAC), None);

        assert_eq!(
            ops.calls(),
            vec![
                NetCall::ReadGateways,
                NetCall::LinkUp(false),
                NetCall::SetMac(MAC),
                NetCall::LinkUp(true),
                NetCall::ReplaceRoute(OLD_GW),
            ]
        );
        assert!(!out.mac_applied, "the failed arm must report not-applied");
        assert!(out.route_restored);
    }

    // A guest with no default route (a segment member) has nothing to restore: the
    // bounce runs and no route op is emitted — restoring `0.0.0.0` would be worse
    // than restoring nothing.
    #[test]
    fn resync_with_no_default_route_restores_nothing() {
        let ops = FakeNet::with_gateways(&[]);
        let out = apply_resync_net(&ops, Some(MAC), None);

        assert_eq!(
            ops.calls(),
            vec![
                NetCall::ReadGateways,
                NetCall::LinkUp(false),
                NetCall::SetMac(MAC),
                NetCall::LinkUp(true),
            ]
        );
        assert!(out.mac_applied && !out.route_restored);
    }

    // An unreadable `/proc/net/route` with nothing else to install a route: refuse
    // the irreversible bounce rather than destroy a route we cannot put back.
    #[test]
    fn resync_skips_the_bounce_when_the_route_table_is_unreadable() {
        let ops = FakeNet::unreadable_routes();
        let out = apply_resync_net(&ops, Some(MAC), None);

        assert_eq!(
            ops.calls(),
            vec![NetCall::ReadGateways],
            "no link may go down when the route it would destroy cannot be read back"
        );
        assert!(!out.mac_applied && !out.route_restored);

        // …but with the IPv4 arm present a route WILL be installed, so the bounce
        // is safe and must still happen.
        let ops = FakeNet::unreadable_routes();
        let out = apply_resync_net(&ops, Some(MAC), Some(NEW_IPV4));
        assert!(
            ops.calls().contains(&NetCall::SetMac(MAC)),
            "the IPv4 arm makes the bounce recoverable: {:?}",
            ops.calls()
        );
        assert!(out.mac_applied && out.ip_applied);
    }

    // A resync with neither arm touches nothing at all (the clock/reseed-only case).
    #[test]
    fn empty_resync_touches_no_interface_state() {
        let ops = FakeNet::with_gateways(&[OLD_GW]);
        let out = apply_resync_net(&ops, None, None);
        assert!(ops.calls().is_empty());
        assert_eq!(out, ResyncNetOutcome::default());
    }

    // The law itself, in isolation: only a bounce that nothing else covers owes the
    // route. RED on `bounced_link` alone (double-installs over the IPv4 arm) or on
    // a constant `false` (the pre-fix behavior).
    #[test]
    fn resync_restores_route_is_bounce_without_a_replacement() {
        assert!(resync_restores_route(true, false), "d1: the mac-only case");
        assert!(!resync_restores_route(true, true), "the IPv4 arm covers it");
        assert!(!resync_restores_route(false, false), "no bounce, no debt");
        assert!(!resync_restores_route(false, true));
    }

    // m25 — the `netif` half of the `ifreq-stack-duplicated-guest-tools` divergence
    // guard (docs/78 §6). The recorded deviation promises "a copy that drifts from
    // the ABI reddens in its own crate"; that only holds if this crate pins the
    // values it issues. Every ioctl request number, both `RTF_*` flags, the
    // `ARPHRD_ETHER` family, and the narrowed `IFF_UP` are asserted against their
    // kernel numbers — the same numbers the guest-tools half pins, so the two copies
    // remain checkable against one another.
    //
    // RED on: any renumbering (a typo'd `0x891c` → `0x891b` turns a netmask write
    // into a netmask *read*), a `libc` constant that changes width, or an `IFF_UP`
    // that does not survive the narrowing to the `ifr_flags` short.
    #[test]
    fn ioctl_requests_and_flags_are_pinned_to_the_kernel_abi() {
        assert_eq!(SIOCGIFFLAGS, 0x8913);
        assert_eq!(SIOCSIFFLAGS, 0x8914);
        assert_eq!(SIOCSIFADDR, 0x8916);
        assert_eq!(SIOCSIFNETMASK, 0x891c);
        assert_eq!(SIOCSIFHWADDR, 0x8924);
        assert_eq!(SIOCADDRT, 0x890b);
        assert_eq!(SIOCDELRT, 0x890c);
        assert_eq!(RTF_UP, 0x0001);
        assert_eq!(RTF_GATEWAY, 0x0002);
        assert_eq!(ARPHRD_ETHER, 1);
        assert_eq!(IFF_UP, 0x1);
        assert_eq!(
            i32::from(IFF_UP),
            libc::IFF_UP,
            "IFF_UP must survive the narrowing to the ifr_flags short"
        );
        assert_eq!(
            u32::from(AF_INET_FAMILY),
            u32::try_from(libc::AF_INET).expect("AF_INET is positive"),
            "AF_INET must survive the narrowing to sa_family_t"
        );
        // The route flags are what tell the kernel this is an UP gateway route; a
        // widened `rt_flags` field would silently drop the high half.
        assert_eq!(
            std::mem::size_of::<u16>(),
            std::mem::size_of_val(&libc::RTF_UP),
            "rt_flags is a c_ushort — the RTF_* constants must stay u16"
        );
    }

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

    // ga-route: a `/proc/net/route` read failure must PROPAGATE, not collapse into
    // an empty vec. Swallowing it skips deletion of the old vmid's stale default
    // route, so the new default is added alongside it and post-restore egress
    // intermittently blackholes. RED on the pre-fix `.unwrap_or_default()` swallow
    // (which returns Ok(vec![])).
    #[test]
    fn default_gateways_to_delete_propagates_read_error() {
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(
            default_gateways_to_delete(Err(err)).is_err(),
            "a /proc/net/route read error must be propagated, not swallowed into an empty list"
        );
        // Ok arm still parses the default gateways (same fixture as the LE-hex test).
        let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t00000000\t0102C80A\t0003\t0\t0\t0\t00000000\n";
        assert_eq!(
            default_gateways_to_delete(Ok(route.to_string())).unwrap(),
            vec![[10, 200, 2, 1]],
            "Ok read must decode the default gateway list"
        );
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
