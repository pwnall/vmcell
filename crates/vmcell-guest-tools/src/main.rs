//! Multicall guest **test-helper** binary: a small Rust stand-in for the distro
//! `ip`, `curl`, and `kvm-ok` tools the integration tests invoke inside the
//! guest.
//!
//! It is baked into the rootfs erofs at `/vmcell-tools/vmcell-guest-tools` (with
//! `ip`/`curl`/`kvm-ok` symlinks), which the guest agent places on the exec
//! `PATH`. Baking — rather than a virtio-fs share — is what lets the *unprivileged*
//! egress test use the tools: virtiofsd cannot enter its sandbox unprivileged, so
//! a share fails there, whereas the erofs rootfs is served over virtio-blk in both
//! modes. This keeps the base image otherwise minimal (no
//! `iproute2`/`curl`/`cpu-checker` packages) while still exercising the real
//! operations the tests assert on: genuine HTTP(S) requests (honoring the proxy
//! env + the `-k` flag), real `/dev/kvm` access, and real interface/route state.
//!
//! Dispatch is busy-box style: when invoked through an `ip`/`curl`/`kvm-ok`
//! symlink the command is taken from `argv[0]`; otherwise the first argument
//! selects it (`vmcell-guest-tools <cmd> …`).
//!
//! `print_stdout`/`print_stderr` are intentionally NOT denied here — reproducing `ip`/`curl`/`kvm-ok`
//! output on stdout/stderr is the whole point of the tool.
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
        clippy::dbg_macro,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use std::io::Write;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|p| basename(p)).unwrap_or_default();

    // `argv[0]` selects the command when invoked via a symlink; otherwise fall
    // back to `vmcell-guest-tools <cmd> …`.
    let (cmd, rest): (String, &[String]) = if is_known(&prog) {
        (prog, args.get(1..).unwrap_or(&[]))
    } else {
        match args.get(1) {
            Some(c) => (c.clone(), args.get(2..).unwrap_or(&[])),
            None => {
                eprintln!("usage: vmcell-guest-tools <ip|curl|kvm-ok> [args…]");
                // expect(disallowed_methods): a busy-box multicall helper relays its status as the
                // process exit code; nothing is owned to unwind here (usage error before any work).
                #[expect(
                    clippy::disallowed_methods,
                    reason = "multicall helper relays status as its exit code; nothing owned to unwind (usage error)"
                )]
                std::process::exit(2);
            }
        }
    };

    let code = match cmd.as_str() {
        "ip" => run_ip(rest),
        "curl" => run_curl(rest),
        "kvm-ok" => run_kvm_ok(),
        other => {
            eprintln!("vmcell-guest-tools: unknown command {other}");
            2
        }
    };
    // expect(disallowed_methods): the multicall helper's whole contract is to relay the selected
    // sub-tool's exit code as its own process status; there is no owned host state to unwind.
    #[expect(
        clippy::disallowed_methods,
        reason = "multicall helper relays the sub-tool's exit code as its status; no owned host state to unwind"
    )]
    std::process::exit(code);
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn is_known(name: &str) -> bool {
    matches!(name, "ip" | "curl" | "kvm-ok")
}

// ---------------------------------------------------------------------------
// `kvm-ok` — nested-virt probe (cpu-checker stand-in).
// ---------------------------------------------------------------------------

fn run_kvm_ok() -> i32 {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => {
            println!("INFO: /dev/kvm exists");
            println!("KVM acceleration can be used");
            0
        }
        Err(e) => {
            println!("INFO: /dev/kvm does not exist: {e}");
            println!("KVM acceleration can NOT be used");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// `ip` — read-only network state from sysfs/procfs (exit 0 diagnostic).
// ---------------------------------------------------------------------------

fn run_ip(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("addr") {
        "link" | "l" => run_ip_link(args.get(1..).unwrap_or(&[])),
        "addr" | "a" | "address" => {
            // Read form (`ip addr`) lists interfaces; write forms
            // (`add`/`flush`/`del`/…) are accepted as no-ops so the orchestrator's
            // post-restore `ip addr …` chain succeeds without clobbering the
            // boot-time (kernel `ip=`) address. In-guest IP rotation on restore is
            // intentionally not performed (see module docs / the zero-netlink
            // invariant); only MAC rotation is applied, via `ip link set`.
            if !is_write_verb(args.get(1)) {
                print_links();
            }
            0
        }
        "route" | "r" => {
            if !is_write_verb(args.get(1)) {
                print_routes();
            }
            0
        }
        "neigh" | "n" | "neighbour" | "neighbor" => {
            print_neigh();
            0
        }
        _ => {
            print_links();
            0
        }
    }
}

fn is_write_verb(verb: Option<&String>) -> bool {
    matches!(
        verb.map(String::as_str),
        Some("add" | "del" | "delete" | "change" | "replace" | "flush")
    )
}

/// Handles `ip link …`. Implements `set <dev> address <mac>` (and `up`/`down`)
/// for real via interface ioctls — the orchestrator's post-restore MAC rotation
/// depends on it. Any other `ip link` form lists interfaces.
fn run_ip_link(args: &[String]) -> i32 {
    if args.first().map(String::as_str) != Some("set") {
        print_links();
        return 0;
    }

    let mut dev: Option<String> = None;
    let mut mac: Option<String> = None;
    let mut up: Option<bool> = None;
    let mut it = args.get(1..).unwrap_or(&[]).iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "dev" => dev = it.next().cloned(),
            "address" | "addr" => mac = it.next().cloned(),
            "up" => up = Some(true),
            "down" => up = Some(false),
            other => {
                // `ip link set eth0 …` — first bare token is the device.
                if dev.is_none() {
                    dev = Some(other.to_string());
                }
            }
        }
    }

    let Some(dev) = dev else {
        eprintln!("ip link set: no device specified");
        return 1;
    };
    if let Some(mac) = mac
        && let Err(e) = set_mac(&dev, &mac)
    {
        eprintln!("ip link set {dev} address {mac}: {e}");
        return 1;
    }
    if let Some(up) = up {
        let fd = match open_inet_socket() {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("ip link set {dev}: {e}");
                return 1;
            }
        };
        let res = set_link_up(fd, &dev, up);
        // SAFETY: `fd` is a valid socket fd we opened above and no longer use.
        unsafe {
            libc::close(fd);
        }
        if let Err(e) = res {
            eprintln!("ip link set {dev}: {e}");
            return 1;
        }
    }
    0
}

fn print_links() {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        println!("(no /sys/class/net)");
        return;
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for (idx, name) in names.iter().enumerate() {
        let mac = read_trim(&format!("/sys/class/net/{name}/address")).unwrap_or_default();
        let state = read_trim(&format!("/sys/class/net/{name}/operstate")).unwrap_or_default();
        let mtu = read_trim(&format!("/sys/class/net/{name}/mtu")).unwrap_or_default();
        println!("{}: {}: state {} mtu {}", idx + 1, name, state, mtu);
        if !mac.is_empty() {
            println!("    link/ether {mac}");
        }
        // The IPv4 address the kernel configured (via IP-PNP `ip=` for eth0) — read over the
        // SIOCGIFADDR ioctl, so `ip a` reports the actual `inet` line like real `ip`. Absent on
        // an unconfigured interface (e.g. a down link), in which case no line is printed.
        if let Some((addr, prefix)) = read_ipv4(name) {
            println!(
                "    inet {}.{}.{}.{}/{}",
                addr[0], addr[1], addr[2], addr[3], prefix
            );
        }
    }
}

fn print_routes() {
    match std::fs::read_to_string("/proc/net/route") {
        Ok(contents) => print!("{contents}"),
        Err(e) => println!("(no /proc/net/route: {e})"),
    }
}

fn print_neigh() {
    match std::fs::read_to_string("/proc/net/arp") {
        Ok(contents) => print!("{contents}"),
        Err(e) => println!("(no /proc/net/arp: {e})"),
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

// --- interface ioctls for `ip link set … address` (restore MAC rotation) ---

const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const SIOCGIFADDR: libc::c_ulong = 0x8915;
const SIOCGIFNETMASK: libc::c_ulong = 0x891b;
const SIOCSIFHWADDR: libc::c_ulong = 0x8924;
const ARPHRD_ETHER: u16 = 1;
const IFF_UP: i16 = 0x1;

/// A `struct ifreq` (40 bytes on 64-bit Linux): the 16-byte interface name
/// followed by the `ifr_ifru` union, which we access as raw bytes for the two
/// shapes we use — `ifr_flags` (a `short` at offset 0) and `ifr_hwaddr` (a
/// `sockaddr`: `sa_family` then `sa_data`, at offset 0).
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    ifru: [u8; 24],
}

impl IfReq {
    fn new(dev: &str) -> Result<Self, String> {
        let bytes = dev.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(format!("device name too long: {dev}"));
        }
        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        for (slot, &b) in name.iter_mut().zip(bytes) {
            *slot = b as libc::c_char;
        }
        Ok(IfReq {
            name,
            ifru: [0u8; 24],
        })
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.trim().split(':') {
        // `get_mut` folds in the ">6 octets → reject" guard without indexing (denied crate-wide).
        let slot = out.get_mut(n)?;
        *slot = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    if n == 6 { Some(out) } else { None }
}

fn open_inet_socket() -> Result<libc::c_int, String> {
    // SAFETY: a constant, valid `socket(2)` call; the returned fd is checked.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    Ok(fd)
}

fn set_link_up(fd: libc::c_int, dev: &str, up: bool) -> Result<(), String> {
    let mut ifr = IfReq::new(dev)?;
    // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCGIFFLAGS reads the
    // name and writes `ifr_flags` into the union bytes.
    if unsafe { libc::ioctl(fd, SIOCGIFFLAGS, &mut ifr) } < 0 {
        return Err(format!("SIOCGIFFLAGS: {}", std::io::Error::last_os_error()));
    }
    let mut flags = i16::from_ne_bytes([ifr.ifru[0], ifr.ifru[1]]);
    if up {
        flags |= IFF_UP;
    } else {
        flags &= !IFF_UP;
    }
    ifr.ifru[0..2].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: same struct, SIOCSIFFLAGS consumes name + ifr_flags.
    if unsafe { libc::ioctl(fd, SIOCSIFFLAGS, &mut ifr) } < 0 {
        return Err(format!("SIOCSIFFLAGS: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Builds the `ifreq` submitted to `SIOCSIFHWADDR` for `dev`+`mac`: the interface
/// name, `ARPHRD_ETHER` in the sockaddr family, then the six MAC bytes. Split out
/// so the byte layout is unit-testable without a live interface (M-GUEST-3),
/// mirroring the guest-agent `netif::hwaddr_ifreq` helper.
fn hwaddr_ifreq(dev: &str, mac: [u8; 6]) -> Result<IfReq, String> {
    let mut ifr = IfReq::new(dev)?;
    // ifr_hwaddr: sa_family (host-order u16) then sa_data; first 6 data bytes are
    // the MAC.
    ifr.ifru[0..2].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
    ifr.ifru[2..8].copy_from_slice(&mac);
    Ok(ifr)
}

/// Extracts the four IPv4 address bytes from an `ifreq` union filled by `SIOCGIFADDR`/
/// `SIOCGIFNETMASK`: the union holds a `sockaddr_in` (`sin_family` u16 @0, `sin_port` u16 @2,
/// `sin_addr` @4). Split out so the offset is unit-testable without a live interface (M-GUEST-3,
/// mirroring `hwaddr_ifreq`).
fn ipv4_from_ifru(ifru: &[u8; 24]) -> [u8; 4] {
    [ifru[4], ifru[5], ifru[6], ifru[7]]
}

/// The CIDR prefix length of a contiguous IPv4 netmask (e.g. `255.255.255.252` → `30`).
fn netmask_to_prefix(mask: [u8; 4]) -> u8 {
    u32::from_be_bytes(mask).count_ones() as u8
}

/// Reads an interface's IPv4 address (`SIOCGIFADDR`) and netmask prefix (`SIOCGIFNETMASK`) via
/// ioctls on an `AF_INET` socket — the same dependency-free path the MAC ioctls use (no netlink).
/// Returns `None` when the interface has no IPv4 address (e.g. `lo` before configuration, or a
/// down link), which the `SIOCGIFADDR` ioctl reports as `EADDRNOTAVAIL`.
fn read_ipv4(dev: &str) -> Option<([u8; 4], u8)> {
    let fd = open_inet_socket().ok()?;
    let res = (|| {
        let mut ifr = IfReq::new(dev).ok()?;
        // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCGIFADDR reads the name and
        // writes the `ifr_addr` sockaddr into the union bytes.
        if unsafe { libc::ioctl(fd, SIOCGIFADDR, &mut ifr) } < 0 {
            return None;
        }
        let addr = ipv4_from_ifru(&ifr.ifru);
        let mut mask_ifr = IfReq::new(dev).ok()?;
        // SAFETY: same struct shape; SIOCGIFNETMASK writes `ifr_netmask` (a sockaddr).
        let prefix = if unsafe { libc::ioctl(fd, SIOCGIFNETMASK, &mut mask_ifr) } < 0 {
            32
        } else {
            netmask_to_prefix(ipv4_from_ifru(&mask_ifr.ifru))
        };
        Some((addr, prefix))
    })();
    // SAFETY: `fd` is the socket we opened and no longer use.
    unsafe {
        libc::close(fd);
    }
    res
}

fn set_mac(dev: &str, mac_str: &str) -> Result<(), String> {
    let mac = parse_mac(mac_str).ok_or_else(|| format!("invalid MAC: {mac_str}"))?;
    let fd = open_inet_socket()?;
    let res = (|| -> Result<(), String> {
        // Some drivers require the link down to change its hardware address;
        // bring it down (best effort) then back up around the set.
        let _ = set_link_up(fd, dev, false);

        let mut ifr = hwaddr_ifreq(dev, mac)?;
        // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCSIFHWADDR reads
        // the name and the `ifr_hwaddr` sockaddr from the union bytes.
        if unsafe { libc::ioctl(fd, SIOCSIFHWADDR, &mut ifr) } < 0 {
            let err = format!("SIOCSIFHWADDR: {}", std::io::Error::last_os_error());
            // M-GUEST-2: the link was brought down above; re-raise it even on this
            // failure path so a failed (best-effort) MAC change never strands the
            // restored guest's eth0 administratively DOWN with no one to re-raise
            // it. The re-up is itself best-effort — the original error is returned.
            let _ = set_link_up(fd, dev, true);
            return Err(err);
        }

        set_link_up(fd, dev, true)?;
        Ok(())
    })();
    // SAFETY: `fd` is the socket we opened and no longer use.
    unsafe {
        libc::close(fd);
    }
    res
}

// ---------------------------------------------------------------------------
// `curl` — real HTTP(S) client (curl-flag subset).
// ---------------------------------------------------------------------------

fn run_curl(args: &[String]) -> i32 {
    let mut insecure = false;
    let mut verbose = false;
    let mut max_time: Option<u64> = None;
    let mut resolve: Vec<(String, u16, std::net::IpAddr)> = Vec::new();
    let mut url: Option<String> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-k" | "--insecure" => insecure = true,
            "-v" | "--verbose" => verbose = true,
            "--max-time" => {
                if let Some(n) = it.next() {
                    max_time = n.parse().ok();
                }
            }
            "--resolve" => {
                if let Some(spec) = it.next()
                    && let Some(parsed) = parse_resolve(spec)
                {
                    resolve.push(parsed);
                }
            }
            // Flags we accept but don't need to act on for the tested behaviour.
            "-4" | "-6" | "-s" | "-S" | "--silent" | "-L" | "--location" | "--compressed" => {}
            // Flags that consume a value we ignore.
            "-H" | "--header" | "-o" | "--output" | "-A" | "--user-agent" | "-X" | "--request" => {
                let _ = it.next();
            }
            other if other.starts_with('-') => {
                // Unknown flag: ignore rather than fail the whole command.
            }
            other => url = Some(other.to_string()),
        }
    }

    let Some(url) = url else {
        eprintln!("curl: no URL specified");
        return 2;
    };

    let mut builder = reqwest::blocking::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(secs) = max_time {
        builder = builder.timeout(Duration::from_secs(secs));
    }
    for (host, port, ip) in &resolve {
        builder = builder.resolve(host, std::net::SocketAddr::new(*ip, *port));
    }

    // Configure the proxy explicitly from the curl-style env vars, rather than
    // relying on reqwest's auto-detection (which proved unreliable here). The
    // egress tests steer traffic at the transparent proxy via http_proxy /
    // https_proxy.
    //
    // Order matters: reqwest applies proxies first-match, and `Proxy::all` matches
    // *every* scheme, so the scheme-specific `http`/`https` proxies MUST be added
    // BEFORE the `all_proxy` catch-all — otherwise `all_proxy` shadows a
    // scheme-specific `https_proxy` for HTTPS URLs, the opposite of curl's
    // precedence (scheme-specific wins over the catch-all) (PRIV-7).
    if let Some(p) = proxy_from_env(&["http_proxy", "HTTP_PROXY"]) {
        match reqwest::Proxy::http(&p) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => eprintln!("curl: bad http_proxy {p}: {e}"),
        }
    }
    if let Some(p) = proxy_from_env(&["https_proxy", "HTTPS_PROXY"]) {
        match reqwest::Proxy::https(&p) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => eprintln!("curl: bad https_proxy {p}: {e}"),
        }
    }
    if let Some(p) = proxy_from_env(&["all_proxy", "ALL_PROXY"]) {
        match reqwest::Proxy::all(&p) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => eprintln!("curl: bad all_proxy {p}: {e}"),
        }
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("curl: failed to build client: {e}");
            return 2;
        }
    };

    match client.get(&url).send() {
        Ok(resp) => {
            if verbose {
                let status = resp.status();
                eprintln!(
                    "< HTTP/1.1 {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("")
                );
                for (name, value) in resp.headers() {
                    eprintln!("< {}: {}", name, value.to_str().unwrap_or(""));
                }
                eprintln!("<");
            }
            let body = resp.bytes().unwrap_or_default();
            let _ = std::io::stdout().write_all(&body);
            let _ = std::io::stdout().flush();
            // curl exits 0 once a response is received (no `--fail`), regardless
            // of HTTP status — the blocked-egress test asserts on the 403 in the
            // verbose stderr, not the exit code.
            0
        }
        Err(e) => {
            // A blocked HTTPS domain makes the proxy refuse the CONNECT with a
            // non-2xx (403 + body); reqwest collapses that to an opaque "tunnel
            // error" without exposing the response. Real curl prints the proxy's
            // refusal (status to stderr, body to stdout), which the egress test
            // asserts on, so on an https-via-proxy failure we redo the CONNECT
            // manually to surface it.
            if url.starts_with("https://")
                && let Some(proxy) =
                    proxy_from_env(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"])
                && let Some((host, port)) = url_host_port(&url, 443)
                && probe_connect(&proxy, &host, port, max_time, verbose)
            {
                return 0;
            }
            // Print the full error source chain — reqwest's top-level Display is
            // just "error sending request for url (...)".
            eprint!("curl: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                eprint!(": {s}");
                src = s.source();
            }
            eprintln!();
            // Transport failure → curl-style non-zero (CURLE_COULDNT_CONNECT).
            7
        }
    }
}

/// Parses `scheme://host[:port][/...]` into `(host, port)`.
fn url_host_port(url: &str, default_port: u16) -> Option<(String, u16)> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let mut parts = authority.rsplitn(2, ':');
    let first = parts.next()?;
    match parts.next() {
        Some(host) => Some((host.to_string(), first.parse().unwrap_or(default_port))),
        None => Some((first.to_string(), default_port)),
    }
}

/// Extracts the numeric status from an HTTP `CONNECT` response's status line
/// (`HTTP/1.1 <code> <reason>`). Returns `None` if the line is missing or the
/// code is not a parseable number.
fn parse_status_code(head: &str) -> Option<u16> {
    head.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// Whether a proxy `CONNECT` response head indicates the tunnel was established —
/// true only for a 2xx status. A non-2xx (e.g. a blocked domain's 403) is a real
/// failure — real curl exits non-zero — so this returns false and the caller must
/// not collapse it to exit 0 (H-GUEST-1).
fn connect_succeeded(head: &str) -> bool {
    parse_status_code(head).is_some_and(|code| (200..300).contains(&code))
}

/// Performs a raw HTTP `CONNECT` to `proxy` for `host:port`, prints the proxy's
/// response — status line + headers to stderr (verbose), body to stdout — the way
/// curl does, and returns whether the tunnel was **established** (a 2xx status).
///
/// A non-2xx refusal (e.g. a blocked domain's 403) is still printed so the egress
/// test can observe it, but returns `false` so the caller surfaces the failure as
/// a non-zero exit instead of collapsing every https-via-proxy failure to exit 0
/// (H-GUEST-1: the banned any-error-to-success probe).
fn probe_connect(proxy: &str, host: &str, port: u16, max_time: Option<u64>, verbose: bool) -> bool {
    use std::io::{Read, Write};
    let Some((phost, pport)) = url_host_port(proxy, 8080) else {
        return false;
    };
    let Ok(mut stream) = std::net::TcpStream::connect((phost.as_str(), pport)) else {
        return false;
    };
    let timeout = Duration::from_secs(max_time.unwrap_or(10));
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                if buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        return false;
    }
    // Split status line + headers from the body on the first blank line.
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body): (&[u8], &[u8]) = match split {
        Some(i) => (
            buf.get(..i).unwrap_or_default(),
            buf.get(i + 4..).unwrap_or_default(),
        ),
        None => (&buf[..], &[]),
    };
    let head_str = String::from_utf8_lossy(head);
    if verbose {
        for line in head_str.lines() {
            eprintln!("< {line}");
        }
        eprintln!("<");
    } else if let Some(status_line) = head_str.lines().next() {
        // Ensure the status (e.g. "403") is observable even without -v.
        eprintln!("< {status_line}");
    }
    let _ = std::io::stdout().write_all(body);
    let _ = std::io::stdout().flush();
    // Success is a 2xx tunnel establishment ONLY. Returning `true` for any
    // response (the pre-fix behaviour) let a blocked domain's 403, a TLS failure,
    // or a mid-body RST collapse to exit 0 (H-GUEST-1).
    connect_succeeded(&head_str)
}

fn proxy_from_env(keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Ok(v) = std::env::var(k)
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    None
}

fn parse_resolve(spec: &str) -> Option<(String, u16, std::net::IpAddr)> {
    // Format: HOST:PORT:ADDR (tests use IPv4, so PORT and ADDR are unambiguous).
    let mut parts = spec.splitn(3, ':');
    let host = parts.next()?.to_string();
    let port: u16 = parts.next()?.parse().ok()?;
    let ip: std::net::IpAddr = parts.next()?.parse().ok()?;
    Some((host, port, ip))
}

#[cfg(test)]
mod tests {
    //! M-GUEST-3: guest-tools had ZERO unit tests, leaving the pure parsers and
    //! the duplicated `ifreq` layout unguarded. Each test below reddens on a
    //! specific inverse (see comments).
    use super::*;

    #[test]
    fn parse_mac_accepts_six_hex_octets() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        // Leading/trailing whitespace is trimmed before splitting.
        assert_eq!(
            parse_mac("  02:00:00:00:00:05\n"),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x05])
        );
    }

    #[test]
    fn parse_mac_rejects_malformed() {
        // Too few octets (5) — must NOT accept a short MAC.
        assert_eq!(parse_mac("ff:01:02:03:04"), None);
        // Too many octets (7) — the `n >= 6` guard must reject it.
        assert_eq!(parse_mac("00:01:02:03:04:05:06"), None);
        // A single token is not a MAC (RED on a bounds-free parser that accepts it).
        assert_eq!(parse_mac("ff"), None);
        // Non-hex octet.
        assert_eq!(parse_mac("zz:00:00:00:00:00"), None);
        assert_eq!(parse_mac(""), None);
    }

    #[test]
    fn url_host_port_parses_scheme_host_port_path() {
        assert_eq!(
            url_host_port("http://host:123/path", 443),
            Some(("host".to_string(), 123))
        );
        // No explicit port → the default.
        assert_eq!(
            url_host_port("https://example.com/x", 443),
            Some(("example.com".to_string(), 443))
        );
        // No scheme, explicit port.
        assert_eq!(
            url_host_port("proxy.local:8080", 8080),
            Some(("proxy.local".to_string(), 8080))
        );
        // A non-numeric port falls back to the default rather than failing.
        assert_eq!(
            url_host_port("http://host:notaport/p", 443),
            Some(("host".to_string(), 443))
        );
    }

    #[test]
    fn parse_resolve_parses_host_port_addr() {
        let (host, port, ip) = parse_resolve("blocked.com:443:1.2.3.4").expect("valid resolve");
        assert_eq!(host, "blocked.com");
        assert_eq!(port, 443);
        assert_eq!(ip, "1.2.3.4".parse::<std::net::IpAddr>().unwrap());
        // Malformed: missing the address field, or a bad port/addr.
        assert!(parse_resolve("blocked.com:443").is_none());
        assert!(parse_resolve("blocked.com:notaport:1.2.3.4").is_none());
        assert!(parse_resolve("blocked.com:443:not.an.ip").is_none());
    }

    #[test]
    fn is_write_verb_matches_only_write_verbs() {
        for v in ["add", "del", "delete", "change", "replace", "flush"] {
            let owned = v.to_string();
            assert!(is_write_verb(Some(&owned)), "{v} must be a write verb");
        }
        for v in ["up", "down", "show", "list"] {
            let owned = v.to_string();
            assert!(!is_write_verb(Some(&owned)), "{v} must NOT be a write verb");
        }
        assert!(!is_write_verb(None), "a read form (no verb) is not a write");
    }

    // M-GUEST-3 / L-GUEST-8 class: pin the guest-tools `IfReq` to the kernel's
    // `struct ifreq` size. C-GUEST-1 showed an unpinned ifreq is an OOB-copy
    // vector, and guest-tools duplicated the layout with no guard. Shrinking
    // `ifru` (e.g. to [u8; 20]) would pass the offset asserts below but reddens
    // here.
    #[test]
    fn ifreq_matches_kernel_struct_size() {
        assert_eq!(
            std::mem::size_of::<IfReq>(),
            std::mem::size_of::<libc::ifreq>(),
            "IfReq must match the kernel `struct ifreq` size (40 bytes on x86-64)"
        );
    }

    // Pins the `ifr_hwaddr` byte layout SIOCSIFHWADDR consumes (parallel to
    // netif.rs). RED on a wrong hwaddr offset (MAC at 0) or a byte-swapped family.
    #[test]
    fn hwaddr_ifreq_layout() {
        let mac = [0x02, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let ifr = hwaddr_ifreq("eth0", mac).expect("ifreq");
        assert_eq!(
            &ifr.name[..4],
            &[
                b'e' as libc::c_char,
                b't' as libc::c_char,
                b'h' as libc::c_char,
                b'0' as libc::c_char
            ],
            "ifr_name must be the device"
        );
        assert_eq!(ifr.name[4], 0, "ifr_name must be NUL-terminated");
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
        assert_eq!(
            &ifr.ifru[2..8],
            &mac,
            "MAC must be at the hwaddr data offset"
        );
    }

    // Pins the `sockaddr_in` offset SIOCGIFADDR/SIOCGIFNETMASK fill: sin_family (2) + sin_port
    // (2) then the 4 address bytes at offset 4. A wrong offset would read port/family bytes as
    // the address and print a garbage `inet` line. Inverse: shift the slice and this reddens.
    #[test]
    fn ipv4_from_ifru_reads_sin_addr_at_offset_4() {
        let mut ifru = [0u8; 24];
        ifru[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes()); // sin_family
        ifru[2..4].copy_from_slice(&0u16.to_ne_bytes()); // sin_port
        ifru[4..8].copy_from_slice(&[10, 200, 23, 2]); // sin_addr
        assert_eq!(ipv4_from_ifru(&ifru), [10, 200, 23, 2]);
    }

    // A contiguous netmask maps to its CIDR prefix (the /30 the design's per-VM subnet uses).
    #[test]
    fn netmask_to_prefix_counts_bits() {
        assert_eq!(netmask_to_prefix([255, 255, 255, 252]), 30);
        assert_eq!(netmask_to_prefix([255, 255, 255, 255]), 32);
        assert_eq!(netmask_to_prefix([255, 255, 255, 0]), 24);
        assert_eq!(netmask_to_prefix([0, 0, 0, 0]), 0);
    }

    // A device name too long for IFNAMSIZ is rejected (not silently truncated),
    // matching netif.rs's IfReq::new.
    #[test]
    fn ifreq_new_rejects_overlong_device() {
        let long = "x".repeat(libc::IFNAMSIZ);
        assert!(IfReq::new(&long).is_err());
        assert!(IfReq::new("eth0").is_ok());
    }

    // H-GUEST-1: probe_connect treats ONLY a 2xx CONNECT as success. RED on the
    // pre-fix "any response ⇒ true": a blocked domain's 403 would be classified as
    // success and collapse to exit 0.
    #[test]
    fn connect_succeeded_only_on_2xx() {
        assert!(connect_succeeded("HTTP/1.1 200 Connection established\r\n"));
        assert!(connect_succeeded("HTTP/1.1 204 No Content"));
        assert!(!connect_succeeded(
            "HTTP/1.1 403 Forbidden\r\nProxy-Agent: x\r\n"
        ));
        assert!(!connect_succeeded("HTTP/1.1 502 Bad Gateway"));
        assert!(!connect_succeeded("garbage-with-no-code"));
        assert!(!connect_succeeded(""));
    }

    #[test]
    fn parse_status_code_extracts_the_numeric_code() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/1.1 403 Forbidden"), Some(403));
        assert_eq!(
            parse_status_code("HTTP/1.0 500 Internal Server Error"),
            Some(500)
        );
        assert_eq!(parse_status_code("no-code-here"), None);
        assert_eq!(parse_status_code(""), None);
    }
}
