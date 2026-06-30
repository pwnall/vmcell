//! Egress networking proxy.
//!
//! This module provides a MITM HTTP/HTTPS proxy that allows the guest virtual
//! machine to access external networks while giving the host visibility,
//! control over egress traffic, and test double capabilities.

/// Module for test doubles and request interception
pub mod doubles;
/// Module for generating and managing the MITM Root CA
pub mod tls;

use crate::error::{Error, Result};
use crate::proxy::doubles::{ProxyHandler, TestDouble};
use hudsucker::builder::ProxyBuilder;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::net::TcpListener;

/// The logged requests type.
pub type RequestLog = Vec<String>;

/// Configuration for an egress proxy.
pub struct ProxyConfig {
    /// The port to listen on.
    pub port: u16,
    /// The network namespace name to enter before listening.
    pub netns: Option<String>,
    /// Test doubles to inject responses.
    pub doubles: Arc<std::sync::RwLock<Vec<TestDouble>>>,
    /// Domains to block.
    pub blocked_domains: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 0,
            netns: None,
            doubles: Arc::new(std::sync::RwLock::new(vec![])),
            blocked_domains: vec![],
        }
    }
}

/// A running egress proxy instance.
#[derive(Debug)]
pub struct EgressProxy {
    /// The port the proxy is listening on.
    pub port: u16,
    kill_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    ca_cert_pem: String,
    requests: Arc<std::sync::Mutex<RequestLog>>,
    doubles: Arc<std::sync::RwLock<Vec<TestDouble>>>,
    record_path: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        tracing::info!("EgressProxy dropping!");
        if let Some(tx) = self.kill_tx.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl EgressProxy {
    /// Starts the egress proxy with the specified configuration.
    ///
    /// # Errors
    /// Returns an error if binding to the port or initializing the CA fails.
    ///
    /// # Examples
    /// ```rust
    /// # use vmcell::proxy::{EgressProxy, ProxyConfig};
    /// # async fn run() {
    /// let proxy = EgressProxy::start(ProxyConfig::default()).await.unwrap();
    /// println!("Proxy listening on port {}", proxy.port);
    /// # }
    /// ```
    pub async fn start(cfg: ProxyConfig) -> Result<Self> {
        Self::start_impl(cfg, false).await
    }

    /// Starts the egress proxy on a **transparent** (`IP_TRANSPARENT`) listener,
    /// the front-end a privileged nftables `TPROXY` ruleset redirects into
    /// (§6.3).
    ///
    /// Identical to [`start`](Self::start) except the listener is created with
    /// `IP_TRANSPARENT` set before `bind` (see [`bind_transparent_listener`]),
    /// so the kernel delivers `TPROXY`-redirected connections and preserves the
    /// original destination. Recover that destination from an accepted
    /// connection with [`original_destination`].
    ///
    /// Note: `hudsucker` is an *explicit*-proxy MITM (it expects
    /// `CONNECT`/absolute-form), so a true transparent intake additionally needs
    /// the orchestrator to reconstruct absolute-form requests from the recovered
    /// destination (or to steer the guest to the proxy explicitly). This method
    /// supplies the transparent socket; the steering is the orchestrator's job.
    ///
    /// # Errors
    /// Returns an error if binding the transparent listener (which needs
    /// `CAP_NET_ADMIN`) or initializing the CA fails.
    pub async fn start_transparent(cfg: ProxyConfig) -> Result<Self> {
        Self::start_impl(cfg, true).await
    }

    /// Internal worker shared by [`start`](Self::start) and
    /// [`start_transparent`](Self::start_transparent). When `transparent`, the
    /// listener is bound with `IP_TRANSPARENT` via [`bind_transparent_listener`].
    async fn start_impl(cfg: ProxyConfig, transparent: bool) -> Result<Self> {
        let (tx, rx) =
            tokio::sync::oneshot::channel::<std::result::Result<(u16, String), String>>();
        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();

        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record_path = Arc::new(std::sync::Mutex::new(None));
        let requests_clone = requests.clone();
        let record_path_clone = record_path.clone();
        let doubles = cfg.doubles.clone();

        // We run the proxy in its own thread to apply `setns` if needed
        let thread = std::thread::spawn(move || {
            #[allow(clippy::collapsible_if)]
            if let Some(ref netns) = cfg.netns {
                match std::fs::File::open(format!("/var/run/netns/{}", netns)) {
                    Ok(file) => {
                        // SAFETY: Thread isolation for network namespace
                        let ret = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
                        if ret != 0 {
                            let _ = tx.send(Err(format!(
                                "Failed to setns: {}",
                                std::io::Error::last_os_error()
                            )));
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("Failed to open netns file: {}", e)));
                        return;
                    }
                }
            }

            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(format!("Failed to build tokio runtime: {}", e)));
                    return;
                }
            };

            rt.block_on(async move {
                // Unprivileged mode (no netns, not transparent) only ever receives
                // connections the smoltcp NAT dials at 127.0.0.1, so bind
                // loopback instead of exposing the proxy on all interfaces. The
                // privileged explicit-proxy and transparent front-ends must
                // accept connections arriving on the per-VM tap inside the
                // netns, so they bind the wildcard address.
                let addr =
                    SocketAddr::from((proxy_bind_ip(transparent, cfg.netns.is_some()), cfg.port));
                let listener = if transparent {
                    // Privileged TPROXY front-end: the listener must carry
                    // IP_TRANSPARENT (set before bind) for the kernel to deliver
                    // redirected connections and preserve the original
                    // destination (recoverable via `original_destination`).
                    match bind_transparent_listener(addr) {
                        Ok(std_listener) => {
                            if let Err(e) = std_listener.set_nonblocking(true) {
                                let _ = tx.send(Err(format!(
                                    "Failed to set transparent listener non-blocking: {}",
                                    e
                                )));
                                return;
                            }
                            match TcpListener::from_std(std_listener) {
                                Ok(l) => l,
                                Err(e) => {
                                    let _ = tx.send(Err(format!(
                                        "Failed to adopt transparent listener: {}",
                                        e
                                    )));
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(format!(
                                "Failed to bind transparent listener on {}: {:?}",
                                addr, e
                            )));
                            return;
                        }
                    }
                } else {
                    match TcpListener::bind(addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            let _ = tx.send(Err(format!("Failed to bind to {}: {}", addr, e)));
                            return;
                        }
                    }
                };

                let port = match listener.local_addr() {
                    Ok(addr) => addr.port(),
                    Err(e) => {
                        let _ = tx.send(Err(format!("Failed to get local address: {}", e)));
                        return;
                    }
                };

                // Initialize the CA manager
                let ca_manager = match tls::CaManager::new() {
                    Ok(cm) => cm,
                    Err(e) => {
                        let _ = tx.send(Err(format!("Failed to initialize CA: {:?}", e)));
                        return;
                    }
                };

                let authority = match ca_manager.authority() {
                    Ok(auth) => auth,
                    Err(e) => {
                        let _ = tx.send(Err(format!("Failed to build CA authority: {:?}", e)));
                        return;
                    }
                };
                let ca_cert_pem = ca_manager.ca_cert_pem().to_string();

                let handler = ProxyHandler {
                    doubles: cfg.doubles.clone(),
                    blocked_domains: cfg.blocked_domains.clone(),
                    requests: requests_clone,
                    record_path: record_path_clone,
                };
                // Use `with_listener` directly instead of dropping and binding again.
                // hudsucker takes ownership of the listener and uses it.
                let shutdown_signal = async {
                    let _ = kill_rx.await;
                };

                let proxy = match ProxyBuilder::new()
                    .with_listener(listener)
                    .with_ca(authority)
                    .with_rustls_client(rustls::crypto::aws_lc_rs::default_provider())
                    .with_http_handler(handler)
                    .with_graceful_shutdown(shutdown_signal)
                    .build()
                {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(format!("Proxy builder failed: {:?}", e)));
                        return;
                    }
                };

                let _ = tx.send(Ok((port, ca_cert_pem)));

                if let Err(e) = proxy.start().await {
                    tracing::error!("Proxy failed: {:?}", e);
                }
            });
        });

        let port_res = match rx.await {
            Ok(res) => res,
            Err(e) => {
                let _ = thread.join();
                return Err(Error::Proxy(e.to_string()));
            }
        };
        let (port, ca_cert_pem) = match port_res {
            Ok(res) => res,
            Err(e) => {
                let _ = thread.join();
                return Err(Error::Proxy(e));
            }
        };
        Ok(Self {
            port,
            kill_tx: Some(kill_tx),
            thread: Some(thread),
            ca_cert_pem,
            requests,
            doubles,
            record_path,
        })
    }

    /// Returns the CA certificate PEM.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Returns the observed requests, including `403 BLOCKED <host>` entries
    /// for denied egress.
    ///
    /// Recovers from a poisoned lock rather than panicking.
    pub fn requests(&self) -> RequestLog {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Installs a new test double dynamically.
    pub fn install_double(
        &self,
        matcher: crate::proxy::doubles::Matcher,
        responder: crate::proxy::doubles::Responder,
    ) {
        let mut doubles = self.doubles.write().unwrap_or_else(|e| e.into_inner());
        doubles.push(TestDouble { matcher, responder });
    }

    /// Sets the cassette file path for recording.
    pub fn record_to(&self, cassette: &std::path::Path) {
        let mut rp = self.record_path.lock().unwrap_or_else(|e| e.into_inner());
        *rp = Some(cassette.to_path_buf());
    }
}

/// Chooses the listener bind IP for the egress proxy.
///
/// Unprivileged mode (no netns, not transparent) only ever receives connections the
/// smoltcp NAT dials at `127.0.0.1:<port>`, so it binds loopback rather than
/// exposing the proxy on all interfaces. The privileged explicit-proxy
/// front-end and the transparent (`IP_TRANSPARENT`) front-end both accept
/// connections arriving on the per-VM tap inside the netns, so they bind the
/// wildcard address.
fn proxy_bind_ip(transparent: bool, has_netns: bool) -> [u8; 4] {
    if transparent || has_netns {
        [0, 0, 0, 0]
    } else {
        [127, 0, 0, 1]
    }
}

/// Sets an integer-valued socket option, mapping a failure to [`Error::Proxy`].
fn setsockopt_int(
    fd: std::os::unix::io::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
    label: &str,
) -> Result<()> {
    // SAFETY: `value` outlives the call and is exactly `c_int`-sized; `fd` is a
    // live socket descriptor owned by the caller. The kernel copies the value.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::Proxy(format!(
            "setsockopt({}): {}",
            label,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Binds a raw IPv4 socket fd to `addr`, mapping a failure to [`Error::Proxy`].
fn bind_ipv4(fd: std::os::unix::io::RawFd, addr: &std::net::SocketAddrV4) -> Result<()> {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `sin` is a fully-initialized `sockaddr_in`; the length passed
    // matches its size, and `fd` is a live socket.
    let rc = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(sin).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::Proxy(format!(
            "transparent bind({}): {}",
            addr,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Binds a TCP listener with `IP_TRANSPARENT` set *before* `bind` — the socket
/// option a privileged nftables `TPROXY` egress front-end requires.
///
/// A privileged egress ruleset (`tproxy to :<port> meta mark set 1 accept`,
/// §6.3) redirects the guest's packets to this local socket while preserving
/// the *original* destination addressing. The kernel only delivers such
/// redirected packets to a listening socket that carries `IP_TRANSPARENT`, and
/// the non-local bind a TPROXY front-end performs is itself rejected without it.
/// Recover the original destination of an accepted connection with
/// [`original_destination`].
///
/// Note: the MITM stack (`hudsucker`) is an *explicit*-proxy intake (it expects
/// `CONNECT`/absolute-form). This function supplies the `IP_TRANSPARENT` socket
/// and original-destination recovery the orchestrator needs to build the
/// transparent front-end on top; the wiring (and steering the guest, or
/// reconstructing absolute-form requests) is the orchestrator's responsibility.
///
/// Setting `IP_TRANSPARENT` requires `CAP_NET_ADMIN`; without it this returns an
/// error rather than silently degrading to a non-transparent bind.
///
/// # Errors
/// Returns [`Error::Proxy`] if the socket cannot be created, if `IP_TRANSPARENT`
/// / `SO_REUSEADDR` cannot be set (e.g. missing `CAP_NET_ADMIN`), if the bind or
/// listen fails, or if `addr` is not IPv4.
pub fn bind_transparent_listener(addr: SocketAddr) -> Result<std::net::TcpListener> {
    use std::os::unix::io::FromRawFd;

    let SocketAddr::V4(addr_v4) = addr else {
        return Err(Error::Proxy(
            "transparent listener requires an IPv4 address".to_string(),
        ));
    };

    // SAFETY: `socket(2)` with constant, valid arguments; the returned fd is
    // checked and then immediately owned by a `TcpListener` (closed on drop).
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Error::Proxy(format!(
            "transparent socket(): {}",
            std::io::Error::last_os_error()
        )));
    }
    // Own the fd now so every early-return path closes it on drop.
    // SAFETY: `fd` is a fresh, exclusively-owned, valid socket descriptor.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };

    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1, "SO_REUSEADDR")?;
    setsockopt_int(
        fd,
        libc::IPPROTO_IP,
        libc::IP_TRANSPARENT,
        1,
        "IP_TRANSPARENT",
    )?;
    bind_ipv4(fd, &addr_v4)?;

    // SAFETY: `listen(2)` on a bound socket fd with a constant backlog.
    let rc = unsafe { libc::listen(fd, 1024) };
    if rc != 0 {
        return Err(Error::Proxy(format!(
            "transparent listen(): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(listener)
}

/// Recovers the original destination of a connection redirected by an nftables
/// `TPROXY` rule.
///
/// With `TPROXY` the kernel preserves the original destination *in the accepted
/// socket's local address* (unlike `REDIRECT`, which needs
/// `getsockopt(SO_ORIGINAL_DST)`): the listener was bound non-locally with
/// `IP_TRANSPARENT` (see [`bind_transparent_listener`]), so the accepted
/// connection's local address is the address the guest dialed. This returns
/// that local address — the guest's intended destination, which is the value
/// the egress filter logs and matches on (§6.3).
///
/// # Errors
/// Returns [`Error::Proxy`] if the stream's local address cannot be read.
pub fn original_destination(stream: &tokio::net::TcpStream) -> Result<SocketAddr> {
    stream
        .local_addr()
        .map_err(|e| Error::Proxy(format!("original destination (local_addr): {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    fn getsockopt_int(
        fd: std::os::unix::io::RawFd,
        level: libc::c_int,
        name: libc::c_int,
    ) -> libc::c_int {
        let mut value: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value`/`len` are valid for the duration of the call; `fd` is
        // a live socket descriptor.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                std::ptr::addr_of_mut!(value).cast(),
                &mut len,
            )
        };
        assert_eq!(
            rc,
            0,
            "getsockopt failed: {}",
            std::io::Error::last_os_error()
        );
        value
    }

    // LOW: unprivileged binds loopback (the NAT only dials 127.0.0.1); the
    // privileged explicit-proxy and transparent front-ends bind wildcard. Buggy
    // impl guarded: the old unconditional `[0,0,0,0]` makes the first assert red.
    #[test]
    fn proxy_bind_ip_is_loopback_only_for_unprivileged() {
        assert_eq!(proxy_bind_ip(false, false), [127, 0, 0, 1]);
        assert_eq!(proxy_bind_ip(false, true), [0, 0, 0, 0]);
        assert_eq!(proxy_bind_ip(true, false), [0, 0, 0, 0]);
        assert_eq!(proxy_bind_ip(true, true), [0, 0, 0, 0]);
    }

    // H-PROXY-1: the transparent listener must actually carry IP_TRANSPARENT.
    // Red on the inverse (a plain `TcpListener::bind` with no IP_TRANSPARENT) in
    // BOTH environments:
    //  - unprivileged: setting IP_TRANSPARENT needs CAP_NET_ADMIN, so the
    //    function errors with an IP_TRANSPARENT-named error; a non-transparent
    //    impl would instead succeed (plain bind), failing the `Err` arm.
    //  - privileged: the function succeeds and getsockopt(IP_TRANSPARENT) == 1;
    //    a non-transparent impl returns a listener with the option == 0.
    #[test]
    fn bind_transparent_listener_actually_sets_ip_transparent() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        // Control: a plain bind on an ephemeral loopback port is possible, so a
        // failure below is specifically from IP_TRANSPARENT, not the address.
        assert!(
            std::net::TcpListener::bind(addr).is_ok(),
            "control: plain loopback bind should succeed"
        );

        match bind_transparent_listener(addr) {
            Ok(listener) => {
                let v =
                    getsockopt_int(listener.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TRANSPARENT);
                assert_eq!(
                    v, 1,
                    "transparent listener returned without IP_TRANSPARENT set"
                );
            }
            Err(Error::Proxy(msg)) => {
                assert!(
                    msg.contains("IP_TRANSPARENT"),
                    "expected an IP_TRANSPARENT failure (missing CAP_NET_ADMIN), got: {msg}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    // H-PROXY-1: original_destination reads the accepted socket's *local*
    // address, which is where TPROXY carries the guest's intended destination.
    // Buggy impl guarded: returning `peer_addr()` (the client's ephemeral port)
    // differs from `local_addr()`, turning the equality assert red.
    #[test]
    fn original_destination_returns_local_addr() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listen");
            let server_addr = listener.local_addr().expect("server addr");
            let _client = tokio::net::TcpStream::connect(server_addr)
                .await
                .expect("connect");
            let (accepted, _) = listener.accept().await.expect("accept");

            let got = original_destination(&accepted).expect("orig dst");
            assert_eq!(got, accepted.local_addr().expect("local"));
            // For this ordinary (non-redirected) loopback pair, the accepted
            // socket's local addr equals the server addr it was accepted on.
            assert_eq!(got, server_addr);
            // Red on the inverse (peer_addr): the peer is the client's ephemeral
            // port, which differs from the server addr.
            assert_ne!(got, accepted.peer_addr().expect("peer"));
        });
    }
}
