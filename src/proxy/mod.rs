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
    /// # use imp_testing::proxy::{EgressProxy, ProxyConfig};
    /// # async fn run() {
    /// let proxy = EgressProxy::start(ProxyConfig::default()).await.unwrap();
    /// println!("Proxy listening on port {}", proxy.port);
    /// # }
    /// ```
    pub async fn start(cfg: ProxyConfig) -> Result<Self> {
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
                let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
                let listener = match TcpListener::bind(addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = tx.send(Err(format!("Failed to bind to {}: {}", addr, e)));
                        return;
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

    /// Returns the observed requests.
    ///
    /// # Panics
    /// Panics if the requests lock is poisoned.
    pub fn requests(&self) -> RequestLog {
        self.requests
            .lock()
            .expect("requests lock poisoned")
            .clone()
    }

    /// Installs a new test double dynamically.
    pub fn install_double(
        &self,
        matcher: crate::proxy::doubles::Matcher,
        responder: crate::proxy::doubles::Responder,
    ) {
        if let Ok(mut doubles) = self.doubles.write() {
            doubles.push(TestDouble { matcher, responder });
        }
    }

    /// Sets the cassette file path for recording.
    pub fn record_to(&self, cassette: &std::path::Path) {
        if let Ok(mut rp) = self.record_path.lock() {
            *rp = Some(cassette.to_path_buf());
        }
    }
}
