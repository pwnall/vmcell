//! Egress networking proxy.
//!
//! This module provides a MITM HTTP/HTTPS proxy that allows the guest virtual
//! machine to access external networks while giving the host visibility,
//! control over egress traffic, and test double capabilities.

/// Module for generating and managing the MITM Root CA
pub mod tls;
/// Module for test doubles and request interception
pub mod doubles;

use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::net::TcpListener;
use hudsucker::builder::ProxyBuilder;
use crate::proxy::doubles::{ProxyHandler, TestDouble};
use std::sync::Arc;

/// Configuration for an egress proxy.
pub struct ProxyConfig {
    /// The port to listen on.
    pub port: u16,
    /// The network namespace name to enter before listening.
    pub netns: Option<String>,
    /// Test doubles to inject responses.
    pub doubles: Arc<Vec<TestDouble>>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 0,
            netns: None,
            doubles: Arc::new(vec![]),
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
    pub async fn start(cfg: ProxyConfig) -> Result<Self> {
        let (tx, rx) = tokio::sync::oneshot::channel::<std::result::Result<u16, String>>();
        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();

        // We run the proxy in its own thread to apply `setns` if needed
        let thread = std::thread::spawn(move || {
            #[allow(clippy::collapsible_if)]
            if let Some(ref netns) = cfg.netns {
                if let Ok(file) = std::fs::File::open(format!("/var/run/netns/{}", netns)) {
                    // SAFETY: Thread isolation for network namespace
                    let ret = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
                    if ret != 0 {
                        let _ = tx.send(Err(format!("Failed to setns: {}", std::io::Error::last_os_error())));
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

                let handler = ProxyHandler {
                    doubles: cfg.doubles.clone(),
                };
                // We only needed the listener to find a free port. 
                // Since hudsucker doesn't natively accept a pre-bound listener with easy access to its port,
                // we drop it and bind again on the known free port.
                
                // hudsucker builder currently does not take a bound listener directly in an easy way without `with_addr` logic overriding.
                // However, since `Proxy::start` takes a shutdown signal, we can drop our dummy listener and bind again.
                // Wait, if port is 0, we must find out which port hudsucker bound to.
                // But hudsucker's `Proxy::start` doesn't return the bound port easily.
                // Actually, hudsucker uses hyper under the hood. Let's just pass `addr` with the exact `port` we discovered.
                drop(listener);
                let proxy_addr = SocketAddr::from(([0, 0, 0, 0], port));
                let shutdown_signal = async {
                    let _ = kill_rx.await;
                };

                let proxy = ProxyBuilder::new()
                    .with_addr(proxy_addr)
                    .with_ca(authority)
                    .with_rustls_client(rustls::crypto::aws_lc_rs::default_provider().into())
                    .with_http_handler(handler)
                    .with_graceful_shutdown(shutdown_signal)
                    .build()
                    .map_err(|e| format!("Proxy builder failed: {:?}", e));

                let _ = tx.send(Ok(port));

                if let Ok(proxy) = proxy {
                    if let Err(e) = proxy.start().await {
                        tracing::error!("Proxy failed: {:?}", e);
                    }
                } else if let Err(e) = proxy {
                    tracing::error!("Failed to build proxy: {:?}", e);
                }
            });
        });

        let port_res = rx.await.map_err(|e| Error::Other(e.to_string()))?;
        let port = port_res.map_err(|e| Error::Other(e.to_string()))?;
        Ok(Self { 
            port,
            kill_tx: Some(kill_tx),
            thread: Some(thread),
        })
    }
}
