//! Egress networking proxy.
//!
//! This module provides a simple HTTP proxy that allows the guest virtual
//! machine to access external networks while giving the host visibility and
//! control over egress traffic.

use crate::error::{Error, Result};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, body::Incoming};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::net::TcpListener;

/// Configuration for an egress proxy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyConfig {
    /// The port to listen on.
    pub port: u16,
    /// The network namespace name to enter before listening.
    pub netns: Option<String>,
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
        println!("EgressProxy dropping!");
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
    /// Returns an error if the proxy fails to start.
    pub async fn start(cfg: ProxyConfig) -> Result<Self> {
        let (tx, rx) = tokio::sync::oneshot::channel::<std::result::Result<u16, String>>();
        let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<()>();

        let thread = std::thread::spawn(move || {
            #[allow(clippy::collapsible_if)]
            if let Some(ref netns) = cfg.netns {
                if let Ok(file) = std::fs::File::open(format!("/var/run/netns/{}", netns)) {
                    // SAFETY: Entering a network namespace requires CAP_SYS_ADMIN. It is safe here because this thread is newly spawned and dedicated entirely to the proxy in this namespace, so it won't affect other threads' networking.
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

                let _ = tx.send(Ok(port));

                loop {
                    tokio::select! {
                        accept_res = listener.accept() => {
                            if let Ok((stream, _)) = accept_res {
                                let io = TokioIo::new(stream);
                                tokio::spawn(async move {
                                    let client = Client::builder(hyper_util::rt::TokioExecutor::new())
                                        .build(HttpConnector::new());
                                    let svc = service_fn(move |mut req: Request<Incoming>| {
                                        let client = client.clone();
                                        async move {
                                            println!("Proxy received request for URI: {}", req.uri());
                                            #[allow(clippy::collapsible_if)]
                                            if req.uri().host().is_none() {
                                                if let Some(host) = req.headers().get("host") {
                                                    let host_str = host.to_str().unwrap_or("");
                                                    let uri = format!(
                                                        "http://{}{}",
                                                        host_str,
                                                        req.uri()
                                                            .path_and_query()
                                                            .map(|x| x.as_str())
                                                            .unwrap_or("/")
                                                    );
                                                    if let Ok(parsed) = uri.parse() {
                                                        *req.uri_mut() = parsed;
                                                    }
                                                }
                                            }
                                            println!("Proxy forwarding request to: {}", req.uri());
                                            let res = client.request(req).await;
                                            println!("Proxy response: {:?}", res.as_ref().map(|r| r.status()));
                                            res
                                        }
                                    });

                                    if let Err(err) = http1::Builder::new().serve_connection(io, svc).await
                                    {
                                        eprintln!("Error serving connection: {:?}", err);
                                    }
                                });
                            }
                        }
                        _ = &mut kill_rx => {
                            break;
                        }
                    }
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
