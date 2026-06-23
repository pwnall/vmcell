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

pub struct ProxyConfig {
    pub port: u16,
    pub netns: Option<String>,
}

pub struct EgressProxy {
    pub port: u16,
}

impl EgressProxy {
    pub async fn start(cfg: ProxyConfig) -> Result<Self> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        std::thread::spawn(move || {
            #[allow(clippy::collapsible_if)]
            if let Some(ref netns) = cfg.netns {
                if let Ok(file) = std::fs::File::open(format!("/var/run/netns/{}", netns)) {
                    unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
                }
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
                let listener = TcpListener::bind(addr).await.unwrap();
                let port = listener.local_addr().unwrap().port();

                let _ = tx.send(port);

                loop {
                    if let Ok((stream, _)) = listener.accept().await {
                        let io = TokioIo::new(stream);
                        tokio::spawn(async move {
                            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
                                .build(HttpConnector::new());
                            let svc = service_fn(move |mut req: Request<Incoming>| {
                                let client = client.clone();
                                async move {
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
                                    client.request(req).await
                                }
                            });

                            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await
                            {
                                eprintln!("Error serving connection: {:?}", err);
                            }
                        });
                    }
                }
            });
        });

        let port = rx.await.map_err(|e| Error::Other(e.to_string()))?;
        Ok(Self { port })
    }
}
