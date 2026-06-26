//! Guest agent communication and client implementation.
//!
//! This module provides the client code required to communicate with the guest agent
//! running inside the virtual machine.

/// Protocol definition for communication with the guest agent.
pub mod protocol;

use crate::error::{Error, Result};
use protocol::Message;
pub use protocol::{ExecOutcome, ExecRequest};

#[cfg(feature = "host-common")]
use futures::{SinkExt, StreamExt};
#[cfg(feature = "host-common")]
use std::path::Path;
#[cfg(feature = "host-common")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "host-common")]
use tokio::net::UnixStream;
#[cfg(feature = "host-common")]
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[cfg(feature = "host-common")]
/// A client for communicating with the guest agent over vsock.
#[derive(Debug)]
pub struct AgentClient {
    stream: Framed<UnixStream, LengthDelimitedCodec>,
}

#[cfg(feature = "host-common")]
impl AgentClient {
    /// Connects to the guest agent on the specified vsock path and port.
    ///
    /// # Errors
    /// Returns an error if the connection fails or the handshake is unsuccessful.
    ///
    /// # Examples
    /// ```rust
    /// # use imp_testing::agent::AgentClient;
    /// # use std::path::Path;
    /// # use std::time::Duration;
    /// # async fn run() {
    /// let serial = imp_testing::vmm::RealSerialLog { path: std::path::PathBuf::from("/dev/null") };
    /// let client = AgentClient::connect(Path::new("/tmp/vsock"), 5000, Duration::from_secs(10), &serial).await.unwrap();
    /// # }
    /// ```
    pub async fn connect(
        vsock_path: &Path,
        port: u32,
        timeout: std::time::Duration,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<Self> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut backoff = std::time::Duration::from_millis(50);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(Error::Timeout("Agent connection timed out".into()));
            }

            // Watch serial log for kernel panic
            if serial_log.contains_panic() {
                return Err(Error::Agent("Panic detected in serial log".into()));
            }

            let mut stream = match UnixStream::connect(vsock_path).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::trace!("Agent connect UnixStream::connect failed: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, std::time::Duration::from_millis(500));
                    continue;
                }
            };

            let connect_msg = format!("CONNECT {}\n", port);
            if let Err(e) = stream.write_all(connect_msg.as_bytes()).await {
                tracing::trace!("Agent connect write_all failed: {}", e);
                continue;
            }

            let mut resp = String::new();
            let mut ok = false;
            loop {
                let mut byte = [0; 1];
                use tokio::io::AsyncReadExt;
                if let Ok(Ok(1)) = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut byte),
                )
                .await
                {
                    resp.push(byte[0] as char);
                    if byte[0] == b'\n' {
                        ok = resp.starts_with("OK ");
                        break;
                    }
                } else {
                    break;
                }
            }
            if !ok {
                tracing::trace!("Agent connect failed! resp was: {:?}", resp);
                tokio::time::sleep(backoff).await;
                continue;
            }

            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let ready_result =
                tokio::time::timeout(std::time::Duration::from_secs(2), framed.next()).await;
            let ready = match ready_result {
                Ok(Some(Ok(bytes))) => bytes,
                other => {
                    tracing::trace!("Agent connect framed.next() returned: {:?}", other);
                    continue;
                }
            };

            let msg: Message = match postcard::from_bytes(&ready) {
                Ok(m) => m,
                Err(e) => {
                    tracing::trace!("Agent connect postcard error: {:?}, bytes: {:?}", e, ready);
                    continue;
                }
            };

            match msg {
                Message::Ready => return Ok(Self { stream: framed }),
                other => {
                    tracing::trace!("Agent connect received unexpected message: {:?}", other);
                    continue;
                }
            }
        }
    }

    /// Reconnects to the guest agent.
    ///
    /// # Errors
    /// Returns an error if the connection fails or times out.
    pub async fn reconnect(
        &mut self,
        vsock_path: &Path,
        port: u32,
        serial_log: &dyn crate::vmm::SerialLog,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let new_client = Self::connect(vsock_path, port, timeout, serial_log).await?;
        self.stream = new_client.stream;
        Ok(())
    }

    /// Executes a command inside the guest VM and waits for the result.
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent or the outcome cannot be received.
    pub async fn exec(&mut self, cmd: ExecRequest) -> Result<ExecOutcome> {
        let timeout = cmd.timeout.unwrap_or(std::time::Duration::from_secs(10));
        tokio::time::timeout(timeout, async {
            let msg = Message::Exec(cmd);
            let bytes = postcard::to_stdvec(&msg)?;

            self.stream
                .send(::bytes::Bytes::from(bytes))
                .await
                .map_err(Error::Io)?;

            let mut outcome = ExecOutcome::default();

            while let Some(res) = self.stream.next().await {
                let bytes: ::bytes::BytesMut = res.map_err(Error::Io)?;
                let msg: Message = postcard::from_bytes(&bytes)?;

                match msg {
                    Message::Stdout(data) => {
                        outcome.stdout.extend(data);
                    }
                    Message::Stderr(data) => {
                        outcome.stderr.extend(data);
                    }
                    Message::Exit(code) => {
                        outcome.code = code;
                        return Ok(outcome);
                    }
                    _ => {}
                }
            }

            // If stream ends without Exit, treat it as connection drop
            Err(Error::Agent("Connection dropped during exec".into()))
        })
        .await
        .map_err(|_| Error::Timeout("Agent exec timed out".into()))?
    }

    /// Uploads a file to the guest VM.
    ///
    /// # Errors
    /// Returns an error if the file transfer fails.
    pub async fn put_file(
        &mut self,
        dst: &str,
        bytes: &[u8],
        timeout: Option<std::time::Duration>,
    ) -> Result<()> {
        tokio::time::timeout(
            timeout.unwrap_or(std::time::Duration::from_secs(10)),
            async {
                let msg = Message::PutFile {
                    dst: dst.to_string(),
                    bytes: bytes.to_vec(),
                };
                let msg_bytes = postcard::to_stdvec(&msg)?;
                self.stream
                    .send(::bytes::Bytes::from(msg_bytes))
                    .await
                    .map_err(Error::Io)?;

                // Wait for ack
                if let Some(res) = self.stream.next().await {
                    let res_bytes: ::bytes::BytesMut = res.map_err(Error::Io)?;
                    let resp_msg: Message = postcard::from_bytes(&res_bytes)?;
                    match resp_msg {
                        Message::Exit(0) => Ok(()),
                        Message::Exit(c) => {
                            Err(Error::Agent(format!("put_file failed with code {}", c)))
                        }
                        _ => Err(Error::Agent("unexpected response to put_file".into())),
                    }
                } else {
                    Err(Error::Agent("connection closed during put_file".into()))
                }
            },
        )
        .await
        .map_err(|_| Error::Timeout("put_file timed out".into()))?
    }
}
