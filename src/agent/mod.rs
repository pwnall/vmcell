//! Guest agent communication and client implementation.
//!
//! This module provides the client code required to communicate with the guest agent
//! running inside the virtual machine.

/// Protocol definition for communication with the guest agent.
pub mod protocol;

use crate::error::{Error, Result};
pub use protocol::{ExecOutcome, ExecRequest};
use protocol::Message;

#[cfg(feature = "host-common")]
use futures::{SinkExt, StreamExt};
#[cfg(feature = "host-common")]
use std::path::Path;
#[cfg(feature = "host-common")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    pub async fn connect(vsock_path: &Path, port: u32) -> Result<Self> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut stream = UnixStream::connect(vsock_path)
                .await
                .map_err(|e| Error::Vmm(format!("Failed to connect to vsock UDS: {}", e)))?;

            let connect_msg = format!("CONNECT {}\n", port);
            stream.write_all(connect_msg.as_bytes()).await?;

            let mut resp = String::new();
            loop {
                let mut byte = [0; 1];
                let n = stream.read(&mut byte).await?;
                if n == 0 {
                    return Err(Error::Vmm("Vsock connection closed before OK".into()));
                }
                resp.push(byte[0] as char);
                if byte[0] == b'\n' {
                    break;
                }
            }

            if !resp.starts_with("OK ") {
                return Err(Error::Vmm(format!("Vsock connection failed: {}", resp)));
            }

            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            // Wait for Ready
            if let Some(res) = framed.next().await {
                let bytes: bytes::BytesMut = res.map_err(Error::Io)?;
                let msg: Message = postcard::from_bytes(&bytes)
                    .map_err(|e| Error::Other(format!("Failed to parse Ready message: {}", e)))?;
                match msg {
                    Message::Ready => {}
                    _ => return Err(Error::Other("Expected Ready message".into())),
                }
            } else {
                return Err(Error::Other("Connection closed waiting for Ready".into()));
            }

            Ok(Self { stream: framed })
        }).await.map_err(|_| Error::Timeout("Agent connection timed out".into()))?
    }

    /// Reconnects to the guest agent.
    pub async fn reconnect(&mut self, vsock_path: &Path, port: u32) -> Result<()> {
        let new_client = Self::connect(vsock_path, port).await?;
        self.stream = new_client.stream;
        Ok(())
    }

    /// Executes a command inside the guest VM and waits for the result.
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent or the outcome cannot be received.
    pub async fn exec(&mut self, cmd: ExecRequest) -> Result<ExecOutcome> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let msg = Message::Exec(cmd);
            let bytes = postcard::to_stdvec(&msg).map_err(|e| Error::Other(e.to_string()))?;

            self.stream
                .send(bytes::Bytes::from(bytes))
                .await
                .map_err(Error::Io)?;

            let mut outcome = ExecOutcome::default();

            while let Some(res) = self.stream.next().await {
                let bytes: bytes::BytesMut = res.map_err(Error::Io)?;
                let msg: Message =
                    postcard::from_bytes(&bytes).map_err(|e| Error::Other(e.to_string()))?;

                match msg {
                    Message::Stdout(data) => {
                        outcome.stdout.extend(data);
                    }
                    Message::Stderr(data) => {
                        outcome.stderr.extend(data);
                    }
                    Message::Exit(code) => {
                        outcome.code = code;
                        break;
                    }
                    _ => {}
                }
            }

            Ok(outcome)
        }).await.map_err(|_| Error::Timeout("Agent exec timed out".into()))?
    }

    /// Uploads a file to the guest VM.
    ///
    /// # Errors
    /// Returns an error if the file transfer fails.
    pub async fn put_file(&mut self, dst: &str, bytes: &[u8]) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let msg = Message::PutFile { dst: dst.to_string(), bytes: bytes.to_vec() };
            let msg_bytes = postcard::to_stdvec(&msg).map_err(|e| Error::Other(e.to_string()))?;
            self.stream.send(bytes::Bytes::from(msg_bytes)).await.map_err(Error::Io)?;
            
            // Wait for ack
            if let Some(res) = self.stream.next().await {
                let res_bytes: bytes::BytesMut = res.map_err(Error::Io)?;
                let resp_msg: Message = postcard::from_bytes(&res_bytes)
                    .map_err(|e| Error::Other(e.to_string()))?;
                match resp_msg {
                    Message::Exit(0) => Ok(()),
                    Message::Exit(c) => Err(Error::Agent(format!("put_file failed with code {}", c))),
                    _ => Err(Error::Agent("unexpected response to put_file".into())),
                }
            } else {
                Err(Error::Agent("connection closed during put_file".into()))
            }
        }).await.map_err(|_| Error::Timeout("put_file timed out".into()))?
    }
}
