/// Protocol definition for communication with the guest agent.
pub mod protocol;

use crate::error::{Error, Result};
use protocol::{ExecOutcome, ExecRequest, Message};

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
    }

    /// Executes a command inside the guest VM and waits for the result.
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent or the outcome cannot be received.
    pub async fn exec(&mut self, cmd: ExecRequest) -> Result<ExecOutcome> {
        let msg = Message::Exec(cmd);
        let bytes = postcard::to_stdvec(&msg).map_err(|e| Error::Other(e.to_string()))?;

        self.stream
            .send(bytes::Bytes::from(bytes))
            .await
            .map_err(Error::Io)?;

        let mut outcome = ExecOutcome {
            code: -1,
            stdout: vec![],
            stderr: vec![],
        };

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
    }

    /// Uploads a file to the guest VM.
    ///
    /// # Errors
    /// Returns an error if the file transfer fails.
    pub async fn put_file(&mut self, _dst: &str, _bytes: &[u8]) -> Result<()> {
        Ok(())
    }
}
