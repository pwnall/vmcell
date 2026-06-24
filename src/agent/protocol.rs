//! Protocol definitions for guest-host communication.
//!
//! This module defines the messages exchanged between the host VMM and the
//! guest agent over the vsock connection.

use serde::{Deserialize, Serialize};

/// A message exchanged between the host and the guest agent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// Hello handshake from the guest.
    Hello,
    /// Agent is ready to accept commands.
    Ready,
    /// Request to execute a command.
    Exec(ExecRequest),
    /// Standard output data from a command.
    Stdout(Vec<u8>),
    /// Standard error data from a command.
    Stderr(Vec<u8>),
    /// Exit code of a completed command.
    Exit(i32),
    /// Request to place a file at a destination path.
    PutFile { 
        /// Destination path in the guest.
        dst: String, 
        /// File contents.
        bytes: Vec<u8> 
    },
    /// Ping message to check agent liveness.
    Ping,
}

/// A request to execute a command inside the guest VM.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecRequest {
    /// The command line arguments (e.g., `["ls", "-l"]`).
    pub argv: Vec<String>,
    /// Environment variables to set.
    pub env: Vec<(String, String)>,
    /// Optional working directory.
    pub cwd: Option<String>,
}

impl ExecRequest {
    /// Creates a new `ExecRequest` with the given arguments.
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            env: vec![],
            cwd: None,
        }
    }

    /// Sets the environment variables.
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// Sets the working directory.
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

/// The result of executing a command inside the guest VM.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecOutcome {
    /// The exit code of the process.
    pub code: i32,
    /// Standard output of the process.
    pub stdout: Vec<u8>,
    /// Standard error of the process.
    pub stderr: Vec<u8>,
}

impl Default for ExecOutcome {
    fn default() -> Self {
        Self {
            code: -1,
            stdout: vec![],
            stderr: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialization() {
        let msg = Message::Exec(ExecRequest {
            argv: vec!["ls".to_string(), "-l".to_string()],
            env: vec![("PATH".to_string(), "/bin".to_string())],
            cwd: Some("/root".to_string()),
        });

        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();

        match decoded {
            Message::Exec(req) => {
                assert_eq!(req.argv, vec!["ls", "-l"]);
                assert_eq!(req.cwd, Some("/root".to_string()));
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_serialization_all_variants() {
        let msgs = vec![
            Message::Hello,
            Message::Ready,
            Message::Stdout(vec![1, 2, 3]),
            Message::Stderr(vec![4, 5, 6]),
            Message::Exit(42),
            Message::PutFile {
                dst: "/tmp/test".to_string(),
                bytes: vec![7, 8, 9],
            },
            Message::Ping,
        ];

        for msg in msgs {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_framing_multiple_messages() {
        let msg1 = Message::Hello;
        let msg2 = Message::Ready;
        
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&postcard::to_stdvec(&msg1).unwrap());
        bytes.extend_from_slice(&postcard::to_stdvec(&msg2).unwrap());
        
        let (decoded1, rest) = postcard::take_from_bytes::<Message>(&bytes).unwrap();
        assert_eq!(decoded1, Message::Hello);
        let (decoded2, rest2) = postcard::take_from_bytes::<Message>(rest).unwrap();
        assert_eq!(decoded2, Message::Ready);
        assert!(rest2.is_empty());
    }
}
