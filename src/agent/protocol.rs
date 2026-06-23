use serde::{Deserialize, Serialize};

/// A message exchanged between the host and the guest agent.
#[derive(Serialize, Deserialize, Debug)]
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
#[derive(Serialize, Deserialize, Debug)]
pub struct ExecRequest {
    /// The command line arguments (e.g., `["ls", "-l"]`).
    pub argv: Vec<String>,
    /// Environment variables to set.
    pub env: Vec<(String, String)>,
    /// Optional working directory.
    pub cwd: Option<String>,
}

/// The result of executing a command inside the guest VM.
#[derive(Debug)]
pub struct ExecOutcome {
    /// The exit code of the process.
    pub code: i32,
    /// Standard output of the process.
    pub stdout: Vec<u8>,
    /// Standard error of the process.
    pub stderr: Vec<u8>,
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
}
