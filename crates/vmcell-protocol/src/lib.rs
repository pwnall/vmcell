//! Framed postcard wire protocol shared by the vmcell host and the guest agent.
//!
//! This is the *only* code the host (`vmcell::agent::AgentClient`) and the guest
//! PID-1 agent (`vmcell-guest-agent`) share — extracting it into its own crate is
//! what lets the guest agent be a standalone, host-stack-free workspace member
//! (v15 §10.1). It defines the messages exchanged over the vsock connection and
//! the framing bound both ends must agree on.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// Maximum length, in bytes, of a single framed control-plane message.
///
/// Both ends of the vsock protocol must agree on this bound: the host
/// `AgentClient` configures its `LengthDelimitedCodec` with it (its 8 MiB
/// default would otherwise reject a frame the guest is willing to send) and the
/// guest agent's hand-rolled framing rejects anything larger. Keeping the two in
/// one constant prevents the asymmetric-cap class where one side silently drops
/// a frame the other accepts.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Default per-exec timeout applied when an [`ExecRequest`] does not set one.
///
/// The host applies this as its own wait bound and propagates it into the
/// request before sending, so the guest always installs a kill thread. Without
/// this, a `None` timeout would let a runaway guest child outlive the host's
/// abandoned wait and leak.
pub const DEFAULT_EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A message exchanged between the host and the guest agent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
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
        bytes: Vec<u8>,
    },
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
    /// Per-exec timeout. If None, a sane default is used.
    pub timeout: Option<std::time::Duration>,
}

impl ExecRequest {
    /// Creates a new `ExecRequest` with the given arguments.
    #[must_use]
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            env: vec![],
            cwd: None,
            timeout: None,
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

    /// Sets the timeout for the request.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
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

impl ExecOutcome {
    /// Creates an outcome with the given exit `code` and captured streams.
    ///
    /// A constructor is provided because [`ExecOutcome`] is `#[non_exhaustive]`:
    /// callers in other crates (the orchestrator, test doubles) cannot use a
    /// struct literal, so this keeps their call sites stable as fields grow.
    #[must_use]
    pub fn new(code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            code,
            stdout,
            stderr,
        }
    }
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
            timeout: None,
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
            Message::Ready,
            Message::Stdout(vec![1, 2, 3]),
            Message::Stderr(vec![4, 5, 6]),
            Message::Exit(42),
            Message::PutFile {
                dst: "/tmp/test".to_string(),
                bytes: vec![7, 8, 9],
            },
        ];

        for msg in msgs {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_framing_multiple_messages() {
        let msg1 = Message::Ready;
        let msg2 = Message::Exit(1);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&postcard::to_stdvec(&msg1).unwrap());
        bytes.extend_from_slice(&postcard::to_stdvec(&msg2).unwrap());

        let (decoded1, rest) = postcard::take_from_bytes::<Message>(&bytes).unwrap();
        assert_eq!(decoded1, Message::Ready);
        let (decoded2, rest2) = postcard::take_from_bytes::<Message>(rest).unwrap();
        assert_eq!(decoded2, Message::Exit(1));
        assert!(rest2.is_empty());
    }

    use proptest::prelude::*;

    fn arb_message() -> impl Strategy<Value = Message> {
        prop_oneof![
            Just(Message::Ready),
            any::<Vec<u8>>().prop_map(Message::Stdout),
            any::<Vec<u8>>().prop_map(Message::Stderr),
            any::<i32>().prop_map(Message::Exit),
            (any::<String>(), any::<Vec<u8>>())
                .prop_map(|(dst, bytes)| Message::PutFile { dst, bytes }),
            (
                any::<Vec<String>>(),
                any::<Vec<(String, String)>>(),
                any::<Option<String>>(),
                any::<Option<std::time::Duration>>()
            )
                .prop_map(|(argv, env, cwd, timeout)| {
                    Message::Exec(ExecRequest {
                        argv,
                        env,
                        cwd,
                        timeout,
                    })
                }),
        ]
    }

    proptest! {
        #[test]
        fn test_message_roundtrip(msg in arb_message()) {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(msg, decoded);
        }
    }
}
