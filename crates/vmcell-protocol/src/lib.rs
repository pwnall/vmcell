//! Framed postcard wire protocol shared by the vmcell host and the guest agent.
//!
//! This is the *only* code the host (`vmcell::agent::AgentClient`) and the guest
//! PID-1 agent (`vmcell-guest-agent`) share — extracting it into its own crate is
//! what lets the guest agent be a standalone, host-stack-free workspace member
//! (v15 §10.1). It defines the messages exchanged over the vsock connection and
//! the framing bound both ends must agree on.
#![forbid(unsafe_code)]
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        // B10: production guest/network-derived values narrow with `try_from`, never `as` (wire
        // crate). Test vectors may still build byte patterns with `as` — the repo's lenient-in-tests
        // idiom (clippy.toml allow-*-in-tests, AGENTS.md; see docs/implementation-notes.md).
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

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

/// IPv4 reconfiguration the guest applies to `eth0` during a post-restore resync
/// (H-VMM-1 — "rotate everything").
///
/// A snapshot is a *zygote*: one suspended VM is resumed into many concurrent
/// children, each of which must have a **distinct** network identity (its own
/// netns/tap/`/30`/MAC/IP) so they don't collide on the host. The restore path
/// therefore rotates the vmid — but the guest resumes with the *frozen* `ip=`
/// address of the original vmid, which no longer matches its rotated host-side
/// tap/`/30` wiring. This message re-points the guest's `eth0` address and default
/// route to the rotated identity, exactly as the `mac` field re-points the
/// hardware address. Octets are carried verbatim (endianness-free on the wire).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Reconfig {
    /// The guest's new `eth0` address (e.g. `10.200.<m>.2`).
    pub addr: [u8; 4],
    /// The subnet prefix length (`30` for the point-to-point `/30`).
    pub prefix_len: u8,
    /// The new default-route gateway — the host side of the `/30`
    /// (e.g. `10.200.<m>.1`).
    pub gateway: [u8; 4],
}

/// A message exchanged between the host and the guest agent.
///
/// **Append-only.** `postcard` encodes each variant by its zero-based
/// declaration index, so the variant order is part of the wire protocol: new
/// variants must be *appended* and existing ones never reordered or removed, or
/// the host and guest would disagree on the discriminant. `#[non_exhaustive]`
/// keeps out-of-crate matches from silently breaking when a variant is appended.
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
    /// Host→guest one-shot post-restore resync request (design 44 §5).
    ///
    /// A snapshot resumes at the frozen instant, so the host drives one native
    /// in-agent resync — replacing the three post-restore subprocess execs
    /// (`date` / `head -c 32 /dev/hwrng` / `ip link set`). It carries the host
    /// wall-clock instant the guest must set `CLOCK_REALTIME` to and an optional
    /// new `eth0` MAC to install; one request elicits exactly one
    /// [`Message::ResyncAck`].
    Resync {
        /// Whole seconds since the Unix epoch for the guest `CLOCK_REALTIME` set.
        unix_secs: u64,
        /// Sub-second nanoseconds component of the target realtime clock.
        unix_nanos: u32,
        /// Optional new `eth0` hardware address to install via `SIOCSIFHWADDR`;
        /// `None` skips the MAC rotation.
        mac: Option<[u8; 6]>,
        /// Optional new `eth0` IPv4 address + default route to install (H-VMM-1);
        /// `None` skips the IP rotation. The restore/zygote path rotates the vmid
        /// so the guest's frozen `ip=` address no longer matches its rotated
        /// host-side tap/`/30` wiring — this re-points it, exactly as `mac`
        /// re-points the hardware address. Appended after `mac` (per-variant
        /// field order is part of the postcard wire encoding).
        ipv4: Option<Ipv4Reconfig>,
    },
    /// Guest→host acknowledgement of a [`Message::Resync`], reporting each step's
    /// outcome (design 44 §5).
    ///
    /// The clock set is mandatory: `clock_error` is `Some(msg)` iff it failed
    /// (the host treats that as a hard, retryable failure and does not clear its
    /// restored flag). The CSPRNG reseed and MAC rotation are best-effort, with
    /// `reseed_applied` / `mac_applied` reporting whether each took effect.
    ResyncAck {
        /// `Some(err)` iff the mandatory `CLOCK_REALTIME` set failed; `None` on
        /// success.
        clock_error: Option<String>,
        /// Whether the best-effort `/dev/hwrng`→`/dev/urandom` reseed applied.
        reseed_applied: bool,
        /// Whether the best-effort `eth0` MAC rotation applied.
        mac_applied: bool,
        /// Whether the best-effort `eth0` IPv4 address + default-route rotation
        /// applied (H-VMM-1). Appended after `mac_applied`.
        ip_applied: bool,
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
    #[must_use]
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets the timeout for the request.
    #[must_use]
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
    /// Creates an outcome with code `-1` — a sentinel for "no exit code was
    /// observed yet", deliberately outside the `0..=255` range any real process
    /// exit status occupies, so a defaulted outcome that is never overwritten
    /// (e.g. a stream that ended before an `Exit` frame) is distinguishable from
    /// a genuine exit.
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
            // Resync/ResyncAck round-trip: a dropped/reordered field or a
            // secs↔nanos swap reddens the `assert_eq!(msg, decoded)` below.
            Message::Resync {
                unix_secs: 1_700_000_000,
                unix_nanos: 123_456_789,
                mac: Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x05]),
                ipv4: Some(Ipv4Reconfig {
                    addr: [10, 200, 5, 2],
                    prefix_len: 30,
                    gateway: [10, 200, 5, 1],
                }),
            },
            Message::Resync {
                unix_secs: 0,
                unix_nanos: 0,
                mac: None,
                ipv4: None,
            },
            Message::ResyncAck {
                clock_error: Some("clock_settime: EPERM".to_string()),
                reseed_applied: true,
                mac_applied: false,
                ip_applied: false,
            },
            Message::ResyncAck {
                clock_error: None,
                reseed_applied: false,
                mac_applied: true,
                ip_applied: true,
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
            (
                any::<u64>(),
                any::<u32>(),
                any::<Option<[u8; 6]>>(),
                prop::option::of((any::<[u8; 4]>(), any::<u8>(), any::<[u8; 4]>()).prop_map(
                    |(addr, prefix_len, gateway)| Ipv4Reconfig {
                        addr,
                        prefix_len,
                        gateway,
                    },
                ),),
            )
                .prop_map(|(unix_secs, unix_nanos, mac, ipv4)| Message::Resync {
                    unix_secs,
                    unix_nanos,
                    mac,
                    ipv4,
                }),
            (
                any::<Option<String>>(),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(|(clock_error, reseed_applied, mac_applied, ip_applied)| {
                    Message::ResyncAck {
                        clock_error,
                        reseed_applied,
                        mac_applied,
                        ip_applied,
                    }
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
