//! Snapshot-and-replay cassettes for the egress proxy (§6.4, The transparent egress proxy).
//!
//! §6.4's shipped `record_to` hook logs one **request line** per forwarded request — "it captures
//! neither the response (status/body) nor blocked requests, so snapshot-and-replay cassettes remain
//! §17 forward work". This module is that forward work: a cassette records the *interaction*
//! (request key → response status/headers/body) so a later run replays it with **no upstream at
//! all**, deterministically.
//!
//! # What an interaction is keyed by
//!
//! One law, [`interaction_key`], and it is deliberately narrow:
//!
//! `METHOD scheme://host[:port]/path[?canonical-query]`
//!
//! * **Headers are not part of the key, and are never persisted on the request side.** They are
//!   where `Authorization`, `Cookie`, `Date` and a fresh `User-Agent` live: matching on them makes
//!   replay brittle against a nonce, and *storing* them turns a cassette — a persisted artifact,
//!   like a serial log — into a credential file.
//! * **The request body is not part of the key either.** A body carries timestamps, nonces and (for
//!   a model API) the prompt; keying on it would make replay brittle and would persist the prompt.
//!   Repeated calls to the *same* key are disambiguated by ORDER instead: [`CassetteState`] serves a
//!   key's interactions in the order they were recorded (see [`CassetteState::take_hit`]).
//! * **The query is canonicalized**: parameters are sorted, and any parameter named in
//!   [`CassetteOptions::redacted_query_params`] is dropped from the key entirely — which is what
//!   makes a per-call `nonce=`/`ts=` non-brittle *and* keeps an `api_key=` out of the artifact. The
//!   defaults are [`REDACTED_QUERY_PARAMS`]; a caller adds its own volatile names with
//!   [`CassetteOptions::redacting`].
//! * The **path is preserved verbatim**. A secret embedded in a path (`/v1/keys/sk-…`) is *not*
//!   redacted — an honest boundary, stated here rather than implied, because no general rule can
//!   tell a secret path segment from a resource id.
//!
//! Response headers are filtered to the [`RECORDED_RESPONSE_HEADERS`] allowlist, so an upstream
//! `set-cookie` never reaches the artifact. The response **body is recorded verbatim** — it is the
//! thing replay exists to serve — so a cassette is exactly as sensitive as the upstream it was
//! recorded against.
//!
//! # A miss is loud
//!
//! In replay mode a request with no unconsumed recorded interaction is a typed
//! [`CassetteError::Miss`]: the guest gets a `504` naming the key, the miss is retained for
//! [`EgressProxy::cassette_misses`](crate::proxy::EgressProxy::cassette_misses), and the proxy
//! **never** falls through to the real upstream. Silently forwarding on a miss is what would make a
//! green replay run prove nothing.
//!
//! # The persisted format
//!
//! JSON Lines: one [`RecordedInteraction`] object per line, each carrying [`CASSETTE_FORMAT`], so
//! recording is a crash-safe append and a cassette stays greppable and diffable. It ships over
//! `serde_json` and **only** `serde_json` — [`RecordedInteraction::headers`] is a
//! `skip_serializing_if` presence attribute, which postcard corrupts (design Appendix A, reversal
//! 10), and `json_round_trip_survives_an_absent_presence_attribute` is the round-trip gate on the
//! codec it actually ships over.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The tag every recorded line carries, so a foreign or stale file is refused at load rather than
/// half-deserialized into a plausible-looking interaction.
pub const CASSETTE_FORMAT: &str = "vmcell-cassette-v1";

/// Upper bound on a recorded response body, in bytes.
///
/// A cassette is a persisted artifact and recording buffers the whole body before writing it, so
/// this bounds host memory *and* the artifact. Exceeding it is a loud
/// [`CassetteError::BodyTooLarge`] — never a silent truncation, because a truncated body replayed
/// later is a lie the next run cannot detect.
///
/// Unrelated to `vmcell_protocol::MAX_FRAME_BYTES`, which bounds the guest control-plane codec;
/// this bounds an HTTP response body arriving from an upstream the host chose to record.
pub const MAX_CASSETTE_BODY_BYTES: usize = 1 << 20;

/// Query-parameter names dropped from every key by default — the union of the two reasons a
/// parameter must not appear: it is a **secret** (a cassette is a persisted artifact) or it is
/// **volatile** (a nonce/timestamp that would make replay match nothing).
///
/// Compared case-insensitively. A caller adds its own with [`CassetteOptions::redacting`].
pub const REDACTED_QUERY_PARAMS: &[&str] = &[
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "key",
    "nonce",
    "password",
    "secret",
    "sig",
    "signature",
    "token",
    "ts",
];

/// The only response headers a cassette persists. An allowlist rather than a deny-list: a new
/// upstream header is *not* recorded until someone adds it here, so `set-cookie` and friends cannot
/// arrive in the artifact by default.
pub const RECORDED_RESPONSE_HEADERS: &[&str] = &["content-type"];

/// Returns whether `name` is a response header a cassette persists ([`RECORDED_RESPONSE_HEADERS`]).
///
/// The one law both the recorder and the replayer read, so the set cannot diverge between what is
/// written and what is served.
#[must_use]
pub fn is_recordable_response_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    RECORDED_RESPONSE_HEADERS.contains(&lower.as_str())
}

/// Everything that can go wrong with a cassette, typed rather than collapsed into a log line.
///
/// Converts into [`Error::Proxy`](crate::error::Error::Proxy) at the crate boundary; the variants
/// stay distinguishable inside the proxy, which is what lets
/// [`EgressProxy::cassette_misses`](crate::proxy::EgressProxy::cassette_misses) report a miss as
/// data instead of a string a test has to grep.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CassetteError {
    /// Replay was asked for an interaction the cassette does not hold (or has already served).
    #[error("cassette miss: no unconsumed recorded interaction for `{key}`")]
    Miss {
        /// The [`interaction_key`] that matched nothing.
        key: String,
    },
    /// The cassette path already exists. Recording is create-only: appending to a previous run's
    /// cassette silently mixes two runs' interactions into one file.
    #[error("cassette {path} already exists; recording is create-only")]
    Exists {
        /// The refused path.
        path: PathBuf,
    },
    /// The cassette could not be read or written.
    #[error("cassette {path}: {msg}")]
    Io {
        /// The cassette path.
        path: PathBuf,
        /// The underlying I/O failure.
        msg: String,
    },
    /// A line of the cassette is not a [`CASSETTE_FORMAT`] interaction.
    #[error("cassette {path} line {line}: {msg}")]
    Parse {
        /// The cassette path.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// What was wrong with it.
        msg: String,
    },
    /// The cassette holds no interactions. Every request would miss, so this is refused at load
    /// rather than discovered one 504 at a time.
    #[error("cassette {path} holds no interactions")]
    Empty {
        /// The cassette path.
        path: PathBuf,
    },
    /// A response body exceeded [`MAX_CASSETTE_BODY_BYTES`].
    #[error("cassette: response body for `{key}` exceeds the {cap}-byte cassette cap")]
    BodyTooLarge {
        /// The interaction being recorded.
        key: String,
        /// The cap that was exceeded.
        cap: usize,
    },
    /// The request named no destination, so no key can be composed for it. On the transparent path
    /// this is an origin-form request with no usable `Host` header.
    #[error("cassette: request `{method} {uri}` names no destination host")]
    UnnamedDestination {
        /// The request method.
        method: String,
        /// The request URI as received.
        uri: String,
    },
    /// A recorded body could not be decoded back into bytes.
    #[error("cassette: recorded body for `{key}` is not decodable: {msg}")]
    UndecodableBody {
        /// The interaction whose body is corrupt.
        key: String,
        /// What was wrong with it.
        msg: String,
    },
}

impl From<CassetteError> for crate::error::Error {
    fn from(e: CassetteError) -> Self {
        crate::error::Error::Proxy(e.to_string())
    }
}

/// A replay request that matched no unconsumed recorded interaction.
///
/// Retained rather than only logged: a replay test asserts on the *absence* of misses, and a
/// deliberate-miss test asserts on their presence, without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CassetteMiss {
    /// The [`interaction_key`] that matched nothing.
    pub key: String,
}

/// How a cassette keys and bounds its interactions.
///
/// `#[non_exhaustive]`: built from [`Default`] and narrowed with the builder methods, so growing it
/// later is not a break.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CassetteOptions {
    /// Query parameters dropped from every key, compared case-insensitively. Defaults to
    /// [`REDACTED_QUERY_PARAMS`].
    pub redacted_query_params: Vec<String>,
    /// Upper bound on a recorded response body. Defaults to [`MAX_CASSETTE_BODY_BYTES`].
    pub max_body_bytes: usize,
}

impl Default for CassetteOptions {
    fn default() -> Self {
        Self {
            redacted_query_params: REDACTED_QUERY_PARAMS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            max_body_bytes: MAX_CASSETTE_BODY_BYTES,
        }
    }
}

impl CassetteOptions {
    /// Adds query-parameter names to the redaction set (the defaults are kept).
    #[must_use]
    pub fn redacting<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for n in names {
            self.redacted_query_params
                .push(n.as_ref().to_ascii_lowercase());
        }
        self
    }

    /// Sets the recorded-body cap.
    #[must_use]
    pub fn with_max_body_bytes(mut self, cap: usize) -> Self {
        self.max_body_bytes = cap;
        self
    }

    fn is_redacted(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.redacted_query_params
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&lower))
    }
}

/// A recorded response body.
///
/// Text when the bytes are valid UTF-8 — which keeps a cassette diffable and greppable, the whole
/// reason the format is JSON Lines — and lowercase hex otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", content = "data", rename_all = "snake_case")]
pub enum RecordedBody {
    /// Valid UTF-8, stored verbatim.
    Text(String),
    /// Lowercase hex, for a body that is not valid UTF-8.
    Hex(String),
}

impl RecordedBody {
    /// Encodes `bytes` for storage.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(s) => RecordedBody::Text(s.to_string()),
            Err(_) => {
                let mut hex = String::with_capacity(bytes.len() * 2);
                for b in bytes {
                    // `write!` to a String is infallible; the two nibbles are formatted directly.
                    hex.push(nibble(b >> 4));
                    hex.push(nibble(b & 0x0f));
                }
                RecordedBody::Hex(hex)
            }
        }
    }

    /// Decodes the stored body back into bytes.
    ///
    /// # Errors
    /// Returns [`CassetteError::UndecodableBody`] if a [`RecordedBody::Hex`] payload is not an even
    /// number of hex digits.
    pub fn to_bytes(&self, key: &str) -> std::result::Result<Vec<u8>, CassetteError> {
        match self {
            RecordedBody::Text(s) => Ok(s.as_bytes().to_vec()),
            RecordedBody::Hex(h) => {
                if !h.len().is_multiple_of(2) {
                    return Err(CassetteError::UndecodableBody {
                        key: key.to_string(),
                        msg: format!("hex body has an odd length ({})", h.len()),
                    });
                }
                let bytes = h.as_bytes();
                let mut out = Vec::with_capacity(h.len() / 2);
                for pair in bytes.chunks(2) {
                    let (Some(hi), Some(lo)) = (pair.first(), pair.get(1)) else {
                        return Err(CassetteError::UndecodableBody {
                            key: key.to_string(),
                            msg: "hex body ended mid-byte".to_string(),
                        });
                    };
                    let (Some(hi), Some(lo)) = (unnibble(*hi), unnibble(*lo)) else {
                        return Err(CassetteError::UndecodableBody {
                            key: key.to_string(),
                            msg: "hex body holds a non-hex digit".to_string(),
                        });
                    };
                    out.push((hi << 4) | lo);
                }
                Ok(out)
            }
        }
    }
}

/// Maps the low four bits of `n` to a lowercase hex digit.
fn nibble(n: u8) -> char {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    // `n & 0x0f` is always in range, so the lookup cannot fail; the `map_or` keeps the
    // `indexing_slicing` deny satisfied without an unwrap.
    DIGITS
        .get(usize::from(n & 0x0f))
        .map_or('0', |b| char::from(*b))
}

/// The inverse of [`nibble`]: a hex digit's value, or `None` if it is not one.
fn unnibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// One recorded request→response interaction: the unit a cassette is a list of.
///
/// The request side is the **key only** — see the module docs for why no request header or body is
/// persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedInteraction {
    /// Always [`CASSETTE_FORMAT`]; refused at load otherwise.
    pub format: String,
    /// The [`interaction_key`] this response answers.
    pub key: String,
    /// The upstream response status.
    pub status: u16,
    /// The [`RECORDED_RESPONSE_HEADERS`]-allowlisted response headers.
    ///
    /// A presence attribute (`default` + `skip_serializing_if`): absent from the line when empty.
    /// That is the shape postcard corrupts (design Appendix A, reversal 10), which is why a
    /// cassette ships over `serde_json` only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// The upstream response body, verbatim.
    pub body: RecordedBody,
}

/// Composes the one deterministic key an interaction is recorded and matched under.
///
/// See the module docs for what is and is not in the key, and why. The canonicalization is: scheme
/// and host lowercased, a trailing root dot stripped from the host, the default port for the scheme
/// omitted, an empty path rendered `/`, and the query sorted with
/// [`CassetteOptions::redacted_query_params`] dropped.
///
/// # Errors
/// Returns [`CassetteError::UnnamedDestination`] when `uri` carries no host — on the transparent
/// path, an origin-form request whose `Host` header could not be used to reconstruct an absolute
/// URI. A request nobody can name a destination for cannot be keyed, and guessing one would make
/// two different destinations share a cassette entry.
pub fn interaction_key(
    method: &str,
    uri: &http::Uri,
    opts: &CassetteOptions,
) -> std::result::Result<String, CassetteError> {
    let Some(host) = uri.host() else {
        return Err(CassetteError::UnnamedDestination {
            method: method.to_string(),
            uri: uri.to_string(),
        });
    };
    let scheme = uri
        .scheme_str()
        .map_or_else(|| "http".to_string(), str::to_ascii_lowercase);
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443,
        _ => 80,
    };
    let port = match uri.port_u16() {
        Some(p) if p != default_port => format!(":{p}"),
        _ => String::new(),
    };
    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    let query = canonical_query(uri.query(), opts);
    Ok(format!(
        "{} {scheme}://{host}{port}{path}{query}",
        method.to_ascii_uppercase()
    ))
}

/// Sorts a query string and drops every redacted parameter, returning `""` or `"?…"`.
fn canonical_query(query: Option<&str>, opts: &CassetteOptions) -> String {
    let Some(q) = query else {
        return String::new();
    };
    let mut kept: Vec<&str> = q
        .split('&')
        .filter(|param| !param.is_empty())
        .filter(|param| {
            let name = param.split_once('=').map_or(*param, |(k, _)| k);
            !opts.is_redacted(name)
        })
        .collect();
    kept.sort_unstable();
    if kept.is_empty() {
        String::new()
    } else {
        format!("?{}", kept.join("&"))
    }
}

/// A proxy's cassette, in exactly one of its two modes.
///
/// Held behind the proxy's own lock; the handler reaches it once per request.
#[derive(Debug)]
pub enum CassetteState {
    /// Appending each forwarded interaction to `path`.
    Record {
        /// The cassette being written.
        path: PathBuf,
        /// The keying/bounding rules.
        opts: CassetteOptions,
    },
    /// Serving from a loaded cassette, with no upstream at all.
    Replay {
        /// The cassette that was loaded, for diagnostics.
        path: PathBuf,
        /// The keying rules (they must match the recording run's, or nothing hits).
        opts: CassetteOptions,
        /// The recorded interactions, in file order, each with its consumed flag.
        entries: Vec<(RecordedInteraction, bool)>,
        /// Every request that matched nothing.
        misses: Vec<CassetteMiss>,
    },
}

impl CassetteState {
    /// Opens `path` for recording. Create-only: an existing file is refused.
    ///
    /// # Errors
    /// [`CassetteError::Exists`] if the path is taken, [`CassetteError::Io`] if it cannot be
    /// created.
    pub fn open_record(
        path: &Path,
        opts: CassetteOptions,
    ) -> std::result::Result<Self, CassetteError> {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(_) => Ok(CassetteState::Record {
                path: path.to_path_buf(),
                opts,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(CassetteError::Exists {
                path: path.to_path_buf(),
            }),
            Err(e) => Err(CassetteError::Io {
                path: path.to_path_buf(),
                msg: e.to_string(),
            }),
        }
    }

    /// Loads `path` for replay, eagerly, so a missing/corrupt/empty cassette fails at the call that
    /// asked for replay rather than one 504 at a time.
    ///
    /// # Errors
    /// [`CassetteError::Io`] if it cannot be read, [`CassetteError::Parse`] for a line that is not a
    /// [`CASSETTE_FORMAT`] interaction, [`CassetteError::Empty`] if it holds none.
    pub fn open_replay(
        path: &Path,
        opts: CassetteOptions,
    ) -> std::result::Result<Self, CassetteError> {
        let text = std::fs::read_to_string(path).map_err(|e| CassetteError::Io {
            path: path.to_path_buf(),
            msg: e.to_string(),
        })?;
        let entries = parse_cassette(path, &text)?;
        if entries.is_empty() {
            return Err(CassetteError::Empty {
                path: path.to_path_buf(),
            });
        }
        Ok(CassetteState::Replay {
            path: path.to_path_buf(),
            opts,
            entries: entries.into_iter().map(|e| (e, false)).collect(),
            misses: Vec::new(),
        })
    }

    /// The keying rules this cassette is operating under.
    #[must_use]
    pub fn options(&self) -> &CassetteOptions {
        match self {
            CassetteState::Record { opts, .. } | CassetteState::Replay { opts, .. } => opts,
        }
    }

    /// Appends one interaction to a recording cassette.
    ///
    /// # Errors
    /// [`CassetteError::BodyTooLarge`] if the body exceeds the configured cap,
    /// [`CassetteError::Io`] if the append fails. Calling this on a replaying cassette is a no-op
    /// `Ok` — replay never records.
    pub fn append(
        &self,
        key: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: &[u8],
    ) -> std::result::Result<(), CassetteError> {
        let CassetteState::Record { path, opts } = self else {
            return Ok(());
        };
        if body.len() > opts.max_body_bytes {
            return Err(CassetteError::BodyTooLarge {
                key: key.to_string(),
                cap: opts.max_body_bytes,
            });
        }
        let interaction = RecordedInteraction {
            format: CASSETTE_FORMAT.to_string(),
            key: key.to_string(),
            status,
            headers,
            body: RecordedBody::from_bytes(body),
        };
        let line = serde_json::to_string(&interaction).map_err(|e| CassetteError::Io {
            path: path.clone(),
            msg: format!("serializing interaction: {e}"),
        })?;
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| CassetteError::Io {
                path: path.clone(),
                msg: e.to_string(),
            })?;
        writeln!(f, "{line}").map_err(|e| CassetteError::Io {
            path: path.clone(),
            msg: e.to_string(),
        })
    }

    /// Takes the first **unconsumed** interaction recorded under `key`, marking it consumed.
    ///
    /// Order is what disambiguates repeated calls to one key (the module docs' reason the request
    /// body is not keyed on): a run that recorded three answers for a key replays those three
    /// answers in that order.
    ///
    /// # Errors
    /// [`CassetteError::Miss`] when the cassette holds no unconsumed interaction for `key` — and the
    /// miss is retained for [`CassetteState::misses`]. Never falls through to an upstream.
    pub fn take_hit(
        &mut self,
        key: &str,
    ) -> std::result::Result<RecordedInteraction, CassetteError> {
        let CassetteState::Replay {
            entries, misses, ..
        } = self
        else {
            return Err(CassetteError::Miss {
                key: key.to_string(),
            });
        };
        if let Some((interaction, consumed)) = entries
            .iter_mut()
            .find(|(e, consumed)| !*consumed && e.key == key)
        {
            *consumed = true;
            return Ok(interaction.clone());
        }
        misses.push(CassetteMiss {
            key: key.to_string(),
        });
        Err(CassetteError::Miss {
            key: key.to_string(),
        })
    }

    /// Every replay request that matched nothing (empty while recording).
    #[must_use]
    pub fn misses(&self) -> Vec<CassetteMiss> {
        match self {
            CassetteState::Record { .. } => Vec::new(),
            CassetteState::Replay { misses, .. } => misses.clone(),
        }
    }

    /// Whether this cassette answers requests itself (replay) rather than recording forwarded ones.
    #[must_use]
    pub fn is_replaying(&self) -> bool {
        matches!(self, CassetteState::Replay { .. })
    }
}

/// Parses a JSON-Lines cassette, refusing any line that is not a [`CASSETTE_FORMAT`] interaction.
fn parse_cassette(
    path: &Path,
    text: &str,
) -> std::result::Result<Vec<RecordedInteraction>, CassetteError> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let interaction: RecordedInteraction =
            serde_json::from_str(line).map_err(|e| CassetteError::Parse {
                path: path.to_path_buf(),
                line: idx + 1,
                msg: e.to_string(),
            })?;
        if interaction.format != CASSETTE_FORMAT {
            return Err(CassetteError::Parse {
                path: path.to_path_buf(),
                line: idx + 1,
                msg: format!(
                    "expected format `{CASSETTE_FORMAT}`, found `{}`",
                    interaction.format
                ),
            });
        }
        out.push(interaction);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> http::Uri {
        s.parse().expect("test URI parses")
    }

    // THE KEY LAW. Buggy impls guarded, one per assert group: keying on the raw URI string (no
    // canonicalization) makes the case/trailing-dot/default-port group red; skipping the sort makes
    // the query group red; skipping the redaction filter makes the secret/nonce group red.
    #[test]
    fn interaction_key_is_canonical_and_redacted() {
        let opts = CassetteOptions::default();
        let base = interaction_key("GET", &uri("http://example.com/v1"), &opts).expect("key");
        assert_eq!(base, "GET http://example.com/v1");

        // Case, trailing root dot and an explicitly-written default port all fold to the same key.
        for spelling in [
            "http://EXAMPLE.com/v1",
            "http://example.com./v1",
            "http://example.com:80/v1",
        ] {
            assert_eq!(
                interaction_key("get", &uri(spelling), &opts).expect("key"),
                base,
                "`{spelling}` must key identically to `{base}`"
            );
        }
        // A NON-default port stays in the key: two ports are two destinations.
        assert_ne!(
            interaction_key("GET", &uri("http://example.com:8080/v1"), &opts).expect("key"),
            base
        );
        // https and http are two destinations too.
        assert_ne!(
            interaction_key("GET", &uri("https://example.com/v1"), &opts).expect("key"),
            base
        );
        // And so are two methods.
        assert_ne!(
            interaction_key("POST", &uri("http://example.com/v1"), &opts).expect("key"),
            base
        );

        // Query params sort, so parameter order is not a source of brittleness.
        assert_eq!(
            interaction_key("GET", &uri("http://example.com/v1?b=2&a=1"), &opts).expect("key"),
            interaction_key("GET", &uri("http://example.com/v1?a=1&b=2"), &opts).expect("key")
        );
        assert_eq!(
            interaction_key("GET", &uri("http://example.com/v1?b=2&a=1"), &opts).expect("key"),
            "GET http://example.com/v1?a=1&b=2"
        );

        // A secret and a per-call nonce drop OUT of the key entirely: two calls differing only in
        // them are the same interaction, and neither reaches the artifact.
        assert_eq!(
            interaction_key(
                "GET",
                &uri("http://example.com/v1?api_key=sk-secret&nonce=1"),
                &opts
            )
            .expect("key"),
            base
        );
        assert_eq!(
            interaction_key(
                "GET",
                &uri("http://example.com/v1?api_key=other&nonce=2"),
                &opts
            )
            .expect("key"),
            base
        );
        // A caller's own volatile parameter joins them.
        let opts = CassetteOptions::default().redacting(["request_id"]);
        assert_eq!(
            interaction_key("GET", &uri("http://example.com/v1?request_id=abc"), &opts)
                .expect("key"),
            base
        );
        // A non-redacted parameter is still discriminating (the redaction is not "drop everything").
        assert_ne!(
            interaction_key("GET", &uri("http://example.com/v1?page=2"), &opts).expect("key"),
            base
        );
    }

    // A request nobody can name a destination for is a typed refusal, not a key that silently
    // collides two destinations. Buggy impl guarded: falling back to the raw URI string makes both
    // origin-form requests key on their path and share a cassette entry.
    #[test]
    fn interaction_key_refuses_an_unnamed_destination() {
        let opts = CassetteOptions::default();
        let err = interaction_key("GET", &uri("/v1/models"), &opts)
            .expect_err("an origin-form URI names no host");
        assert!(
            matches!(err, CassetteError::UnnamedDestination { .. }),
            "expected UnnamedDestination, got {err:?}"
        );
    }

    // NO REQUEST HEADERS, NO REQUEST BODY, EVER — the secrets rule for a persisted artifact. The
    // key is composed from `(method, uri)` alone, so this is structural: there is no parameter a
    // header could enter through. This asserts the *shape* of what lands in the file.
    #[test]
    fn a_recorded_line_holds_no_request_headers_and_no_request_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.jsonl");
        let state = CassetteState::open_record(&path, CassetteOptions::default()).expect("record");
        state
            .append(
                "POST https://api.example.test/v1/chat",
                200,
                vec![("content-type".to_string(), "application/json".to_string())],
                b"{\"ok\":true}",
            )
            .expect("append");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("api.example.test"), "{text}");
        assert!(text.contains("{\\\"ok\\\":true}"), "{text}");
        // The things that must never be there, spelled as the JSON keys they would arrive under.
        for forbidden in ["authorization", "\"request_headers\"", "\"request_body\""] {
            assert!(
                !text.contains(forbidden),
                "a cassette line must not carry `{forbidden}`: {text}"
            );
        }
    }

    // Create-only. Buggy impl guarded: an `append(true).create(true)` open silently mixes two runs'
    // interactions into one file, and this `Exists` assert goes red.
    #[test]
    fn recording_refuses_an_existing_cassette() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.jsonl");
        std::fs::write(&path, "").expect("pre-create");
        let err = CassetteState::open_record(&path, CassetteOptions::default())
            .expect_err("an existing cassette must be refused");
        assert!(
            matches!(err, CassetteError::Exists { .. }),
            "expected Exists, got {err:?}"
        );
    }

    // Record → replay round trip through the real file, plus the ORDER law for a repeated key, plus
    // the loud miss. Buggy impls guarded: serving a consumed entry again makes the `two` assert red;
    // returning `Ok` on an unmatched key makes the miss assert red.
    #[test]
    fn replay_serves_recorded_bodies_in_order_and_misses_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.jsonl");
        let rec = CassetteState::open_record(&path, CassetteOptions::default()).expect("record");
        rec.append("GET http://a.test/", 200, vec![], b"one")
            .expect("append 1");
        rec.append("GET http://a.test/", 201, vec![], b"two")
            .expect("append 2");
        rec.append("GET http://b.test/", 204, vec![], &[0xff, 0x00])
            .expect("append 3");

        let mut play =
            CassetteState::open_replay(&path, CassetteOptions::default()).expect("replay loads");
        let first = play.take_hit("GET http://a.test/").expect("first hit");
        assert_eq!(first.status, 200);
        assert_eq!(first.body.to_bytes("k").expect("decode"), b"one");
        let second = play.take_hit("GET http://a.test/").expect("second hit");
        assert_eq!(second.status, 201);
        assert_eq!(second.body.to_bytes("k").expect("decode"), b"two");
        // Exhausted: a third call to the same key is a MISS, not a re-served entry.
        let err = play
            .take_hit("GET http://a.test/")
            .expect_err("an exhausted key must miss");
        assert!(matches!(err, CassetteError::Miss { .. }), "{err:?}");

        // A non-UTF-8 body round-trips through the hex encoding.
        let third = play.take_hit("GET http://b.test/").expect("third hit");
        assert_eq!(third.body.to_bytes("k").expect("decode"), vec![0xff, 0x00]);

        // A never-recorded key misses too, and every miss is retained as typed data.
        assert!(play.take_hit("GET http://never.test/").is_err());
        let misses = play.misses();
        assert_eq!(misses.len(), 2, "{misses:?}");
        assert!(misses.iter().any(|m| m.key == "GET http://never.test/"));
    }

    // The body cap is loud, never a truncation. Buggy impl guarded: truncating to the cap and
    // recording anyway returns Ok, and this `expect_err` goes red — while the next run would replay
    // a body that never existed.
    #[test]
    fn an_oversized_body_is_refused_rather_than_truncated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.jsonl");
        let rec =
            CassetteState::open_record(&path, CassetteOptions::default().with_max_body_bytes(16))
                .expect("record");
        let err = rec
            .append("GET http://a.test/", 200, vec![], &[b'x'; 17])
            .expect_err("an over-cap body must be refused");
        assert!(matches!(err, CassetteError::BodyTooLarge { .. }), "{err:?}");
        // And nothing was written: a refused interaction leaves no half-truth in the artifact.
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "");
        // Positive control: exactly at the cap records.
        rec.append("GET http://a.test/", 200, vec![], &[b'x'; 16])
            .expect("an at-cap body records");
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .contains("xxx")
        );
    }

    // An empty / foreign / corrupt cassette is refused AT LOAD. Buggy impl guarded: a lazy loader
    // returns Ok here and turns every later request into an indistinguishable 504.
    #[test]
    fn replay_refuses_an_empty_or_foreign_cassette() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().join("empty.jsonl");
        std::fs::write(&empty, "\n\n").expect("write");
        assert!(matches!(
            CassetteState::open_replay(&empty, CassetteOptions::default())
                .expect_err("empty must be refused"),
            CassetteError::Empty { .. }
        ));

        let foreign = dir.path().join("foreign.jsonl");
        std::fs::write(
            &foreign,
            "{\"format\":\"someone-elses-v9\",\"key\":\"GET http://a.test/\",\"status\":200,\"body\":{\"encoding\":\"text\",\"data\":\"hi\"}}\n",
        )
        .expect("write");
        let err = CassetteState::open_replay(&foreign, CassetteOptions::default())
            .expect_err("a foreign format must be refused");
        assert!(
            matches!(err, CassetteError::Parse { line: 1, .. }),
            "{err:?}"
        );

        let missing = dir.path().join("nope.jsonl");
        assert!(matches!(
            CassetteState::open_replay(&missing, CassetteOptions::default())
                .expect_err("a missing cassette must be refused"),
            CassetteError::Io { .. }
        ));
    }

    // Rule 8 (the postcard trap, design Appendix A reversal 10): `headers` is a presence attribute
    // (`default` + `skip_serializing_if`), so it round-trips on the codec it actually ships over —
    // `serde_json` — in BOTH states, present and absent. Buggy impl guarded: dropping `default`
    // makes the absent-headers line fail to deserialize.
    #[test]
    fn json_round_trip_survives_an_absent_presence_attribute() {
        let bare = RecordedInteraction {
            format: CASSETTE_FORMAT.to_string(),
            key: "GET http://a.test/".to_string(),
            status: 200,
            headers: vec![],
            body: RecordedBody::Text("hi".to_string()),
        };
        let line = serde_json::to_string(&bare).expect("serialize");
        assert!(
            !line.contains("headers"),
            "an empty header set must be ABSENT from the line, not `[]`: {line}"
        );
        assert_eq!(
            serde_json::from_str::<RecordedInteraction>(&line).expect("deserialize"),
            bare
        );

        let full = RecordedInteraction {
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            ..bare
        };
        let line = serde_json::to_string(&full).expect("serialize");
        assert!(line.contains("content-type"), "{line}");
        assert_eq!(
            serde_json::from_str::<RecordedInteraction>(&line).expect("deserialize"),
            full
        );
    }

    // The response-header allowlist is one law both sides read. Buggy impl guarded: a deny-list
    // (`!= "set-cookie"`) admits `authorization`/`x-api-key` and turns the negative asserts red.
    #[test]
    fn only_allowlisted_response_headers_are_recordable() {
        assert!(is_recordable_response_header("content-type"));
        assert!(is_recordable_response_header("Content-Type"));
        for secret in [
            "set-cookie",
            "authorization",
            "x-api-key",
            "www-authenticate",
        ] {
            assert!(
                !is_recordable_response_header(secret),
                "`{secret}` must never reach a persisted cassette"
            );
        }
    }

    // Hex encoding is only for what UTF-8 cannot hold, so a cassette stays diffable.
    #[test]
    fn bodies_are_text_when_they_can_be() {
        assert_eq!(
            RecordedBody::from_bytes(b"hello"),
            RecordedBody::Text("hello".to_string())
        );
        // 0xff/0xfe start no UTF-8 sequence at all. (0xde 0xad does — it is U+07AD — which is
        // why the encoder asks `from_utf8` rather than eyeballing the high bit.)
        assert_eq!(
            RecordedBody::from_bytes(&[0xff, 0xfe]),
            RecordedBody::Hex("fffe".to_string())
        );
        assert!(RecordedBody::Hex("abc".to_string()).to_bytes("k").is_err());
        assert!(RecordedBody::Hex("zz".to_string()).to_bytes("k").is_err());
    }
}
