//! Full MITM on the **transparent** egress path (§6.4, The transparent egress proxy).
//!
//! # The gap this closes
//!
//! `hudsucker` is an *explicit*-proxy MITM: every intake it understands names its destination in
//! the HTTP layer — a `CONNECT host:443` or an absolute-form request line. A **transparently
//! redirected** connection names it nowhere in HTTP: a privileged `TPROXY` ruleset or the
//! unprivileged smoltcp NAT hands the proxy a raw connection the guest believes it opened to
//! `93.184.216.34:443`. §6.4 recorded the consequence honestly — the transparent path "currently
//! only **constrains** egress …, not reconstruct and re-originate the request".
//!
//! Two intakes, two ways to recover the destination, and this module is the one place either is
//! recovered:
//!
//! * **Plain HTTP.** The origin-form request line (`GET /v1 HTTP/1.1`) plus the `Host` header
//!   reconstruct the absolute URI — [`reconstruct_absolute_uri`], applied once, before the request
//!   reaches the block/double/cassette decisions so every one of them sees the real destination.
//! * **TLS.** Nothing in the byte stream is HTTP at all, so the destination has to come from the
//!   `server_name` extension of the ClientHello — [`sni_from_client_hello`] — read by
//!   [`serve_intake`] *before* a byte reaches `hudsucker`. The connection is then handed to
//!   `hudsucker` behind a **synthesized `CONNECT`**, which is precisely the explicit-proxy intake it
//!   does understand; from there its own MITM (mint a cert for the authority, terminate, re-issue)
//!   runs unchanged.
//!
//! # The boundary, stated
//!
//! The ClientHello must arrive in **one** TLS record within [`MAX_INTAKE_PREFIX_BYTES`]; a ClientHello split
//! across records (legal, and what a client sending a huge `session_ticket` or post-quantum key
//! share can do) is refused loudly rather than guessed at. A TLS intake with **no** SNI falls back
//! to the original destination address when the kernel preserved one (the `TPROXY` case, where the
//! accepted socket's local address is the guest's intended destination) and is otherwise refused —
//! the unprivileged NAT bridges to the proxy's own loopback port, so there is no destination left in
//! the socket to fall back to. Both refusals are recorded in the proxy's request log, never
//! swallowed.
//!
//! # Guest-controlled bytes cross an HTTP boundary here
//!
//! The SNI and the `Host` header are chosen by the guest and are spliced into a request line
//! (`CONNECT <authority> HTTP/1.1`) and a URI. [`validate_authority_host`] is the one gate both go
//! through, so a `Host: example.com\r\nX-Injected: 1` cannot smuggle a header into the synthesized
//! request.

use crate::proxy::RequestLog;
use crate::proxy::doubles::push_bounded;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How many of the guest's first bytes the intake will buffer while classifying the connection.
///
/// Large enough for an ordinary ClientHello (a few hundred bytes) with room for a session ticket
/// and a key share; small enough that a guest cannot make the intake buffer arbitrary memory. The
/// buffered prefix is written to the explicit-proxy intake before the splice begins, so classifying
/// consumes nothing the destination does not then receive.
pub(crate) const MAX_INTAKE_PREFIX_BYTES: usize = 8 * 1024;

/// Whole-operation budget for classifying one connection: the classification reads, the synthesized
/// `CONNECT` write, and the reading of its response.
///
/// It bounds the *whole* handshake with the front-end, not the gaps between polls: a guest that
/// opens a connection and sends one byte a minute is dropped instead of holding an intake task
/// forever.
pub(crate) const INTAKE_HANDSHAKE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Upper bound on the synthesized `CONNECT`'s response headers, read a byte at a time so no tunnel
/// byte is ever consumed past the header terminator.
const MAX_CONNECT_RESPONSE_BYTES: usize = 4096;

/// The longest DNS name, per RFC 1035.
const MAX_HOST_LEN: usize = 253;

/// What went wrong recovering a transparently-redirected connection's destination.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum TransparentError {
    /// An origin-form request arrived with no usable `Host` header, so it names no destination.
    #[error("origin-form request with no Host header names no destination")]
    NoHost,
    /// A guest-supplied authority is not a syntactically valid host[:port].
    #[error("refusing guest-supplied authority `{authority}`: {why}")]
    BadAuthority {
        /// The rejected value, as the guest sent it.
        authority: String,
        /// Which rule it broke.
        why: &'static str,
    },
    /// The reconstructed URI did not parse.
    #[error("reconstructed URI `{uri}` does not parse: {msg}")]
    BadUri {
        /// The URI that was composed.
        uri: String,
        /// The parser's complaint.
        msg: String,
    },
    /// The peeked bytes are TLS but the ClientHello could not be read.
    #[error("unreadable TLS ClientHello: {0}")]
    BadClientHello(&'static str),
}

/// What the first bytes of a transparently-redirected connection turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Intake {
    /// Plain HTTP (explicit-proxy or origin-form): hand it to `hudsucker` unchanged.
    Http,
    /// A TLS ClientHello, with the `server_name` it carried (if any).
    Tls {
        /// The SNI host, absent when the client sent no `server_name` extension.
        sni: Option<String>,
    },
}

/// The result of looking at what has arrived so far.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Peek {
    /// Not enough bytes yet to decide; read more.
    NeedMore,
    /// Decided.
    Decided(Intake),
    /// TLS, but unreadable — refuse the connection rather than guess a destination.
    Malformed(TransparentError),
}

/// Classifies the bytes seen so far on a transparently-redirected connection.
///
/// A TLS record always opens `0x16` (handshake) followed by a version whose major byte is `0x03`;
/// no HTTP method starts with that byte, which is the same two-byte discriminator `hudsucker`
/// itself uses on an upgraded `CONNECT` tunnel. Anything else is HTTP and is decided immediately,
/// so an explicit-proxy request pays exactly one byte of latency.
pub(crate) fn classify(buf: &[u8]) -> Peek {
    let Some(first) = buf.first() else {
        return Peek::NeedMore;
    };
    if *first != 0x16 {
        return Peek::Decided(Intake::Http);
    }
    // A TLS record header is 5 bytes: type, version(2), length(2).
    let (Some(len_hi), Some(len_lo)) = (buf.get(3), buf.get(4)) else {
        return Peek::NeedMore;
    };
    let record_len = usize::from(u16::from_be_bytes([*len_hi, *len_lo]));
    if record_len == 0 {
        return Peek::Malformed(TransparentError::BadClientHello("empty TLS record"));
    }
    let Some(record) = buf.get(5..5 + record_len) else {
        if buf.len() >= MAX_INTAKE_PREFIX_BYTES {
            return Peek::Malformed(TransparentError::BadClientHello(
                "ClientHello does not fit in the intake window",
            ));
        }
        return Peek::NeedMore;
    };
    match sni_from_client_hello(record) {
        Ok(sni) => Peek::Decided(Intake::Tls { sni }),
        Err(e) => Peek::Malformed(e),
    }
}

/// A bounds-checked forward reader over a byte slice.
///
/// Every field of a ClientHello is length-prefixed by the peer, so every read is a guest-controlled
/// length: this returns `None` instead of panicking or over-reading, which is what keeps the parser
/// free of `indexing_slicing` and free of a way to walk off the record.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    fn u24(&mut self) -> Option<u32> {
        let b = self.take(3)?;
        Some(u32::from_be_bytes([0, *b.first()?, *b.get(1)?, *b.get(2)?]))
    }

    /// Reads a `n`-byte-length-prefixed vector.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// Extracts the `server_name` (SNI) from one TLS handshake record's payload.
///
/// `record` is the record's *payload* — the bytes after the 5-byte record header. Returns
/// `Ok(None)` for a well-formed ClientHello that carried no `server_name` extension, which is a
/// legal client and a *different* outcome from an unreadable one.
///
/// # Errors
/// [`TransparentError::BadClientHello`] when the record is not a ClientHello, is truncated, or has
/// a malformed extension block. Refusing loudly matters: an intake that guessed a destination here
/// would mint a certificate for, and re-originate to, a host the guest never named.
pub(crate) fn sni_from_client_hello(
    record: &[u8],
) -> std::result::Result<Option<String>, TransparentError> {
    let mut r = Reader::new(record);
    let bad = |why: &'static str| TransparentError::BadClientHello(why);

    if r.u8().ok_or_else(|| bad("truncated handshake header"))? != 0x01 {
        return Err(bad("handshake message is not a ClientHello"));
    }
    let body_len = r.u24().ok_or_else(|| bad("truncated handshake length"))? as usize;
    let body = r
        .take(body_len)
        .ok_or_else(|| bad("truncated ClientHello"))?;

    let mut r = Reader::new(body);
    r.take(2).ok_or_else(|| bad("truncated client_version"))?;
    r.take(32).ok_or_else(|| bad("truncated random"))?;
    r.vec8().ok_or_else(|| bad("truncated session_id"))?;
    r.vec16().ok_or_else(|| bad("truncated cipher_suites"))?;
    r.vec8()
        .ok_or_else(|| bad("truncated compression_methods"))?;
    // TLS 1.2 permits a ClientHello with no extension block at all.
    let Some(extensions) = r.vec16() else {
        return Ok(None);
    };

    let mut ext = Reader::new(extensions);
    while ext.pos < extensions.len() {
        let ext_type = ext.u16().ok_or_else(|| bad("truncated extension type"))?;
        let ext_data = ext.vec16().ok_or_else(|| bad("truncated extension body"))?;
        if ext_type != 0x0000 {
            continue;
        }
        let mut sni = Reader::new(ext_data);
        let list = sni
            .vec16()
            .ok_or_else(|| bad("truncated server_name_list"))?;
        let mut entry = Reader::new(list);
        while entry.pos < list.len() {
            let name_type = entry
                .u8()
                .ok_or_else(|| bad("truncated server_name type"))?;
            let name = entry.vec16().ok_or_else(|| bad("truncated server_name"))?;
            if name_type == 0 {
                let name =
                    std::str::from_utf8(name).map_err(|_| bad("server_name is not valid UTF-8"))?;
                return Ok(Some(name.to_string()));
            }
        }
        return Ok(None);
    }
    Ok(None)
}

/// The one gate every guest-supplied authority passes through before it is spliced into a
/// synthesized request line or a reconstructed URI.
///
/// Accepts `host` or `host:port` where the host is DNS-shaped (ASCII alphanumerics, `-`, `.`, at
/// most [`MAX_HOST_LEN`] bytes, an optional single trailing root dot) and the port is a decimal
/// 1–65535. Everything else — an embedded `\r\n` (request smuggling), a space, a `/`, an empty
/// host, a port of `0` — is a typed refusal.
///
/// # Errors
/// [`TransparentError::BadAuthority`] naming which rule was broken.
pub(crate) fn validate_authority_host(
    authority: &str,
) -> std::result::Result<(), TransparentError> {
    let refuse = |why: &'static str| TransparentError::BadAuthority {
        authority: authority.to_string(),
        why,
    };
    if authority.is_empty() {
        return Err(refuse("empty authority"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(refuse("empty host"));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(refuse("host longer than 253 bytes"));
    }
    let core = host.strip_suffix('.').unwrap_or(host);
    if core.is_empty() {
        return Err(refuse("host is a bare root dot"));
    }
    if !core
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(refuse(
            "host holds a character outside [A-Za-z0-9.-] (control characters and spaces included)",
        ));
    }
    if let Some(port) = port {
        match port.parse::<u16>() {
            Ok(0) | Err(_) => return Err(refuse("port is not a decimal 1-65535")),
            Ok(_) => {}
        }
    }
    Ok(())
}

/// Rebuilds an origin-form request's absolute URI from its `Host` header.
///
/// Returns `Ok(None)` when there is nothing to do — the URI already carries an authority, which is
/// every explicit-proxy request and every request `hudsucker` re-stamps inside a MITM'd `CONNECT`
/// tunnel (it copies the tunnel's scheme and authority onto each request). So this is a no-op on
/// exactly the paths that already worked, and the whole fix on the one that did not.
///
/// The scheme is `http`: this reconstruction runs on the front-end's *plaintext* intake. A
/// transparently-redirected TLS connection never reaches it as HTTP — it arrives as a ClientHello,
/// and [`serve_intake`] gives it an authority through a synthesized `CONNECT` instead.
///
/// # Errors
/// [`TransparentError::NoHost`] when no `Host` header names a destination,
/// [`TransparentError::BadAuthority`] when the guest's `Host` fails
/// [`validate_authority_host`], [`TransparentError::BadUri`] when the composition does not parse.
pub(crate) fn reconstruct_absolute_uri(
    uri: &http::Uri,
    host_header: Option<&str>,
) -> std::result::Result<Option<http::Uri>, TransparentError> {
    if uri.authority().is_some() {
        return Ok(None);
    }
    let host = host_header.ok_or(TransparentError::NoHost)?.trim();
    validate_authority_host(host)?;
    let path_and_query = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let composed = format!("http://{host}{path_and_query}");
    composed
        .parse::<http::Uri>()
        .map(Some)
        .map_err(|e| TransparentError::BadUri {
            uri: composed,
            msg: e.to_string(),
        })
}

/// Chooses the port the synthesized `CONNECT` names.
///
/// `local` is the accepted socket's local address. Under `TPROXY` the kernel preserves the guest's
/// intended destination there, so a local port that differs from the front-end's own listening port
/// **is** the destination port (443, or a non-standard TLS port). When they are equal there is no
/// preserved destination — the unprivileged NAT bridges to the front-end's loopback port — and TLS
/// on a transparent intake means 443.
pub(crate) fn connect_port(local_port: u16, proxy_port: u16) -> u16 {
    if local_port == proxy_port || local_port == 0 {
        443
    } else {
        local_port
    }
}

/// The shared state one intake task needs.
pub(crate) struct IntakeCtx {
    /// `hudsucker`'s own loopback listener, which every classified connection is spliced onto.
    pub inner: SocketAddr,
    /// The front-end's listening port, for [`connect_port`]'s "no preserved destination" test.
    pub proxy_port: u16,
    /// The proxy's request log, so a refused intake is host-observable rather than only logged.
    pub requests: Arc<std::sync::Mutex<RequestLog>>,
}

/// Accepts transparently-redirected connections, recovers each one's destination, and splices it
/// onto `hudsucker`'s explicit-proxy intake.
///
/// Runs until the task is dropped (the proxy worker's runtime ends at graceful shutdown). Each
/// connection is handled in its own task, so one wedged guest cannot stall the accept loop; the
/// per-connection work is bounded by [`INTAKE_HANDSHAKE_BUDGET`].
pub(crate) async fn serve_intake(listener: tokio::net::TcpListener, ctx: Arc<IntakeCtx>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(e) = handle_intake(stream, &ctx).await {
                        tracing::debug!("transparent intake from {peer} ended: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::error!("transparent intake accept failed: {e}");
                return;
            }
        }
    }
}

/// Records a refused intake in the proxy's request log (and the trace), so "the guest's connection
/// died" is answerable from the host without a packet capture.
fn record_refusal(ctx: &IntakeCtx, reason: &str) {
    tracing::warn!("transparent intake refused: {reason}");
    let mut log = ctx.requests.lock().unwrap_or_else(|e| e.into_inner());
    push_bounded(&mut log, format!("TRANSPARENT REFUSED {reason}"));
}

/// Classifies one connection and splices it onto the explicit-proxy intake.
async fn handle_intake(mut guest: TcpStream, ctx: &IntakeCtx) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + INTAKE_HANDSHAKE_BUDGET;
    let local = guest.local_addr()?;

    let (intake, prefix) = match tokio::time::timeout_at(deadline, read_intake(&mut guest)).await {
        Ok(Ok(decided)) => decided,
        Ok(Err(e)) => {
            record_refusal(ctx, &e.to_string());
            return Ok(());
        }
        Err(_) => {
            record_refusal(ctx, "classification timed out");
            return Ok(());
        }
    };

    let mut upstream = TcpStream::connect(ctx.inner).await?;

    if let Intake::Tls { sni } = intake {
        let authority = match tls_authority(sni.as_deref(), local, ctx.proxy_port) {
            Ok(a) => a,
            Err(e) => {
                record_refusal(ctx, &e.to_string());
                return Ok(());
            }
        };
        match tokio::time::timeout_at(deadline, synthesize_connect(&mut upstream, &authority)).await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // A non-2xx CONNECT is the blocked-domain path: the front-end refused this
                // destination, so the guest's TLS connection is closed rather than tunneled.
                record_refusal(ctx, &format!("{authority}: {e}"));
                return Ok(());
            }
            Err(_) => {
                record_refusal(ctx, &format!("{authority}: CONNECT timed out"));
                return Ok(());
            }
        }
    }

    // Classification CONSUMED the prefix, so it is replayed here — after the tunnel is open —
    // before the splice takes over. Losing it would drop the ClientHello or the request line.
    upstream.write_all(&prefix).await?;

    match tokio::io::copy_bidirectional(&mut guest, &mut upstream).await {
        Ok((_g2u, _u2g)) => Ok(()),
        // A peer that resets mid-splice is ordinary, not a proxy failure.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        Err(e) => Err(e),
    }
}

/// Names the destination of a transparent TLS intake: the SNI when the client sent one, else the
/// kernel-preserved original destination, else a typed refusal.
fn tls_authority(
    sni: Option<&str>,
    local: SocketAddr,
    proxy_port: u16,
) -> std::result::Result<String, TransparentError> {
    let port = connect_port(local.port(), proxy_port);
    if let Some(sni) = sni {
        validate_authority_host(sni)?;
        return Ok(format!("{sni}:{port}"));
    }
    if local.port() != proxy_port && local.port() != 0 {
        // TPROXY preserved the guest's intended destination in the socket's local address.
        return Ok(format!("{}:{port}", local.ip()));
    }
    Err(TransparentError::BadAuthority {
        authority: local.to_string(),
        why: "TLS intake carried no SNI and the socket preserves no original destination",
    })
}

/// Reads until the connection can be classified, returning the intake and the bytes consumed.
///
/// The prefix is handed back rather than discarded: the caller replays it onto the explicit-proxy
/// intake once the tunnel is open. Reading (rather than `MSG_PEEK`ing) is deliberate — a peek loop
/// that needs more bytes than are queued spins hot, because the socket stays readable on the bytes
/// it has already shown.
async fn read_intake(
    guest: &mut TcpStream,
) -> std::result::Result<(Intake, Vec<u8>), TransparentError> {
    let mut prefix: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        match classify(&prefix) {
            Peek::Decided(intake) => return Ok((intake, prefix)),
            Peek::Malformed(e) => return Err(e),
            Peek::NeedMore => {}
        }
        let room = MAX_INTAKE_PREFIX_BYTES.saturating_sub(prefix.len());
        if room == 0 {
            return Err(TransparentError::BadClientHello(
                "ClientHello does not fit in the intake window",
            ));
        }
        let window = chunk
            .get_mut(..room.min(2048))
            .ok_or(TransparentError::BadClientHello("intake window is empty"))?;
        let n = guest
            .read(window)
            .await
            .map_err(|_| TransparentError::BadClientHello("intake read failed"))?;
        if n == 0 {
            return Err(TransparentError::BadClientHello(
                "connection closed before the intake could be classified",
            ));
        }
        prefix.extend_from_slice(window.get(..n).unwrap_or(&[]));
    }
}

/// Writes `CONNECT <authority> HTTP/1.1` to the explicit-proxy intake and consumes exactly its
/// response headers, so the tunnel that follows starts at the guest's first byte.
///
/// The response is read **one byte at a time**: any byte past the `\r\n\r\n` terminator belongs to
/// the tunnel, and a buffered read that swallowed one would silently corrupt the TLS handshake.
async fn synthesize_connect(upstream: &mut TcpStream, authority: &str) -> std::io::Result<()> {
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    upstream.write_all(request.as_bytes()).await?;
    upstream.flush().await?;

    let mut header = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = upstream.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "CONNECT response ended before its headers did",
            ));
        }
        header.extend_from_slice(&byte);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() >= MAX_CONNECT_RESPONSE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CONNECT response headers exceeded the cap",
            ));
        }
    }
    if connect_response_is_success(&header) {
        Ok(())
    } else {
        let status = String::from_utf8_lossy(&header)
            .lines()
            .next()
            .unwrap_or("<no status line>")
            .to_string();
        Err(std::io::Error::other(format!(
            "synthesized CONNECT refused: {status}"
        )))
    }
}

/// Whether a `CONNECT` response's header block reports success (a 2xx status).
///
/// A `403` here is the egress filter doing its job on a transparently-redirected TLS connection:
/// the destination the ClientHello named is on the deny list, so there is no tunnel to open.
///
/// A RECORDED SECOND COPY, deliberately: `vmcell-guest-tools`' curl shim has its own
/// `connect_succeeded`, because it is the *client* end of a CONNECT inside the guest and shares no
/// crate with this one. The shared thing is HTTP's own rule ("2xx opened the tunnel"), not a vmcell
/// invariant, and the composer side — where a guest-chosen authority crosses into a request line —
/// *is* gated to one law by `scripts/ban-http-connect-composers.sh`, which rosters that shim as its
/// one exemption with this reason.
pub(crate) fn connect_response_is_success(header: &[u8]) -> bool {
    let text = String::from_utf8_lossy(header);
    let Some(status_line) = text.lines().next() else {
        return false;
    };
    let mut parts = status_line.split_whitespace();
    let Some(version) = parts.next() else {
        return false;
    };
    if !version.starts_with("HTTP/") {
        return false;
    }
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a TLS record carrying a ClientHello with the given SNI (or none).
    ///
    /// Handwritten rather than captured, so the parser is tested against the wire shape the RFC
    /// specifies rather than against one client's habits. `client_hello_matches_a_real_rustls_hello`
    /// pins this builder to what an actual TLS client emits.
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(name) = sni {
            let mut entry = vec![0x00]; // host_name
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);
            ext.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
            ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ext.extend_from_slice(&list);
        }
        // A second extension after the SNI, so "stops at the first extension" is not a passing impl.
        ext.extend_from_slice(&0x002bu16.to_be_bytes()); // supported_versions
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.extend_from_slice(&[0x02, 0x03, 0x04]);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0x41; 32]); // random
        body.push(0); // session_id
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression_methods
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        let len = body.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    // THE DESTINATION-RECOVERY LAW for TLS. Buggy impls guarded: a parser that skips the
    // session_id/cipher_suites/compression vectors lands mid-field and returns garbage or an error
    // (the `Some("example.com")` assert reddens); one that returns the first extension's body
    // regardless of type returns the supported_versions bytes.
    #[test]
    fn sni_is_recovered_from_a_client_hello() {
        let record = client_hello(Some("example.com"));
        match classify(&record) {
            Peek::Decided(Intake::Tls { sni }) => {
                assert_eq!(sni.as_deref(), Some("example.com"));
            }
            other => panic!("expected a TLS intake with SNI, got {other:?}"),
        }
        // A legal ClientHello with no server_name is Ok(None) — a DIFFERENT outcome from unreadable,
        // because it selects the original-destination fallback rather than a refusal.
        match classify(&client_hello(None)) {
            Peek::Decided(Intake::Tls { sni }) => assert_eq!(sni, None),
            other => panic!("expected a TLS intake with no SNI, got {other:?}"),
        }
    }

    // THE HANDWRITTEN BUILDER IS PINNED TO A REAL CLIENT. Every other TLS test here feeds
    // `client_hello()`, which is this file's own idea of the wire format; if that idea were wrong in
    // the same way the parser is wrong, they would all pass against a stream no client ever sends.
    // So drive one ClientHello out of `rustls` — the same TLS stack the proxy terminates with — and
    // parse THAT. Buggy impl guarded: any field-walk error in the parser (a session_id read as a
    // 2-byte vector, extensions read before compression_methods) survives a matched builder and dies
    // here.
    #[test]
    fn sni_is_recovered_from_a_real_rustls_client_hello() {
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let server_name =
            rustls::pki_types::ServerName::try_from("api.example.test").expect("server name");
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .expect("client connection");
        let mut wire = Vec::new();
        conn.write_tls(&mut wire).expect("ClientHello is emitted");

        assert_eq!(
            classify(&wire),
            Peek::Decided(Intake::Tls {
                sni: Some("api.example.test".to_string())
            }),
            "the SNI of a REAL ClientHello must be recovered"
        );
        // And the same bytes one short of complete are NEED-MORE, not a refusal: a real
        // ClientHello is big enough to arrive in two segments, which is the case the intake loop
        // exists to handle.
        assert_eq!(
            classify(wire.get(..wire.len() - 1).expect("truncate")),
            Peek::NeedMore
        );
    }

    // The classifier must not mistake HTTP for TLS or vice versa. Buggy impl guarded: keying off
    // "looks like a method name" instead of the 0x16 record type sends a ClientHello into hudsucker
    // as HTTP — the exact "unexpected eof" failure §6.4 records.
    #[test]
    fn http_intakes_are_decided_immediately() {
        for line in [
            &b"GET / HTTP/1.1\r\n"[..],
            &b"CONNECT example.com:443 HTTP/1.1\r\n"[..],
            &b"POST http://a.test/ HTTP/1.1\r\n"[..],
        ] {
            assert_eq!(classify(line), Peek::Decided(Intake::Http));
        }
        // One byte is enough to decide HTTP, and not enough to decide TLS.
        assert_eq!(classify(b"G"), Peek::Decided(Intake::Http));
        assert_eq!(classify(b"\x16"), Peek::NeedMore);
        assert_eq!(classify(&[]), Peek::NeedMore);
    }

    // A truncated record is NEED-MORE (peek again), a malformed one is a REFUSAL. Buggy impl
    // guarded: treating truncation as malformed refuses every connection whose ClientHello arrives
    // in two segments; treating malformed as need-more hangs until the budget expires.
    #[test]
    fn a_partial_record_asks_for_more_and_a_broken_one_refuses() {
        let record = client_hello(Some("example.com"));
        let half = record.len() / 2;
        assert_eq!(
            classify(record.get(..half).expect("split")),
            Peek::NeedMore,
            "a half-arrived ClientHello must be peeked again, not refused"
        );
        // Well-framed record, but the handshake type is a ServerHello.
        let mut bad = record.clone();
        if let Some(b) = bad.get_mut(5) {
            *b = 0x02;
        }
        assert!(
            matches!(classify(&bad), Peek::Malformed(_)),
            "a non-ClientHello handshake must be refused"
        );
        // A length field that claims more than the record holds.
        let mut lying = record.clone();
        if let Some(b) = lying.get_mut(7) {
            *b = 0xff;
        }
        assert!(matches!(classify(&lying), Peek::Malformed(_)));
    }

    // GUEST-CONTROLLED BYTES CROSS AN HTTP BOUNDARY. Buggy impl guarded: dropping
    // `validate_authority_host` from the SNI/Host path lets `\r\n` smuggle a header into the
    // synthesized `CONNECT` line — the assert below is exactly that injection.
    #[test]
    fn a_guest_supplied_authority_cannot_smuggle_a_request_line() {
        assert!(validate_authority_host("example.com").is_ok());
        assert!(validate_authority_host("example.com:8443").is_ok());
        assert!(validate_authority_host("example.com.").is_ok());
        assert!(validate_authority_host("10.0.0.7:443").is_ok());
        for hostile in [
            "example.com\r\nX-Injected: 1",
            "example.com\nX-Injected: 1",
            "example.com HTTP/1.1",
            "example.com/../evil",
            "exa mple.com",
            "",
            ":443",
            "example.com:0",
            "example.com:notaport",
            "example.com\0",
        ] {
            assert!(
                validate_authority_host(hostile).is_err(),
                "`{hostile}` must be refused before it reaches a request line"
            );
        }
        // A 254-byte host is over the DNS limit.
        assert!(validate_authority_host(&"a".repeat(254)).is_err());
    }

    // THE PLAIN-HTTP HALF of §6.4's gap: origin-form + Host reconstructs the absolute URI, and does
    // nothing at all where an authority already exists. Buggy impls guarded: reconstructing
    // unconditionally rewrites an explicit-proxy request's authority to its Host header (they can
    // legitimately differ), and dropping the path/query silently rewrites every request to `/`.
    #[test]
    fn origin_form_plus_host_reconstructs_the_absolute_uri() {
        let origin: http::Uri = "/v1/models?page=2".parse().expect("uri");
        let rebuilt = reconstruct_absolute_uri(&origin, Some("api.example.test"))
            .expect("reconstructs")
            .expect("origin-form must be reconstructed");
        assert_eq!(
            rebuilt.to_string(),
            "http://api.example.test/v1/models?page=2"
        );
        assert_eq!(rebuilt.host(), Some("api.example.test"));

        // A non-default port in the Host header is the client's own truth and is kept.
        let rebuilt = reconstruct_absolute_uri(&"/x".parse().expect("uri"), Some("a.test:8080"))
            .expect("reconstructs")
            .expect("origin-form");
        assert_eq!(rebuilt.to_string(), "http://a.test:8080/x");

        // Already absolute (explicit proxy, or hudsucker's re-stamp inside a MITM'd tunnel): no-op.
        let absolute: http::Uri = "https://other.test/v1".parse().expect("uri");
        assert_eq!(
            reconstruct_absolute_uri(&absolute, Some("api.example.test")).expect("no-op"),
            None
        );

        // No Host at all names no destination: typed refusal, never a guess.
        assert_eq!(
            reconstruct_absolute_uri(&origin, None).expect_err("no host"),
            TransparentError::NoHost
        );
        // A hostile Host is refused by the same one gate.
        assert!(matches!(
            reconstruct_absolute_uri(&origin, Some("a.test\r\nX: 1")),
            Err(TransparentError::BadAuthority { .. })
        ));
    }

    // Which port the synthesized CONNECT names. Buggy impl guarded: always using the local port
    // makes the unprivileged NAT's intake CONNECT to the proxy's own port (a loop); always using 443
    // makes a TPROXY'd non-standard TLS port re-originate to the wrong service.
    #[test]
    fn connect_port_prefers_a_preserved_destination() {
        // Unprivileged NAT: the local address IS the front-end, so there is nothing preserved.
        assert_eq!(connect_port(41234, 41234), 443);
        assert_eq!(connect_port(0, 41234), 443);
        // TPROXY: the local address is the guest's intended destination.
        assert_eq!(connect_port(443, 41234), 443);
        assert_eq!(connect_port(8443, 41234), 8443);
    }

    // The SNI-absent fallback, and the refusal when there is nothing to fall back TO.
    #[test]
    fn a_tls_intake_names_its_destination_or_is_refused() {
        let tproxy: SocketAddr = "93.184.216.34:443".parse().expect("addr");
        let nat: SocketAddr = "127.0.0.1:41234".parse().expect("addr");
        assert_eq!(
            tls_authority(Some("example.com"), nat, 41234).expect("sni names it"),
            "example.com:443"
        );
        assert_eq!(
            tls_authority(Some("example.com"), tproxy, 41234).expect("sni wins"),
            "example.com:443"
        );
        // No SNI, but TPROXY preserved the destination.
        assert_eq!(
            tls_authority(None, tproxy, 41234).expect("original destination"),
            "93.184.216.34:443"
        );
        // No SNI and nothing preserved: refused, never guessed.
        assert!(matches!(
            tls_authority(None, nat, 41234),
            Err(TransparentError::BadAuthority { .. })
        ));
    }

    // The synthesized CONNECT's response gate. Buggy impl guarded: treating any response as success
    // splices a TLS handshake onto a 403 body, so a blocked domain would look like a TLS error
    // instead of a refusal.
    #[test]
    fn only_a_2xx_connect_response_opens_the_tunnel() {
        assert!(connect_response_is_success(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(connect_response_is_success(
            b"HTTP/1.1 204 No Content\r\n\r\n"
        ));
        assert!(!connect_response_is_success(
            b"HTTP/1.1 403 Forbidden\r\n\r\n"
        ));
        assert!(!connect_response_is_success(
            b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
        ));
        assert!(!connect_response_is_success(b"garbage\r\n\r\n"));
        assert!(!connect_response_is_success(b""));
    }
}
