//! The long-lived **host-TCP → guest-vsock** port-forward bridge (§17, Open gaps and future
//! capabilities: "a generic vsock↔TCP bridge … the persistent port-forward bridge remains").
//!
//! It lives beside [`VsockDial`] rather than in a module of its own because the non-portable host
//! half-close — the property its whole API turns on — is measured and documented on that type, one
//! item away.
//!
//! [`MicroVm::dial_vsock`](crate::MicroVm::dial_vsock) is the one-shot primitive: one host→guest
//! byte stream, dialled by a caller that already speaks the guest's protocol. This module is the
//! persistent shape built on it — a host `TcpListener` that accepts ordinary TCP connections and
//! relays each one into a guest AF_VSOCK port, so a tool that knows nothing about vsock (a browser,
//! `psql`, `curl`) reaches an in-guest listener over `127.0.0.1:<port>`.
//!
//! # The half-close problem is the whole design
//!
//! A byte relay has to answer one question the two transports do not agree on: what happens when
//! one side half-closes. Guest→host is portable — the guest's `SHUT_WR` (or exit) surfaces on the
//! host as a clean `Ok(0)` on every backend — so this forwarder always propagates it to the host
//! client. **Host→guest is not portable**: [`VsockDial`] carries the measured per-backend table,
//! and on Firecracker and QEMU a host `shutdown()` tears the whole vsock connection down and
//! *silently* discards whatever the guest had not yet flushed.
//!
//! So the forwarder never guesses. The decision is a value of [`EndOfStream`] carried in
//! [`ForwardOptions`] — explicit in the type, not implicit in a timing assumption — and its
//! default, [`EndOfStream::DrainThenClose`], is the portable one: a host client's half-close is
//! **not** forwarded into the guest at all. What happens instead is a bounded drain
//! ([`ForwardOptions::drain_budget`]), which is exactly the design's advice made mechanical: a
//! protocol whose reply is self-delimiting completes inside the drain, and a protocol that expects
//! the guest to key off EOF does not — on any backend — so the forwarder ends the connection at a
//! deadline it declared rather than hanging on one backend and working on another.
//!
//! # What this module does not do
//!
//! The **reverse** direction (a guest process dialling out through a host-side listener) is not
//! built here, and deliberately: it is not one mechanism but two. On the in-kernel AF_VSOCK
//! transports it is a host AF_VSOCK `bind`/`listen`; on the hybrid AF_UNIX bridges the guest's
//! connect surfaces on a *different host socket path* per backend convention, which
//! [`VsockEndpoint`] does not model and nothing in the tree measures. Building it against one
//! transport and calling it "the reverse forwarder" would ship exactly the kind of
//! quietly-per-backend behavior the half-close table exists to prevent.

use crate::config::Timeouts;
use crate::error::{Error, Result};
use crate::steward::VsockDial;
use crate::vmm::VsockEndpoint;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

/// The per-read relay buffer, in bytes.
///
/// A constant rather than a knob: it is a memory/syscall trade with no observable protocol effect
/// (the relay is a byte pipe — a payload larger than this, larger than a socket window, or larger
/// than [`MAX_FRAME_BYTES`](vmcell_protocol::MAX_FRAME_BYTES) crosses it in as many reads as it
/// takes), and an accepted input that changes nothing a caller can see is a knob nobody can test.
const RELAY_BUF_BYTES: usize = 64 * 1024;

/// The pause after a failed `accept`, so a listener that has gone permanently bad cannot spin.
///
/// A long-lived forwarder must not die on a transient `accept` error (`EMFILE` under load, a peer
/// that reset between the SYN and the accept), and must not busy-loop on a permanent one either.
/// One fixed pause rather than the growing cadence `vmcell-guest-tools`' accept loops use: that
/// growth exists because *their* log is the guest serial console, which vmcell persists as a
/// per-VM artifact, and a host tracing subscriber is not that.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

/// How the forwarder signals **end of stream to the guest** when the host client half-closes its
/// write side.
///
/// The guest→host direction is not configurable: a guest half-close is portable on every backend,
/// so it is always propagated to the host client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum EndOfStream {
    /// **The portable default.** A host client's half-close is *not* forwarded into the guest.
    ///
    /// The guest keeps a fully open connection; the forwarder keeps relaying guest→host for at most
    /// [`ForwardOptions::drain_budget`] and then closes both sides. Nothing is lost on any backend,
    /// because nothing was half-closed on the transport whose half-close is not portable.
    ///
    /// The cost, stated: a guest protocol that waits for EOF before replying never sees one, so it
    /// replies not at all and the connection ends at the drain deadline. That is the same outcome
    /// on all four backends — which is the point. Frame the guest protocol (length prefix,
    /// delimiter, fixed size) rather than reaching for [`EndOfStream::ForwardHalfClose`].
    #[default]
    DrainThenClose,
    /// Forwards the half-close into the guest as [`VsockDial`]'s `shutdown()`.
    ///
    /// **Portable on Cloud Hypervisor and crosvm only.** On Firecracker and QEMU the bridge
    /// translates the host's `SHUT_WR` into a teardown of the whole vsock connection, so a reply
    /// the guest had not yet flushed is discarded — and discarded *silently*, as an ordinary clean
    /// EOF on the next host read. [`VsockDial`] carries the measured table; this is the one arm
    /// that depends on it, so a caller selecting it is choosing its backends and should say so.
    ForwardHalfClose,
}

/// Knobs for a [`PortForward`]. Every field is honored or the bind is refused
/// ([`PortForward::bind`] validates them at construction).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ForwardOptions {
    /// How a host client's half-close reaches the guest. See [`EndOfStream`].
    pub end_of_stream: EndOfStream,
    /// Bounds the **whole** per-connection dial into the guest — transport open plus the hybrid
    /// `CONNECT`/`OK` prologue — through [`VsockDial::connect_endpoint`].
    pub dial_timeout: Duration,
    /// Bounds what remains of a connection once its **first** direction has ended.
    ///
    /// Computed as an absolute [`Instant`] at that moment and enforced over the whole remainder,
    /// never re-armed per poll. Zero is legal and means "close as soon as one direction ends".
    pub drain_budget: Duration,
    /// An optional ceiling on a connection's **entire** life — dial included — as one absolute
    /// deadline propagated into every read, write and half-close.
    ///
    /// `None` (the default) is the long-lived shape this module exists for: a forwarded connection
    /// lives as long as its peers do.
    pub connection_budget: Option<Duration>,
    /// The per-VM cadence the dial's hybrid prologue reads (`connect_ok_read`); the same
    /// [`Timeouts`] the cell was configured with.
    pub timeouts: Timeouts,
}

impl Default for ForwardOptions {
    fn default() -> Self {
        Self {
            end_of_stream: EndOfStream::default(),
            dial_timeout: Duration::from_secs(5),
            drain_budget: Duration::from_secs(5),
            connection_budget: None,
            timeouts: Timeouts::default(),
        }
    }
}

impl ForwardOptions {
    /// Selects how a host client's half-close reaches the guest. See [`EndOfStream`].
    #[must_use]
    pub fn with_end_of_stream(mut self, end_of_stream: EndOfStream) -> Self {
        self.end_of_stream = end_of_stream;
        self
    }

    /// Sets the per-connection dial budget ([`ForwardOptions::dial_timeout`]).
    #[must_use]
    pub fn with_dial_timeout(mut self, dial_timeout: Duration) -> Self {
        self.dial_timeout = dial_timeout;
        self
    }

    /// Sets the post-first-EOF drain budget ([`ForwardOptions::drain_budget`]).
    #[must_use]
    pub fn with_drain_budget(mut self, drain_budget: Duration) -> Self {
        self.drain_budget = drain_budget;
        self
    }

    /// Bounds a connection's whole life, dial included ([`ForwardOptions::connection_budget`]).
    /// `None` restores the long-lived default.
    #[must_use]
    pub fn with_connection_budget(mut self, connection_budget: Option<Duration>) -> Self {
        self.connection_budget = connection_budget;
        self
    }

    /// Uses `timeouts` for the dial's hybrid prologue — hand it the cell's own
    /// [`VmConfig::timeouts`](crate::config::VmConfig::timeouts).
    #[must_use]
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Rejects a value that could never be honored, so a caller learns at `bind` rather than
    /// through a connection that behaves in a way nobody asked for.
    fn validate(&self) -> Result<()> {
        if self.dial_timeout.is_zero() {
            return Err(Error::Config(
                "ForwardOptions::dial_timeout must be non-zero: a zero budget cannot complete a \
                 dial, so every forwarded connection would fail"
                    .into(),
            ));
        }
        match self.connection_budget {
            Some(budget) if budget <= self.dial_timeout => Err(Error::Config(format!(
                "ForwardOptions::connection_budget ({budget:?}) must exceed dial_timeout ({:?}): \
                 the budget bounds the whole connection INCLUDING the dial, so a smaller one \
                 forwards no bytes at all",
                self.dial_timeout
            ))),
            _ => Ok(()),
        }
    }
}

/// Which way bytes are moving, for the counters and the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// Host client → guest listener.
    ToGuest,
    /// Guest listener → host client.
    ToHost,
}

impl Direction {
    /// The direction's name, as the logs spell it.
    fn label(self) -> &'static str {
        match self {
            Self::ToGuest => "client->guest",
            Self::ToHost => "guest->client",
        }
    }
}

/// The forwarder's observable state, shared with every task it owns.
///
/// `Relaxed` throughout: these are monotone counters read for observability and by the gates, never
/// used to order anything.
#[derive(Debug, Default)]
struct ForwardCounters {
    accepted: AtomicU64,
    active: AtomicUsize,
    dial_failures: AtomicU64,
    to_guest: AtomicU64,
    to_host: AtomicU64,
}

impl ForwardCounters {
    /// Adds `n` bytes to `direction`'s total.
    fn add_bytes(&self, direction: Direction, n: u64) {
        match direction {
            Direction::ToGuest => self.to_guest.fetch_add(n, Ordering::Relaxed),
            Direction::ToHost => self.to_host.fetch_add(n, Ordering::Relaxed),
        };
    }
}

/// Ownership of one entry in the active-connection count: the count drops when the relay task's
/// frame is dropped, which includes the abort path the ordered teardown uses.
struct ActiveConnection(Arc<ForwardCounters>);

impl ActiveConnection {
    /// Counts one live connection until this guard is dropped.
    fn new(counters: &Arc<ForwardCounters>) -> Self {
        counters.active.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(counters))
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What every accepted connection is dialled into: shared by `Arc` so the accept loop clones a
/// pointer per connection rather than a `VsockEndpoint` + `Timeouts`.
#[derive(Debug)]
struct Target {
    endpoint: VsockEndpoint,
    guest_port: u32,
    options: ForwardOptions,
}

/// A long-lived host TCP listener relaying each accepted connection into a guest AF_VSOCK port.
///
/// # Teardown is ownership
///
/// The handle **owns** the accept task and, transitively, every per-connection relay task. Nothing
/// outlives it — no listener, no task, no half-open guest connection — and there is exactly **one**
/// ordered teardown, in the accept loop's tail: stop listening, then abort-and-join every relay.
/// Both paths reach that one order through the same signal, and differ only in whether they wait:
///
/// - **The panic path is ownership itself.** The handle holds the only cancel sender, so dropping it
///   — on an unwind, or by falling out of scope — raises the signal the accept loop is waiting on.
///   There is deliberately **no `Drop` impl**: one that re-signalled what the field's own drop
///   already signals would be a second teardown path no test could tell from the first, and a `Drop`
///   that *is* the only signal is a `Drop` somebody can forget to write. What a gate can see is the
///   mechanism — `tests/port_forward.rs`'s dropped-forwarder leg reddens the moment the accept loop
///   stops honoring a dropped sender.
/// - **The graceful path** is [`close`](Self::close): the same signal, raised explicitly, and then
///   awaited, so on return every step has completed.
///
/// ```no_run
/// use vmcell::steward::forward::{ForwardOptions, PortForward};
/// use vmcell::vmm::VmInstance as _;
///
/// # async fn demo<V: vmcell::vmm::Vmm>(vm: &vmcell::MicroVm<V>) -> vmcell::Result<()> {
/// // Everything the guest listener on vsock port 7000 speaks is now reachable over TCP.
/// let forward = PortForward::bind(
///     "127.0.0.1:0".parse().expect("a literal address"),
///     vm.instance().vsock_endpoint(),
///     7000,
///     ForwardOptions::default(),
/// )
/// .await?;
/// let addr = forward.local_addr(); // e.g. hand this to a client that knows nothing about vsock
/// assert_ne!(addr.port(), 0);
/// forward.close().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PortForward {
    local_addr: SocketAddr,
    counters: Arc<ForwardCounters>,
    /// Step 1 of the ordered teardown. A `watch` rather than a flag because it *wakes* the accept
    /// loop and every relay: a polled flag would leave teardown latency at the mercy of whatever
    /// each task happens to be awaiting.
    cancel: watch::Sender<bool>,
    /// `None` once [`PortForward::close`] has taken it, so the graceful path cannot run twice.
    accept: Option<JoinHandle<()>>,
}

impl PortForward {
    /// Binds `listen` and starts forwarding every accepted connection to `guest_port` on
    /// `endpoint`'s guest.
    ///
    /// `endpoint` is the cell's own vsock endpoint — `vm.instance().vsock_endpoint()` — whose port
    /// is replaced by `guest_port`, exactly as [`MicroVm::dial_vsock`](crate::MicroVm::dial_vsock)
    /// does. Bind `127.0.0.1:0` and read [`local_addr`](Self::local_addr) to let the kernel pick a
    /// free port.
    ///
    /// Accepting is immediate; the guest is dialled **per connection**, so a forwarder may be bound
    /// before the in-guest listener exists. A connection whose dial fails is closed and counted
    /// ([`dial_failures`](Self::dial_failures)); the forwarder keeps serving, which is what
    /// "long-lived" has to mean.
    ///
    /// # Errors
    /// [`Error::Config`] when `guest_port` is 0 (`VMADDR_PORT_ANY` is not a listener) or when
    /// `options` carries a value that could never be honored, and [`Error::Io`] — errno intact —
    /// when `listen` cannot be bound.
    pub async fn bind(
        listen: SocketAddr,
        endpoint: VsockEndpoint,
        guest_port: u32,
        options: ForwardOptions,
    ) -> Result<Self> {
        if guest_port == 0 {
            return Err(Error::Config(
                "port-forward guest_port 0 is VMADDR_PORT_ANY, which no guest can listen on".into(),
            ));
        }
        options.validate()?;

        let listener = TcpListener::bind(listen).await.map_err(Error::Io)?;
        let local_addr = listener.local_addr().map_err(Error::Io)?;
        let counters = Arc::new(ForwardCounters::default());
        let (cancel, cancel_rx) = watch::channel(false);
        let target = Arc::new(Target {
            endpoint,
            guest_port,
            options,
        });
        let accept = tokio::spawn(accept_loop(
            listener,
            Arc::clone(&target),
            Arc::clone(&counters),
            cancel_rx,
        ));
        tracing::debug!(
            "port-forward listening on {local_addr}, relaying to guest vsock port {guest_port}"
        );
        Ok(Self {
            local_addr,
            counters,
            cancel,
            accept: Some(accept),
        })
    }

    /// The address actually bound, including the kernel-assigned port when `listen` named port 0.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Connections currently being relayed.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.counters.active.load(Ordering::Relaxed)
    }

    /// Connections accepted since the bind, whether or not their guest dial succeeded.
    #[must_use]
    pub fn accepted_total(&self) -> u64 {
        self.counters.accepted.load(Ordering::Relaxed)
    }

    /// Accepted connections whose dial into the guest failed (no listener on `guest_port`, a dial
    /// that outran [`ForwardOptions::dial_timeout`], a transport that could not be opened).
    #[must_use]
    pub fn dial_failures(&self) -> u64 {
        self.counters.dial_failures.load(Ordering::Relaxed)
    }

    /// Bytes relayed host client → guest.
    #[must_use]
    pub fn bytes_to_guest(&self) -> u64 {
        self.counters.to_guest.load(Ordering::Relaxed)
    }

    /// Bytes relayed guest → host client.
    #[must_use]
    pub fn bytes_to_host(&self) -> u64 {
        self.counters.to_host.load(Ordering::Relaxed)
    }

    /// Raises the teardown signal and takes ownership of the accept task, so the graceful path
    /// cannot run twice.
    ///
    /// The order itself lives in [`accept_loop`]'s tail, spelled once; [`cancelled`] treats a
    /// dropped [`watch::Sender`] exactly as a raised flag, which is what makes dropping the handle
    /// the panic path (see the type's "Teardown is ownership").
    fn signal_teardown(&mut self) -> Option<JoinHandle<()>> {
        self.cancel.send_replace(true);
        self.accept.take()
    }

    /// The graceful teardown: stop accepting, tear every relay down, and **wait** for it.
    ///
    /// On return the listening socket is closed (its port is rebindable) and no task the forwarder
    /// spawned is still running. Dropping the handle instead runs the same ordered teardown without
    /// waiting for it — see [`PortForward`]'s "Teardown is ownership".
    ///
    /// # Errors
    /// [`Error::Network`] if the accept task panicked; the teardown itself has still happened.
    pub async fn close(mut self) -> Result<()> {
        match self.signal_teardown() {
            Some(handle) => handle.await.map_err(|e| {
                Error::Network(format!(
                    "port-forward accept task did not shut down cleanly: {e}"
                ))
            }),
            None => Ok(()),
        }
    }
}

/// Resolves when the forwarder's teardown has been signalled.
///
/// A dropped [`watch::Sender`] means the same thing as a `true` value — the handle is gone — so
/// both arms return rather than one of them wedging a task that would otherwise never be woken.
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

/// Accepts forever, relaying each connection, until the teardown signal — then runs the ordered
/// teardown's tail.
async fn accept_loop(
    listener: TcpListener,
    target: Arc<Target>,
    counters: Arc<ForwardCounters>,
    mut cancel: watch::Receiver<bool>,
) {
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            // Biased so a raised cancel wins over a connection that is queued and ready: teardown
            // must not be starved by a busy listener.
            biased;
            () = cancelled(&mut cancel) => break,
            // Reap finished relays so a long-lived forwarder does not accumulate their handles.
            // Guarded, because `join_next` on an empty set returns `None` at once and would spin.
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((client, peer)) => {
                    counters.accepted.fetch_add(1, Ordering::Relaxed);
                    connections.spawn(relay_connection(
                        client,
                        peer,
                        Arc::clone(&target),
                        Arc::clone(&counters),
                    ));
                }
                Err(e) => {
                    tracing::warn!("port-forward accept failed: {e}");
                    tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
                }
            },
        }
    }

    // THE ORDERED TEARDOWN'S TAIL, spelled once (see `PortForward::signal_teardown`). Stop
    // listening FIRST — the port is free the moment this drops, whether or not a relay is slow to
    // wind down — then abort and JOIN every relay, so "the accept task has finished" means every
    // socket this forwarder opened is closed.
    drop(listener);
    connections.shutdown().await;
}

/// One accepted TCP connection, relayed to the guest for its whole life.
async fn relay_connection(
    client: TcpStream,
    peer: SocketAddr,
    target: Arc<Target>,
    counters: Arc<ForwardCounters>,
) {
    // Dropped when this task ends OR is aborted, so the count cannot survive the teardown.
    let _active = ActiveConnection::new(&counters);

    // ONE absolute deadline for the whole connection, dial included, computed before the first
    // await and propagated outer-bounds-inner from here (`None` = the long-lived shape).
    let deadline = target
        .options
        .connection_budget
        .map(|budget| Instant::now() + budget);
    let dial_timeout = match deadline {
        // The dial gets the smaller of its own budget and what is left of the connection's.
        Some(deadline) => target
            .options
            .dial_timeout
            .min(deadline.saturating_duration_since(Instant::now())),
        None => target.options.dial_timeout,
    };

    let dial = match VsockDial::connect_endpoint(
        &target.endpoint,
        target.guest_port,
        dial_timeout,
        &target.options.timeouts,
    )
    .await
    {
        Ok(dial) => dial,
        Err(e) => {
            counters.dial_failures.fetch_add(1, Ordering::Relaxed);
            // Dropping `client` closes the accepted socket, so the peer learns immediately instead
            // of waiting on a forwarder that has nothing to forward to.
            tracing::warn!(
                "port-forward: dial to guest vsock port {} for {peer} failed: {e}",
                target.guest_port
            );
            return;
        }
    };

    let (client_reader, client_writer) = tokio::io::split(client);
    let (guest_reader, guest_writer) = tokio::io::split(dial);

    // A `JoinSet` rather than two detached `spawn`s: dropping it aborts both directions, which is
    // what makes "the forwarder owns its tasks" true through the abort path as well as the tidy one.
    let mut directions: JoinSet<(Direction, std::io::Result<u64>)> = JoinSet::new();
    let eos = target.options.end_of_stream;
    let to_guest_counters = Arc::clone(&counters);
    directions.spawn(async move {
        (
            Direction::ToGuest,
            client_to_guest(
                client_reader,
                guest_writer,
                eos,
                deadline,
                &to_guest_counters,
            )
            .await,
        )
    });
    let to_host_counters = Arc::clone(&counters);
    directions.spawn(async move {
        (
            Direction::ToHost,
            guest_to_client(guest_reader, client_writer, deadline, &to_host_counters).await,
        )
    });

    if let Some(first) = directions.join_next().await {
        log_direction(peer, first);
    }
    // The drain bounds what is LEFT of the connection once one direction has ended: one absolute
    // deadline over the whole remainder (and never past the connection budget), not a per-poll
    // window. This is where `EndOfStream::DrainThenClose` gets its "then close".
    let drain_deadline = match deadline {
        Some(deadline) => deadline.min(Instant::now() + target.options.drain_budget),
        None => Instant::now() + target.options.drain_budget,
    };
    match tokio::time::timeout_at(drain_deadline, directions.join_next()).await {
        Ok(Some(second)) => log_direction(peer, second),
        Ok(None) => {}
        Err(_elapsed) => tracing::debug!(
            "port-forward: {peer} drained for {:?} after its first direction ended; closing",
            target.options.drain_budget
        ),
    }
    // Whatever is left is aborted and JOINED here, so no relay outlives its connection.
    directions.shutdown().await;
}

/// Renders one finished direction, so a relay failure is visible rather than swallowed.
fn log_direction(
    peer: SocketAddr,
    finished: std::result::Result<(Direction, std::io::Result<u64>), tokio::task::JoinError>,
) {
    match finished {
        Ok((direction, Ok(bytes))) => {
            tracing::trace!(
                "port-forward {peer}: {} ended after {bytes} bytes",
                direction.label()
            );
        }
        Ok((direction, Err(e))) => {
            tracing::debug!("port-forward {peer}: {} ended: {e}", direction.label());
        }
        Err(e) => tracing::warn!("port-forward {peer}: a relay task did not finish cleanly: {e}"),
    }
}

/// Host client → guest, then the [`EndOfStream`] decision.
async fn client_to_guest(
    reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<VsockDial>,
    end_of_stream: EndOfStream,
    deadline: Option<Instant>,
    counters: &ForwardCounters,
) -> std::io::Result<u64> {
    let moved = pump(reader, &mut writer, Direction::ToGuest, deadline, counters).await?;
    match end_of_stream {
        // Deliberately nothing: see `EndOfStream::DrainThenClose`. The guest's connection stays
        // whole, so no backend's bridge can discard a reply that is still in flight.
        EndOfStream::DrainThenClose => {}
        EndOfStream::ForwardHalfClose => half_close_guest_write_side(&mut writer, deadline).await?,
    }
    Ok(moved)
}

/// **The one site that half-closes the guest side of a forwarded connection.**
///
/// Isolated as its own function because it is the non-portable operation the module's whole design
/// turns on ([`VsockDial`]'s table): a second call site anywhere would be a half-close nobody chose
/// through [`EndOfStream`]. `steward::forward::tests::half_close_gate` pins that it has exactly one
/// caller in the crate.
async fn half_close_guest_write_side(
    writer: &mut tokio::io::WriteHalf<VsockDial>,
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    bounded(deadline, writer.shutdown(), "guest half-close").await
}

/// Guest → host client, then the portable half-close.
async fn guest_to_client(
    reader: tokio::io::ReadHalf<VsockDial>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    deadline: Option<Instant>,
    counters: &ForwardCounters,
) -> std::io::Result<u64> {
    let moved = pump(reader, &mut writer, Direction::ToHost, deadline, counters).await?;
    // Unconditional, and this is the direction where that is safe: a guest half-close is portable
    // on every backend, so the host client is told the guest is done exactly when it is.
    bounded(deadline, writer.shutdown(), "client half-close").await?;
    Ok(moved)
}

/// Moves bytes from `reader` to `writer` until the reader's EOF, counting them.
///
/// **Counts are honored, never assumed.** A read reports how many bytes it put in the buffer, and
/// only that prefix is written (`get(..n)`, so a length that could not be a prefix is an error and
/// not a silent slice of stale bytes from a previous iteration). `write_all` is the loop over
/// partial writes: it re-offers the unwritten remainder and fails loud (`WriteZero`) rather than
/// dropping a tail — the defect class that shipped in the NAT's `send_slice` path.
async fn pump<R, W>(
    mut reader: R,
    writer: &mut W,
    direction: Direction,
    deadline: Option<Instant>,
    counters: &ForwardCounters,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF_BYTES];
    let mut total: u64 = 0;
    loop {
        let read = bounded(deadline, reader.read(&mut buf), direction.label()).await?;
        if read == 0 {
            break;
        }
        let chunk = buf.get(..read).ok_or_else(|| {
            std::io::Error::other(format!(
                "{}: a read reported {read} bytes into a {}-byte buffer",
                direction.label(),
                RELAY_BUF_BYTES
            ))
        })?;
        bounded(deadline, writer.write_all(chunk), direction.label()).await?;
        let moved = u64::try_from(read).map_err(std::io::Error::other)?;
        total = total.saturating_add(moved);
        counters.add_bytes(direction, moved);
    }
    bounded(deadline, writer.flush(), direction.label()).await?;
    Ok(total)
}

/// Bounds one awaited step by the connection's **absolute** deadline.
///
/// Absolute, so the budget bounds the whole connection rather than each step of it: a relay that
/// makes a little progress every second cannot renew its own budget forever.
async fn bounded<F, T>(deadline: Option<Instant>, op: F, what: &str) -> std::io::Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    match deadline {
        None => op.await,
        Some(deadline) => match tokio::time::timeout_at(deadline, op).await {
            Ok(result) => result,
            Err(_elapsed) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{what} exceeded the port-forward connection budget"),
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Accepted inputs are honored or refused AT CONSTRUCTION.
    // ---------------------------------------------------------------------

    #[test]
    fn the_default_end_of_stream_is_the_portable_one() {
        // Not decoration: the default decides what happens on Firecracker and QEMU for every caller
        // who never read the table. RED ON THE INVERSE: move `#[default]` to `ForwardHalfClose` and
        // this fails — which is the review conversation that change has to have.
        assert_eq!(EndOfStream::default(), EndOfStream::DrainThenClose);
        assert_eq!(
            ForwardOptions::default().end_of_stream,
            EndOfStream::DrainThenClose
        );
    }

    #[test]
    fn default_options_are_accepted() {
        ForwardOptions::default()
            .validate()
            .expect("the shipped defaults must be a legal configuration");
    }

    #[test]
    fn a_zero_dial_timeout_is_refused() {
        let options = ForwardOptions::default().with_dial_timeout(Duration::ZERO);
        let err = options
            .validate()
            .expect_err("a zero dial budget can never complete a dial");
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
        assert!(
            err.to_string().contains("dial_timeout"),
            "the refusal must name the field: {err}"
        );
    }

    #[test]
    fn a_connection_budget_that_cannot_outlive_the_dial_is_refused() {
        let options = ForwardOptions::default()
            .with_dial_timeout(Duration::from_secs(5))
            .with_connection_budget(Some(Duration::from_secs(5)));
        let err = options
            .validate()
            .expect_err("a budget that the dial alone consumes forwards no bytes");
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
        // …and one microsecond more is legal: the refusal is a boundary, not a ban on tight budgets.
        options
            .with_connection_budget(Some(Duration::from_secs(5) + Duration::from_micros(1)))
            .validate()
            .expect("a budget above the dial's is fine");
    }

    #[tokio::test]
    async fn binding_to_guest_port_zero_is_refused() {
        let err = PortForward::bind(
            "127.0.0.1:0".parse().expect("literal"),
            VsockEndpoint::Vsock { cid: 3, port: 5000 },
            0,
            ForwardOptions::default(),
        )
        .await
        .expect_err("VMADDR_PORT_ANY is not a listener");
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_refused_bind_reports_the_os_error() {
        // Port 1 on loopback: EACCES unprivileged. A typed `Error::Io` with errno intact, never a
        // stringly-typed "bind failed".
        let err = PortForward::bind(
            "127.0.0.1:1".parse().expect("literal"),
            VsockEndpoint::Vsock { cid: 3, port: 5000 },
            7000,
            ForwardOptions::default(),
        )
        .await
        .expect_err("binding a privileged port unprivileged must fail");
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
    }

    // ---------------------------------------------------------------------
    // The count law, with no VM in sight.
    // ---------------------------------------------------------------------

    /// A cheap order-sensitive digest, so a dropped, duplicated or reordered span is visible.
    fn digest(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    // `pump`'s two count obligations, driven so that BOTH can fail. The source delivers the payload
    // in ~1.5 KiB bursts, so a read returns far less than the 64 KiB buffer it was handed (the
    // "consume only what the read filled" arm); the sink takes 64 bytes at a time, so nearly every
    // write is partial (the "loop the remainder, never drop it" arm). A first cut of this test used
    // one 64-byte pipe on each side, which made every read exactly 64 bytes and every write whole —
    // and BOTH inverses below passed against it. The asymmetry is the test.
    //
    // The drainer stops reading the moment it has seen more than was sent, which breaks the pipe and
    // fails the pump immediately: an inflating relay is a fast red instead of a slow one.
    //
    // RED ON THE INVERSE (both arms driven, both verified):
    //   * write `&buf` instead of `buf.get(..read)` → ~64 KiB per ~1.5 KiB read: the drainer trips
    //     its excess guard, the sink closes and the pump fails loud;
    //   * replace `write_all` with a single `write` → every partial write's tail is dropped: the
    //     sink receives 1024 of 1048576 bytes.
    #[tokio::test]
    async fn pump_moves_every_byte_through_a_backpressuring_pipe() {
        // 1 MiB in ~1.5 KiB bursts over a sink that takes 64 bytes at a time: ~16k partial writes.
        let payload: Vec<u8> = (0..1024u64 * 1024)
            .map(|i| i.wrapping_mul(2_654_435_761) as u8)
            .collect();
        let want = digest(&payload);
        let sent_len = payload.len();

        let (source_near, mut source_far) = tokio::io::duplex(256 * 1024);
        let (sink_near, mut sink_far) = tokio::io::duplex(64);

        let feeder = {
            let payload = payload.clone();
            tokio::spawn(async move {
                for burst in payload.chunks(1500) {
                    source_far.write_all(burst).await.expect("feed");
                    // Let the pump run between bursts, so its reads see a burst rather than the
                    // whole payload — that is what makes a read SHORT.
                    tokio::task::yield_now().await;
                }
                source_far.shutdown().await.expect("feeder half-close");
            })
        };
        let drainer = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut scratch = vec![0u8; 8192];
            loop {
                let read = sink_far.read(&mut scratch).await.expect("drain");
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(scratch.get(..read).expect("read fits its buffer"));
                if seen.len() > sent_len {
                    // Excess: stop reading. The sink closes, so the pump fails at once.
                    break;
                }
            }
            seen
        });

        let counters = ForwardCounters::default();
        let mut sink_near = sink_near;
        let moved = pump(
            source_near,
            &mut sink_near,
            Direction::ToGuest,
            None,
            &counters,
        )
        .await
        .expect(
            "the pump failed on a healthy pipe — a relay that writes MORE than the read filled \
             trips the drainer's excess guard and breaks the pipe",
        );
        drop(sink_near); // let the drainer see EOF
        feeder.await.expect("feeder task");
        let seen = drainer.await.expect("drainer task");

        assert_eq!(
            usize::try_from(moved).expect("a 1 MiB count fits usize"),
            sent_len,
            "the pump must report every byte it moved"
        );
        assert_eq!(seen.len(), sent_len, "the sink must receive every byte");
        assert_eq!(
            digest(&seen),
            want,
            "the relayed bytes must be the SAME bytes, in order"
        );
        assert_eq!(
            counters.to_guest.load(Ordering::Relaxed),
            moved,
            "the counter and the return value are one fact"
        );
    }

    // The absolute deadline bounds the WHOLE pump, not the gap between two polls: a peer that keeps
    // dribbling one byte per tick makes progress forever and must still be cut off at the deadline.
    // RED ON THE INVERSE: re-arm the budget per read (a `timeout(d, ..)` inside the loop instead of
    // `timeout_at(deadline, ..)`) and this never returns.
    #[tokio::test]
    async fn a_connection_deadline_bounds_a_pump_that_is_always_making_progress() {
        let (near, mut far) = tokio::io::duplex(64);
        let dribbler = tokio::spawn(async move {
            loop {
                if far.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let (sink_near, sink_far) = tokio::io::duplex(64 * 1024);
        let reader = tokio::spawn(async move {
            let mut sink_far = sink_far;
            let mut scratch = vec![0u8; 4096];
            while sink_far.read(&mut scratch).await.unwrap_or(0) > 0 {}
        });

        let counters = ForwardCounters::default();
        let started = Instant::now();
        let mut sink_near = sink_near;
        let err = pump(
            near,
            &mut sink_near,
            Direction::ToGuest,
            Some(started + Duration::from_millis(300)),
            &counters,
        )
        .await
        .expect_err("the deadline must cut a still-progressing pump off");
        let elapsed = started.elapsed();

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "got {err}");
        assert!(
            elapsed < Duration::from_secs(3),
            "the pump ran {elapsed:?} past a 300 ms deadline — the budget is being re-armed per poll"
        );
        assert!(
            counters.to_guest.load(Ordering::Relaxed) > 0,
            "the peer WAS making progress; a vacuous timeout proves nothing"
        );
        dribbler.abort();
        reader.abort();
    }

    // ---------------------------------------------------------------------
    // Call-site gate: the non-portable half-close has ONE site.
    // ---------------------------------------------------------------------

    /// The guest-side half-close is the one operation [`VsockDial`]'s table says is not portable, so
    /// it is spelled once and reached only through [`EndOfStream::ForwardHalfClose`]. Nothing about
    /// planting a second `shutdown()` is a compile error — a relay is exactly the shape of code where
    /// "and then close the other side too" reads as tidy — so a source scan is the only thing that can
    /// go red on it.
    ///
    /// Shares the crate's ONE source walker (`net::tap::netns_layout_gate::production_sources`); the
    /// predicate is this gate's own, as `net::usage`'s is. The zero-file scan is a misconfiguration,
    /// never a clean verdict (docs/90 G4).
    mod half_close_gate {
        use std::collections::BTreeMap;

        /// The one guest-side half-close helper: its definition plus its single call site.
        const HELPER_NEEDLE: &str = "half_close_guest_write_side";

        /// A stream half-close, as this crate spells one. Both live in the forwarder: one per
        /// direction. (`JoinSet::shutdown` is `connections.shutdown()` / `directions.shutdown()`,
        /// which this needle deliberately does not match.)
        const SHUTDOWN_NEEDLE: &str = "writer.shutdown()";

        /// `(file relative to `crates/vmcell/src`, production occurrences)`.
        const HELPER_ROSTER: &[(&str, usize)] = &[("steward/forward.rs", 2)];

        /// One per direction, in the one module that relays: the guest's (inside the helper above,
        /// behind the `ForwardHalfClose` arm) and the client's (unconditional, and portable).
        const SHUTDOWN_ROSTER: &[(&str, usize)] = &[("steward/forward.rs", 2)];

        /// Files the scan must have opened for any verdict to mean anything: the law's own file, the
        /// two other host-side vsock modules a second half-close would most plausibly land in, and
        /// the orchestrator that owns `MicroVm`.
        const MUST_SCAN: &[&str] = &[
            "steward/forward.rs",
            "steward/mod.rs",
            "steward/session.rs",
            "orchestrator.rs",
        ];

        /// The verdict as a pure function of the file set, so the misconfiguration arms below are
        /// drivable without deleting the tree.
        fn audit(
            sources: &[(String, String)],
            needle: &str,
            roster: &[(&str, usize)],
            must_scan: &[&str],
        ) -> Result<(), String> {
            if sources.is_empty() {
                return Err(format!(
                    "gate misconfigured: the scan for {needle:?} read ZERO files. The only way to \
                     open nothing is to have been pointed at nothing; a verdict over an empty tree \
                     is vacuous, not clean"
                ));
            }
            for required in must_scan {
                if !sources.iter().any(|(rel, _)| rel == required) {
                    return Err(format!(
                        "gate misconfigured: the scan for {needle:?} never read {required}; it is \
                         walking the wrong tree and would pass vacuously"
                    ));
                }
            }
            let found: BTreeMap<&str, usize> = sources
                .iter()
                .map(|(rel, text)| (rel.as_str(), text.matches(needle).count()))
                .filter(|(_, count)| *count > 0)
                .collect();
            let expected: BTreeMap<&str, usize> = roster.iter().copied().collect();
            if found == expected {
                Ok(())
            } else {
                Err(format!(
                    "the {needle:?} law must be spelled ONLY by its roster. found={found:?} \
                     expected={expected:?}. An extra entry is a half-close no caller chose through \
                     `EndOfStream` — route it through `half_close_guest_write_side` behind the \
                     `ForwardHalfClose` arm instead. A missing or moved entry means the law itself \
                     was renamed or relocated; move the row with it in the same change"
                ))
            }
        }

        #[test]
        fn the_guest_half_close_has_exactly_one_call_site() {
            let sources = crate::net::tap::netns_layout_gate::production_sources();
            audit(&sources, HELPER_NEEDLE, HELPER_ROSTER, MUST_SCAN)
                .expect("guest half-close roster");
        }

        #[test]
        fn a_forwarded_stream_is_half_closed_in_exactly_two_places() {
            let sources = crate::net::tap::netns_layout_gate::production_sources();
            audit(&sources, SHUTDOWN_NEEDLE, SHUTDOWN_ROSTER, MUST_SCAN)
                .expect("stream half-close roster");
        }

        // THE ZERO-FILE ARM, driven rather than asserted about. RED ON THE INVERSE: delete `audit`'s
        // `sources.is_empty()` guard and an empty scan starts reporting a difference against a
        // one-row roster instead of a misconfiguration — and a roster that ever becomes empty would
        // then match an unread tree perfectly, which is how a gate wears a green verdict on nothing.
        #[test]
        fn the_audit_reports_an_empty_tree_as_a_misconfiguration() {
            let empty: Vec<(String, String)> = Vec::new();
            let err = audit(&empty, HELPER_NEEDLE, &[], MUST_SCAN)
                .expect_err("an empty tree must not be a clean verdict");
            assert!(err.contains("gate misconfigured"), "got {err}");

            // …and a non-empty scan that simply missed the law's own file is the same class.
            let partial = vec![("steward/session.rs".to_string(), String::new())];
            let err = audit(&partial, HELPER_NEEDLE, HELPER_ROSTER, MUST_SCAN)
                .expect_err("a scan missing the law's file must not pass");
            assert!(err.contains("gate misconfigured"), "got {err}");
        }

        // The needles are countable and prose is not a call site — the comparison both rosters rest
        // on — and a re-planted half-close is visible as a difference.
        #[test]
        fn the_gate_reddens_on_a_second_half_close() {
            let mut sources: Vec<(String, String)> = MUST_SCAN
                .iter()
                .map(|f| ((*f).to_string(), String::new()))
                .collect();
            for (rel, text) in &mut sources {
                if rel == "steward/forward.rs" {
                    *text = format!("fn {HELPER_NEEDLE}() {{}}\n{HELPER_NEEDLE}(w).await?;");
                }
            }
            audit(&sources, HELPER_NEEDLE, HELPER_ROSTER, MUST_SCAN)
                .expect("the fixture reproduces the shipped roster");

            // A third call site anywhere — here, the session module reaching for the same helper.
            for (rel, text) in &mut sources {
                if rel == "steward/session.rs" {
                    *text = format!("{HELPER_NEEDLE}(&mut w, None).await?;");
                }
            }
            let err = audit(&sources, HELPER_NEEDLE, HELPER_ROSTER, MUST_SCAN)
                .expect_err("a second caller must redden the roster");
            assert!(err.contains("steward/session.rs"), "got {err}");

            // And prose naming the helper in a comment is NOT a call site only because the roster
            // counts every occurrence in the file that owns it — which is why the row is 2 (the
            // definition and its one call), not 1.
            assert_eq!(
                "// see half_close_guest_write_side for why"
                    .matches(HELPER_NEEDLE)
                    .count(),
                1,
                "the needle must be countable in prose too — the roster is a COUNT, so a comment \
                 mentioning the helper in another file is a difference the reviewer must resolve"
            );
        }
    }
}
