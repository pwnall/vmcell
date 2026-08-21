#[cfg(feature = "net-unprivileged")]
/// Low-level backend networking types and state for `smoltcp`.
pub mod backend {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use vhost::vhost_user::Listener;
    use vhost::vhost_user::message::VhostUserProtocolFeatures;
    use vhost_user_backend::{
        VhostUserBackendMut, VhostUserDaemon, VringMutex, VringState, VringT,
    };
    use virtio_bindings::bindings::virtio_ring::{
        VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
    };
    use virtio_queue::{DescriptorChain, QueueOwnedT};
    use vm_memory::{
        Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
    };
    use vmm_sys_util::epoll::EventSet;
    use vmm_sys_util::event::{EventConsumer, EventNotifier};

    use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
    use smoltcp::time::Instant;
    use smoltcp::wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
        IpListenEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket,
    };

    const VIRTIO_F_VERSION_1: u32 = 32;
    const QUEUE_SIZE: usize = 1024;
    const NUM_QUEUES: usize = 2; // rx and tx

    /// Number of bytes to read from the host stream this poll tick so the
    /// following `send_slice` enqueues **all** of them (C-NET-1). Bounded by the
    /// smoltcp socket's free TX room (`capacity - queued`) and the scratch buffer
    /// length: reading more than the socket can accept would leave an un-enqueued
    /// tail that the host→guest pump would silently drop, corrupting the stream.
    fn host_read_budget(send_capacity: usize, send_queue: usize, buf_len: usize) -> usize {
        send_capacity.saturating_sub(send_queue).min(buf_len)
    }

    /// Performs one guest→host drain step from inside `TcpSocket::recv`'s closure
    /// and returns `(bytes to consume from the RX ring, the host write's result)`
    /// (B1, `nat-guest-to-host-wrap-panic`).
    ///
    /// `contiguous` is exactly what `recv` hands its closure: the **largest
    /// contiguous** run of queued octets, `min(len, capacity - read_at)`.
    /// `RingBuffer::dequeue_many_with` then `assert!`s — a real assert, not a
    /// debug one — that the returned count fits that slice. The pre-fix pump
    /// peeked with `peek_slice`, whose `read_allocated` does a **two-part copy
    /// across the ring wrap**, and fed the resulting count back to `recv`: on any
    /// sustained >64 KiB guest→host stream, the first tick whose queued data
    /// straddles the 65536-byte ring boundary returned a count larger than the
    /// contiguous span and tripped that assert, killing the `run_network` thread
    /// while the vhost thread kept the device attached — a silently wedged link,
    /// on a path NET-1/C2 requires to never panic. Writing from inside the closure
    /// makes `consumed <= contiguous.len()` true by construction; the wrapped
    /// remainder drains on the next tick, with no data loss.
    ///
    /// A short host write consumes exactly the accepted prefix (the unwritten tail
    /// stays queued for the next tick); an error — `WouldBlock` or fatal — consumes
    /// nothing, so nothing is dropped on the floor.
    fn drain_to_host<W>(contiguous: &[u8], write: W) -> (usize, std::io::Result<usize>)
    where
        W: FnOnce(&[u8]) -> std::io::Result<usize>,
    {
        if contiguous.is_empty() {
            return (0, Ok(0));
        }
        let res = write(contiguous);
        let consumed = match &res {
            // The `min` is belt-and-braces: a writer over-reporting what it took
            // would re-arm the very `dequeue_many_with` assert this helper defuses.
            Ok(written) => (*written).min(contiguous.len()),
            Err(_) => 0,
        };
        (consumed, res)
    }

    /// Bit position of `VIRTIO_NET_F_CTRL_VQ` in the virtio-net feature set.
    ///
    /// The backend deliberately does **not** advertise this bit (NET-2): it
    /// declares only [`NUM_QUEUES`] `== 2` (rx/tx) and `handle_event` services no
    /// control queue, so advertising an unbacked control vq is dead-feature drift
    /// a guest driver could act on. Named here so the guard test can assert the
    /// advertised set keeps it clear (test-only; production never references the
    /// omitted bit).
    #[cfg(test)]
    const VIRTIO_NET_F_CTRL_VQ_BIT: u32 = 17;

    /// Bit position of `VIRTIO_NET_F_MAC` (device supplies a fixed MAC).
    const VIRTIO_NET_F_MAC_BIT: u32 = 5;

    /// The virtio feature set advertised by the unprivileged vhost-user-net
    /// backend.
    ///
    /// Extracted from `VhostUserBackendMut::features` so the exact advertised bit
    /// set is unit-testable without constructing a live backend (NET-2). It
    /// advertises virtio 1.0, indirect descriptors, the event-index optimization,
    /// the vhost-user protocol features, and a fixed MAC — and deliberately
    /// **omits** `VIRTIO_NET_F_CTRL_VQ`, for which there is no control queue or
    /// handler here.
    fn advertised_features() -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | vhost::vhost_user::message::VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
            | (1 << VIRTIO_NET_F_MAC_BIT)
    }

    // virtio-net header size is 12 bytes
    const VIRTIO_NET_HDR_SIZE: usize = 12;

    /// Maximum length of a single guest TX frame the NAT will buffer: 1500 (the
    /// `max_transmission_unit` this device reports to smoltcp) plus the 12-byte
    /// virtio-net header. The bound stops a crafted descriptor chain from forcing
    /// a multi-gigabyte host allocation off a guest-controlled `desc.len()`.
    ///
    /// It is a *cap*, not an equality (`max-frame-len-comment-overstates`): on
    /// `Medium::Ethernet` smoltcp's `max_transmission_unit` is frame-inclusive
    /// (it counts the 14-byte Ethernet header), while the guest — never told an
    /// MTU, since `VIRTIO_NET_F_MTU` is not advertised — uses a 1500-byte *IP*
    /// MTU. A legitimate full-MTU guest frame is therefore 12 + 14 + 1500 = 1526
    /// bytes and IS dropped here; the older comment's "a frame never legitimately
    /// exceeds this" conflated the two MTUs. That is inert today because this NAT
    /// forwards TCP only and the MSS it offers comes off smoltcp's frame-inclusive
    /// MTU (`ip_mtu()` = 1500 − 14 = 1486, minus 20 + 20 of IP/TCP headers = 1446),
    /// so the largest legitimate guest TCP frame is 12 + 14 + 20 + 20 + 1446 = 1512
    /// — exactly this cap (no segmentation offload either:
    /// `VIRTIO_NET_F_GUEST_TSO`/`GSO` are not negotiated). Raising the cap is a
    /// data-plane change, not a comment fix: revisit it when non-TCP forwarding
    /// lands.
    const MAX_FRAME_LEN: usize = VIRTIO_NET_HDR_SIZE + 1500;

    /// Returns how many bytes of a TX descriptor may be read into a frame that
    /// has already accumulated `accumulated` bytes, or `None` if reading the
    /// full descriptor would push the frame past [`MAX_FRAME_LEN`].
    ///
    /// `desc_len` is guest-controlled (a virtio descriptor length, up to 4 GiB),
    /// so it must be bounded before it is ever used as an allocation size.
    fn bounded_tx_read(desc_len: usize, accumulated: usize) -> Option<usize> {
        let remaining = MAX_FRAME_LEN.checked_sub(accumulated)?;
        if desc_len > remaining {
            None
        } else {
            Some(desc_len)
        }
    }

    /// Depth bound on the guest→host frame queue ([`SharedState::tx_queue`]), in frames.
    ///
    /// The queue's only consumer is `run_network`'s poll tick, and that tick legitimately stalls:
    /// one mapping's host dial owns the single datapath task for up to [`HOST_DIAL_BUDGET`]. An
    /// unbounded queue hands a guest that keeps kicking its TX ring during such a stall unbounded
    /// *host* memory — the same hostile-guest surface as the [`MAX_FRAME_LEN`] cap, one level up
    /// (per-frame bytes were bounded; the frame count was not).
    ///
    /// Sized at four ring-depths (≈6 MB at the 1512-byte frame cap) so a legitimately bursty guest
    /// is never dropped: the vhost worker can drain the guest's whole 1024-descriptor ring several
    /// times between two 5 ms poll ticks, and only a genuinely stalled consumer reaches the bound.
    const MAX_TX_QUEUE_FRAMES: usize = 4 * QUEUE_SIZE;

    /// Queues one guest→host frame for the smoltcp poll loop, honoring [`MAX_TX_QUEUE_FRAMES`].
    /// Returns whether the frame was queued (`false` = tail-dropped).
    ///
    /// A full queue tail-drops, the way a NIC does under overload, rather than growing: the
    /// descriptor is still returned to the guest (so its ring never stalls), and TCP retransmits
    /// what was dropped. Dropping is the *only* correct answer here — the alternative, blocking the
    /// vhost worker until the net thread catches up, would hold the state mutex the net thread
    /// itself needs to drain the queue.
    fn push_tx_frame(tx_queue: &mut VecDeque<Vec<u8>>, payload: &[u8]) -> bool {
        if tx_queue.len() >= MAX_TX_QUEUE_FRAMES {
            return false;
        }
        tx_queue.push_back(payload.to_vec());
        true
    }

    /// How often a *sustained* tail drop repeats its report: one line per this many dropped frames,
    /// after the first.
    ///
    /// A stalled consumer drops at whatever rate the guest kicks, so a line per frame would be its
    /// own flood — the console log is a persisted artifact. One queue-depth's worth per line keeps a
    /// sustained overload to a trickle while still growing with it.
    const TX_DROP_REPORT_EVERY: u64 = MAX_TX_QUEUE_FRAMES as u64;

    /// Whether the `total`-th tail-dropped guest→host frame is one that gets logged: the **first**
    /// always, then every [`TX_DROP_REPORT_EVERY`]-th.
    ///
    /// [`push_tx_frame`]'s drop is otherwise completely silent — the guest gets its descriptor back,
    /// TCP retransmits, and nothing on the host says the NAT is behind — so the bound needs an
    /// operator-visible signal or it is a silent data-plane behavior change. The first drop is
    /// always reported because "it happened at all" is the interesting bit: a NAT that reaches a
    /// four-ring-deep queue has a stalled consumer, which is a bug report, not a tuning hint.
    fn tx_drop_is_reportable(total: u64) -> bool {
        total == 1 || total.is_multiple_of(TX_DROP_REPORT_EVERY)
    }

    /// Computes the smoltcp interface addresses for `vmid` from the shared
    /// `crate::net::ip_math` /30 host-IP math (M-NET-2/NET-4): the host gateway
    /// (`10.200.n.1`, assigned to the NAT interface) and the guest address
    /// (`10.200.n.2`, used as the default-route gateway). Returns an error for an
    /// out-of-range vmid — which `run_network` surfaces loudly and then exits its
    /// thread cleanly instead of panicking. This is the *single* place the /30
    /// addresses are derived (no re-hardcoded `10.200.x.y` literals) and the exact
    /// fallible prologue the NET-4 guard test drives.
    fn nat_addrs(vmid: u32) -> crate::error::Result<(Ipv4Address, Ipv4Address)> {
        let (host_gw_std, guest_ip_std, _) = crate::net::ip_math(vmid)?;
        // smoltcp 0.13's `Ipv4Address` is a re-export of `core::net::Ipv4Addr`
        // (== `std::net::Ipv4Addr`), so `ip_math`'s std addresses already ARE `Ipv4Address` —
        // returned directly (an explicit `Ipv4Address::from` would be a useless self-conversion).
        Ok((host_gw_std, guest_ip_std))
    }

    /// Computes the used length to report for an RX frame delivery (L-NET-2).
    ///
    /// `offset` is how many bytes of the `frame_len`-byte frame were written into
    /// the guest's writable descriptors. If the whole frame fit, report it
    /// (`Some(frame_len)`); if it was truncated (the writable descriptors could
    /// not hold the frame) or a descriptor write failed, the partial bytes must
    /// NOT be forwarded — return `None` so the caller drops the frame and returns
    /// the descriptor with a zero used length instead of a corrupt, truncated one.
    fn rx_used_len(offset: usize, frame_len: usize, write_failed: bool) -> Option<usize> {
        if write_failed || offset < frame_len {
            None
        } else {
            Some(frame_len)
        }
    }

    /// MAC address for the host side of the unprivileged NAT.
    ///
    /// The third octet (`0xff`) is chosen so this address lies outside the range
    /// `crate::net::mac_math` can ever produce for a valid vmid (1..=254), whose
    /// third octet is always `0`. This guarantees the host NAT MAC can never
    /// collide with a guest MAC (NET-2). The old `02:00:00:00:00:fe` collided
    /// with `mac_math(254)`, silently wedging that link.
    const HOST_NAT_MAC: [u8; 6] = [0x02, 0x00, 0xff, 0x00, 0x00, 0xfe];

    /// Upper bound on dynamically-created NAT sockets (proxy interception).
    ///
    /// A guest sending SYNs to many distinct destination ports would otherwise
    /// grow the socket/port-map pool without bound (~128 KiB of buffers per
    /// socket). Capping the pool and reclaiming closed mappings bounds host
    /// memory (NET-5).
    const MAX_DYNAMIC_SOCKETS: usize = 256;

    /// Number of listening sockets pre-armed each time a guest SYN finds **no unclaimed listener**
    /// for its destination port (a small burst absorbs quick reconnects without a per-connection
    /// round trip). Growth is refused once the pool would exceed [`MAX_DYNAMIC_SOCKETS`];
    /// `MAX_DYNAMIC_SOCKETS` is a multiple of this.
    ///
    /// Not "per newly-seen port": an accepted connection stops being a listener, so a port whose
    /// burst is fully claimed earns another one (see [`syn_already_served`]) — otherwise concurrency
    /// per destination is capped at this constant. Since the TX scan runs before the poll that
    /// claims listeners, more than `SYN_BURST` simultaneous SYNs to one port converge over
    /// consecutive ticks (the guest's own SYN retry), rather than being refused forever.
    const SYN_BURST: usize = 4;

    /// Number of listening sockets pre-armed per **forwarded** port (invariant #4,
    /// design §6.2). A single `TcpSocket` per port means one HTTP keep-alive
    /// connection holds the only slot and silently wedges the link, so the pool is
    /// sized for concurrent *and* keep-alive connections (≈16 per port). These are
    /// the permanent forward-port listeners; the dynamic SYN-intercept pool is
    /// bounded separately by [`MAX_DYNAMIC_SOCKETS`].
    const FORWARD_PORT_POOL: usize = 16;

    /// Per-worker deadline for `SmoltcpProcess::Drop` to join a thread before
    /// detaching it, so a wedged worker cannot hang teardown forever (NET-3).
    const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Whole-operation budget for the NAT's per-mapping dial to the host-side target
    /// (`nat-host-dial-unbounded`).
    ///
    /// The dial runs on the **single** task that services the entire datapath: while it is
    /// awaited, no other mapping is pumped, no guest frame is delivered, and the stop flag is not
    /// re-read. A bare `TcpStream::connect(..).await` therefore hands a black-holed destination the
    /// power to wedge the whole VM's network until the kernel's own SYN retry budget (~130 s)
    /// expires — and `SmoltcpProcess::Drop` then waits out its 5 s join and detaches the thread.
    /// The target is always a loopback address, where a live listener answers in microseconds and
    /// a closed port refuses immediately, so a second is already generous; anything slower is a
    /// wedge, not a slow connect.
    const HOST_DIAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);

    /// Whether the NAT may open outbound host connections on the guest's behalf
    /// (`egress-blocked-is-a-silent-no-op`).
    ///
    /// The unprivileged half of [`Egress`](crate::config::Egress). `Egress::Blocked` promises "all
    /// egress traffic is blocked"; on this datapath every byte leaves through a per-mapping host
    /// dial, so honoring that promise is exactly refusing the dial. `Open`/`Filtered` pass
    /// [`Allow`](NatEgressPolicy::Allow); `Blocked` passes [`Deny`](NatEgressPolicy::Deny) *and*
    /// registers no forward ports.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum NatEgressPolicy {
        /// Dial the host target when a guest socket becomes readable/writable.
        Allow,
        /// Never dial: the guest socket is closed instead, so the guest sees a reset rather than a
        /// silent black hole, and no host connection is ever attempted on its behalf.
        Deny,
    }

    /// Dials `target_port` on loopback under a **whole-operation** budget, returning the connected
    /// stream or a rendered diagnostic (`nat-host-dial-unbounded`).
    ///
    /// `connect` is taken as an un-polled future so the budget covers socket creation and the
    /// handshake, not merely the gaps between polls; the caller passes
    /// `tokio::net::TcpStream::connect(..)`. The `Err` arm is a *value*, not a discarded result:
    /// the pre-fix code dropped a failed dial on the floor with no log at all, while its
    /// neighbouring `send_slice`/`recv` failures logged at `error!` — so a NAT that could not reach
    /// the host service looked identical to an idle one.
    async fn bounded_host_dial<Fut>(
        target_port: u16,
        budget: std::time::Duration,
        connect: Fut,
    ) -> std::result::Result<tokio::net::TcpStream, String>
    where
        Fut: std::future::Future<Output = std::io::Result<tokio::net::TcpStream>>,
    {
        match tokio::time::timeout(budget, connect).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(format!("dial 127.0.0.1:{target_port} failed: {e}")),
            Err(_) => Err(format!(
                "dial 127.0.0.1:{target_port} exceeded its {budget:?} budget; \
                 the NAT datapath is single-tasked, so a wedged connect stalls the whole VM"
            )),
        }
    }

    /// Consumes every pending signal on the vhost exit event, returning how many reads it took.
    ///
    /// `VhostUserHandler::drop` notifies this eventfd to stop its vring workers and **nothing ever
    /// reads it** (`VringEpollHandler::run` breaks out of its loop on the epoll wakeup without
    /// consuming the counter). Since one eventfd is shared by every connection this NAT serves, a
    /// counter left hot by connection *n*'s teardown makes connection *n+1*'s epoll loop see an
    /// immediate exit and process nothing — a NAT that accepts the re-spawned VMM and then
    /// silently moves no packets. It is non-blocking, so the drain ends on `WouldBlock`.
    fn drain_exit_event(consumer: &EventConsumer) -> usize {
        let mut drained = 0;
        while consumer.consume().is_ok() {
            drained += 1;
        }
        drained
    }

    /// Clears everything in [`SharedState`] that belonged to the connection that just ended.
    ///
    /// The memory table and vrings are the dead VMM's (`handle_event` latches vrings only while
    /// `state.vrings.is_none()`, so a stale set would never be replaced), and its queued frames
    /// must not be delivered to its successor.
    fn reset_device_state(state: &mut SharedState) {
        state.mem = None;
        state.vrings = None;
        state.tx_queue.clear();
        state.rx_queue.clear();
    }

    /// Why a NAT mapping has no host stream this tick.
    ///
    /// Typed rather than one string because the two cases are not the same event and must not be
    /// logged at the same level: a policy refusal is the configured outcome working, a dial failure
    /// is a host service that could not be reached.
    #[derive(Debug)]
    enum HostDialRefusal {
        /// [`NatEgressPolicy::Deny`]: no socket was created and none ever will be.
        Policy(String),
        /// The dial was attempted and failed — refused, or over its budget.
        Failed(String),
    }

    /// The NAT's **one** host-dial site: honors [`NatEgressPolicy`], then dials `target_port` on
    /// loopback under `budget`.
    ///
    /// Under [`NatEgressPolicy::Deny`] no socket is created and no packet leaves — the refusal is
    /// the point, not an error to recover from — and the caller closes the guest socket so the
    /// guest sees a reset instead of a black hole. Keeping the decision here (rather than at the
    /// call site) is what makes "a blocked VM opens no outbound connection" a property one test can
    /// drive against a real listener.
    async fn dial_host_target(
        egress: NatEgressPolicy,
        target_port: u16,
        budget: std::time::Duration,
    ) -> std::result::Result<tokio::net::TcpStream, HostDialRefusal> {
        match egress {
            NatEgressPolicy::Deny => Err(HostDialRefusal::Policy(format!(
                "refusing the host dial to 127.0.0.1:{target_port}: this VM's egress is Blocked"
            ))),
            NatEgressPolicy::Allow => bounded_host_dial(
                target_port,
                budget,
                tokio::net::TcpStream::connect(format!("127.0.0.1:{target_port}")),
            )
            .await
            .map_err(HostDialRefusal::Failed),
        }
    }

    /// A NAT port mapping: `(listen_port, target_port, socket, host_stream)`.
    type NatPortMapping = (u16, u16, SocketHandle, Option<tokio::net::TcpStream>);

    /// Shared state across the smoltcp background thread and API interfaces.
    pub struct SharedState {
        /// Packets the guest wants to send (received from guest virtio-net).
        pub tx_queue: VecDeque<Vec<u8>>,
        /// Packets the host wants to send to the guest virtio-net.
        pub rx_queue: VecDeque<Vec<u8>>,
        /// Shared memory between host and guest.
        pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
        /// Virtio rings for RX and TX queues.
        pub vrings: Option<Vec<VringMutex>>,
    }

    /// A `smoltcp` device implementation wrapping the `SharedState`.
    pub struct SmoltcpDevice<'a> {
        /// Mutex guard over the shared network state.
        pub state: std::sync::MutexGuard<'a, SharedState>,
    }

    impl<'a> Device for SmoltcpDevice<'a> {
        type RxToken<'b>
            = RxTokenImpl
        where
            Self: 'b;
        type TxToken<'b>
            = TxTokenImpl<'b>
        where
            Self: 'b;

        fn receive(
            &mut self,
            _timestamp: Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            if let Some(packet) = self.state.tx_queue.pop_front() {
                Some((RxTokenImpl(packet), TxTokenImpl(&mut self.state.rx_queue)))
            } else {
                None
            }
        }

        fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
            Some(TxTokenImpl(&mut self.state.rx_queue))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 1500;
            caps.medium = Medium::Ethernet;
            caps
        }
    }

    /// Token for receiving packets in the `smoltcp` stack.
    pub struct RxTokenImpl(Vec<u8>);
    impl RxToken for RxTokenImpl {
        // smoltcp 0.13 made `RxToken::consume` take `self` by value and an immutable
        // `&[u8]` buffer (RX is read-only); only `TxToken` keeps the `&mut [u8]` form.
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.0)
        }
    }

    /// Token for transmitting packets in the `smoltcp` stack.
    pub struct TxTokenImpl<'a>(&'a mut VecDeque<Vec<u8>>);
    impl<'a> TxToken for TxTokenImpl<'a> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            tracing::trace!("TxTokenImpl::consume called with len={}", len);
            let mut packet = vec![0; len];
            let result = f(&mut packet);
            self.0.push_back(packet);
            result
        }
    }

    /// What one guest→host (transmitq) pass did, and whether the caller may poll the ring again.
    ///
    /// The reason this is a value rather than an `io::Result` is M7: an `Err` out of
    /// [`VhostUserBackendMut::handle_event`] is **terminal** in the vendored framework —
    /// `VringEpollHandler::run` propagates it out of the epoll loop, the vring worker thread
    /// returns, and `VhostUserHandler::drop` discards that return value at `join` (it only reports a
    /// *panic*). The vhost-user device stays attached throughout, so the guest keeps seeing a live
    /// link that never drains again: the same silent wedge as the B1 ring-wrap panic, one error path
    /// over. A ring the guest broke must cost one pass, never the link.
    #[derive(Debug, PartialEq, Eq)]
    enum TxPass {
        /// The available chains were drained (there may have been none). The ring is healthy, so
        /// with `VIRTIO_RING_F_EVENT_IDX` the caller may re-arm notifications and poll again.
        Drained,
        /// The ring could not be read at all: `virtio-queue` refused the guest's avail ring, or no
        /// guest memory table is installed yet. Nothing was drained and the caller must stop polling
        /// this tick — re-polling a refused ring spins on the state mutex the net thread needs.
        Unreadable,
    }

    /// Masks the transmitq's kick notifications before a drain pass, **reporting** a failure rather
    /// than discarding it.
    ///
    /// The one place the mask is turned on, so the report cannot be forgotten at a second call site.
    /// A failure costs at most one extra wakeup — the mask never went on, so the guest keeps kicking
    /// a ring this loop is about to read anyway — which is why it is a `warn` and not the `error`
    /// [`rearm_tx_notifications`] uses. It is still not a discarded `Result`: the write that failed
    /// is a guest-memory store into the used ring, so its failure says that ring's addresses no
    /// longer map, and the very next `add_used` will fail for the same reason.
    fn mask_tx_notifications(vring_state: &mut VringState<GuestMemoryAtomic<GuestMemoryMmap>>) {
        if let Err(e) = vring_state.disable_notification() {
            tracing::warn!(
                "smoltcp NAT: could not mask transmitq kicks ({e}); this pass costs an extra \
                 wakeup, and the used ring the write failed against is the one add_used writes"
            );
        }
    }

    /// Re-arms the transmitq's kick notifications on the way out of a pass, **reporting** a failure
    /// rather than discarding it. Returns whether the guest supplied more chains while the mask was
    /// on — `false` on failure, because a ring that cannot be re-armed is not one to keep polling.
    ///
    /// Unlike [`mask_tx_notifications`] this direction is **not** advisory, which is why its failure
    /// is an `error`: the mask that is being lifted is `VRING_USED_F_NO_NOTIFY` (or, with
    /// `VIRTIO_RING_F_EVENT_IDX`, an `avail_event` watermark), i.e. the flag by which the *guest's*
    /// driver is told not to kick. Leaving it set tells a healthy guest to stay quiet about a ring
    /// nothing will poll again — the same silently wedged link [`TxPass`] exists to prevent, reached
    /// through the error path of the fix for it.
    ///
    /// It cannot be repaired here: the write that failed *is* the repair, and an `Err` handed back to
    /// the framework kills the vring worker (see [`TxPass`]). So the honest posture is a loud log
    /// plus a caller that stops polling this tick.
    fn rearm_tx_notifications(
        vring_state: &mut VringState<GuestMemoryAtomic<GuestMemoryMmap>>,
    ) -> bool {
        match vring_state.enable_notification() {
            Ok(more_available) => more_available,
            Err(e) => {
                tracing::error!(
                    "smoltcp NAT: could not re-arm transmitq kicks ({e}); the guest's driver may \
                     stay masked on a ring nothing will poll again"
                );
                false
            }
        }
    }

    struct VhostUserNetBackend {
        event_idx: bool,
        kill_evt: (EventConsumer, EventNotifier),
        /// The exit-event pair the next daemon's vring worker will be handed, reserved by
        /// [`VhostUserNetBackend::arm_exit_event`] before that daemon exists. Interior mutability
        /// because [`VhostUserBackendMut::exit_event`] takes `&self` (the framework calls it through
        /// a *read* guard on the `RwLock` around this backend).
        exit_evt: Mutex<Option<(EventConsumer, EventNotifier)>>,
        /// Guest→host frames tail-dropped at [`MAX_TX_QUEUE_FRAMES`] since bring-up, cumulative over
        /// every vhost-user connection this NAT serves.
        ///
        /// It lives here rather than in [`SharedState`] because that struct is public with public
        /// fields: a counter nobody outside this module reads has no business being a breaking change
        /// to a downstream constructor. Atomic because `process_tx_queue` takes it by shared
        /// reference while holding the state guard.
        tx_drops: AtomicU64,
        state: Arc<Mutex<SharedState>>,
    }

    impl VhostUserNetBackend {
        /// Reserves the exit-event pair the next [`VhostUserDaemon`]'s vring worker will be handed,
        /// so [`VhostUserBackendMut::exit_event`] itself cannot fail.
        ///
        /// `exit_event` returns an `Option` with no error channel, and `None` is not a graceful
        /// degradation: the framework then registers **no** exit fd, `send_exit_event` becomes a
        /// no-op, `VringEpollHandler::run` never breaks out of `epoll_wait`, and
        /// `VhostUserHandler::drop` — reached by `drop(vu_daemon)` — joins that worker *forever*.
        /// So the fallible half (two fd clones, which fail exactly when the host is out of
        /// descriptors) runs here, at bring-up, where the caller can refuse to serve the connection
        /// at all instead of building one that can never be torn down.
        ///
        /// # Errors
        /// The underlying `try_clone` error when the host cannot hand out two more descriptors.
        fn arm_exit_event(&mut self) -> std::io::Result<()> {
            let pair = (self.kill_evt.0.try_clone()?, self.kill_evt.1.try_clone()?);
            *self.exit_evt.lock().unwrap_or_else(|e| e.into_inner()) = Some(pair);
            Ok(())
        }

        /// Drains one guest→host pass, counting every frame [`push_tx_frame`] tail-drops into
        /// `tx_drops` (the caller's [`VhostUserNetBackend::tx_drops`]) so an overload is reported
        /// rather than silent.
        fn process_tx_queue(
            state: &mut SharedState,
            vring_state: &mut VringState<GuestMemoryAtomic<GuestMemoryMmap>>,
            tx_drops: &AtomicU64,
        ) -> TxPass {
            let mut used_any = false;
            let guest_mem = match &state.mem {
                Some(m) => m,
                None => {
                    // A kick before SET_MEM_TABLE: normal during bring-up, and nothing can be read
                    // until the table arrives — so this is not an error, but it is not a drain
                    // either (re-polling would spin).
                    tracing::trace!("process_tx_queue: kick before the guest memory table arrived");
                    return TxPass::Unreadable;
                }
            };

            let mem_obj = guest_mem.memory();
            let iter = match vring_state.get_queue_mut().iter(mem_obj.clone()) {
                Ok(iter) => iter,
                Err(e) => {
                    // M7: guest-driven and NOT fatal. `virtio-queue` refuses the avail ring when
                    // the guest advances `avail.idx` more than a queue's worth past what the backend
                    // has consumed (its documented misbehaviour detection), when the queue is not
                    // ready, and when the ring address does not map — all reachable from inside the
                    // guest, whose hostility this NAT exists to survive. Log it and give up on this
                    // pass; the caller re-arms the kick, so a guest that re-initializes its ring is
                    // served again.
                    tracing::error!(
                        "process_tx_queue: the guest's transmitq avail ring was refused ({e:?}); \
                         skipping this pass rather than killing the vring worker"
                    );
                    return TxPass::Unreadable;
                }
            };
            let avail_chains: Vec<DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>> =
                iter.collect();

            for chain in avail_chains {
                used_any = true;
                let head_index = chain.head_index();

                let mut packet = Vec::new();
                let mut oversized = false;
                let mut read_failed = false;
                for desc in chain.readable() {
                    // Bound the guest-controlled descriptor length so a crafted
                    // chain cannot drive a multi-gigabyte host allocation. An
                    // over-MTU frame is dropped (it cannot be a valid virtio-net
                    // frame here, where no offload is negotiated).
                    match bounded_tx_read(desc.len() as usize, packet.len()) {
                        Some(n) => {
                            let mut buf = vec![0; n];
                            if mem_obj.read_slice(&mut buf, desc.addr()).is_ok() {
                                packet.extend_from_slice(&buf);
                            } else {
                                // L-NET-2: a descriptor read failed mid-frame.
                                // Continuing would splice the following descriptors
                                // onto the hole and forward a CORRUPT frame, so
                                // poison and drop the whole frame (mirror the
                                // oversized path).
                                read_failed = true;
                                break;
                            }
                        }
                        None => {
                            oversized = true;
                            break;
                        }
                    }
                }

                if oversized {
                    tracing::trace!(
                        "process_tx_queue: dropping over-MTU frame (cap {} bytes)",
                        MAX_FRAME_LEN
                    );
                } else if read_failed {
                    tracing::trace!(
                        "process_tx_queue: dropping frame after a guest-memory read failure"
                    );
                } else if let Some(payload) = packet.get(VIRTIO_NET_HDR_SIZE..) {
                    tracing::trace!(
                        "process_tx_queue: Read packet of length {} from vring: {:?}",
                        packet.len(),
                        payload
                    );
                    if !push_tx_frame(&mut state.tx_queue, payload) {
                        // Sibling 20's depth bound drops frames when the poll loop stalls. A drop
                        // nobody can see is the same class of defect as the wedge above it, so it is
                        // COUNTED and the count is reported at a level a default subscriber shows —
                        // a `trace!` here was one `RUST_LOG` away from silence.
                        let total = tx_drops.fetch_add(1, Ordering::Relaxed) + 1;
                        if tx_drop_is_reportable(total) {
                            tracing::warn!(
                                "smoltcp NAT: guest→host queue at its {MAX_TX_QUEUE_FRAMES} frame \
                                 bound; {total} frame(s) tail-dropped since bring-up — the smoltcp \
                                 poll loop is not draining it"
                            );
                        }
                    }
                } else {
                    tracing::trace!("process_tx_queue: packet too short: {}", packet.len());
                }

                if vring_state.add_used(head_index, 0).is_err() {
                    tracing::error!("Couldn't return used descriptors");
                }
            }

            if used_any {
                // Best-effort guest notification: a signal failure only forgoes a
                // wakeup this tick (the guest still drains on its next kick), so it
                // is logged nowhere and non-fatal here.
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "virtio hot loop: a failed used-queue signal forgoes one wakeup and the guest drains on its next kick"
                )]
                let _ = vring_state.signal_used_queue();
            }

            TxPass::Drained
        }
    }

    impl VhostUserBackendMut for VhostUserNetBackend {
        type Bitmap = ();
        type Vring = VringMutex;

        fn num_queues(&self) -> usize {
            NUM_QUEUES
        }

        fn max_queue_size(&self) -> usize {
            QUEUE_SIZE
        }

        fn features(&self) -> u64 {
            advertised_features()
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::REPLY_ACK
        }

        fn set_event_idx(&mut self, enabled: bool) {
            self.event_idx = enabled;
        }

        fn update_memory(
            &mut self,
            mem: GuestMemoryAtomic<GuestMemoryMmap>,
        ) -> std::io::Result<()> {
            self.state.lock().unwrap_or_else(|e| e.into_inner()).mem = Some(mem);
            Ok(())
        }

        fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
            // Called by the framework while it builds this connection's vring worker. It hands back
            // the pair `arm_exit_event` reserved *before* the daemon was constructed, because
            // returning `None` here does not degrade gracefully — it wedges teardown (see
            // `arm_exit_event`). Both handles are clones of the shared kill event, which is what
            // lets `SmoltcpProcess::Drop`'s `notify()` reach this worker and `drain_exit_event`
            // clear the counter between connections.
            if let Some(pair) = self
                .exit_evt
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                return Some(pair);
            }
            // Unreachable while this backend keeps the default `queues_per_thread` (one worker
            // thread per connection, so one `exit_event` call): a second thread would find the
            // reservation already taken. Clone live rather than hand the framework a `None`.
            match (self.kill_evt.0.try_clone(), self.kill_evt.1.try_clone()) {
                (Ok(consumer), Ok(notifier)) => Some((consumer, notifier)),
                _ => {
                    tracing::error!(
                        "smoltcp exit_event: no armed exit event and the kill-event clone failed; \
                         this connection's vring worker has no exit fd, so the daemon's own drop \
                         will not be able to join it"
                    );
                    None
                }
            }
        }

        fn handle_event(
            &mut self,
            device_event: u16,
            evset: EventSet,
            vrings: &[VringMutex],
            _thread_id: usize,
        ) -> std::io::Result<()> {
            if evset != EventSet::IN {
                return Err(std::io::Error::other("NotEpollIn"));
            }

            {
                // Latch this connection's vrings under a SHORT-LIVED lock. Sibling 20: the pre-fix
                // handler took one guard here and held it across the whole drain loop below, and the
                // net thread — the only consumer of `tx_queue` — needs that same mutex to poll. A
                // guest that kept the loop fed therefore starved the very drain the loop was
                // filling for, on top of growing the queue without bound.
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.vrings.is_none() {
                    state.vrings = Some(vrings.to_vec());
                }
            }

            if device_event == 1 {
                // transmitq (guest -> host)
                let Some(vring1) = vrings.get(1) else {
                    // The VMM negotiates NUM_QUEUES rings; a missing tx ring is a
                    // protocol error, not a reason to panic the worker thread.
                    return Err(std::io::Error::other("transmitq vring missing"));
                };
                loop {
                    // Notification masking touches the ring only, so its guard is taken alone — the
                    // state mutex is not held across it, and the temporary is released before the
                    // pass below takes both. The failure is reported inside the helper.
                    mask_tx_notifications(&mut vring1.get_mut());
                    let pass = {
                        // Sibling 20: ONE state lock per pass, taken in the net thread's own order
                        // (state, then ring) so the two can never deadlock, and released before the
                        // next pass so the drain this queue is being filled for actually gets to
                        // run. The pre-fix handler held a single guard across this whole loop, which
                        // starved that drain exactly while a guest hammered the ring — and grew
                        // `tx_queue` without bound in the meantime. A pass is bounded by the ring
                        // size, so this hold is bounded too.
                        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                        let mut vring_state = vring1.get_mut();
                        Self::process_tx_queue(&mut state, &mut vring_state, &self.tx_drops)
                    };
                    let keep_polling = {
                        let mut vring_state = vring1.get_mut();
                        // Every arm re-arms the kick through the one reporting helper: the mask this
                        // loop set is what tells the guest's driver to stay quiet, so a failure to
                        // lift it is a wedge, not a throughput hint (see `rearm_tx_notifications`).
                        match pass {
                            // M7: a ring the guest broke ends this tick and nothing more. Re-arm the
                            // kick on the way out so the refusal costs one pass rather than the link
                            // — and never turn it into an `Err`, which the framework's epoll loop
                            // treats as terminal (see [`TxPass`]).
                            TxPass::Unreadable => {
                                rearm_tx_notifications(&mut vring_state);
                                false
                            }
                            // Without EVENT_IDX there is nothing to re-poll: one pass per kick. The
                            // re-arm still has to happen — it is what lets the guest kick again — so
                            // only its "more available" hint is unused here.
                            TxPass::Drained if !self.event_idx => {
                                rearm_tx_notifications(&mut vring_state);
                                false
                            }
                            // With EVENT_IDX, keep draining while the guest keeps supplying.
                            TxPass::Drained => rearm_tx_notifications(&mut vring_state),
                        }
                    };
                    if !keep_polling {
                        break;
                    }
                    // The unlocked window between passes is short, and `std::sync::Mutex` is not
                    // fair: hand the drain thread the CPU explicitly rather than trusting it to win
                    // a race against this loop's immediate re-lock.
                    std::thread::yield_now();
                }
            }

            Ok(())
        }
    }

    /// Background process managing `smoltcp` networking state.
    #[derive(Debug)]
    pub struct SmoltcpProcess {
        kill_notifier: EventNotifier,
        stop_flag: Arc<std::sync::atomic::AtomicBool>,
        vhost_thread: Option<std::thread::JoinHandle<()>>,
        net_thread: Option<std::thread::JoinHandle<()>>,
        socket_path: PathBuf,
    }

    /// Joins a worker thread but gives up after `timeout`, detaching the thread
    /// rather than blocking teardown indefinitely (NET-3). We cannot safely
    /// force-kill an OS thread, so a wedged worker is logged and detached.
    fn join_with_timeout(
        handle: std::thread::JoinHandle<()>,
        label: &str,
        timeout: std::time::Duration,
    ) {
        let deadline = std::time::Instant::now() + timeout;
        while !handle.is_finished() {
            if std::time::Instant::now() >= deadline {
                tracing::error!(
                    "smoltcp {} worker did not exit within {:?}; detaching",
                    label,
                    timeout
                );
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // The thread has finished; reap it. A panic payload is intentionally
        // discarded because Drop must not unwind.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "Drop must not unwind: a finished worker's panic payload is dropped, never resumed"
        )]
        let _ = handle.join();
    }

    /// Drops a host-side `TcpStream` from a NAT mapping whose guest socket has
    /// closed, issuing an explicit `shutdown` so the upstream connection is torn
    /// down promptly rather than lingering. Returns whether a stream was present.
    ///
    /// Invoked on every transition to `!is_open()` (both the permanent re-listen
    /// path and the dynamic reclaim path) so a re-armed listener can never
    /// cross-wire the next guest connection onto a stale host stream (H-NET-1),
    /// and a closed dynamic mapping is never counted "live" forever (H-NET-2).
    fn take_and_shutdown_stream(stream: &mut Option<tokio::net::TcpStream>) -> bool {
        match stream.take() {
            Some(s) => {
                // `into_std` can fail if the stream is mid-operation; on failure
                // the owned stream is dropped here, which still closes the fd.
                if let Ok(std_stream) = s.into_std() {
                    // An explicit FIN so the upstream connection tears down promptly instead of lingering.
                    // The owned stream is dropped at the end of this arm either way, which closes the fd —
                    // so the shutdown is a promptness optimization, not the teardown itself.
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "promptness optimization: dropping the owned stream at the end of this arm closes the fd regardless"
                    )]
                    let _ = std_stream.shutdown(std::net::Shutdown::Both);
                }
                true
            }
            None => false,
        }
    }

    /// The **one** law for *where* a permanent NAT forward-port listener accepts: the VM's own
    /// `/30` gateway address (`10.200.<n>.1`), never "any destination" (C7).
    ///
    /// [`Egress::Open`](crate::config::Egress::Open) selects "no interception proxy"; it is not
    /// arbitrary outbound egress, and on this datapath the only destination it admits is the
    /// §6.3 host endpoint the guest reaches *at its gateway*. The interface runs with
    /// `set_any_ip(true)` — load-bearing for
    /// [`Egress::Filtered`](crate::config::Egress::Filtered)'s transparent L4 interception
    /// (§6.4), which must see a SYN addressed anywhere — and smoltcp's `TcpSocket::accepts`
    /// treats a listen endpoint whose `addr` is `None` as matching **every** destination
    /// address. Those two together made a bare `listen(port)` forward *arbitrary* destinations:
    /// a guest dialing `93.184.216.34:<host_services_port>` was accepted by the NAT and spliced
    /// onto `127.0.0.1:<host_services_port>`, the host's own service. That is neither the egress
    /// the guest asked for nor the refusal `Open` documents — a silent destination substitution
    /// standing in for the arbitrary outbound this datapath does not implement (§17). Pinning
    /// `addr` to the gateway makes the unadmitted destination fall through to smoltcp's
    /// `rst_reply`, so the guest is *refused* rather than mis-originated.
    ///
    /// Scope, deliberately: only the **permanent** forward mappings are pinned. The dynamic
    /// mappings [`admit_syn`] arms exist to intercept a destination the guest chose, so they keep
    /// the unpinned form — that asymmetry is exactly the difference between `Open` (refuse) and
    /// `Filtered` (intercept). A `Filtered` VM's SYN to a foreign address *on a forwarded port*
    /// is therefore refused rather than intercepted; it was never intercepted before either — it
    /// was mis-originated — so the refusal removes a wrong answer without removing a right one.
    fn nat_forward_endpoint(host_gw: Ipv4Address, port: u16) -> IpListenEndpoint {
        IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(host_gw)),
            port,
        }
    }

    /// Handles a NAT mapping whose guest TCP socket has gone `!is_open()`.
    ///
    /// The stale host stream is dropped **first** (H-NET-1/H-NET-2). A permanent
    /// forward-port listener is then re-armed with a cleared stream, so the next
    /// guest connection dials a fresh host stream; a dynamic mapping is left
    /// closed for the NET-5 reclaimer. Returns `true` if the caller should skip
    /// the mapping (a closed dynamic mapping awaiting reclamation), `false` if it
    /// was re-armed.
    ///
    /// `listen` is the endpoint the permanent arm re-arms on, and it arrives as a whole
    /// [`IpListenEndpoint`] rather than a bare port precisely so this — the NAT's only permanent
    /// `listen` site — cannot spell the destination scope itself: it is composed once by
    /// [`nat_forward_endpoint`] (C7).
    fn rearm_or_release_closed(
        socket: &mut TcpSocket<'_>,
        listen: IpListenEndpoint,
        stream: &mut Option<tokio::net::TcpStream>,
        is_permanent: bool,
    ) -> bool {
        take_and_shutdown_stream(stream);
        if is_permanent {
            // Permanent forward-port listeners are always re-armed. `listen` on a
            // just-closed socket can only fail if the port is 0 or the socket is
            // already open; neither holds here (forward ports are non-zero and the
            // socket is Closed), and a spurious failure is retried next tick — so
            // the result is deliberately ignored.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "listen on a just-closed socket fails only for port 0 or an already-open socket, neither of which holds for a permanent forward port"
            )]
            let _ = socket.listen(listen);
            false
        } else {
            // NET-5: leave the closed dynamic socket closed (stream cleared) so
            // it can be reclaimed; a fresh SYN recreates it on demand.
            true
        }
    }

    /// Reclaims closed, idle *dynamic* NAT mappings and reports whether the pool
    /// has room for `additional` more sockets (NET-5).
    ///
    /// The first `permanent_count` mappings are the forward-port listeners and
    /// are never reclaimed. A dynamic mapping whose socket is closed is
    /// reclaimed regardless of whether a host stream is still attached: the
    /// stale stream is taken and shut down (a closed guest socket cannot consume
    /// any more upstream bytes), then the mapping is removed from both the
    /// mapping list and the `SocketSet`. Counting such a mapping "live" purely
    /// because its stream is `Some` is the H-NET-2 leak that wedges the cap.
    /// Growth past `MAX_DYNAMIC_SOCKETS` is refused.
    fn reclaim_and_has_room(
        sockets: &mut SocketSet<'_>,
        port_mappings: &mut Vec<NatPortMapping>,
        permanent_count: usize,
        additional: usize,
    ) -> bool {
        let mut reclaimed = Vec::new();
        for (idx, (_, _, handle, stream)) in port_mappings.iter_mut().enumerate() {
            if idx < permanent_count {
                continue;
            }
            if sockets.get::<TcpSocket>(*handle).is_open() {
                // Still live (listening or an active connection): keep it.
                continue;
            }
            // H-NET-2: the guest closed this dynamic socket. Drop any stale host
            // stream so the mapping is genuinely free before reclaiming it.
            take_and_shutdown_stream(stream);
            reclaimed.push(*handle);
        }
        port_mappings.retain(|(_, _, handle, _)| !reclaimed.contains(handle));
        for handle in &reclaimed {
            // Drop the removed `Socket`, freeing its buffers.
            let _ = sockets.remove(*handle);
        }
        let dynamic_count = port_mappings.len().saturating_sub(permanent_count);
        dynamic_count + additional <= MAX_DYNAMIC_SOCKETS
    }

    /// Whether a SYN to `dst_port` is already served by an existing mapping — the one question
    /// [`admit_syn`] asks before growing the dynamic pool.
    ///
    /// Two mapping kinds answer it differently:
    ///
    /// * A **permanent** forward-port mapping (index below `permanent_count`) ends the question
    ///   whatever state its socket is in: that port's pool is sized by [`FORWARD_PORT_POOL`] and
    ///   re-armed every tick by [`rearm_or_release_closed`], and a *dynamic* mapping for the same
    ///   port would dial the proxy port instead of the configured target.
    /// * A **dynamic** mapping only serves the SYN while its socket is still `Listen`ing.
    ///   `is_listening()`, not `is_open()`: an accepted connection is open but no longer accepting,
    ///   so the `is_open()` form capped transparent interception at [`SYN_BURST`] *concurrent*
    ///   connections per destination — the `SYN_BURST + 1`-th guest connection to a port found the
    ///   first burst "open", grew nothing, and its SYN went unanswered until the guest gave up.
    fn syn_already_served(
        sockets: &SocketSet<'_>,
        port_mappings: &[NatPortMapping],
        permanent_count: usize,
        dst_port: u16,
    ) -> bool {
        port_mappings.iter().enumerate().any(|(idx, mapping)| {
            let (listen_port, _, handle, _) = mapping;
            *listen_port == dst_port
                && (idx < permanent_count || sockets.get::<TcpSocket>(*handle).is_listening())
        })
    }

    /// Admits a guest SYN to `dst_port` into the dynamic NAT socket pool.
    ///
    /// Extracted from the `run_network` TX scan so the per-SYN admission decision
    /// is unit-testable without a live vhost device (NET-3). For a SYN no existing
    /// mapping serves ([`syn_already_served`]), it first reclaims closed dynamic
    /// mappings and then — **only if the pool has room for the whole `burst`** —
    /// creates `burst` listening sockets mapped to `pxy_port`.
    /// When the pool is full the SYN is dropped without any growth; that refusal is
    /// the guard that keeps `port_mappings` bounded at
    /// `permanent_count + MAX_DYNAMIC_SOCKETS` under a SYN spray, whether the spray
    /// hits many distinct destination ports or one port many times over.
    fn admit_syn(
        sockets: &mut SocketSet<'_>,
        port_mappings: &mut Vec<NatPortMapping>,
        permanent_count: usize,
        dst_port: u16,
        pxy_port: u16,
        burst: usize,
    ) {
        // Short-circuit: `reclaim_and_has_room` (with its reclamation side effect)
        // only runs when nothing already serves this SYN.
        if syn_already_served(sockets, port_mappings, permanent_count, dst_port)
            || !reclaim_and_has_room(sockets, port_mappings, permanent_count, burst)
        {
            return;
        }
        for _ in 0..burst {
            let rx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
            let tx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
            let mut socket = TcpSocket::new(rx_buffer, tx_buffer);
            // `dst_port` is guest-controlled; `listen` fails only for port 0, in
            // which case the fresh socket is simply added un-listening and later
            // reclaimed (the SYN is effectively dropped) — so the result is
            // deliberately ignored rather than propagated.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "dst_port is guest-controlled: a listen failure means port 0, and the un-listening socket is reclaimed (the SYN is dropped)"
            )]
            let _ = socket.listen(dst_port);
            let handle = sockets.add(socket);
            port_mappings.push((dst_port, pxy_port, handle, None::<tokio::net::TcpStream>));
        }
    }

    impl Drop for SmoltcpProcess {
        fn drop(&mut self) {
            tracing::info!("SmoltcpProcess dropping!");
            self.stop_flag
                .store(true, std::sync::atomic::Ordering::Relaxed);
            // Best-effort wakeups so the workers observe the stop flag promptly;
            // errors here are non-fatal (the bounded joins below still apply).
            #[expect(
                clippy::let_underscore_must_use,
                reason = "wakeup poke on a Drop path: the bounded joins below are what actually end the workers"
            )]
            let _ = self.kill_notifier.notify();
            // Connect to the socket to unblock listener.accept() if it's stuck. Retried over a
            // short bounded window because the vhost worker now serves connections in a loop: a
            // single shot fired while it is *between* listeners (the microseconds after one
            // connection ends and before the next bind) would hit nothing, and the worker would
            // then block in `accept` until the join below gave up and detached it.
            for _ in 0..20 {
                if self.vhost_thread.as_ref().is_none_or(|t| t.is_finished()) {
                    break;
                }
                // A self-connect to unblock a worker parked in `accept()`. Failing to connect is one of
                // the expected outcomes — the worker may be between listeners — which is exactly why this
                // is a bounded retry loop and not a single checked shot.
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "self-connect wakeup: a failure is an expected outcome of firing between listeners, which is why this is a bounded retry loop"
                )]
                let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // NET-3: bound each join so a wedged worker cannot hang teardown.
            if let Some(t) = self.vhost_thread.take() {
                join_with_timeout(t, "vhost", JOIN_TIMEOUT);
            }
            if let Some(t) = self.net_thread.take() {
                join_with_timeout(t, "net", JOIN_TIMEOUT);
            }
        }
    }

    impl SmoltcpProcess {
        /// Starts the background network thread to process packets and manage connections.
        ///
        /// `egress` decides whether the NAT may dial host targets on the guest's behalf at all
        /// ([`NatEgressPolicy`]).
        ///
        /// The vhost-user socket at `socket_path` is bound **here**, on the caller's thread, so it
        /// exists the moment this returns; the worker then serves connections on it in a loop.
        /// Serving a **second** connection is load-bearing, not a nicety: `MicroVm::start`'s
        /// control-plane health gate recovers a VMM bring-up flake by dropping the instance and
        /// re-spawning the VMM on the *same* per-VM resources, and this NAT is one of them
        /// (`nat-socket-dies-with-first-vmm`).
        ///
        /// # Panics
        ///
        /// Panics if the underlying system resources or background threads fail to start.
        pub fn start(
            vmid: u32,
            forward_ports: Vec<u16>,
            proxy_port: Option<u16>,
            socket_path: PathBuf,
            egress: NatEgressPolicy,
        ) -> Self {
            if let Err(e) = crate::net::ip_math(vmid) {
                // NET-4: surface an out-of-range vmid loudly. The signature stays
                // infallible for API compatibility; `run_network` re-checks and
                // exits its thread cleanly instead of panicking on `.expect`.
                tracing::error!(
                    "SmoltcpProcess::start: out-of-range vmid {} ({}); network thread will not configure",
                    vmid,
                    e
                );
            }
            let state = Arc::new(Mutex::new(SharedState {
                tx_queue: VecDeque::new(),
                rx_queue: VecDeque::new(),
                mem: None,
                vrings: None,
            }));

            let state_clone = state.clone();

            let (kill_evt_consumer, kill_evt_notifier) =
                vmm_sys_util::event::new_event_consumer_and_notifier(
                    vmm_sys_util::event::EventFlag::NONBLOCK,
                )
                .expect("event consumer");
            // A third handle on the same eventfd, kept by the worker loop. The framework's
            // `VhostUserHandler::drop` signals THIS event to stop its vring workers, and nothing
            // ever reads it — so between two connections the counter stays hot and the *next*
            // connection's epoll loop would see an immediate exit and serve nothing. The worker
            // drains it after each connection.
            let kill_evt_drain = kill_evt_consumer.try_clone().expect("clone kill consumer");
            let kill_evt = (
                kill_evt_consumer,
                kill_evt_notifier.try_clone().expect("clone notifier"),
            );

            let backend = std::sync::Arc::new(std::sync::RwLock::new(VhostUserNetBackend {
                event_idx: false,
                kill_evt,
                // Armed per connection by the worker loop, before each daemon is constructed.
                exit_evt: Mutex::new(None),
                tx_drops: AtomicU64::new(0),
                state: state_clone,
            }));

            let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

            // Bound on the CALLER's thread so the socket exists when `start` returns — the VMM's
            // socket wait races nothing.
            let first_listener = Listener::new(&socket_path, true).expect("listener new");

            let socket_path_clone = socket_path.clone();
            let vhost_state = state.clone();
            let vhost_stop = stop_flag.clone();
            let vhost_thread = std::thread::spawn(move || {
                Self::serve_vhost_connections(
                    &socket_path_clone,
                    first_listener,
                    &backend,
                    &kill_evt_drain,
                    &vhost_state,
                    &vhost_stop,
                );
            });

            let stop_flag_clone = stop_flag.clone();
            let net_thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("runtime new");
                rt.block_on(async move {
                    Self::run_network(
                        vmid,
                        forward_ports,
                        proxy_port,
                        egress,
                        state,
                        stop_flag_clone,
                    )
                    .await;
                });
            });

            SmoltcpProcess {
                kill_notifier: kill_evt_notifier,
                stop_flag,
                vhost_thread: Some(vhost_thread),
                net_thread: Some(net_thread),
                socket_path: socket_path.clone(),
            }
        }

        /// Serves vhost-user connections on `socket_path` until the stop flag is set
        /// (`nat-socket-dies-with-first-vmm`).
        ///
        /// One connection per iteration, each with its **own** `Listener` + `VhostUserDaemon`,
        /// because neither is reusable: `VhostUserDaemon::start` is `BackendListener::new` + a
        /// single `accept` (the `BackendListener` `take()`s the backend on that accept, so a second
        /// accept could not be served even if one were attempted), and `impl Drop for Listener`
        /// **unlinks the socket path**. The pre-fix worker did exactly one of each, so the first
        /// VMM's hang-up deleted the NAT socket: every control-plane re-spawn — the recovery
        /// `MicroVm::start` performs on the *same* per-VM resources for QEMU's recorded
        /// `vhost-device-vsock` bring-up flake — then died on the 2 s socket wait, burning every
        /// attempt to report a control-plane error whose real cause was the unlinked NAT socket.
        ///
        /// Between connections the shared device state is reset and the exit event drained, so the
        /// next VMM starts from a clean device rather than inheriting the dead one's memory table,
        /// vrings, queued frames, and a hot exit signal.
        fn serve_vhost_connections(
            socket_path: &std::path::Path,
            first_listener: Listener,
            backend: &Arc<std::sync::RwLock<VhostUserNetBackend>>,
            kill_evt_drain: &EventConsumer,
            state: &Arc<Mutex<SharedState>>,
            stop_flag: &Arc<std::sync::atomic::AtomicBool>,
        ) {
            let mut pending = Some(first_listener);
            while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let mut listener = match pending.take() {
                    Some(l) => l,
                    None => match Listener::new(socket_path, true) {
                        Ok(l) => l,
                        Err(e) => {
                            // Fail loud and stop: without a listener there is no NAT, and a silent
                            // spin would hide that from every later re-spawn.
                            tracing::error!(
                                "vhost-user-net: cannot re-bind the NAT socket {:?}: {:?}; \
                                 no further VMM connection can be served",
                                socket_path,
                                e
                            );
                            return;
                        }
                    },
                };

                // Arm this connection's exit event BEFORE the daemon that will consume it exists:
                // `exit_event` cannot report a failure, and the `None` it used to fall back to
                // leaves the vring worker with no exit fd — `drop(vu_daemon)` below then joins a
                // thread that never breaks out of `epoll_wait`. A NAT that cannot be torn down is
                // worse than one that never came up, so a failed arming is terminal for this
                // worker, exactly like a failed re-bind.
                if let Err(e) = backend
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .arm_exit_event()
                {
                    tracing::error!(
                        "vhost-user-net: cannot arm the exit event for {:?}: {}; refusing to serve \
                         a connection whose vring worker could never be joined",
                        socket_path,
                        e
                    );
                    return;
                }

                let mut vu_daemon = match VhostUserDaemon::new(
                    String::from("vhost-user-net"),
                    backend.clone(),
                    GuestMemoryAtomic::new(GuestMemoryMmap::new()),
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!(
                            "vhost-user-net: daemon construction failed for {:?}: {:?}; \
                             no further VMM connection can be served",
                            socket_path,
                            e
                        );
                        return;
                    }
                };

                tracing::info!("vhost-user-net daemon starting on {:?}", socket_path);
                // `nat-daemon-start-error-swallowed`: the bring-up result was logged and then
                // ignored, so a daemon that never accepted anything went straight into `wait()`
                // and the worker reported a clean exit for a NAT that had never come up. It is
                // terminal for this worker instead — the caller observes it as an unserved socket
                // and fails its own bring-up, rather than running a VM with a dead network.
                if let Err(e) = vu_daemon.start(&mut listener) {
                    if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        // Teardown raced the accept (`Drop` connects to the socket to unblock it).
                        tracing::debug!("vhost-user-net daemon accept ended at teardown: {:?}", e);
                    } else {
                        tracing::error!(
                            "vhost-user-net daemon failed to come up on {:?}: {:?}; \
                             the NAT is down for this VM",
                            socket_path,
                            e
                        );
                    }
                    return;
                }
                if let Err(e) = vu_daemon.wait() {
                    // A VMM hang-up is `Ok` (the framework maps `SocketBroken`), so anything else
                    // is a real protocol/handler failure worth surfacing — but not fatal: the next
                    // VMM gets a fresh daemon. At teardown the wakeup connection this worker just
                    // accepted speaks no vhost-user, so its parse failure is expected, not news.
                    if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        tracing::debug!("vhost-user-net daemon ended at teardown: {:?}", e);
                    } else {
                        tracing::error!("vhost-user-net daemon connection ended with {:?}", e);
                    }
                }

                // Drop the daemon FIRST: its handler's `Drop` signals the exit event and joins the
                // vring worker threads, so nothing is still touching the device state we reset.
                // That join only terminates because the worker was given an exit fd above — hence
                // the arming, and hence its failure being terminal.
                drop(vu_daemon);
                // …then the listener, unlinking the path this iteration bound.
                drop(listener);

                drain_exit_event(kill_evt_drain);
                reset_device_state(&mut state.lock().unwrap_or_else(|e| e.into_inner()));
                tracing::info!(
                    "vhost-user-net: connection closed; re-arming {:?} for a re-spawned VMM",
                    socket_path
                );
            }
        }

        async fn run_network(
            vmid: u32,
            forward_ports: Vec<u16>,
            proxy_port: Option<u16>,
            egress: NatEgressPolicy,
            state: Arc<Mutex<SharedState>>,
            stop_flag: Arc<std::sync::atomic::AtomicBool>,
        ) {
            // M-NET-2/NET-4: derive both /30 addresses from the shared ip_math via
            // the single `nat_addrs` helper (no re-hardcoded `10.200.x.y` literals);
            // an out-of-range vmid fails loud and exits the thread cleanly instead
            // of panicking. `host_gw` (10.200.n.1) is the NAT interface address;
            // `guest_gw` (10.200.n.2) is the default-route gateway.
            let (host_gw, guest_gw) = match nat_addrs(vmid) {
                Ok(addrs) => addrs,
                Err(e) => {
                    tracing::error!("smoltcp run_network: invalid vmid {}: {}", vmid, e);
                    return;
                }
            };
            // NET-2: use a host MAC that `crate::net::mac_math` can never produce
            // for a valid vmid, so it can never collide with a guest MAC.
            let mac_addr = EthernetAddress(HOST_NAT_MAC);

            let mut config = Config::new(HardwareAddress::Ethernet(mac_addr));
            // L-NET-5: seed the TCP ISN / ephemeral-port RNG per instance so the
            // sequence space is neither predictable nor identical across VMs (the
            // old fixed `0` seed was both). Read the OS entropy pool directly and
            // XOR in `vmid` — `std::hash::RandomState` is clippy-banned (B4: never
            // for content addressing) and there is no `rand` dependency here.
            {
                use std::io::Read;
                let mut seed = [0u8; 8];
                let entropy = std::fs::File::open("/dev/urandom")
                    .and_then(|mut f| f.read_exact(&mut seed).map(|()| u64::from_ne_bytes(seed)))
                    .unwrap_or_else(|_| {
                        // Near-impossible on Linux; fall back to wall-clock nanos so
                        // the seed still varies across boots.
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_nanos() as u64)
                    });
                config.random_seed = entropy ^ u64::from(vmid);
            }
            let mut iface = Interface::new(
                config,
                &mut SmoltcpDevice {
                    state: state.lock().unwrap_or_else(|e| e.into_inner()),
                },
                Instant::now(),
            );
            iface.set_any_ip(true);
            // NET-5: the address/route storage is fixed-capacity and we add a
            // single entry to a fresh interface, so these cannot legitimately
            // fail. Rather than `expect` (which would silently kill the net
            // thread on any future regression), fail loud and exit the thread
            // cleanly so teardown still runs.
            let mut push_ok = true;
            iface.update_ip_addrs(|ip_addrs| {
                if ip_addrs
                    .push(IpCidr::new(IpAddress::Ipv4(host_gw), 30))
                    .is_err()
                {
                    push_ok = false;
                }
            });
            if !push_ok {
                tracing::error!(
                    "smoltcp run_network: host IP push rejected (address storage full); \
                     exiting net thread"
                );
                return;
            }
            if let Err(e) = iface.routes_mut().add_default_ipv4_route(guest_gw) {
                tracing::error!(
                    "smoltcp run_network: failed to add default route: {:?}; exiting net thread",
                    e
                );
                return;
            }
            tracing::trace!("smoltcp iface configured with IPs: {:?}", iface.ip_addrs());

            let mut sockets = SocketSet::new(vec![]);

            let mut port_mappings: Vec<NatPortMapping> = Vec::new();
            for port in forward_ports {
                for _ in 0..FORWARD_PORT_POOL {
                    let rx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
                    let tx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
                    let socket = TcpSocket::new(rx_buffer, tx_buffer);
                    let handle = sockets.add(socket);
                    port_mappings.push((port, port, handle, None::<tokio::net::TcpStream>));
                }
            }
            // Forward-port mappings are permanent; everything appended later is a
            // reclaimable dynamic mapping (NET-5).
            let permanent_count = port_mappings.len();

            loop {
                if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                {
                    let mut state_guard = state.lock().unwrap_or_else(|e| e.into_inner());

                    // Process receiveq (host -> guest)
                    let (mem_opt, vrings_opt) =
                        (state_guard.mem.clone(), state_guard.vrings.clone());
                    if let (Some(mem), Some(vrings)) = (mem_opt, vrings_opt) {
                        // NET-1/C2: the RX ring may be absent; never panic.
                        if let Some(vring0) = vrings.first() {
                            let mut vring_state = vring0.get_mut();
                            let mem_obj = mem.memory();
                            let mut used_any = false;

                            let mut used_descs = Vec::new();
                            let avail_chains = vring_state.get_queue_mut().iter(mem_obj.clone());
                            if let Ok(mut chains) = avail_chains {
                                while let Some(packet) = state_guard.rx_queue.pop_front() {
                                    if let Some(chain) = chains.next() {
                                        tracing::trace!(
                                            "process_rx_queue: Sending packet of length {} to guest",
                                            packet.len()
                                        );
                                        let head_index = chain.head_index();

                                        let mut full_packet = vec![0; VIRTIO_NET_HDR_SIZE];
                                        full_packet.extend_from_slice(&packet);

                                        let mut offset = 0;
                                        let mut write_failed = false;
                                        for desc in chain.writable() {
                                            let to_write = std::cmp::min(
                                                full_packet.len() - offset,
                                                desc.len() as usize,
                                            );
                                            if to_write > 0
                                                && let Some(chunk) =
                                                    full_packet.get(offset..offset + to_write)
                                            {
                                                if mem_obj.write_slice(chunk, desc.addr()).is_ok() {
                                                    offset += to_write;
                                                } else {
                                                    // L-NET-2: a descriptor write
                                                    // failed; the frame is now
                                                    // partial and must be dropped.
                                                    write_failed = true;
                                                    break;
                                                }
                                            }
                                        }
                                        // L-NET-2: only forward a frame that fully fit
                                        // the writable descriptors. A truncated frame
                                        // (writable room < frame, or a write failure)
                                        // is DROPPED — return the descriptor with a
                                        // zero used length rather than deliver a
                                        // corrupt, truncated frame to the guest.
                                        let used_len = match rx_used_len(
                                            offset,
                                            full_packet.len(),
                                            write_failed,
                                        ) {
                                            Some(len) => len as u32,
                                            None => {
                                                tracing::trace!(
                                                    "process_rx_queue: dropping frame that did not fit the writable descriptors ({} of {} bytes)",
                                                    offset,
                                                    full_packet.len()
                                                );
                                                0
                                            }
                                        };
                                        used_descs.push((head_index, used_len));
                                    } else {
                                        state_guard.rx_queue.push_front(packet);
                                        break;
                                    }
                                }
                            }
                            for (head_index, written) in used_descs {
                                // NET-1/C2: head_index is guest-controlled. Mirror the
                                // TX path — on an invalid index log and skip, never panic.
                                if vring_state.add_used(head_index, written).is_err() {
                                    tracing::error!(
                                        "smoltcp RX: couldn't return used descriptor (guest index {})",
                                        head_index
                                    );
                                } else {
                                    used_any = true;
                                }
                            }
                            if used_any {
                                // Best-effort guest notification: a signal failure
                                // only forgoes a wakeup this tick (the guest drains
                                // on its next kick), so the result is ignored.
                                #[expect(
                                    clippy::let_underscore_must_use,
                                    reason = "same virtio notification on the guest-facing drain: one forgone wakeup, never a lost descriptor"
                                )]
                                let _ = vring_state.signal_used_queue();
                            }
                        }
                    }

                    if let Some(pxy_port) = proxy_port {
                        for packet in &state_guard.tx_queue {
                            if let Ok(frame) = EthernetFrame::new_checked(&packet[..])
                                && frame.ethertype() == EthernetProtocol::Ipv4
                                && let Ok(ipv4) = Ipv4Packet::new_checked(frame.payload())
                                && ipv4.next_header() == IpProtocol::Tcp
                                && let Ok(tcp) = TcpPacket::new_checked(ipv4.payload())
                            {
                                let dst_port = tcp.dst_port();
                                if tcp.syn() && !tcp.ack() {
                                    // NET-3/NET-5: the per-SYN admission
                                    // decision (reclaim closed dynamic
                                    // mappings, then refuse growth past
                                    // the cap so a SYN spray cannot
                                    // exhaust host memory) lives in the
                                    // unit-tested `admit_syn` helper.
                                    admit_syn(
                                        &mut sockets,
                                        &mut port_mappings,
                                        permanent_count,
                                        dst_port,
                                        pxy_port,
                                        SYN_BURST,
                                    );
                                }
                            }
                        }
                    }

                    let mut device = SmoltcpDevice { state: state_guard };
                    iface.poll(Instant::now(), &mut device, &mut sockets);
                    drop(device); // releases state_guard
                }

                for (i, (listen_port, target_port, handle, tcp_stream)) in
                    port_mappings.iter_mut().enumerate()
                {
                    let socket = sockets.get_mut::<TcpSocket>(*handle);
                    if !socket.is_open() {
                        // H-NET-1/H-NET-2: on any transition to a closed guest
                        // socket, drop the stale host stream BEFORE re-arming a
                        // permanent listener or leaving a dynamic mapping for
                        // reclamation. A guest RST / guest-first close drives the
                        // smoltcp socket to Closed with the host stream still
                        // attached; without this, a re-armed permanent listener
                        // cross-wires the next guest connection onto the old host
                        // stream, and a closed dynamic mapping is counted "live"
                        // forever, defeating the NET-5 cap.
                        // C7: the re-armed permanent listener is scoped to this VM's own
                        // gateway through the one `nat_forward_endpoint` composer — never a
                        // bare port, which under `set_any_ip(true)` accepts every destination.
                        if rearm_or_release_closed(
                            socket,
                            nat_forward_endpoint(host_gw, *listen_port),
                            tcp_stream,
                            i < permanent_count,
                        ) {
                            continue;
                        }
                    }

                    if socket.can_send() || socket.can_recv() {
                        let mut refused = false;
                        if tcp_stream.is_none() {
                            match dial_host_target(egress, *target_port, HOST_DIAL_BUDGET).await {
                                Ok(stream) => {
                                    // TCP_NODELAY is a latency optimization; if the
                                    // setsockopt fails the connection still works
                                    // (merely with Nagle enabled), so the result is
                                    // deliberately ignored.
                                    #[expect(
                                        clippy::let_underscore_must_use,
                                        reason = "TCP_NODELAY is a latency optimization: a failed setsockopt leaves a working connection with Nagle enabled"
                                    )]
                                    let _ = stream.set_nodelay(true);
                                    *tcp_stream = Some(stream);
                                }
                                // A policy refusal is the configuration working, so it is `info!`;
                                // a dial that was attempted and failed is `error!`, matching the
                                // neighbouring `send_slice`/`recv` failures.
                                Err(HostDialRefusal::Policy(why)) => {
                                    tracing::info!("smoltcp NAT: {}", why);
                                    refused = true;
                                }
                                Err(HostDialRefusal::Failed(e)) => {
                                    tracing::error!("smoltcp NAT: {}", e);
                                    // Close the guest socket (below) on EITHER failure. Under
                                    // `Deny` there will never be a stream, so leaving it open
                                    // black-holes the guest. Under `Allow` the pre-fix code left
                                    // it open and silently re-dialled every 5 ms tick forever:
                                    // invisible to the guest, and — now that the failure is
                                    // logged — a 200-lines-per-second console flood. Recovery
                                    // stays retryable, just observably: the mapping is re-armed as
                                    // a listener and the guest's next connection dials again.
                                    refused = true;
                                }
                            }
                        }

                        let mut closed = refused;
                        if let Some(stream) = tcp_stream {
                            if socket.can_send() {
                                // C-NET-1: bound the host read to the socket's
                                // *available* TX capacity. `send_slice` enqueues
                                // only up to the free TX buffer ("down to zero"),
                                // and `can_send()` above is true when as little as
                                // one byte is free — so an unbounded 8 KiB read
                                // whose tail does not fit was silently DROPPED,
                                // corrupting any host→guest stream large enough to
                                // fill the guest receive window. Reading only what
                                // will fit guarantees the whole read is enqueued.
                                let mut buf = [0u8; 8192];
                                let avail = host_read_budget(
                                    socket.send_capacity(),
                                    socket.send_queue(),
                                    buf.len(),
                                );
                                // `can_send()` guarantees `avail >= 1`; guard anyway
                                // so a zero-length read can never be mis-read as EOF.
                                let read_res = if avail == 0 {
                                    Ok(0)
                                } else {
                                    stream.try_read(buf.get_mut(..avail).unwrap_or(&mut []))
                                };
                                match read_res {
                                    Ok(0) if avail > 0 => {
                                        closed = true;
                                    }
                                    Ok(0) => {}
                                    Ok(n) => {
                                        // NET-1/C2: guest-driven; never panic. On a
                                        // send error close the socket and drop the
                                        // host stream below.
                                        match socket.send_slice(buf.get(..n).unwrap_or(&[])) {
                                            Ok(enqueued) => {
                                                // The read was bounded by `avail`, so
                                                // the whole `n` must have enqueued —
                                                // pin the no-drop invariant loudly.
                                                debug_assert_eq!(
                                                    enqueued, n,
                                                    "send_slice must enqueue the whole bounded read (no drop)"
                                                );
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    "smoltcp send_slice failed: {:?}",
                                                    e
                                                );
                                                closed = true;
                                            }
                                        }
                                    }
                                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                    Err(_) => {
                                        closed = true;
                                    }
                                }
                            }

                            if socket.can_recv() {
                                // B1 (`nat-guest-to-host-wrap-panic`): the host
                                // write happens INSIDE the `recv` closure, over
                                // the contiguous slice smoltcp offers, so the
                                // consumed count can never exceed
                                // `dequeue_many_with`'s `max_size` (see
                                // `drain_to_host`). Peeking with `peek_slice` —
                                // which copies across the RX ring wrap — and
                                // feeding its count back to `recv` tripped that
                                // assert on every sustained >64 KiB upload,
                                // killing this thread while the device stayed
                                // attached.
                                match socket.recv(|contiguous| {
                                    drain_to_host(contiguous, |bytes| stream.try_write(bytes))
                                }) {
                                    // NET-1/C2: guest-driven; never panic.
                                    Ok(Ok(_)) => {}
                                    Ok(Err(ref e))
                                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                    Ok(Err(_)) => {
                                        closed = true;
                                    }
                                    Err(e) => {
                                        tracing::error!("smoltcp recv failed: {:?}", e);
                                        closed = true;
                                    }
                                }
                            }
                        }

                        if closed {
                            *tcp_stream = None;
                            socket.close();
                        }
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicBool, Ordering};
        // Shadow the glob-imported `smoltcp::time::Instant` with the std clock.
        use std::time::{Duration, Instant};
        // The queue setters `TxRing` needs to stand in for a guest driver's SET_VRING_* messages.
        use virtio_queue::QueueT;

        // C-NET-1: the host→guest pump must read only as many bytes as the socket
        // can enqueue this tick. With a nearly-full 64 KiB TX buffer (one byte
        // free), the pump must read exactly ONE byte — not the full 8 KiB scratch,
        // whose 8191-byte tail `send_slice` would silently drop. RED on the old
        // unbounded read (which always yielded `min(8192, ∞) == 8192`).
        #[test]
        fn host_read_budget_bounds_read_to_free_tx_room() {
            // One byte free in a 64 KiB TX buffer → read exactly one byte.
            assert_eq!(host_read_budget(65536, 65535, 8192), 1);
            // Empty TX buffer → read a full scratch-buffer's worth.
            assert_eq!(host_read_budget(65536, 0, 8192), 8192);
            // Full TX buffer → read nothing (no drop, no false EOF).
            assert_eq!(host_read_budget(65536, 65536, 8192), 0);
            // Room larger than the scratch buffer is capped by the buffer.
            assert_eq!(host_read_budget(65536, 40000, 8192), 8192);
            // Never underflows if the queue somehow exceeds capacity.
            assert_eq!(host_read_budget(1024, 2048, 8192), 0);
        }

        // B1 (`nat-guest-to-host-wrap-panic`) / M13: the guest→host pump must
        // consume from the RX ring EXACTLY what the host accepted, and never more
        // than the contiguous span the closure was offered. Driven against a REAL
        // `TcpSocketBuffer` (the very `RingBuffer` a `TcpSocket`'s rx_buffer is)
        // positioned across its wrap, so `dequeue_many_with`'s own
        // `assert!(size <= max_size)` is the judge, not a restatement of it.
        //
        // RED on the inverse — the shipped-until-B1 `peek_slice` + `recv(|_|
        // (written, ()))` shape, i.e. `let n = ring.read_allocated(0, &mut buf);
        // ring.dequeue_many_with(|_| (n, ()))`: `read_allocated` copies across the
        // wrap, `n` (10) exceeds `max_size` (4), and this test panics exactly as
        // the `run_network` thread did on every sustained >64 KiB upload. The
        // live half of this gate (a real >1 MiB guest→host stream through the
        // device, which no fake moves) is `tests/nat_window_fill.rs`'s upload leg.
        #[test]
        fn guest_to_host_drain_consumes_only_the_contiguous_span() {
            // A 16-byte ring holding 10 payload bytes that straddle the wrap:
            // payload[0..4] at storage[12..16], payload[4..10] at storage[0..6),
            // `read_at` = 12. The contiguous span is 4; `peek_slice` reports 10.
            // The filler dance is required because `enqueue_many_with` resets
            // `read_at` to 0 whenever the ring goes EMPTY — so the ring is walked
            // to offset 12 while staying non-empty, then the two remaining filler
            // bytes are drained off the front.
            let mut storage = [0u8; 16];
            let mut ring = TcpSocketBuffer::new(&mut storage[..]);
            assert_eq!(ring.enqueue_slice(&[0xAA; 12]), 12);
            assert_eq!(ring.dequeue_slice(&mut [0u8; 10]), 10);
            let payload: Vec<u8> = (0..10u8).collect();
            assert_eq!(ring.enqueue_slice(&payload), 10);
            assert_eq!(ring.dequeue_slice(&mut [0u8; 2]), 2);
            assert_eq!(ring.len(), 10);

            // A host writer that accepts everything offered consumes exactly the
            // contiguous span, leaving the wrapped remainder queued for next tick.
            let mut seen: Vec<u8> = Vec::new();
            let (consumed, res) = ring.dequeue_many_with(|contiguous| {
                assert_eq!(contiguous.len(), 4, "pre-wrap span");
                drain_to_host(contiguous, |bytes| {
                    seen.extend_from_slice(bytes);
                    Ok(bytes.len())
                })
            });
            assert_eq!(consumed, 4, "consumed past the contiguous span");
            assert_eq!(res.expect("write ok"), 4);
            assert_eq!(seen, payload[..4], "wrong bytes handed to the host");
            assert_eq!(ring.len(), 6, "the wrapped remainder must stay queued");

            // A SHORT host write consumes exactly the accepted prefix — the tail
            // stays queued (consuming `contiguous.len()` here would lose bytes).
            let (consumed, res) = ring.dequeue_many_with(|contiguous| {
                assert_eq!(contiguous.len(), 6, "post-wrap span");
                drain_to_host(contiguous, |bytes| {
                    seen.extend_from_slice(&bytes[..2]);
                    Ok(2)
                })
            });
            assert_eq!(consumed, 2, "a short write must consume only what it took");
            assert_eq!(res.expect("write ok"), 2);
            assert_eq!(seen, payload[..6]);
            assert_eq!(ring.len(), 4);

            // `WouldBlock` (and any other error) consumes nothing: the queue is
            // intact and the same bytes are re-offered next tick.
            let (consumed, res) = ring.dequeue_many_with(|contiguous| {
                drain_to_host(contiguous, |_| {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                })
            });
            assert_eq!(consumed, 0, "a blocked write must consume nothing");
            assert_eq!(
                res.expect_err("blocked").kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(ring.len(), 4);

            // A writer over-reporting what it took is clamped to the offered span
            // rather than re-arming the `dequeue_many_with` assert.
            let (consumed, _) =
                ring.dequeue_many_with(|contiguous| drain_to_host(contiguous, |_| Ok(usize::MAX)));
            assert_eq!(consumed, 4);
            assert_eq!(ring.len(), 0);

            // Nothing queued → nothing offered, nothing consumed, no write
            // attempted (the empty slice must not be mistaken for an EOF write).
            let attempted = AtomicBool::new(false);
            let (consumed, res) = ring.dequeue_many_with(|contiguous| {
                drain_to_host(contiguous, |bytes| {
                    attempted.store(true, Ordering::SeqCst);
                    Ok(bytes.len())
                })
            });
            assert_eq!(consumed, 0);
            assert_eq!(res.expect("no write"), 0);
            assert!(!attempted.load(Ordering::SeqCst), "wrote on an empty ring");
        }

        // Invariant #4 (design §6.2): the per-forward-port socket pool must hold MORE
        // THAN ONE connection so an HTTP keep-alive connection cannot hold the only
        // slot and wedge the link. A 'simplify to 0..1' refactor sets
        // FORWARD_PORT_POOL = 1, reddening `> 1`; `>= 16` pins the documented
        // ≈16-per-port sizing so a silent shrink below it also reddens.
        #[test]
        fn forward_port_pool_holds_more_than_one_connection_per_port() {
            // Bind to a runtime local so the assertion is a real (fail-able) runtime
            // check, not a compile-time constant assertion.
            let pool = FORWARD_PORT_POOL;
            assert!(
                pool > 1,
                "a single socket per forward port lets one HTTP keep-alive connection \
                 hold the only slot and silently wedge the link (invariant #4)"
            );
            assert!(
                pool >= 16,
                "the forward-port pool must keep the design §6.2 ≈16-per-port sizing \
                 for concurrent + keep-alive connections"
            );
        }

        // NET-2: the host NAT MAC must never collide with any guest MAC produced
        // by `mac_math` for a valid vmid. Buggy impl guarded: HOST_NAT_MAC =
        // 02:00:00:00:00:fe == mac_math(254), which silently wedged vmid 254.
        #[test]
        fn host_nat_mac_never_collides_with_guest_mac() {
            let host = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                HOST_NAT_MAC[0],
                HOST_NAT_MAC[1],
                HOST_NAT_MAC[2],
                HOST_NAT_MAC[3],
                HOST_NAT_MAC[4],
                HOST_NAT_MAC[5],
            );
            for vmid in 1u32..=254 {
                assert_ne!(
                    crate::net::mac_math(vmid).unwrap(),
                    host,
                    "host NAT MAC collides with guest MAC for vmid {vmid}"
                );
            }
        }

        // M-NET-4/NET-4: exercise the EXACT fallible prologue `run_network` uses
        // (`nat_addrs`), not `ip_math` in isolation. Out-of-range vmids must be
        // rejected — so `run_network` exits its thread cleanly instead of
        // panicking on `.expect`. Buggy impl guarded: reintroducing an `.expect`
        // into `nat_addrs`/`run_network` would panic here on vmid 0/255.
        //
        // M-NET-2: the addresses `nat_addrs` builds must equal the shared ip_math
        // /30 output byte-for-byte (no re-hardcoded `10.200.x.y` literals that
        // could silently diverge). Boundary + interior vmids are checked.
        #[test]
        fn run_network_vmid_is_validated_by_ip_math() {
            assert!(nat_addrs(0).is_err());
            assert!(nat_addrs(255).is_err());

            for vmid in [1u32, 2, 127, 253, 254] {
                let (host_gw, guest_gw) = nat_addrs(vmid).expect("in-range vmid must resolve");
                let (host_std, guest_std, _) = crate::net::ip_math(vmid).unwrap();
                // Byte-for-byte equality with the shared /30 math.
                assert_eq!(
                    host_gw.octets(),
                    host_std.octets(),
                    "host gw drifted for vmid {vmid}"
                );
                assert_eq!(
                    guest_gw.octets(),
                    guest_std.octets(),
                    "guest gw drifted for vmid {vmid}"
                );
                // The host gateway is the /30 `.1` and the guest is the `.2`.
                assert_eq!(host_gw.octets()[3], 1, "host gw must be the .1 of the /30");
                assert_eq!(
                    guest_gw.octets()[3],
                    2,
                    "guest gw must be the .2 of the /30"
                );
            }
        }

        // NET-2: the backend must NOT advertise VIRTIO_NET_F_CTRL_VQ — it
        // declares only NUM_QUEUES == 2 (rx/tx) and services no control queue.
        // Buggy impl guarded: re-adding `(1 << 17)` sets the CTRL_VQ bit and
        // reddens the first assert. The positive asserts guard the test's
        // meaning, so the CTRL_VQ check is not vacuously true against an
        // all-zero feature word.
        #[test]
        fn advertised_features_omit_ctrl_vq() {
            let feats = advertised_features();
            assert_eq!(
                feats & (1u64 << VIRTIO_NET_F_CTRL_VQ_BIT),
                0,
                "must not advertise VIRTIO_NET_F_CTRL_VQ without a control queue/handler"
            );
            // The features actually backed by the device stay advertised.
            assert_ne!(
                feats & (1u64 << VIRTIO_F_VERSION_1),
                0,
                "VIRTIO_F_VERSION_1 must remain advertised"
            );
            assert_ne!(
                feats & (1u64 << VIRTIO_NET_F_MAC_BIT),
                0,
                "VIRTIO_NET_F_MAC must remain advertised"
            );
        }

        // NET-3: drive the real per-SYN admission path (`admit_syn`, the exact
        // helper `run_network` calls) with more distinct destination ports than
        // the pool can ever hold, and assert the dynamic pool stays capped at
        // MAX_DYNAMIC_SOCKETS. Buggy impl guarded: an admission path that skipped
        // the `reclaim_and_has_room` room check (admitting every SYN) would push
        // distinct_ports * SYN_BURST sockets, blowing past the cap and reddening
        // both asserts.
        #[test]
        fn admit_syn_caps_dynamic_pool_under_distinct_port_spray() {
            let mut sockets = SocketSet::new(vec![]);
            let mut port_mappings: Vec<NatPortMapping> = Vec::new();
            let permanent_count = 0;
            let pxy_port = 6000u16;

            let distinct_ports = MAX_DYNAMIC_SOCKETS + 64;
            for i in 0..distinct_ports {
                // Distinct ports (10_000..) so each SYN is a newly-seen port with
                // no already-open mapping, forcing the admission/room decision.
                let dst_port = 10_000u16 + (i as u16);
                admit_syn(
                    &mut sockets,
                    &mut port_mappings,
                    permanent_count,
                    dst_port,
                    pxy_port,
                    SYN_BURST,
                );
            }

            let dynamic = port_mappings.len() - permanent_count;
            assert!(
                dynamic <= MAX_DYNAMIC_SOCKETS,
                "dynamic NAT pool exceeded the cap under a SYN spray: {dynamic} > {MAX_DYNAMIC_SOCKETS}"
            );
            // Admission is in whole bursts up to the cap, and MAX_DYNAMIC_SOCKETS
            // is a multiple of SYN_BURST, so the pool fills to exactly the cap.
            assert_eq!(
                dynamic, MAX_DYNAMIC_SOCKETS,
                "the pool should fill to exactly the cap under a large spray"
            );
        }

        // NET-3: a bounded join must not block teardown on a wedged worker.
        // Buggy impl guarded: a plain `handle.join()` blocks until the worker
        // exits — and this worker only exits after we set `release`, *after* the
        // join call, so a blocking join would deadlock this test.
        #[test]
        fn join_with_timeout_does_not_block_on_wedged_worker() {
            let release = Arc::new(AtomicBool::new(false));
            let r2 = release.clone();
            let handle = std::thread::spawn(move || {
                while !r2.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let start = Instant::now();
            join_with_timeout(handle, "test", Duration::from_millis(50));
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "join_with_timeout blocked on a wedged worker"
            );
            // Let the detached worker exit cleanly.
            release.store(true, Ordering::Relaxed);
        }

        // A finished worker is reaped promptly without hitting the deadline.
        #[test]
        fn join_with_timeout_reaps_finished_worker() {
            let handle = std::thread::spawn(|| {});
            let start = Instant::now();
            join_with_timeout(handle, "test", Duration::from_secs(5));
            assert!(start.elapsed() < Duration::from_secs(2));
        }

        fn new_tcp_socket() -> TcpSocket<'static> {
            TcpSocket::new(
                TcpSocketBuffer::new(vec![0; 64]),
                TcpSocketBuffer::new(vec![0; 64]),
            )
        }

        // NET-5: closed, idle dynamic mappings are reclaimed; permanent ones are
        // kept. Buggy impl guarded: without reclamation the closed dynamic
        // mapping accumulates forever (len stays 2).
        #[test]
        fn reclaim_removes_closed_dynamic_sockets_but_keeps_permanent() {
            let mut sockets = SocketSet::new(vec![]);
            let mut port_mappings: Vec<NatPortMapping> = Vec::new();

            // One permanent mapping (closed, but must be kept).
            let perm = sockets.add(new_tcp_socket());
            port_mappings.push((9, 9, perm, None));
            let permanent_count = port_mappings.len();

            // One dynamic mapping: a fresh socket is in the Closed state.
            let dynamic = sockets.add(new_tcp_socket());
            port_mappings.push((100, 200, dynamic, None));

            let room = reclaim_and_has_room(&mut sockets, &mut port_mappings, permanent_count, 4);
            assert_eq!(
                port_mappings.len(),
                1,
                "closed dynamic mapping not reclaimed"
            );
            assert!(room, "pool should have room after reclamation");
        }

        // NET-5: the dynamic pool is capped. Buggy impl guarded: unbounded growth
        // would always report room for more sockets.
        #[test]
        fn reclaim_caps_dynamic_pool_growth() {
            let mut sockets = SocketSet::new(vec![]);
            let mut port_mappings: Vec<NatPortMapping> = Vec::new();
            // Fill with live (listening) dynamic sockets so none are reclaimed.
            for i in 0..MAX_DYNAMIC_SOCKETS {
                let mut s = new_tcp_socket();
                let _ = s.listen(10_000 + (i as u16));
                let h = sockets.add(s);
                port_mappings.push((10_000 + (i as u16), 9_999, h, None));
            }
            let room = reclaim_and_has_room(&mut sockets, &mut port_mappings, 0, 4);
            assert!(!room, "dynamic socket pool cap not enforced");
        }

        // Builds a real, connected `tokio::net::TcpStream` (loopback) for use as
        // a NAT mapping's host stream. The server end is dropped; the client fd
        // stays valid, which is all these tests inspect. Must be called inside a
        // tokio runtime context (`rt.enter()`), which `from_std` requires.
        fn connected_host_stream() -> tokio::net::TcpStream {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            let client = std::net::TcpStream::connect(addr).expect("connect");
            let (_server, _) = listener.accept().expect("accept");
            client.set_nonblocking(true).expect("nonblocking");
            tokio::net::TcpStream::from_std(client).expect("from_std")
        }

        // H-NET-2: a closed *dynamic* mapping whose host stream is still attached
        // must be reclaimed (the pool shrinks). Buggy impl guarded: the pre-fix
        // reclaim computed `live = stream.is_some() || is_open()`, so a closed
        // dynamic mapping with `stream = Some(..)` was counted live forever and
        // never freed — defeating the NET-5 cap. With that inverse, `len` stays
        // 1 and this assert goes red. (The existing reclaim test only uses
        // `stream = None`, so it never exercised the live-stream leak path.)
        #[test]
        fn reclaim_frees_closed_dynamic_mapping_with_live_stream() {
            let rt = tokio::runtime::Runtime::new().expect("rt");
            let _guard = rt.enter();

            let mut sockets = SocketSet::new(vec![]);
            let mut port_mappings: Vec<NatPortMapping> = Vec::new();

            // A fresh smoltcp socket is in the Closed state => `!is_open()`.
            let dynamic = sockets.add(new_tcp_socket());
            port_mappings.push((100, 200, dynamic, Some(connected_host_stream())));

            let room = reclaim_and_has_room(&mut sockets, &mut port_mappings, 0, 4);
            assert_eq!(
                port_mappings.len(),
                0,
                "a closed dynamic mapping with a live host stream must be reclaimed"
            );
            assert!(room, "pool should have room after reclamation");
        }

        // H-NET-1: on a guest-closed socket, the stale host stream is dropped
        // BEFORE a permanent listener is re-armed (so the next guest connection
        // dials a fresh host stream) and before a dynamic mapping is left for
        // reclamation. Buggy impl guarded: re-arming / continuing without
        // clearing `tcp_stream` leaves it `Some`, so `stream.is_none()` goes red.
        #[test]
        fn rearm_or_release_closed_clears_stale_stream() {
            let rt = tokio::runtime::Runtime::new().expect("rt");
            let _guard = rt.enter();

            // Permanent mapping: re-armed (not skipped) with a cleared stream.
            let mut socket = new_tcp_socket();
            assert!(!socket.is_open());
            let mut stream = Some(connected_host_stream());
            let (gw, _guest) = nat_test_addrs();
            let skip = rearm_or_release_closed(
                &mut socket,
                nat_forward_endpoint(gw, 8080),
                &mut stream,
                true,
            );
            assert!(!skip, "permanent mapping must be re-armed, not skipped");
            assert!(socket.is_open(), "permanent listener must be re-armed");
            assert!(
                stream.is_none(),
                "stale host stream must be cleared before re-arming (H-NET-1)"
            );

            // Dynamic mapping: skipped for reclamation, stream cleared.
            let mut dsocket = new_tcp_socket();
            let mut dstream = Some(connected_host_stream());
            let skip = rearm_or_release_closed(
                &mut dsocket,
                nat_forward_endpoint(gw, 9090),
                &mut dstream,
                false,
            );
            assert!(
                skip,
                "closed dynamic mapping must be skipped for reclamation"
            );
            assert!(!dsocket.is_open(), "dynamic mapping must stay closed");
            assert!(
                dstream.is_none(),
                "stale host stream must be cleared before continue (H-NET-2)"
            );
        }

        // ---- C7: `Egress::Open` forwards what its mode admits, and refuses the rest ----------
        //
        // These legs drive the REAL smoltcp stack the NAT runs (`nat_test_iface` mirrors
        // `run_network`'s interface configuration byte for byte, `set_any_ip(true)` included) and
        // assert on the frames that come back out of the device — the data plane, not a
        // descriptor or a proxy signal. No KVM, no vhost, no guest.

        /// The vmid whose `/30` the C7 legs run on.
        ///
        /// Every address below is derived from it through the shared `(vmid % 254) + 1` math
        /// (`nat_addrs` → `crate::net::ip_math`, `crate::net::mac_math`) — never a test-local
        /// literal, so an off-by-one in the octet map reddens these legs instead of hiding
        /// behind a hardcoded twin.
        const NAT_TEST_VMID: u32 = 7;

        /// This VM's `/30`: `(host gateway, guest address)`.
        fn nat_test_addrs() -> (Ipv4Address, Ipv4Address) {
            nat_addrs(NAT_TEST_VMID).expect("the /30 math must accept the C7 test vmid")
        }

        /// This VM's guest MAC, through the shared `mac_math`.
        fn nat_test_guest_mac() -> EthernetAddress {
            crate::net::mac_math(NAT_TEST_VMID)
                .expect("mac_math must accept the C7 test vmid")
                .parse()
                .expect("mac_math emits a parseable MAC")
        }

        /// The NAT's interface, configured exactly as `run_network` configures it.
        fn nat_test_iface(state: &Arc<Mutex<SharedState>>) -> Interface {
            let (host_gw, guest_gw) = nat_test_addrs();
            let mut device = SmoltcpDevice {
                state: state.lock().unwrap_or_else(|e| e.into_inner()),
            };
            let mut iface = Interface::new(
                Config::new(HardwareAddress::Ethernet(EthernetAddress(HOST_NAT_MAC))),
                &mut device,
                smoltcp::time::Instant::now(),
            );
            drop(device);
            // Load-bearing for the negative leg's honesty: with AnyIP the foreign-destination
            // SYN really is accepted by the IP layer, so what refuses it below is the socket's
            // destination scope — not the interface quietly dropping an off-`/30` packet.
            iface.set_any_ip(true);
            iface.update_ip_addrs(|addrs| {
                addrs
                    .push(IpCidr::new(IpAddress::Ipv4(host_gw), 30))
                    .expect("address storage");
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(guest_gw)
                .expect("default route");
            iface
        }

        /// Queues one guest→host Ethernet frame the way the vhost TX pump does.
        fn guest_sends(state: &Arc<Mutex<SharedState>>, frame: Vec<u8>) {
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tx_queue
                .push_back(frame);
        }

        /// Polls the interface once and drains everything the NAT emitted toward the guest.
        fn nat_replies(
            iface: &mut Interface,
            state: &Arc<Mutex<SharedState>>,
            sockets: &mut SocketSet<'_>,
        ) -> Vec<Vec<u8>> {
            let mut device = SmoltcpDevice {
                state: state.lock().unwrap_or_else(|e| e.into_inner()),
            };
            iface.poll(smoltcp::time::Instant::now(), &mut device, sockets);
            drop(device);
            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
            guard.rx_queue.drain(..).collect()
        }

        /// Wraps `payload` in an Ethernet frame from the guest to the NAT.
        fn guest_frame(ethertype: EthernetProtocol, payload: &[u8]) -> Vec<u8> {
            let mut buf = vec![0u8; EthernetFrame::<&[u8]>::header_len() + payload.len()];
            let mut frame = EthernetFrame::new_unchecked(&mut buf[..]);
            frame.set_src_addr(nat_test_guest_mac());
            frame.set_dst_addr(EthernetAddress(HOST_NAT_MAC));
            frame.set_ethertype(ethertype);
            frame.payload_mut().copy_from_slice(payload);
            buf
        }

        /// An ARP request from the guest for the gateway — the neighbour-cache seed without which
        /// the NAT could not put *any* reply on the wire, so the negative leg below would be
        /// indistinguishable from an unreachable guest.
        fn guest_arp_request() -> Vec<u8> {
            let (host_gw, guest_ip) = nat_test_addrs();
            let repr = smoltcp::wire::ArpRepr::EthernetIpv4 {
                operation: smoltcp::wire::ArpOperation::Request,
                source_hardware_addr: nat_test_guest_mac(),
                source_protocol_addr: guest_ip,
                target_hardware_addr: EthernetAddress([0; 6]),
                target_protocol_addr: host_gw,
            };
            let mut payload = vec![0u8; repr.buffer_len()];
            repr.emit(&mut smoltcp::wire::ArpPacket::new_unchecked(
                &mut payload[..],
            ));
            guest_frame(EthernetProtocol::Arp, &payload)
        }

        /// A guest TCP SYN to `dst:dst_port` — the one frame the C7 legs differ in.
        fn guest_syn(dst: Ipv4Address, dst_port: u16, src_port: u16) -> Vec<u8> {
            let (_host_gw, guest_ip) = nat_test_addrs();
            let checksum = smoltcp::phy::ChecksumCapabilities::default();
            let tcp = smoltcp::wire::TcpRepr {
                src_port,
                dst_port,
                control: smoltcp::wire::TcpControl::Syn,
                seq_number: smoltcp::wire::TcpSeqNumber(0x1234_5678),
                ack_number: None,
                window_len: 65535,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload: &[],
            };
            let ip = smoltcp::wire::Ipv4Repr {
                src_addr: guest_ip,
                dst_addr: dst,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            };
            let mut payload = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
            let mut packet = Ipv4Packet::new_unchecked(&mut payload[..]);
            ip.emit(&mut packet, &checksum);
            tcp.emit(
                &mut TcpPacket::new_unchecked(packet.payload_mut()),
                &IpAddress::Ipv4(guest_ip),
                &IpAddress::Ipv4(dst),
                &checksum,
            );
            guest_frame(EthernetProtocol::Ipv4, &payload)
        }

        /// The `(src, dst, syn, ack, rst)` of the single TCP frame in `frames`.
        fn sole_tcp_reply(frames: &[Vec<u8>]) -> (Ipv4Address, Ipv4Address, bool, bool, bool) {
            let mut found = None;
            for bytes in frames {
                let frame = EthernetFrame::new_checked(&bytes[..]).expect("an ethernet frame");
                if frame.ethertype() != EthernetProtocol::Ipv4 {
                    continue;
                }
                let ipv4 = Ipv4Packet::new_checked(frame.payload()).expect("an ipv4 packet");
                if ipv4.next_header() != IpProtocol::Tcp {
                    continue;
                }
                let tcp = TcpPacket::new_checked(ipv4.payload()).expect("a tcp segment");
                assert!(found.is_none(), "expected exactly one TCP reply");
                found = Some((
                    ipv4.src_addr(),
                    ipv4.dst_addr(),
                    tcp.syn(),
                    tcp.ack(),
                    tcp.rst(),
                ));
            }
            found.expect("the NAT must answer the guest's SYN with a TCP segment")
        }

        // C7 (design §6.2 / §17, AGENTS.md "`Egress::Open` must actually forward what its mode
        // admits — and is *not* arbitrary outbound"): a permanent NAT forward admits the §6.3
        // host endpoint **at this VM's own gateway** and REFUSES every other destination on the
        // same port, instead of silently splicing it onto the host's loopback service.
        //
        // The two legs are one socket, one forwarded port, one source guest, differing in
        // exactly one field: the SYN's destination address. The negative runs first so its
        // "still Listen" assertion cannot be an artifact of an already-consumed socket, and the
        // positive control that follows proves the very same socket does answer the destination
        // the mode admits — so the refusal is the scope working, not a dead NAT.
        //
        // RED ON THE INVERSE, observed: restoring the bare `socket.listen(*listen_port)` form
        // (i.e. `nat_forward_endpoint` returning `addr: None`) makes the foreign-destination SYN
        // be ACCEPTED — the reply is a SYN|ACK sourced from 93.184.216.34 and the socket leaves
        // `Listen` — which is production splicing an arbitrary internet destination onto
        // `127.0.0.1:<host_services_port>`.
        #[test]
        fn open_admits_the_gateway_endpoint_and_refuses_an_arbitrary_destination() {
            let (host_gw, _guest_ip) = nat_test_addrs();
            // An off-`/30` address the NAT has no business serving; the port is the forwarded
            // one, which is what makes this the *silent substitution* case rather than a SYN to
            // a port nothing listens on.
            let foreign = Ipv4Address::new(93, 184, 216, 34);
            const FORWARDED: u16 = 8080;

            let state = Arc::new(Mutex::new(empty_state(None)));
            let mut iface = nat_test_iface(&state);
            let mut sockets = SocketSet::new(vec![]);

            // Seed the neighbour cache, exactly as a booting guest does.
            guest_sends(&state, guest_arp_request());
            let arp = nat_replies(&mut iface, &state, &mut sockets);
            assert_eq!(arp.len(), 1, "the NAT must answer the guest's ARP request");

            // One permanent forward mapping, armed through the one composer — the shipped path.
            let handle = sockets.add(new_tcp_socket());
            let mut stream = None;
            assert!(!rearm_or_release_closed(
                sockets.get_mut::<TcpSocket>(handle),
                nat_forward_endpoint(host_gw, FORWARDED),
                &mut stream,
                true,
            ));
            assert!(sockets.get::<TcpSocket>(handle).is_listening());

            // ---- negative: an arbitrary outbound destination is REFUSED ---------------------
            guest_sends(&state, guest_syn(foreign, FORWARDED, 40_001));
            let refused = nat_replies(&mut iface, &state, &mut sockets);
            let (src, _dst, syn, _ack, rst) = sole_tcp_reply(&refused);
            assert!(
                rst && !syn,
                "a SYN to an arbitrary destination must be refused with a RST, not accepted: \
                 syn={syn} rst={rst}"
            );
            assert_eq!(
                src, foreign,
                "the RST must come back from the dialled address"
            );
            assert!(
                sockets.get::<TcpSocket>(handle).is_listening(),
                "the forward-port listener must not have accepted a connection addressed \
                 somewhere else — that is the silent destination substitution C7 removes"
            );

            // ---- positive control: the destination the mode DOES admit is served ------------
            guest_sends(&state, guest_syn(host_gw, FORWARDED, 40_002));
            let admitted = nat_replies(&mut iface, &state, &mut sockets);
            let (src, _dst, syn, ack, rst) = sole_tcp_reply(&admitted);
            assert!(
                syn && ack && !rst,
                "the §6.3 host endpoint at this VM's gateway must still be admitted: \
                 syn={syn} ack={ack} rst={rst}"
            );
            assert_eq!(src, host_gw, "the SYN|ACK must be sourced from the gateway");
            assert!(
                !sockets.get::<TcpSocket>(handle).is_listening(),
                "the admitted connection must have claimed the forward-port listener"
            );
        }

        // The composer itself: a permanent forward is destination-scoped, and it is scoped to the
        // gateway the shared `/30` math derives — not to whatever address a call site had handy.
        #[test]
        fn nat_forward_endpoint_pins_the_destination_to_this_vms_gateway() {
            let (host_gw, guest_ip) = nat_test_addrs();
            let ep = nat_forward_endpoint(host_gw, 8080);
            assert_eq!(
                ep.addr,
                Some(IpAddress::Ipv4(host_gw)),
                "an unscoped (`None`) listen address is what `TcpSocket::accepts` reads as \
                 'every destination'"
            );
            assert_eq!(ep.port, 8080);
            assert_ne!(
                ep.addr,
                Some(IpAddress::Ipv4(guest_ip)),
                "the forward must be scoped to the host side of the /30, not the guest side"
            );
        }

        // LOW: a guest-controlled descriptor length must be bounded before it is
        // used as an allocation size. Buggy impl guarded: `vec![0; desc.len()]`
        // unbounded would allocate up to ~4 GiB; here the 4 GiB case must be
        // refused (`None`), and accumulation across descriptors is honored.
        #[test]
        fn bounded_tx_read_caps_guest_controlled_length() {
            assert_eq!(bounded_tx_read(0, 0), Some(0));
            assert_eq!(bounded_tx_read(100, 0), Some(100));
            assert_eq!(bounded_tx_read(MAX_FRAME_LEN, 0), Some(MAX_FRAME_LEN));
            // A 4 GiB descriptor must be refused, never allocated.
            assert_eq!(bounded_tx_read(u32::MAX as usize, 0), None);
            // The bound accounts for bytes already accumulated across descriptors.
            assert_eq!(bounded_tx_read(5, MAX_FRAME_LEN - 5), Some(5));
            assert_eq!(bounded_tx_read(6, MAX_FRAME_LEN - 5), None);
            assert_eq!(bounded_tx_read(1, MAX_FRAME_LEN), None);
        }

        /// Connects to the NAT's vhost-user socket, retrying until `deadline`.
        ///
        /// The socket is bound before `SmoltcpProcess::start` returns and re-bound between
        /// connections, so a retry window (not a single shot) is what distinguishes "briefly
        /// re-arming" from "gone forever".
        fn connect_nat_socket(
            path: &std::path::Path,
            deadline: Duration,
        ) -> std::io::Result<std::os::unix::net::UnixStream> {
            let until = Instant::now() + deadline;
            loop {
                match std::os::unix::net::UnixStream::connect(path) {
                    Ok(s) => return Ok(s),
                    Err(e) if Instant::now() >= until => return Err(e),
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        }

        /// Sends a vhost-user `GET_FEATURES` and reads the reply header, proving the daemon
        /// **accepted and is serving** this connection — not merely that a bound socket queued it.
        ///
        /// The header is 3 native-endian `u32`s (request, flags, size); flags carry the protocol
        /// version in the low two bits and the reply bit (0x4) on the way back.
        fn vhost_user_served(sock: &std::os::unix::net::UnixStream) -> std::io::Result<()> {
            use std::io::{Read, Write};
            const GET_FEATURES: u32 = 1;
            const VERSION_1: u32 = 1;
            const REPLY_BIT: u32 = 0x4;

            sock.set_read_timeout(Some(Duration::from_secs(2)))?;
            sock.set_write_timeout(Some(Duration::from_secs(2)))?;
            let mut req = Vec::with_capacity(12);
            req.extend_from_slice(&GET_FEATURES.to_ne_bytes());
            req.extend_from_slice(&VERSION_1.to_ne_bytes());
            req.extend_from_slice(&0u32.to_ne_bytes());
            (&mut &*sock).write_all(&req)?;

            let mut hdr = [0u8; 12];
            (&mut &*sock).read_exact(&mut hdr)?;
            let request = u32::from_ne_bytes(hdr[0..4].try_into().expect("4 bytes"));
            let flags = u32::from_ne_bytes(hdr[4..8].try_into().expect("4 bytes"));
            let size = u32::from_ne_bytes(hdr[8..12].try_into().expect("4 bytes"));
            assert_eq!(request, GET_FEATURES, "reply must answer GET_FEATURES");
            assert_ne!(flags & REPLY_BIT, 0, "the daemon must mark its reply");
            assert_eq!(size, 8, "GET_FEATURES carries a u64 feature word");
            let mut body = vec![0u8; size as usize];
            (&mut &*sock).read_exact(&mut body)?;
            Ok(())
        }

        // `nat-socket-dies-with-first-vmm` (M2): the NAT socket must survive the first VMM's
        // hang-up and serve the NEXT connection, because `MicroVm::start`'s control-plane health
        // gate re-spawns the VMM on the same per-VM resources — of which this NAT is one.
        //
        // RED on today's single-accept worker, watched before the fix: `Listener`'s `Drop` unlinks
        // the path when the closure ends, so the second `connect_nat_socket` fails with
        // `No such file or directory` and the test reports
        // "the NAT socket must survive the first VMM's disconnect". The `vhost_user_served`
        // exchange makes it stronger than "the path exists": it proves a *daemon* is behind the
        // socket, so a worker that re-bound a listener nobody ever accepts on would still be red.
        #[test]
        fn nat_socket_serves_a_second_connection_after_the_first_hangs_up() {
            let dir = tempfile::tempdir().expect("tempdir");
            let socket_path = dir.path().join("smoltcp.sock");
            let nat =
                SmoltcpProcess::start(7, vec![], None, socket_path.clone(), NatEgressPolicy::Deny);

            let first = connect_nat_socket(&socket_path, Duration::from_secs(2))
                .expect("the NAT socket must be connectable once `start` returns");
            vhost_user_served(&first).expect("the first connection must be served");
            // The VMM goes away (a crash, or the control-plane health gate dropping the instance).
            drop(first);

            // Settle: on the pre-fix worker the listener is dropped — and the path unlinked —
            // within milliseconds of the hang-up, so this window is where the defect shows.
            std::thread::sleep(Duration::from_millis(300));

            let second = connect_nat_socket(&socket_path, Duration::from_secs(3))
                .expect("the NAT socket must survive the first VMM's disconnect");
            vhost_user_served(&second).expect("the re-spawned VMM's connection must be served too");
            drop(second);

            // Residue: the socket existed (both connects prove it) and teardown removes it — a
            // re-serving loop must not leave a bound path behind after `Drop`.
            assert!(
                socket_path.exists(),
                "the NAT socket must exist before drop"
            );
            drop(nat);
            let gone_by = Instant::now() + Duration::from_secs(3);
            while socket_path.exists() && Instant::now() < gone_by {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                !socket_path.exists(),
                "teardown must reclaim the NAT socket, not leave a re-armed listener behind"
            );
        }

        // `nat-daemon-start-error-swallowed` (m18): a bring-up failure ENDS the worker, loudly. The
        // pre-fix code logged `start returned {:?}` and fell through to `wait()` — which returns
        // `Ok` when no daemon thread was ever started — so a NAT that never came up reported a
        // clean exit. In the re-serving loop that swallow is worse than cosmetic: falling through
        // means looping straight back into a bring-up that cannot succeed.
        //
        // The arm driven here is the listener re-bind (the one reachable without `unsafe`: the
        // module is `#![forbid(unsafe_code)]`, so a deliberately broken accept fd cannot be built).
        // Its sibling — `VhostUserDaemon::new`/`start` failing — is the identical
        // `error!` + `return` three lines below.
        //
        // RED on the inverse (a `continue` that retries, or the pre-fix fall-through): the worker
        // never returns and the bounded join below reports "the worker must return".
        #[test]
        fn a_bring_up_failure_ends_the_vhost_worker_instead_of_being_swallowed() {
            let dir = tempfile::tempdir().expect("tempdir");
            let socket_path = dir.path().join("smoltcp.sock");
            let first = Listener::new(&socket_path, true).expect("first listener");

            let (consumer, notifier) = vmm_sys_util::event::new_event_consumer_and_notifier(
                vmm_sys_util::event::EventFlag::NONBLOCK,
            )
            .expect("event pair");
            let drain = consumer.try_clone().expect("clone consumer");
            let state = Arc::new(Mutex::new(SharedState {
                tx_queue: VecDeque::new(),
                rx_queue: VecDeque::new(),
                mem: None,
                vrings: None,
            }));
            let backend = Arc::new(std::sync::RwLock::new(VhostUserNetBackend {
                event_idx: false,
                kill_evt: (consumer, notifier),
                // The worker arms this itself, per connection.
                exit_evt: Mutex::new(None),
                tx_drops: AtomicU64::new(0),
                state: state.clone(),
            }));
            // Never set: the worker must stop because bring-up failed, not because it was told to.
            let stop_flag = Arc::new(AtomicBool::new(false));

            let (worker_path, worker_state, worker_stop) =
                (socket_path.clone(), state.clone(), stop_flag.clone());
            let worker = std::thread::spawn(move || {
                SmoltcpProcess::serve_vhost_connections(
                    &worker_path,
                    first,
                    &backend,
                    &drain,
                    &worker_state,
                    &worker_stop,
                );
            });

            // Serve one connection, then make the NEXT bind impossible: an already-bound listener
            // keeps working after its directory is gone, so this is deterministic — the re-bind
            // that follows the hang-up hits `ENOENT`.
            let client = connect_nat_socket(&socket_path, Duration::from_secs(2))
                .expect("the first listener must be connectable");
            std::fs::remove_dir_all(dir.path()).expect("remove the socket's directory");
            drop(client);

            let until = Instant::now() + Duration::from_secs(5);
            while !worker.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                worker.is_finished(),
                "the worker must return when it cannot bring the NAT up again, not swallow the \
                 failure and loop"
            );
            worker.join().expect("worker joined");
            assert!(
                !stop_flag.load(Ordering::SeqCst),
                "this test's exit must come from the bring-up failure, not from a stop request"
            );
        }

        // `nat-socket-dies-with-first-vmm` (M2), the between-connections half: the shared device
        // state and the shared exit event must be reset before the next VMM is served, or the
        // re-spawn connects to a NAT that carries the dead VM's memory table, vrings and frames —
        // and whose epoll workers exit immediately on a counter nobody ever consumed.
        //
        // RED on the inverse: deleting the drain leaves the consumer readable (the last assert),
        // and deleting any line of the reset leaves that field populated.
        #[test]
        fn between_connections_the_device_and_exit_event_are_reset() {
            let (consumer, notifier) = vmm_sys_util::event::new_event_consumer_and_notifier(
                vmm_sys_util::event::EventFlag::NONBLOCK,
            )
            .expect("event pair");
            notifier.notify().expect("signal 1");
            notifier.notify().expect("signal 2");
            assert!(
                drain_exit_event(&consumer) >= 1,
                "a signalled exit event must be drained"
            );
            assert!(
                consumer.consume().is_err(),
                "the exit event must be empty afterwards, or the next connection's vring workers \
                 exit before they process a single frame"
            );

            let mut state = SharedState {
                tx_queue: VecDeque::from(vec![vec![1u8, 2, 3]]),
                rx_queue: VecDeque::from(vec![vec![4u8, 5]]),
                mem: Some(GuestMemoryAtomic::new(GuestMemoryMmap::new())),
                // A populated (if empty) vrings latch: seeding `None` here would make the
                // `vrings.is_none()` assertion below vacuous, and the latch is the one field
                // `handle_event` never replaces once set.
                vrings: Some(Vec::new()),
            };
            reset_device_state(&mut state);
            assert!(state.tx_queue.is_empty(), "the dead VM's guest→host frames");
            assert!(state.rx_queue.is_empty(), "the dead VM's host→guest frames");
            assert!(state.mem.is_none(), "the dead VM's memory table");
            assert!(state.vrings.is_none(), "the dead VM's vrings");
        }

        // `nat-host-dial-unbounded` (m11): the per-mapping host dial is bounded as a WHOLE
        // operation and its failure is a value the caller can log, not a discarded `Err`.
        //
        // RED on the inverse (`TcpStream::connect(..).await` with no timeout and `if let Ok(..)`):
        // the pending-connect leg never returns, so the OUTER timeout below fires and the assert
        // reports it — on the single task that services the entire datapath, that is the whole VM's
        // network wedged behind one connect.
        #[tokio::test]
        async fn bounded_host_dial_bounds_the_whole_connect_and_surfaces_the_error() {
            let budget = Duration::from_millis(120);

            // A connect that never completes (a black-holed destination) must return within its
            // own budget, with a diagnostic naming the target and the budget.
            let started = Instant::now();
            let wedged = tokio::time::timeout(
                Duration::from_secs(5),
                bounded_host_dial(9, budget, std::future::pending()),
            )
            .await
            .expect("the dial must return within its own budget, not the test's");
            let elapsed = started.elapsed();
            let err = wedged.expect_err("a wedged connect must not report success");
            assert!(
                err.contains("127.0.0.1:9") && err.contains("budget"),
                "the timeout must name its target and its budget: {err}"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "the budget must bound the connect itself (took {elapsed:?})"
            );

            // A refused connect surfaces the OS error instead of being dropped on the floor.
            let dead_port = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
                l.local_addr().expect("addr").port() // listener dropped here → port refuses
            };
            let refused = bounded_host_dial(
                dead_port,
                budget,
                tokio::net::TcpStream::connect(format!("127.0.0.1:{dead_port}")),
            )
            .await
            .expect_err("a dial to a closed port must fail");
            assert!(
                refused.contains(&format!("127.0.0.1:{dead_port}")) && refused.contains("failed"),
                "a refused dial must be surfaced with its cause: {refused}"
            );

            // Positive control: a live listener is reached, and the stream is handed back.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let ok = bounded_host_dial(
                port,
                budget,
                tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")),
            )
            .await
            .expect("a live listener must be reachable");
            assert_eq!(ok.peer_addr().expect("peer").port(), port);
        }

        // `egress-blocked-is-a-silent-no-op` (M1, NAT half): under `Egress::Blocked` the NAT opens
        // NO outbound connection — asserted against a real listener that must never see an accept —
        // with the identical dial under `Allow` reaching it as the positive control.
        //
        // RED on the inverse (today's code, which has no policy at all and always dials): the
        // `Deny` leg returns `Ok` and the listener accepts, so both asserts below fail.
        #[tokio::test]
        async fn blocked_egress_opens_no_outbound_connection() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let budget = Duration::from_millis(200);

            let denied = dial_host_target(NatEgressPolicy::Deny, port, budget).await;
            match denied.expect_err("a Blocked VM must not get a host stream") {
                // Typed as a POLICY refusal, not a failure: the two are logged at different
                // levels, and a blocked VM's NAT is not malfunctioning.
                HostDialRefusal::Policy(why) => assert!(
                    why.contains("Blocked") && why.contains(&format!("127.0.0.1:{port}")),
                    "the refusal must name the policy and the target it refused: {why}"
                ),
                other => panic!("a policy refusal must not be typed as a dial failure: {other:?}"),
            }
            // Nothing arrived: the refusal is "no socket was opened", not "a socket was opened and
            // then dropped" — which would still have handed the guest a connection to a host port.
            let stray = tokio::time::timeout(Duration::from_millis(150), listener.accept()).await;
            assert!(
                stray.is_err(),
                "a Blocked VM's NAT must open no outbound connection at all"
            );

            // Positive control: the same dial under `Allow` reaches the same listener.
            let allowed = dial_host_target(NatEgressPolicy::Allow, port, budget)
                .await
                .expect("Allow must reach the local listener");
            assert_eq!(allowed.peer_addr().expect("peer").port(), port);
            let (_accepted, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("the positive control must be accepted")
                .expect("accept");
        }

        // L-NET-2: an RX frame that does not fully fit the guest's writable
        // descriptors (or hits a descriptor write failure) must be DROPPED, never
        // forwarded truncated. Buggy impl guarded: the pre-fix code reported the
        // partial `written` length unconditionally, delivering a corrupt frame —
        // here the truncated/failed cases must yield `None` (drop), not a partial
        // `Some`.
        #[test]
        fn rx_used_len_drops_truncated_frames() {
            // Whole frame fit: report its full length.
            assert_eq!(rx_used_len(1512, 1512, false), Some(1512));
            // Truncated (writable descriptors too small): drop, never forward partial.
            assert_eq!(rx_used_len(1000, 1512, false), None);
            // A descriptor write failure drops even a fully-offset frame.
            assert_eq!(rx_used_len(1512, 1512, true), None);
            // Zero-length edge is not a truncation.
            assert_eq!(rx_used_len(0, 0, false), Some(0));
        }

        // Sibling 20, the pure half: the guest→host queue must stop growing at its bound.
        // Buggy impl guarded: an unconditional `push_back` accepts frame `MAX_TX_QUEUE_FRAMES + 1`,
        // reddening the `false` assertion and the length that follows it.
        #[test]
        fn push_tx_frame_bounds_the_queue_depth() {
            let mut q: VecDeque<Vec<u8>> = VecDeque::new();
            for _ in 0..MAX_TX_QUEUE_FRAMES {
                assert!(push_tx_frame(&mut q, &[0xAB, 0xCD]));
            }
            assert_eq!(q.len(), MAX_TX_QUEUE_FRAMES);
            assert!(
                !push_tx_frame(&mut q, &[0xAB, 0xCD]),
                "a full queue must tail-drop, not grow"
            );
            assert_eq!(q.len(), MAX_TX_QUEUE_FRAMES, "the bound must hold");
            // Draining makes room again: the bound is a depth, not a lifetime quota.
            q.pop_front();
            assert!(push_tx_frame(&mut q, &[0xAB, 0xCD]));
            // The frame is queued verbatim (the virtio-net header is already stripped upstream).
            assert_eq!(q.back().map(Vec::as_slice), Some(&[0xAB, 0xCD][..]));
            // The bound is four ring-depths, so a bursty guest is never dropped between polls.
            assert_eq!(MAX_TX_QUEUE_FRAMES, 4 * QUEUE_SIZE);
        }

        /// Guest-memory layout of [`TxRing`]: a descriptor table, an avail ring, a used ring, and
        /// one small data buffer per ring slot. Sparse on purpose — each region starts on its own
        /// 64 KiB boundary so an off-by-one write is a wrong assertion, not silent corruption of a
        /// neighbour.
        const DESC_TABLE: u64 = 0x1_0000;
        const AVAIL_RING: u64 = 0x2_0000;
        const USED_RING: u64 = 0x3_0000;
        const DATA_BASE: u64 = 0x4_0000;
        const DATA_STRIDE: u64 = 128;
        /// Size of one split-virtqueue descriptor (addr, len, flags, next).
        const DESC_SIZE: u64 = 16;

        /// A hand-built split virtqueue in real guest memory: enough of a transmitq to drive the
        /// **real** [`VhostUserNetBackend::process_tx_queue`] and `handle_event`, KVM-free.
        ///
        /// Rule 4, the effect class the fakes are blind to: `FakeVmm` has no vring at all, so
        /// nothing in the suite had ever driven the TX path — which is where the B1 ring-wrap panic,
        /// M7's worker-killing iterate error and sibling 20's unbounded queue all shipped.
        ///
        /// Slot `i` of the avail ring permanently refers to descriptor `i`, which points at data
        /// buffer `i`; publishing frames is then a memory write plus an `avail.idx` bump, exactly
        /// what a guest driver does.
        struct TxRing {
            mem: GuestMemoryAtomic<GuestMemoryMmap>,
            vring: VringMutex,
            size: u16,
        }

        impl TxRing {
            fn new(size: u16) -> Self {
                let bytes = DATA_BASE as usize + (size as usize) * (DATA_STRIDE as usize);
                let mem = GuestMemoryAtomic::new(
                    GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0), bytes)])
                        .expect("guest memory"),
                );
                let vring: VringMutex = VringT::new(mem.clone(), size).expect("vring");
                {
                    let mut state = vring.get_mut();
                    state
                        .set_queue_info(DESC_TABLE, AVAIL_RING, USED_RING)
                        .expect("queue addresses");
                    let queue = state.get_queue_mut();
                    queue.set_size(size);
                    // `iter()` refuses a queue that is not ready, so a real driver's
                    // SET_VRING_ENABLE is part of the fixture.
                    queue.set_ready(true);
                }
                let ring = TxRing { mem, vring, size };
                for slot in 0..size {
                    ring.write_desc(slot, 0);
                }
                ring
            }

            /// Points descriptor `slot` at its data buffer with `len` readable bytes, and pins the
            /// avail entry that refers to it.
            fn write_desc(&self, slot: u16, len: u32) {
                let mem = self.mem.memory();
                let at = DESC_TABLE + u64::from(slot) * DESC_SIZE;
                mem.write_obj(
                    DATA_BASE + u64::from(slot) * DATA_STRIDE,
                    vm_memory::GuestAddress(at),
                )
                .expect("desc addr");
                mem.write_obj(len, vm_memory::GuestAddress(at + 8))
                    .expect("desc len");
                // flags = 0: readable (guest → host) and no NEXT, i.e. a one-descriptor chain.
                mem.write_obj(0u16, vm_memory::GuestAddress(at + 12))
                    .expect("desc flags");
                mem.write_obj(0u16, vm_memory::GuestAddress(at + 14))
                    .expect("desc next");
                mem.write_obj(
                    slot,
                    vm_memory::GuestAddress(AVAIL_RING + 4 + u64::from(slot) * 2),
                )
                .expect("avail entry");
            }

            /// Publishes `count` frames carrying `payload` (with the 12-byte virtio-net header the
            /// backend strips), advancing `avail.idx` the way a guest driver does.
            fn publish(&self, count: u16, payload: &[u8]) {
                let mut frame = vec![0u8; VIRTIO_NET_HDR_SIZE];
                frame.extend_from_slice(payload);
                assert!(
                    frame.len() as u64 <= DATA_STRIDE,
                    "the fixture's data buffers hold {DATA_STRIDE} bytes"
                );
                let start = self.avail_idx();
                for n in 0..count {
                    let slot = start.wrapping_add(n) % self.size;
                    self.mem
                        .memory()
                        .write_slice(
                            &frame,
                            vm_memory::GuestAddress(DATA_BASE + u64::from(slot) * DATA_STRIDE),
                        )
                        .expect("frame bytes");
                    self.write_desc(slot, frame.len() as u32);
                }
                self.set_avail_idx(start.wrapping_add(count));
            }

            fn avail_idx(&self) -> u16 {
                self.mem
                    .memory()
                    .read_obj(vm_memory::GuestAddress(AVAIL_RING + 2))
                    .expect("avail idx")
            }

            fn set_avail_idx(&self, idx: u16) {
                self.mem
                    .memory()
                    .write_obj(idx, vm_memory::GuestAddress(AVAIL_RING + 2))
                    .expect("avail idx");
            }

            fn used_idx(&self) -> u16 {
                self.mem
                    .memory()
                    .read_obj(vm_memory::GuestAddress(USED_RING + 2))
                    .expect("used idx")
            }

            /// Re-points the used ring at an **unmapped** guest address, the way a guest driver that
            /// programmed a bogus `SET_VRING_USED` does (only alignment is validated, by design:
            /// `try_set_used_ring_address` never sees the memory table).
            ///
            /// Every used-ring access then fails with `virtio_queue::Error::GuestMemory` — which is
            /// the only KVM-free way to reach the notification-toggle error paths, the class of
            /// result the M7 fix discarded.
            fn break_used_ring(&self) {
                let mut state = self.vring.get_mut();
                state
                    .set_queue_info(DESC_TABLE, AVAIL_RING, UNMAPPED_USED_RING)
                    .expect("the address is 4-byte aligned; only alignment is validated");
            }
        }

        /// Aligned, and far outside the [`TxRing`] fixture's mapped guest memory.
        const UNMAPPED_USED_RING: u64 = 0x1000_0000;

        fn empty_state(mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>) -> SharedState {
            SharedState {
                tx_queue: VecDeque::new(),
                rx_queue: VecDeque::new(),
                mem,
                vrings: None,
            }
        }

        /// A backend over `state`, with its own kill event and its exit event armed — the shape
        /// `serve_vhost_connections` hands to `VhostUserDaemon::new`.
        fn armed_backend(state: Arc<Mutex<SharedState>>) -> VhostUserNetBackend {
            let (consumer, notifier) = vmm_sys_util::event::new_event_consumer_and_notifier(
                vmm_sys_util::event::EventFlag::NONBLOCK,
            )
            .expect("event pair");
            let mut backend = VhostUserNetBackend {
                event_idx: false,
                kill_evt: (consumer, notifier),
                exit_evt: Mutex::new(None),
                tx_drops: AtomicU64::new(0),
                state,
            };
            backend.arm_exit_event().expect("arming");
            backend
        }

        // Sibling 20, at the call site: a guest that keeps kicking a ring nobody is draining must
        // not grow host memory without bound — and the frames that are dropped must still have
        // their descriptors returned, or the guest's own ring stalls instead.
        //
        // Buggy impl guarded: the shipped-until-now `state.tx_queue.push_back(payload.to_vec())`
        // queues all five ring-fulls (5120 frames ≈ 7.5 MB for a 1024-entry ring, and unbounded for
        // a guest that keeps going), reddening the length assertion. This drives the real
        // `process_tx_queue` over a real vring, so a bound applied only inside the helper — and not
        // at the enqueue site — is still red.
        //
        // And the drop is OBSERVABLE: the bound is a data-plane behavior change, so the frames it
        // discards are counted and the count is logged at `warn`. RED on the inverse in two ways —
        // dropping the `fetch_add` reddens the count assertion, and demoting the report back to the
        // `trace!` it shipped as (or deleting it) reddens the level-checked `logs_assert`, which is
        // the whole difference between a bounded queue and a silently lossy one.
        #[test]
        #[tracing_test::traced_test]
        fn the_guest_to_host_queue_is_depth_bounded_and_still_returns_descriptors() {
            let ring = TxRing::new(QUEUE_SIZE as u16);
            let mut state = empty_state(Some(ring.mem.clone()));
            let drops = AtomicU64::new(0);

            let fulls = 5u32;
            for _ in 0..fulls {
                ring.publish(ring.size, &[0xAB, 0xCD, 0xEF]);
                let mut vring_state = ring.vring.get_mut();
                assert_eq!(
                    VhostUserNetBackend::process_tx_queue(&mut state, &mut vring_state, &drops),
                    TxPass::Drained,
                    "a healthy ring must drain"
                );
            }

            let published = fulls * (QUEUE_SIZE as u32);
            assert_eq!(
                state.tx_queue.len(),
                MAX_TX_QUEUE_FRAMES,
                "the queue must stop at its depth bound under a kick flood ({published} frames \
                 published with nothing draining)"
            );
            assert_eq!(
                u32::from(ring.used_idx()),
                published % 65_536,
                "every descriptor must be returned to the guest, dropped frames included, or its \
                 ring stalls"
            );
            // The frames that WERE queued are the payload, header stripped — a drop must not
            // corrupt the ones it drops around.
            assert!(
                state
                    .tx_queue
                    .iter()
                    .all(|f| f.as_slice() == [0xAB, 0xCD, 0xEF]),
                "queued frames must be the guest payload with the virtio-net header stripped"
            );
            // Every frame the bound discarded is accounted for, exactly once.
            assert_eq!(
                drops.load(Ordering::Relaxed),
                u64::from(published) - MAX_TX_QUEUE_FRAMES as u64,
                "the frames the bound discarded must be counted"
            );
            // A tail drop an operator cannot see is the same class of defect as a silent wedge, and
            // the LEVEL is what decides whether they can: `tracing_test` captures TRACE and up, so
            // asserting mere presence would accept the `trace!` this shipped as.
            logs_assert(|lines: &[&str]| {
                match lines
                    .iter()
                    .find(|line| line.contains("frame(s) tail-dropped since bring-up"))
                {
                    Some(line) if line.contains("WARN") => Ok(()),
                    Some(line) => Err(format!(
                        "the tail-drop report sits below WARN, where no default subscriber shows \
                         it: {line}"
                    )),
                    None => Err("the tail drop is not reported at all".to_string()),
                }
            });
        }

        // The reporting cadence itself: the FIRST drop always reports (a NAT that reaches a
        // four-ring-deep queue has a stalled consumer, which is a bug report), and a sustained
        // overload then reports once per queue-depth rather than once per frame.
        //
        // RED on the inverse: a bare `total % TX_DROP_REPORT_EVERY == 0` swallows the first 4095
        // drops (the second assertion), and an unconditional `true` floods a persisted console log
        // (the third).
        #[test]
        fn the_first_tail_drop_reports_and_a_sustained_one_does_not_flood() {
            assert!(tx_drop_is_reportable(1), "the first drop must be reported");
            assert!(
                !tx_drop_is_reportable(2),
                "a per-frame report would flood the console artifact"
            );
            assert!(!tx_drop_is_reportable(TX_DROP_REPORT_EVERY - 1));
            assert!(
                tx_drop_is_reportable(TX_DROP_REPORT_EVERY),
                "a sustained overload must keep saying so"
            );
            assert!(tx_drop_is_reportable(TX_DROP_REPORT_EVERY * 3));
            // One line per queue-depth: the cadence is tied to the bound it reports on.
            assert_eq!(TX_DROP_REPORT_EVERY, MAX_TX_QUEUE_FRAMES as u64);
        }

        // M7: a refused avail ring — `virtio-queue`'s own guest-misbehaviour detection — must cost
        // ONE pass, not the link. The pre-fix `process_tx_queue` mapped it to an `io::Error` and
        // `handle_event` propagated it with `?`; `VringEpollHandler::run` then returns, the vring
        // worker thread exits, `VhostUserHandler::drop` discards that return value at `join`, and
        // the device stays attached — a guest looking at a live link that never drains again.
        //
        // RED on the inverse in two ways: restoring the `?` makes `handle_event` return `Err` (the
        // `is_ok` assertion), and swallowing the error *without* breaking the EVENT_IDX loop spins
        // forever on a ring that can never be read (the bounded wait below reports it instead of
        // hanging the suite).
        #[test]
        fn a_refused_avail_ring_costs_one_pass_not_the_vring_worker() {
            let ring = TxRing::new(64);
            let state = Arc::new(Mutex::new(empty_state(Some(ring.mem.clone()))));
            let drops = AtomicU64::new(0);

            // One legitimate frame first, so the fixture is proven able to drain at all — otherwise
            // "nothing was queued" below would be vacuous.
            ring.publish(1, &[0x11, 0x22]);
            {
                let mut vring_state = ring.vring.get_mut();
                let mut guard = state.lock().expect("state");
                assert_eq!(
                    VhostUserNetBackend::process_tx_queue(&mut guard, &mut vring_state, &drops),
                    TxPass::Drained
                );
                assert_eq!(guard.tx_queue.len(), 1, "the fixture must be able to drain");
                guard.tx_queue.clear();
            }

            // The guest advances `avail.idx` more than a queue's worth past what the backend has
            // consumed: `AvailIter::new` refuses the ring with `InvalidAvailRingIndex`.
            ring.set_avail_idx(ring.avail_idx().wrapping_add(ring.size + 1));
            {
                let mut vring_state = ring.vring.get_mut();
                let mut guard = state.lock().expect("state");
                assert_eq!(
                    VhostUserNetBackend::process_tx_queue(&mut guard, &mut vring_state, &drops),
                    TxPass::Unreadable,
                    "a refused ring is not a drain"
                );
                assert!(
                    guard.tx_queue.is_empty(),
                    "a refused ring must queue nothing"
                );
            }
            assert_eq!(
                drops.load(Ordering::Relaxed),
                0,
                "a refused ring drops no FRAMES — miscounting it as a tail drop would report an \
                 overload that never happened"
            );

            // The call site: `handle_event` must return `Ok` — and terminate — on that same ring,
            // in the EVENT_IDX mode whose loop would otherwise re-poll it forever.
            let mut backend = armed_backend(state.clone());
            backend.set_event_idx(true);
            let rx_vring: VringMutex = VringT::new(ring.mem.clone(), ring.size).expect("rx vring");
            let vrings = vec![rx_vring, ring.vring.clone()];
            let worker =
                std::thread::spawn(move || backend.handle_event(1, EventSet::IN, &vrings, 0));
            let until = Instant::now() + Duration::from_secs(5);
            while !worker.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                worker.is_finished(),
                "handle_event must give up on a refused ring, not re-poll it forever while holding \
                 the state mutex the net thread needs"
            );
            let outcome = worker.join().expect("the handler must not panic");
            assert!(
                outcome.is_ok(),
                "a guest-refused ring must not become an Err out of handle_event, which the \
                 framework's epoll loop treats as terminal: {outcome:?}"
            );
        }

        // The notification-mask toggles are the two `Result`s the M7 fix discarded outright, plus the
        // two `unwrap_or(false)` siblings beside them. Failing to RE-ARM is not a throughput hint:
        // the mask is how the *guest's* driver is told not to kick, so leaving it set is the same
        // silently wedged link M7 exists to prevent — reached through the error path of the fix for
        // it. So a toggle failure is reported, at a level a default subscriber shows, and never
        // becomes the `Err` that kills the vring worker.
        //
        // RED on the inverse: restoring either `let _ = vring_state.enable_notification();` or
        // `vring_state.enable_notification().unwrap_or(false)` inside the helper leaves the log empty
        // and the level-checked `logs_assert` fails, while every other assertion here still passes —
        // which is exactly how the discard shipped in the first place. Restoring it at a *call site*
        // instead is invisible here by construction, which is what
        // `exit_event_arming_gate::every_notification_toggle_routes_through_its_reporting_helper`
        // exists for.
        #[test]
        #[tracing_test::traced_test]
        fn a_failed_notification_toggle_is_reported_not_discarded() {
            // POSITIVE CONTROL first, on a healthy ring: the helpers are silent, and the re-arm
            // reports what the guest actually supplied. Without this leg an unconditional log would
            // satisfy the assertions below.
            let healthy = TxRing::new(64);
            {
                let mut vring_state = healthy.vring.get_mut();
                mask_tx_notifications(&mut vring_state);
                assert!(
                    !rearm_tx_notifications(&mut vring_state),
                    "an empty ring has nothing more to poll"
                );
                healthy.publish(1, &[0x11, 0x22]);
                assert!(
                    rearm_tx_notifications(&mut vring_state),
                    "a frame published while the mask was on must be reported as more-available"
                );
            }
            assert!(
                !logs_contain("could not mask transmitq kicks")
                    && !logs_contain("could not re-arm transmitq kicks"),
                "a healthy ring must not report a toggle failure"
            );

            // Now the error path: a used ring the guest pointed at unmapped memory.
            let broken = TxRing::new(64);
            broken.break_used_ring();
            {
                let mut vring_state = broken.vring.get_mut();
                mask_tx_notifications(&mut vring_state);
                assert!(
                    !rearm_tx_notifications(&mut vring_state),
                    "a ring whose mask could not be lifted is not one to keep polling"
                );
            }
            // Both failures are reported, and at the level their consequence deserves: the mask is a
            // lost wakeup (`warn`), the re-arm is a wedged link (`error`). The level is asserted
            // because `tracing_test` captures TRACE and up — presence alone would accept a report
            // demoted to a level no host enables, which is the same silence one step removed.
            logs_assert(|lines: &[&str]| {
                for (level, needle, consequence) in [
                    (
                        "WARN",
                        "could not mask transmitq kicks",
                        "a failed mask must be reported, not discarded",
                    ),
                    (
                        "ERROR",
                        "could not re-arm transmitq kicks",
                        "a failed re-arm leaves the guest masked on a ring nothing will poll again",
                    ),
                ] {
                    match lines.iter().find(|line| line.contains(needle)) {
                        Some(line) if line.contains(level) => {}
                        Some(line) => {
                            return Err(format!("{consequence}, at {level}: got {line}"));
                        }
                        None => return Err(format!("{consequence}; nothing was logged")),
                    }
                }
                Ok(())
            });

            // And the call site keeps the framework's contract: a broken ring still returns `Ok`,
            // because an `Err` here kills the vring worker and wedges the link (M7).
            let state = Arc::new(Mutex::new(empty_state(Some(broken.mem.clone()))));
            let mut backend = armed_backend(state);
            backend.set_event_idx(true);
            let rx_vring: VringMutex =
                VringT::new(broken.mem.clone(), broken.size).expect("rx vring");
            let vrings = vec![rx_vring, broken.vring.clone()];
            let outcome = backend.handle_event(1, EventSet::IN, &vrings, 0);
            assert!(
                outcome.is_ok(),
                "a broken used ring must not become an Err out of handle_event, which the \
                 framework's epoll loop treats as terminal: {outcome:?}"
            );
        }

        // `smoltcp.rs:553`: the exit-event pair is reserved at bring-up, and what `exit_event` hands
        // the framework is a handle on the SHARED kill event — which is what lets
        // `SmoltcpProcess::Drop`'s `notify()` wake this connection's vring worker and
        // `drain_exit_event` clear the counter between connections.
        //
        // RED on the inverse: an `arm_exit_event` that reserves nothing leaves the slot `None`
        // (second assertion), and an `exit_event` that returns a FRESH eventfd pair instead of a
        // clone leaves the shared observer unreadable (fourth assertion).
        #[test]
        fn exit_event_hands_out_a_handle_on_the_armed_shared_kill_event() {
            let (consumer, notifier) = vmm_sys_util::event::new_event_consumer_and_notifier(
                vmm_sys_util::event::EventFlag::NONBLOCK,
            )
            .expect("event pair");
            // The worker loop's own third handle (`kill_evt_drain`), standing in as the observer.
            let observer = consumer.try_clone().expect("clone consumer");
            let mut backend = VhostUserNetBackend {
                event_idx: false,
                kill_evt: (consumer, notifier),
                exit_evt: Mutex::new(None),
                tx_drops: AtomicU64::new(0),
                state: Arc::new(Mutex::new(empty_state(None))),
            };

            assert!(
                backend.exit_evt.lock().expect("exit slot").is_none(),
                "nothing is armed before bring-up"
            );
            backend.arm_exit_event().expect("arming must succeed");
            assert!(
                backend.exit_evt.lock().expect("exit slot").is_some(),
                "arming must reserve the pair BEFORE the daemon exists — `exit_event` has no error \
                 channel and its `None` wedges the daemon's own drop"
            );

            let (armed_consumer, armed_notifier) = backend
                .exit_event(0)
                .expect("an armed backend must hand out its pair");
            armed_notifier.notify().expect("notify");
            assert!(
                observer.consume().is_ok(),
                "the handed-out pair must be a handle on the shared kill event, not a fresh eventfd"
            );
            assert!(
                armed_consumer.consume().is_err(),
                "…and share its counter, which the observer just drained"
            );

            // The reservation is consumed once. A second worker thread (not this backend's shape
            // today) falls back to a live clone rather than the `None` that cannot be recovered.
            assert!(
                backend.exit_event(0).is_some(),
                "exit_event must never hand the framework a None"
            );
        }

        /// A minimal backend for driving the vendored framework's own exit-event semantics, with
        /// `exit_event` switchable. Not a fake of vmcell's backend: the claim under test is about
        /// `vhost-user-backend`, so the probe must be as small as the trait allows.
        struct ExitProbeBackend {
            exit: Mutex<Option<(EventConsumer, EventNotifier)>>,
        }

        impl VhostUserBackendMut for ExitProbeBackend {
            type Bitmap = ();
            type Vring = VringMutex;

            fn num_queues(&self) -> usize {
                1
            }

            fn max_queue_size(&self) -> usize {
                64
            }

            fn features(&self) -> u64 {
                1 << VIRTIO_F_VERSION_1
            }

            fn protocol_features(&self) -> VhostUserProtocolFeatures {
                VhostUserProtocolFeatures::empty()
            }

            fn set_event_idx(&mut self, _enabled: bool) {}

            fn update_memory(
                &mut self,
                _mem: GuestMemoryAtomic<GuestMemoryMmap>,
            ) -> std::io::Result<()> {
                Ok(())
            }

            fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
                self.exit.lock().expect("exit slot").take()
            }

            fn handle_event(
                &mut self,
                _device_event: u16,
                _evset: EventSet,
                _vrings: &[VringMutex],
                _thread_id: usize,
            ) -> std::io::Result<()> {
                Ok(())
            }
        }

        // The premise `arm_exit_event` rests on, pinned against the vendored framework instead of
        // asserted in a comment — the pre-fix rustdoc claimed the opposite ("only forgoes the
        // prompt-wakeup optimization … so teardown completes") and was wrong: with no exit event,
        // `VringEpollHandler::new` registers no exit fd, `send_exit_event` is a no-op, `run` never
        // breaks out of `epoll_wait`, and `VhostUserHandler::drop` joins that worker forever.
        //
        // This goes red the day the framework grows a fallback — at which point the arming's
        // rationale (and its terminal-on-failure treatment) must be revisited, not silently kept.
        // The absent-exit-event leg deliberately leaks its wedged worker: the drop cannot return,
        // which is the whole point, and nextest runs each test in its own process.
        #[test]
        fn a_daemon_without_an_exit_event_cannot_join_its_vring_worker() {
            fn drop_daemon_on_a_thread(
                exit: Option<(EventConsumer, EventNotifier)>,
            ) -> std::thread::JoinHandle<()> {
                let backend = Arc::new(std::sync::RwLock::new(ExitProbeBackend {
                    exit: Mutex::new(exit),
                }));
                let daemon = VhostUserDaemon::new(
                    String::from("exit-probe"),
                    backend,
                    GuestMemoryAtomic::new(GuestMemoryMmap::new()),
                )
                .expect("daemon");
                std::thread::spawn(move || drop(daemon))
            }

            // Positive control first: a daemon whose backend hands out an exit event is joinable.
            let (consumer, notifier) = vmm_sys_util::event::new_event_consumer_and_notifier(
                vmm_sys_util::event::EventFlag::NONBLOCK,
            )
            .expect("event pair");
            let armed = drop_daemon_on_a_thread(Some((consumer, notifier)));
            let until = Instant::now() + Duration::from_secs(5);
            while !armed.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                armed.is_finished(),
                "a daemon whose worker has an exit fd must be droppable"
            );
            armed.join().expect("the armed drop must not panic");

            // The inverse: `None` is not a graceful degradation, it is a teardown that never ends.
            let wedged = drop_daemon_on_a_thread(None);
            std::thread::sleep(Duration::from_millis(500));
            assert!(
                !wedged.is_finished(),
                "the framework grew a fallback for a backend with no exit event; `arm_exit_event`'s \
                 rationale must be re-derived rather than kept on a stale premise"
            );
        }

        /// A scratch smoltcp interface, only for the `Context` [`TcpSocket::connect`] needs.
        fn scratch_iface() -> Interface {
            let state = Arc::new(Mutex::new(empty_state(None)));
            let mut device = SmoltcpDevice {
                state: state.lock().unwrap_or_else(|e| e.into_inner()),
            };
            Interface::new(
                Config::new(HardwareAddress::Ethernet(EthernetAddress(HOST_NAT_MAC))),
                &mut device,
                // The glob-imported smoltcp clock, not the `std::time::Instant` shadowing it above.
                smoltcp::time::Instant::now(),
            )
        }

        /// Drives `handle`'s socket into the state an **accepted** connection leaves it in: open,
        /// but no longer able to answer a SYN.
        ///
        /// A real claim is an inbound handshake, which would need a hand-built SYN frame through the
        /// device; `connect` reaches the equivalent open-and-not-listening state (SYN-SENT), and the
        /// question [`syn_already_served`] asks — `is_listening()` — is answered identically by
        /// every claimed state. `abort` first, because `connect` refuses an already-open socket.
        fn claim_socket(iface: &mut Interface, sockets: &mut SocketSet<'_>, handle: SocketHandle) {
            let socket = sockets.get_mut::<TcpSocket>(handle);
            socket.abort();
            socket
                .connect(
                    iface.context(),
                    (IpAddress::Ipv4(Ipv4Address::new(10, 200, 8, 2)), 80),
                    smoltcp::wire::IpListenEndpoint {
                        addr: Some(IpAddress::Ipv4(Ipv4Address::new(10, 200, 8, 1))),
                        port: 49_152,
                    },
                )
                .expect("a claimed socket");
            assert!(socket.is_open(), "a claimed socket is still open");
            assert!(!socket.is_listening(), "a claimed socket cannot accept");
        }

        /// Claims every still-listening mapping for `dst_port`, i.e. one full round of concurrent
        /// guest connections landing on that destination.
        fn claim_all_listeners(
            iface: &mut Interface,
            sockets: &mut SocketSet<'_>,
            port_mappings: &[NatPortMapping],
            dst_port: u16,
        ) {
            let handles: Vec<SocketHandle> = port_mappings
                .iter()
                .filter(|(p, _, h, _)| {
                    *p == dst_port && sockets.get::<TcpSocket>(*h).is_listening()
                })
                .map(|(_, _, h, _)| *h)
                .collect();
            for handle in handles {
                claim_socket(iface, sockets, handle);
            }
        }

        // `smoltcp.rs:764`: transparent interception must not cap at SYN_BURST *concurrent*
        // connections per destination.
        //
        // RED on the inverse (the shipped-until-now `is_open()` predicate): a claimed burst reads as
        // "already handled", nothing grows, the pool stays at SYN_BURST — and in production the
        // SYN_BURST+1-th connection's SYN is never answered at all.
        #[test]
        fn admit_syn_grows_when_a_destinations_whole_burst_is_claimed() {
            let mut iface = scratch_iface();
            let mut sockets = SocketSet::new(vec![]);
            let mut port_mappings: Vec<NatPortMapping> = Vec::new();
            let (dst, pxy) = (80u16, 6_000u16);

            // A newly-seen destination arms one burst.
            admit_syn(&mut sockets, &mut port_mappings, 0, dst, pxy, SYN_BURST);
            assert_eq!(port_mappings.len(), SYN_BURST);
            // While a listener is free, another SYN must NOT grow the pool — that is what the burst
            // is for, and it is what keeps a SYN spray bounded.
            admit_syn(&mut sockets, &mut port_mappings, 0, dst, pxy, SYN_BURST);
            assert_eq!(
                port_mappings.len(),
                SYN_BURST,
                "an unclaimed listener already serves the next SYN"
            );

            // Now every listener for that destination is claimed by a connection.
            claim_all_listeners(&mut iface, &mut sockets, &port_mappings, dst);
            admit_syn(&mut sockets, &mut port_mappings, 0, dst, pxy, SYN_BURST);
            assert_eq!(
                port_mappings.len(),
                2 * SYN_BURST,
                "the SYN_BURST+1-th concurrent connection to one destination must earn a listener"
            );

            // …and the NET-5 cap still binds when the spray is one destination rather than many:
            // every round claims what it got, so growth is the only way out.
            for _ in 0..(MAX_DYNAMIC_SOCKETS / SYN_BURST + 8) {
                claim_all_listeners(&mut iface, &mut sockets, &port_mappings, dst);
                admit_syn(&mut sockets, &mut port_mappings, 0, dst, pxy, SYN_BURST);
            }
            assert_eq!(
                port_mappings.len(),
                MAX_DYNAMIC_SOCKETS,
                "per-destination growth must still stop at the dynamic pool cap"
            );
        }

        // The other half of `syn_already_served`: a *permanent* forward-port mapping ends the
        // question whatever state its socket is in. Buggy impl guarded: dropping the
        // `idx < permanent_count` clause grows a dynamic mapping for a forwarded port, and that
        // mapping dials the PROXY port instead of the port the configuration forwards to.
        #[test]
        fn a_forwarded_port_is_never_intercepted_even_when_its_pool_is_busy() {
            let mut iface = scratch_iface();
            let mut sockets = SocketSet::new(vec![]);
            let mut port_mappings: Vec<NatPortMapping> = Vec::new();
            let (fwd, pxy) = (8_080u16, 6_000u16);

            // One permanent forward-port mapping, claimed (its whole pool busy).
            let handle = sockets.add(new_tcp_socket());
            port_mappings.push((fwd, fwd, handle, None));
            let permanent_count = port_mappings.len();
            claim_socket(&mut iface, &mut sockets, handle);
            assert!(syn_already_served(
                &sockets,
                &port_mappings,
                permanent_count,
                fwd
            ));

            admit_syn(
                &mut sockets,
                &mut port_mappings,
                permanent_count,
                fwd,
                pxy,
                SYN_BURST,
            );
            assert_eq!(
                port_mappings.len(),
                permanent_count,
                "a forwarded port must not grow a dynamic mapping that would dial the proxy \
                 instead of its configured target"
            );

            // Positive control: a *different*, un-forwarded destination is still intercepted.
            admit_syn(
                &mut sockets,
                &mut port_mappings,
                permanent_count,
                81,
                pxy,
                SYN_BURST,
            );
            assert_eq!(port_mappings.len(), permanent_count + SYN_BURST);
        }
    }

    /// Call-site gates for the three NAT-worker claims no signature can force and no live daemon
    /// makes observable — each about **where** a statement sits:
    ///
    /// * `smoltcp.rs:553`: the worker arms its exit event *before* it constructs the daemon that
    ///   consumes it. By the time `VhostUserDaemon::new` has called `exit_event`, an unarmed backend
    ///   has already fallen back to a live clone and looks identical — until the day that clone
    ///   fails, which is the whole defect.
    /// * Sibling 20: `handle_event` takes its state lock *inside* the drain loop, one per pass. A
    ///   guard hoisted back out is invisible to every unit test (the drain it starves lives on
    ///   another thread) and to any timing assertion worth shipping (`std::sync::Mutex` is unfair,
    ///   so "the other thread got in" is a race, not a property).
    /// * Every notification toggle goes through [`mask_tx_notifications`] /
    ///   [`rearm_tx_notifications`], the one pair that reports a failure. A raw
    ///   `enable_notification()` at a fourth call site is a re-introduced discarded `Result` — and a
    ///   behavior test cannot see it unless that particular site happens to be driven against a
    ///   broken ring, which is precisely how the M7 fix shipped two of them.
    /// * C7: the NAT's **permanent** forward listener is armed on the endpoint
    ///   [`nat_forward_endpoint`] composes, never a bare port. The two spellings compile
    ///   identically — `TcpSocket::listen` takes `impl Into<IpListenEndpoint>`, and `u16` converts
    ///   into one whose `addr` is `None` — so nothing but a scan can see the day a call site drops
    ///   the scope and re-opens `Egress::Open` onto every destination (§6.2).
    ///
    /// All four read this file's own production text, the shape `orchestrator.rs`'s `nat_plan_gate`
    /// established, and share its limit: a scan sees spellings, not values.
    #[cfg(test)]
    mod exit_event_arming_gate {
        const SOURCE: &str = include_str!("smoltcp.rs");

        /// This file's production text: everything before the unit-test module, comment lines
        /// dropped and whitespace collapsed (so a call split across rustfmt lines is still seen
        /// whole, and a rustdoc mention of a spelling is not a call site).
        fn production_code(source: &str) -> String {
            let (production, _) = source
                .split_once("mod tests {")
                .expect("smoltcp.rs must carry its unit-test module marker");
            production
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with("//"))
                .collect::<Vec<_>>()
                .join(" ")
        }

        /// Checks that `code` arms the exit event exactly once, before the one daemon construction.
        /// `Err` names the specific violation — factored out so the test below can drive it against
        /// buggy inputs (AGENTS.md rule 2).
        fn arming_precedes_the_daemon(code: &str) -> Result<(), String> {
            let daemon = code
                .find("VhostUserDaemon::new(")
                .ok_or("no `VhostUserDaemon::new(` call site")?;
            let arms: Vec<usize> = code
                .match_indices("arm_exit_event(")
                // The definition is not a call site.
                .filter(|&(at, _)| !code[..at].ends_with("fn "))
                .map(|(at, _)| at)
                .collect();
            match arms.as_slice() {
                [] => Err("the worker never arms an exit event".to_string()),
                [at] if *at < daemon => Ok(()),
                [_] => Err(
                    "the arming follows the daemon construction; by then the framework has already \
                     called `exit_event`"
                        .to_string(),
                ),
                many => Err(format!(
                    "expected exactly one arming call site; found {}",
                    many.len()
                )),
            }
        }

        #[test]
        fn the_shipped_worker_arms_before_it_constructs_a_daemon() {
            let code = production_code(SOURCE);
            assert!(
                code.contains("VhostUserDaemon::new("),
                "the gate must not pass vacuously on text it failed to find"
            );
            arming_precedes_the_daemon(&code).expect("the shipped worker must arm first");
        }

        /// Checks that `handle_event`'s body locks the shared state **inside** its drain loop: once
        /// to latch the vrings, once per pass. Pre-fix there was a single lock, before the loop.
        fn the_pass_takes_its_own_lock(handler_body: &str) -> Result<(), String> {
            let drain_loop = handler_body
                .find("loop {")
                .ok_or("no drain loop in handle_event")?;
            let locks: Vec<usize> = handler_body
                .match_indices("self.state.lock()")
                .map(|(at, _)| at)
                .collect();
            if !locks.iter().any(|at| *at > drain_loop) {
                return Err(
                    "the drain loop reuses a state guard taken outside it, so one kick can hold the \
                     mutex the net thread needs for as long as the guest keeps feeding the ring"
                        .to_string(),
                );
            }
            if locks.len() != 2 {
                return Err(format!(
                    "expected exactly 2 state locks in handle_event (the vrings latch and the \
                     per-pass one); found {}",
                    locks.len()
                ));
            }
            Ok(())
        }

        /// `handle_event`'s production body, from its signature to the end of the `impl` block.
        fn handle_event_body(code: &str) -> String {
            let at = code
                .find("fn handle_event(")
                .expect("smoltcp.rs must carry the backend's handle_event");
            code[at..].to_string()
        }

        #[test]
        fn the_drain_loop_locks_the_state_once_per_pass() {
            let code = production_code(SOURCE);
            let body = handle_event_body(&code);
            assert!(
                body.contains("process_tx_queue("),
                "the gate must not pass vacuously on text it failed to find"
            );
            the_pass_takes_its_own_lock(&body).expect("the shipped handler locks per pass");
        }

        #[test]
        fn the_gate_reddens_on_a_guard_hoisted_out_of_the_drain_loop() {
            // The pre-fix shape: one guard, taken before the loop and used inside it.
            assert!(
                the_pass_takes_its_own_lock(
                    "fn handle_event() { let mut state = self.state.lock(); loop { \
                     Self::process_tx_queue(&mut state, &mut vring_state); } }"
                )
                .is_err(),
                "a guard held across the drain loop must be caught"
            );
            // A latch plus a per-pass lock is the shipped shape.
            assert!(
                the_pass_takes_its_own_lock(
                    "fn handle_event() { { let mut state = self.state.lock(); } loop { let pass = \
                     { let mut state = self.state.lock(); Self::process_tx_queue(&mut state); }; } }"
                )
                .is_ok(),
                "the correct shape must pass, or the gate is vacuous"
            );
            // A third lock is a shape nobody reviewed: fail loud rather than guess.
            assert!(
                the_pass_takes_its_own_lock(
                    "fn handle_event() { let a = self.state.lock(); loop { let b = \
                     self.state.lock(); let c = self.state.lock(); } }"
                )
                .is_err(),
                "an unreviewed number of state locks must be caught"
            );
        }

        /// Checks that the two `virtio-queue` notification toggles are spelled **once each**, inside
        /// the reporting helpers. `Err` names the specific violation, so the self-test below can
        /// drive it against buggy inputs (AGENTS.md rule 2).
        ///
        /// Counted rather than located: the helpers are the only functions that may name them, and
        /// each names its own toggle exactly once, so any additional occurrence in production text is
        /// a call site that answers the failure itself — the discard this gate exists to keep out.
        fn toggles_route_through_the_reporting_helpers(code: &str) -> Result<(), String> {
            for (toggle, helper) in [
                ("disable_notification()", "fn mask_tx_notifications"),
                ("enable_notification()", "fn rearm_tx_notifications"),
            ] {
                if !code.contains(helper) {
                    return Err(format!("{helper} is gone; {toggle} has no reporting owner"));
                }
                // Neither spelling is a substring of the other (`dis`+`able` vs `en`+`able`), so a
                // plain count needs no disambiguation.
                match code.matches(toggle).count() {
                    1 => {}
                    0 => return Err(format!("nothing calls {toggle}; the mask is gone")),
                    n => {
                        return Err(format!(
                            "{toggle} appears {n} times outside {helper}; a raw toggle answers its \
                             own failure, which is the discarded Result this gate keeps out"
                        ));
                    }
                }
            }
            Ok(())
        }

        #[test]
        fn every_notification_toggle_routes_through_its_reporting_helper() {
            let code = production_code(SOURCE);
            assert!(
                code.contains("rearm_tx_notifications(&mut vring_state)"),
                "the gate must not pass vacuously on text it failed to find"
            );
            toggles_route_through_the_reporting_helpers(&code)
                .expect("the shipped worker toggles notifications through the reporting helpers");
        }

        #[test]
        fn the_gate_reddens_on_a_raw_notification_toggle() {
            // The shape the M7 fix shipped: a discarded toggle at the call site.
            assert!(
                toggles_route_through_the_reporting_helpers(
                    "fn mask_tx_notifications() { v.disable_notification() } \
                     fn rearm_tx_notifications() { v.enable_notification() } \
                     fn handle_event() { let _ = v.enable_notification(); }"
                )
                .is_err(),
                "a raw enable_notification() beside the helper must be caught"
            );
            // …and its `unwrap_or(false)` sibling, the same discard one spelling over.
            assert!(
                toggles_route_through_the_reporting_helpers(
                    "fn mask_tx_notifications() { v.disable_notification() } \
                     fn rearm_tx_notifications() { v.enable_notification() } \
                     fn handle_event() { v.disable_notification().unwrap_or(false); }"
                )
                .is_err(),
                "a raw disable_notification() beside the helper must be caught"
            );
            // A helper deleted outright (its callers left calling the raw API) is caught too.
            assert!(
                toggles_route_through_the_reporting_helpers(
                    "fn handle_event() { v.disable_notification(); v.enable_notification(); }"
                )
                .is_err(),
                "toggles with no reporting owner must be caught"
            );
            // The shipped shape passes, or the gate is vacuous.
            assert!(
                toggles_route_through_the_reporting_helpers(
                    "fn mask_tx_notifications() { if let Err(e) = v.disable_notification() { warn } } \
                     fn rearm_tx_notifications() { match v.enable_notification() { } } \
                     fn handle_event() { mask_tx_notifications(&mut v); rearm_tx_notifications(&mut v); }"
                )
                .is_ok(),
                "the correct shape must pass, or the gate is vacuous"
            );
        }

        /// Checks that every permanent NAT forward is armed on a **composed**, destination-scoped
        /// endpoint (C7). `Err` names the specific violation, so the self-test below can drive it
        /// against buggy inputs (AGENTS.md rule 2).
        ///
        /// Three things have to hold at once, and each has its own failure text:
        ///
        /// 1. [`nat_forward_endpoint`] exists and has exactly **one** call site — a second one is
        ///    a second spelling of the scope, which is how every duplicated law in this tree has
        ///    drifted.
        /// 2. That call site is the endpoint `rearm_or_release_closed` re-arms with, and the
        ///    permanent arm listens on that parameter rather than re-deriving anything.
        /// 3. Production text holds exactly **two** `listen(` sites: the permanent one above and
        ///    `admit_syn`'s deliberately unscoped dynamic interception listener, which is what
        ///    `Egress::Filtered` is for. A third is an un-reviewed shape — fail loud, don't guess.
        fn permanent_forwards_are_gateway_scoped(code: &str) -> Result<(), String> {
            if !code.contains("fn nat_forward_endpoint(") {
                return Err(
                    "`nat_forward_endpoint` is gone; the permanent forward's destination scope \
                     has no owner"
                        .to_string(),
                );
            }
            let calls: Vec<usize> = code
                .match_indices("nat_forward_endpoint(")
                // The definition is not a call site.
                .filter(|&(at, _)| !code[..at].ends_with("fn "))
                .map(|(at, _)| at)
                .collect();
            if calls.len() != 1 {
                return Err(format!(
                    "expected exactly 1 `nat_forward_endpoint(` call site; found {}",
                    calls.len()
                ));
            }
            if !code.contains("rearm_or_release_closed( socket, nat_forward_endpoint(") {
                return Err("the permanent re-arm no longer takes its endpoint from \
                     `nat_forward_endpoint`; a bare port listens on EVERY destination under \
                     `set_any_ip(true)`"
                    .to_string());
            }
            if !code.contains("socket.listen(listen)") {
                return Err(
                    "the permanent arm does not listen on the endpoint it was handed; it is \
                     re-deriving the scope at the call site"
                        .to_string(),
                );
            }
            match code.matches("socket.listen(").count() {
                2 => {}
                n => {
                    return Err(format!(
                        "expected exactly 2 `socket.listen(` sites (the composed permanent forward \
                         and `admit_syn`'s dynamic interception listener); found {n}"
                    ));
                }
            }
            if !code.contains("socket.listen(dst_port)") {
                return Err(
                    "`admit_syn`'s dynamic interception listener is gone or renamed; the second \
                     `listen` site this gate accounts for is no longer the one it reviewed"
                        .to_string(),
                );
            }
            Ok(())
        }

        #[test]
        fn every_permanent_forward_is_armed_on_the_composed_gateway_endpoint() {
            let code = production_code(SOURCE);
            assert!(
                code.contains("fn rearm_or_release_closed("),
                "the gate must not pass vacuously on text it failed to find"
            );
            permanent_forwards_are_gateway_scoped(&code)
                .expect("the shipped NAT scopes its permanent forwards to the VM's gateway");
        }

        #[test]
        fn the_gateway_scope_gate_reddens_on_a_bare_port_listen() {
            const SHIPPED: &str = "fn nat_forward_endpoint(host_gw, port) -> IpListenEndpoint { } \
                                   fn rearm_or_release_closed(socket, listen, s, p) -> bool { \
                                   let _ = socket.listen(listen); } \
                                   fn admit_syn() { let _ = socket.listen(dst_port); } \
                                   fn run() { if rearm_or_release_closed( socket, \
                                   nat_forward_endpoint(host_gw, *listen_port), tcp_stream, x, ) {} }";
            assert!(
                permanent_forwards_are_gateway_scoped(SHIPPED).is_ok(),
                "the shipped shape must pass, or the gate is vacuous"
            );
            // The pre-C7 shape: the permanent re-arm listens on a bare port, which
            // `TcpSocket::accepts` reads as "every destination address".
            assert!(
                permanent_forwards_are_gateway_scoped(
                    &SHIPPED
                        .replace("socket.listen(listen)", "socket.listen(listen_port)")
                        .replace(
                            "nat_forward_endpoint(host_gw, *listen_port)",
                            "*listen_port"
                        )
                )
                .is_err(),
                "a permanent forward re-armed on a bare port must be caught"
            );
            // A second composer call site — the duplicate-law shape.
            assert!(
                permanent_forwards_are_gateway_scoped(&format!(
                    "{SHIPPED} fn other() {{ nat_forward_endpoint(gw, 80); }}"
                ))
                .is_err(),
                "a second `nat_forward_endpoint` call site must be caught"
            );
            // A third `listen` site is a shape nobody reviewed.
            assert!(
                permanent_forwards_are_gateway_scoped(&format!(
                    "{SHIPPED} fn extra() {{ let _ = socket.listen(9000); }}"
                ))
                .is_err(),
                "an unreviewed number of listen sites must be caught"
            );
            // The composer itself deleted.
            assert!(
                permanent_forwards_are_gateway_scoped(
                    &SHIPPED.replace("fn nat_forward_endpoint(", "fn gone(")
                )
                .is_err(),
                "deleting the one composer must be caught"
            );
            // A gate pointed at nothing opens nothing: an empty scan is misconfiguration,
            // never a green verdict.
            assert!(
                permanent_forwards_are_gateway_scoped("").is_err(),
                "an empty production text must be a misconfigured gate, not a pass"
            );
        }

        #[test]
        fn the_gate_reddens_on_a_worker_that_arms_late_or_not_at_all() {
            assert!(
                arming_precedes_the_daemon("let d = VhostUserDaemon::new( backend );").is_err(),
                "a worker that never arms must be caught"
            );
            assert!(
                arming_precedes_the_daemon(
                    "let d = VhostUserDaemon::new( backend ); backend.arm_exit_event();"
                )
                .is_err(),
                "arming after the daemon is constructed must be caught"
            );
            assert!(
                arming_precedes_the_daemon(
                    "backend.arm_exit_event(); let d = VhostUserDaemon::new( backend );"
                )
                .is_ok(),
                "the correct order must pass, or the gate is vacuous"
            );
        }
    }
}
