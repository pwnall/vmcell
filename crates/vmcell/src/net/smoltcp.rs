#[cfg(feature = "net-unprivileged")]
/// Low-level backend networking types and state for `smoltcp`.
pub mod backend {
    use std::collections::VecDeque;
    use std::path::PathBuf;
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
        IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket,
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

    /// Maximum length of a single guest TX frame the NAT will buffer: the
    /// virtio MTU (1500, the `max_transmission_unit` reported by the device)
    /// plus the 12-byte virtio-net header. virtio-net here negotiates no
    /// segmentation offload (no `VIRTIO_NET_F_GUEST_TSO`/`GSO`), so
    /// a frame never legitimately exceeds this. The bound stops a crafted
    /// descriptor chain from forcing a multi-gigabyte host allocation off a
    /// guest-controlled `desc.len()`.
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
        // smoltcp 0.11 provides `From<std::net::Ipv4Addr>`, so the shared std
        // addresses convert directly rather than being rebuilt octet-by-octet.
        Ok((
            Ipv4Address::from(host_gw_std),
            Ipv4Address::from(guest_ip_std),
        ))
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

    /// Number of listening sockets pre-armed per newly-seen destination port when
    /// admitting a guest SYN (a small burst absorbs quick reconnects without a
    /// per-connection round trip). Growth is refused once the pool would exceed
    /// [`MAX_DYNAMIC_SOCKETS`]; `MAX_DYNAMIC_SOCKETS` is a multiple of this.
    const SYN_BURST: usize = 4;

    /// Per-worker deadline for `SmoltcpProcess::Drop` to join a thread before
    /// detaching it, so a wedged worker cannot hang teardown forever (NET-3).
    const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
        fn consume<R, F>(mut self, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            f(&mut self.0)
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

    struct VhostUserNetBackend {
        event_idx: bool,
        kill_evt: (EventConsumer, EventNotifier),
        state: Arc<Mutex<SharedState>>,
    }

    impl VhostUserNetBackend {
        fn process_tx_queue(
            state: &mut SharedState,
            vring_state: &mut VringState<GuestMemoryAtomic<GuestMemoryMmap>>,
        ) -> std::io::Result<bool> {
            let mut used_any = false;
            let guest_mem = match &state.mem {
                Some(m) => m,
                None => return Ok(false),
            };

            let mem_obj = guest_mem.memory();
            let avail_chains: Vec<DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>> =
                vring_state
                    .get_queue_mut()
                    .iter(mem_obj.clone())
                    .map_err(|_| std::io::Error::other("IterateQueue"))?
                    .collect();

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
                    state.tx_queue.push_back(payload.to_vec());
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
                let _ = vring_state.signal_used_queue();
            }

            Ok(used_any)
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
            // Called by the vhost-user framework during setup (VMM-driven). A
            // clone failure (e.g. fd exhaustion) must not panic the worker
            // thread; log and report "no exit event", which only forgoes the
            // prompt-wakeup optimization — `Drop` still sets the stop flag and
            // connects the socket to unblock `accept()`, so teardown completes.
            match (self.kill_evt.0.try_clone(), self.kill_evt.1.try_clone()) {
                (Ok(consumer), Ok(notifier)) => Some((consumer, notifier)),
                _ => {
                    tracing::error!(
                        "smoltcp exit_event: failed to clone kill event fd; \
                         teardown will rely on the stop flag and socket wakeup"
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

            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.vrings.is_none() {
                state.vrings = Some(vrings.to_vec());
            }

            if device_event == 1 {
                // transmitq (guest -> host)
                let Some(vring1) = vrings.get(1) else {
                    // The VMM negotiates NUM_QUEUES rings; a missing tx ring is a
                    // protocol error, not a reason to panic the worker thread.
                    return Err(std::io::Error::other("transmitq vring missing"));
                };
                let mut vring_state = vring1.get_mut();
                if self.event_idx {
                    loop {
                        // Masking notifications is a throughput hint; a failure only
                        // costs an extra wakeup, so the result is deliberately ignored.
                        let _ = vring_state.disable_notification();
                        Self::process_tx_queue(&mut state, &mut vring_state)?;
                        if !vring_state.enable_notification().unwrap_or(false) {
                            break;
                        }
                    }
                } else {
                    // As above: notification masking is advisory; a failure is
                    // non-fatal (at worst an extra wakeup), so the result is ignored.
                    let _ = vring_state.disable_notification();
                    Self::process_tx_queue(&mut state, &mut vring_state)?;
                    vring_state.enable_notification().unwrap_or(false);
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
                    let _ = std_stream.shutdown(std::net::Shutdown::Both);
                }
                true
            }
            None => false,
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
    fn rearm_or_release_closed(
        socket: &mut TcpSocket<'_>,
        listen_port: u16,
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
            let _ = socket.listen(listen_port);
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

    /// Admits a guest SYN to `dst_port` into the dynamic NAT socket pool.
    ///
    /// Extracted from the `run_network` TX scan so the per-SYN admission decision
    /// is unit-testable without a live vhost device (NET-3). For a SYN whose
    /// destination port has no already-open mapping, it first reclaims closed
    /// dynamic mappings and then — **only if the pool has room for the whole
    /// `burst`** — creates `burst` listening sockets mapped to `pxy_port`. When
    /// the pool is full the SYN is dropped without any growth; that refusal is
    /// the guard that keeps `port_mappings` bounded at
    /// `permanent_count + MAX_DYNAMIC_SOCKETS` under a SYN spray to many distinct
    /// destination ports.
    fn admit_syn(
        sockets: &mut SocketSet<'_>,
        port_mappings: &mut Vec<NatPortMapping>,
        permanent_count: usize,
        dst_port: u16,
        pxy_port: u16,
        burst: usize,
    ) {
        let has_open = port_mappings
            .iter()
            .any(|(p, _, h, _)| *p == dst_port && sockets.get::<TcpSocket>(*h).is_open());
        // Short-circuit: `reclaim_and_has_room` (with its reclamation side effect)
        // only runs when there is no already-open mapping for this port, matching
        // the original inline guard.
        if has_open || !reclaim_and_has_room(sockets, port_mappings, permanent_count, burst) {
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
            let _ = self.kill_notifier.notify();
            // Connect to the socket to unblock listener.accept() if it's stuck.
            let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
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
        /// # Panics
        ///
        /// Panics if the underlying system resources or background threads fail to start.
        pub fn start(
            vmid: u32,
            forward_ports: Vec<u16>,
            proxy_port: Option<u16>,
            socket_path: PathBuf,
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
            let kill_evt = (
                kill_evt_consumer,
                kill_evt_notifier.try_clone().expect("clone notifier"),
            );

            let backend = std::sync::Arc::new(std::sync::RwLock::new(VhostUserNetBackend {
                event_idx: false,
                kill_evt,
                state: state_clone,
            }));

            let mut listener = Listener::new(&socket_path, true).expect("listener new");

            let socket_path_clone = socket_path.clone();
            let vhost_thread = std::thread::spawn(move || {
                let mut vu_daemon = VhostUserDaemon::new(
                    String::from("vhost-user-net"),
                    backend,
                    GuestMemoryAtomic::new(GuestMemoryMmap::new()),
                )
                .expect("vu daemon new");

                tracing::info!("vhost-user-net daemon starting on {:?}", socket_path_clone);
                let res = vu_daemon.start(&mut listener);
                tracing::info!("vhost-user-net daemon start returned {:?}", res);
                let wait_res = vu_daemon.wait();
                tracing::info!("vhost-user-net daemon exited with {:?}", wait_res);
            });

            let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_flag_clone = stop_flag.clone();
            let net_thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("runtime new");
                rt.block_on(async move {
                    Self::run_network(vmid, forward_ports, proxy_port, state, stop_flag_clone)
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

        async fn run_network(
            vmid: u32,
            forward_ports: Vec<u16>,
            proxy_port: Option<u16>,
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
                for _ in 0..16 {
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
                        if rearm_or_release_closed(
                            socket,
                            *listen_port,
                            tcp_stream,
                            i < permanent_count,
                        ) {
                            continue;
                        }
                    }

                    if socket.can_send() || socket.can_recv() {
                        if tcp_stream.is_none()
                            && let Ok(stream) =
                                tokio::net::TcpStream::connect(format!("127.0.0.1:{target_port}"))
                                    .await
                        {
                            // TCP_NODELAY is a latency optimization; if the
                            // setsockopt fails the connection still works
                            // (merely with Nagle enabled), so the result is
                            // deliberately ignored.
                            let _ = stream.set_nodelay(true);
                            *tcp_stream = Some(stream);
                        }

                        let mut closed = false;
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
                                let mut buf = [0; 8192];
                                if let Ok(n) = socket.peek_slice(&mut buf)
                                    && n > 0
                                {
                                    match stream.try_write(buf.get(..n).unwrap_or(&[])) {
                                        Ok(written) => {
                                            // NET-1/C2: guest-driven; never panic.
                                            if let Err(e) = socket.recv(|_| (written, ())) {
                                                tracing::error!("smoltcp recv failed: {:?}", e);
                                                closed = true;
                                            }
                                        }
                                        Err(ref e)
                                            if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                        Err(_) => {
                                            closed = true;
                                        }
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
                    host_gw.0,
                    host_std.octets(),
                    "host gw drifted for vmid {vmid}"
                );
                assert_eq!(
                    guest_gw.0,
                    guest_std.octets(),
                    "guest gw drifted for vmid {vmid}"
                );
                // The host gateway is the /30 `.1` and the guest is the `.2`.
                assert_eq!(host_gw.0[3], 1, "host gw must be the .1 of the /30");
                assert_eq!(guest_gw.0[3], 2, "guest gw must be the .2 of the /30");
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
            let skip = rearm_or_release_closed(&mut socket, 8080, &mut stream, true);
            assert!(!skip, "permanent mapping must be re-armed, not skipped");
            assert!(socket.is_open(), "permanent listener must be re-armed");
            assert!(
                stream.is_none(),
                "stale host stream must be cleared before re-arming (H-NET-1)"
            );

            // Dynamic mapping: skipped for reclamation, stream cleared.
            let mut dsocket = new_tcp_socket();
            let mut dstream = Some(connected_host_stream());
            let skip = rearm_or_release_closed(&mut dsocket, 9090, &mut dstream, false);
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
    }
}
