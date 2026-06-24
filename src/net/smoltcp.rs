#[cfg(feature = "net-rootless")]
/// Low-level backend networking types and state for `smoltcp`.
pub mod backend {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use vhost::vhost_user::Listener;
    use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
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

    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

    const VIRTIO_F_VERSION_1: u32 = 32;
    const QUEUE_SIZE: usize = 1024;
    const NUM_QUEUES: usize = 2; // rx and tx

    // virtio-net header size is 12 bytes
    const VIRTIO_NET_HDR_SIZE: usize = 12;

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
            log::trace!("TxTokenImpl::consume called with len={}", len);
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
                for desc in chain.readable() {
                    let mut buf = vec![0; desc.len() as usize];
                    if mem_obj.read_slice(&mut buf, desc.addr()).is_ok() {
                        packet.extend_from_slice(&buf);
                    }
                }

                if packet.len() >= VIRTIO_NET_HDR_SIZE {
                    log::trace!("process_tx_queue: Read packet of length {} from vring: {:?}", packet.len(), packet.get(VIRTIO_NET_HDR_SIZE..).expect("invariant"));
                    state
                        .tx_queue
                        .push_back(packet.get(VIRTIO_NET_HDR_SIZE..).expect("invariant").to_vec());
                } else {
                    log::trace!("process_tx_queue: packet too short: {}", packet.len());
                }

                if vring_state.add_used(head_index, 0).is_err() {
                    tracing::error!("Couldn't return used descriptors");
                }
            }

            if used_any {
                vring_state.signal_used_queue().expect("invariant");
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
            1 << VIRTIO_F_VERSION_1
                | 1 << VIRTIO_RING_F_INDIRECT_DESC
                | 1 << VIRTIO_RING_F_EVENT_IDX
                | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::MQ
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
            Some((
                self.kill_evt.0.try_clone().expect("invariant"),
                self.kill_evt.1.try_clone().expect("invariant"),
            ))
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
                let mut vring_state = vrings.get(1).expect("invariant").get_mut();
                if self.event_idx {
                    loop {
                        vring_state.disable_notification().expect("invariant");
                        Self::process_tx_queue(&mut state, &mut vring_state)?;
                        if !vring_state.enable_notification().expect("invariant") {
                            break;
                        }
                    }
                } else {
                    Self::process_tx_queue(&mut state, &mut vring_state)?;
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
    }

    impl Drop for SmoltcpProcess {
        fn drop(&mut self) {
            tracing::info!("SmoltcpProcess dropping!");
            self.stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = self.kill_notifier.notify();
            if let Some(h) = self.vhost_thread.take() {
                let _ = h.join();
            }
            if let Some(h) = self.net_thread.take() {
                let _ = h.join();
            }
        }
    }

    impl SmoltcpProcess {
        /// Starts the background network thread to process packets and manage connections.
        ///
        /// # Panics
        ///
        /// Panics if the underlying system resources or background threads fail to start.
        pub fn start(vmid: u32, forward_ports: Vec<u16>, socket_path: PathBuf) -> Self {
            let state = Arc::new(Mutex::new(SharedState {
                tx_queue: VecDeque::new(),
                rx_queue: VecDeque::new(),
                mem: None,
                vrings: None,
            }));

            let state_clone = state.clone();

            let (kill_evt_consumer, kill_evt_notifier) = vmm_sys_util::event::new_event_consumer_and_notifier(
                vmm_sys_util::event::EventFlag::NONBLOCK,
            )
            .expect("invariant");
            let kill_evt = (kill_evt_consumer, kill_evt_notifier.try_clone().expect("invariant"));

            let backend = std::sync::Arc::new(std::sync::RwLock::new(VhostUserNetBackend {
                event_idx: false,
                kill_evt,
                state: state_clone,
            }));

            let mut listener = Listener::new(&socket_path, true).expect("invariant");

            let vhost_thread = std::thread::spawn(move || {
                let mut vu_daemon = VhostUserDaemon::new(
                    String::from("vhost-user-net"),
                    backend,
                    GuestMemoryAtomic::new(GuestMemoryMmap::new()),
                )
                .expect("invariant");

                let _ = vu_daemon.start(&mut listener);
            });

            let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_flag_clone = stop_flag.clone();
            let net_thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("invariant");
                rt.block_on(async move {
                    Self::run_network(vmid, forward_ports, state, stop_flag_clone).await;
                });
            });

            SmoltcpProcess {
                kill_notifier: kill_evt_notifier,
                stop_flag,
                vhost_thread: Some(vhost_thread),
                net_thread: Some(net_thread),
            }
        }

        async fn run_network(vmid: u32, forward_ports: Vec<u16>, state: Arc<Mutex<SharedState>>, stop_flag: Arc<std::sync::atomic::AtomicBool>) {
            let host_gw = Ipv4Address::new(10, 200, (vmid % 256) as u8, 1);
            // Use a different MAC for the host to avoid dropping packets from the guest.
            let mac_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0xfe]);

            let mut config = Config::new(HardwareAddress::Ethernet(mac_addr));
            config.random_seed = 0;
            let mut iface = Interface::new(
                config,
                &mut SmoltcpDevice {
                    state: state.lock().unwrap_or_else(|e| e.into_inner()),
                },
                Instant::now(),
            );
            iface.update_ip_addrs(|ip_addrs| {
                ip_addrs
                    .push(IpCidr::new(IpAddress::Ipv4(host_gw), 30))
                    .expect("invariant");
            });
            iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 200, (vmid % 256) as u8, 2)).expect("invariant");
            log::trace!("smoltcp iface configured with IPs: {:?}", iface.ip_addrs());

            let mut sockets = SocketSet::new(vec![]);

            let mut port_mappings = Vec::new();
            for port in forward_ports {
                let rx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
                let tx_buffer = TcpSocketBuffer::new(vec![0; 65536]);
                let socket = TcpSocket::new(rx_buffer, tx_buffer);
                let handle = sockets.add(socket);
                port_mappings.push((port, handle, None::<tokio::net::TcpStream>));
            }

            loop {
                if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                {
                    let mut state_guard = state.lock().unwrap_or_else(|e| e.into_inner());

                    // Process receiveq (host -> guest)
                    let (mem_opt, vrings_opt) = (state_guard.mem.clone(), state_guard.vrings.clone());
                    if let (Some(mem), Some(vrings)) = (mem_opt, vrings_opt) {
                        let mut vring_state = vrings.get(0).expect("invariant").get_mut();
                        let mem_obj = mem.memory();
                        let mut used_any = false;

                        while let Some(packet) = state_guard.rx_queue.pop_front() {
                            let avail_chains = vring_state.get_queue_mut().iter(mem_obj.clone());
                            if let Ok(mut chains) = avail_chains {
                                if let Some(chain) = chains.next() {
                                    log::trace!("process_rx_queue: Sending packet of length {} to guest", packet.len());
                                    let head_index = chain.head_index();

                                    let mut full_packet = vec![0; VIRTIO_NET_HDR_SIZE];
                                    full_packet.extend_from_slice(&packet);

                                    let mut offset = 0;
                                    let mut written = 0;
                                    for desc in chain.writable() {
                                        let to_write = std::cmp::min(
                                            full_packet.len() - offset,
                                            desc.len() as usize,
                                        );
                                        if to_write > 0
                                            && mem_obj
                                                .write_slice(
                                                    full_packet.get(offset..offset + to_write).expect("invariant"),
                                                    desc.addr(),
                                                )
                                                .is_ok()
                                        {
                                            offset += to_write;
                                            written += to_write;
                                        }
                                    }
                                    vring_state.add_used(head_index, written as u32).expect("invariant");
                                    used_any = true;
                                } else {
                                    state_guard.rx_queue.push_front(packet);
                                    break;
                                }
                            } else {
                                state_guard.rx_queue.push_front(packet);
                                break;
                            }
                        }
                        if used_any {
                            vring_state.signal_used_queue().expect("invariant");
                        }
                    }

                    let mut device = SmoltcpDevice { state: state_guard };
                    iface.poll(Instant::now(), &mut device, &mut sockets);
                    drop(device); // releases state_guard
                }

                for (port, handle, tcp_stream) in port_mappings.iter_mut() {
                    let socket = sockets.get_mut::<TcpSocket>(*handle);
                    if !socket.is_open() {
                        socket.listen(*port).expect("invariant");
                    }

                    if socket.can_send() || socket.can_recv() {
                        if tcp_stream.is_none() {
                            if let Ok(stream) =
                                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await
                            {
                                stream.set_nodelay(true).expect("invariant");
                                *tcp_stream = Some(stream);
                            }
                        }

                        let mut closed = false;
                        if let Some(stream) = tcp_stream {
                            if socket.can_send() {
                                let mut buf = [0; 8192];
                                match stream.try_read(&mut buf) {
                                    Ok(0) => {
                                        closed = true;
                                    }
                                    Ok(n) => {
                                        socket.send_slice(buf.get(..n).expect("invariant")).expect("invariant");
                                    }
                                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                    Err(_) => {
                                        closed = true;
                                    }
                                }
                            }

                            if socket.can_recv() {
                                let mut buf = [0; 8192];
                                if let Ok(n) = socket.peek_slice(&mut buf) {
                                    if n > 0 {
                                        match stream.try_write(buf.get(..n).expect("invariant")) {
                                            Ok(written) => {
                                                socket.recv(|_| (written, ())).expect("invariant");
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
}
