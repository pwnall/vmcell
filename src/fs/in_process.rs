//!
//! In-process virtio-fs daemon implementation using vhost-user.
//!
#[cfg(feature = "experiment-fuse")]
pub mod backend {
    use fuse_backend_rs::api::{Vfs, VfsOptions, server::Server};
    use fuse_backend_rs::passthrough::{Config, PassthroughFs};
    use fuse_backend_rs::transport::{FsCacheReqHandler, Reader, VirtioFsWriter};
    use std::sync::{Arc, Mutex, RwLock};
    use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
    use vhost::vhost_user::{Backend, Listener};
    use vhost_user_backend::{
        VhostUserBackendMut, VhostUserDaemon, VringMutex, VringState, VringT,
    };
    use virtio_bindings::bindings::virtio_ring::{
        VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
    };
    use virtio_queue::DescriptorChain;
    use virtio_queue::QueueOwnedT;
    use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
    use vmm_sys_util::epoll::EventSet;
    use vmm_sys_util::event::{EventConsumer, EventNotifier};

    const VIRTIO_F_VERSION_1: u32 = 32;
    const QUEUE_SIZE: usize = 1024;
    const NUM_QUEUES: usize = 2;

    const HIPRIO_QUEUE_EVENT: u16 = 0;
    const REQ_QUEUE_EVENT: u16 = 1;

    struct VhostUserFsBackend {
        event_idx: bool,
        kill_evt: (EventConsumer, EventNotifier),
        mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
        server: Arc<Server<Arc<Vfs>>>,
        vu_req: Option<Backend>,
    }

    impl VhostUserFsBackend {
        fn process_queue(
            &mut self,
            vring_state: &mut std::sync::MutexGuard<VringState>,
        ) -> std::io::Result<bool> {
            let mut used_any = false;
            let guest_mem: &GuestMemoryAtomic<GuestMemoryMmap> = match &self.mem {
                Some(m) => m,
                None => {
                    return Err(std::io::Error::other("QueueMemoryUnset"));
                }
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

                let reader = Reader::from_descriptor_chain(&*mem_obj, chain.clone())
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let writer = VirtioFsWriter::new(&*mem_obj, chain.clone())
                    .map(|w| w.into())
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                self.server
                    .handle_message(
                        reader,
                        writer,
                        None as Option<&mut dyn FsCacheReqHandler>,
                        None,
                    )
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                if self.event_idx {
                    if vring_state.add_used(head_index, 0).is_err() {
                        tracing::error!("Couldn't return used descriptors to the ring");
                    }

                    match vring_state.needs_notification() {
                        Err(_) => {
                            vring_state.signal_used_queue().expect("invariant");
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                vring_state.signal_used_queue().expect("invariant");
                            }
                        }
                    }
                } else {
                    if vring_state.add_used(head_index, 0).is_err() {
                        tracing::error!("Couldn't return used descriptors to the ring");
                    }
                    vring_state.signal_used_queue().expect("invariant");
                }
            }

            Ok(used_any)
        }
    }

    struct VhostUserFsBackendHandler {
        backend: Mutex<VhostUserFsBackend>,
    }

    impl VhostUserFsBackendHandler {
        fn new(vfs: Arc<Vfs>) -> std::io::Result<Self> {
            let backend = VhostUserFsBackend {
                event_idx: false,
                kill_evt: vmm_sys_util::event::new_event_consumer_and_notifier(
                    vmm_sys_util::event::EventFlag::NONBLOCK,
                )?,
                mem: None,
                server: Arc::new(Server::new(vfs)),
                vu_req: None,
            };

            Ok(VhostUserFsBackendHandler {
                backend: Mutex::new(backend),
            })
        }
    }

    impl VhostUserBackendMut for VhostUserFsBackendHandler {
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
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::BACKEND_REQ
        }

        fn set_event_idx(&mut self, enabled: bool) {
            self.backend.lock().expect("invariant").event_idx = enabled
        }

        fn update_memory(
            &mut self,
            mem: GuestMemoryAtomic<GuestMemoryMmap>,
        ) -> std::io::Result<()> {
            self.backend.lock().expect("invariant").mem = Some(mem);
            Ok(())
        }

        fn set_backend_req_fd(&mut self, vu_req: Backend) {
            self.backend.lock().expect("invariant").vu_req = Some(vu_req);
        }

        fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
            let backend = self.backend.lock().expect("invariant");
            let consumer = backend.kill_evt.0.try_clone().expect("invariant");
            let notifier = backend.kill_evt.1.try_clone().expect("invariant");
            Some((consumer, notifier))
        }

        fn handle_event(
            &mut self,
            device_event: u16,
            evset: EventSet,
            vrings: &[VringMutex],
            _thread_id: usize,
        ) -> std::io::Result<()> {
            if evset != EventSet::IN {
                return Err(std::io::Error::other("HandleEventNotEpollIn"));
            }

            let mut vring_state = match device_event {
                HIPRIO_QUEUE_EVENT => vrings.get(0).expect("invariant").get_mut(),
                REQ_QUEUE_EVENT => vrings.get(1).expect("invariant").get_mut(),
                _ => {
                    return Err(std::io::Error::other("HandleEventUnknownEvent"));
                }
            };

            if self.backend.lock().expect("invariant").event_idx {
                loop {
                    vring_state.disable_notification().expect("invariant");
                    self.backend
                        .lock()
                        .expect("invariant")
                        .process_queue(&mut vring_state)?;
                    if !vring_state.enable_notification().expect("invariant") {
                        break;
                    }
                }
            } else {
                self.backend
                    .lock()
                    .expect("invariant")
                    .process_queue(&mut vring_state)?;
            }

            Ok(())
        }
    }

    pub fn start_in_process_virtiofsd(
        socket_path: &std::path::Path,
        host_path: &std::path::Path,
        read_only: bool,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        let vfs = Vfs::new(VfsOptions {
            no_open: false,
            no_opendir: false,
            ..Default::default()
        });

        // fuse-backend-rs PassthroughFs does not have a config option for readonly,
        // so we must handle it manually or acknowledge it.
        // TODO: Enforce read_only flag inside the VFS layer or via bind mounts.
        if read_only {
            tracing::warn!(
                "Read-only mode requested but in-process virtiofsd does not fully support it natively yet."
            );
        }

        let cfg = Config {
            root_dir: host_path.to_string_lossy().to_string(),
            do_import: false,
            ..Default::default()
        };

        let fs = PassthroughFs::<()>::new(cfg).map_err(|e| std::io::Error::other(e.to_string()))?;
        fs.import()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        vfs.mount(Box::new(fs), "/")
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let backend = Arc::new(RwLock::new(VhostUserFsBackendHandler::new(Arc::new(vfs))?));
        let mut listener =
            Listener::new(socket_path, true).map_err(|e| std::io::Error::other(e.to_string()))?;

        let socket_path_str = socket_path.to_string_lossy().into_owned();
        let handle = std::thread::spawn(move || {
            tracing::error!(
                "in-process virtiofsd: thread started, listening on {:?}",
                socket_path_str
            );
            let mut vu_daemon = VhostUserDaemon::new(
                String::from("in-process-virtiofsd"),
                backend,
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .expect("invariant");
            let _ = vu_daemon.start(&mut listener).map_err(|e| {
                tracing::error!("in-process virtiofsd panic: {:?}", e);
            });
        });

        Ok(handle)
    }
}
