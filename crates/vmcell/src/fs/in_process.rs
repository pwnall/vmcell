//!
//! In-process virtio-fs daemon implementation using vhost-user.
//!
#[cfg(feature = "experiment-fuse")]
pub(crate) mod backend {
    use fuse_backend_rs::api::{Vfs, VfsOptions, server::Server};
    use fuse_backend_rs::passthrough::{Config, PassthroughFs};
    use fuse_backend_rs::transport::{FsCacheReqHandler, Reader, VirtioFsWriter};
    use std::sync::{Arc, Mutex, RwLock};
    use vhost::vhost_user::Listener;
    use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
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
                            // Best-effort guest notification on the event-idx path: a failed signal
                            // forgoes ONE wakeup, and the guest still drains on its next kick. This
                            // is the virtio hot loop, so reporting per-descriptor would be a flood,
                            // not a diagnosis.
                            #[expect(
                                clippy::let_underscore_must_use,
                                reason = "virtio hot loop: a failed used-queue signal forgoes one wakeup and the guest drains on its next kick"
                            )]
                            let _ = vring_state.signal_used_queue();
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                #[expect(
                                    clippy::let_underscore_must_use,
                                    reason = "same event-idx notification, needs-notification arm: one forgone wakeup, never a lost descriptor"
                                )]
                                let _ = vring_state.signal_used_queue();
                            }
                        }
                    }
                } else {
                    if vring_state.add_used(head_index, 0).is_err() {
                        tracing::error!("Couldn't return used descriptors to the ring");
                    }
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "same notification on the non-event-idx path: one forgone wakeup, never a lost descriptor"
                    )]
                    let _ = vring_state.signal_used_queue();
                }
            }

            Ok(used_any)
        }
    }

    struct VhostUserFsBackendHandler {
        backend: Mutex<VhostUserFsBackend>,
        /// Pre-cloned kill eventfd pair handed to the framework's epoll worker via
        /// the `exit_event` trait method. The clone (an fd `dup`, fallible
        /// under `EMFILE`) happens ONCE here at construction, where the failure is a
        /// typed `io::Result` the caller surfaces — not inside `exit_event`, whose
        /// signature cannot report it and so used to `.expect()`, a production panic
        /// on a load-dependent host condition (M-HOST-6). Handed out at most once
        /// (single serve thread); a second call yields `None`, which is safe because
        /// shutdown is also driven by the caller's `kill_notifier` clone.
        exit_event: Mutex<Option<(EventConsumer, EventNotifier)>>,
    }

    // METRICS-FS-4: recover from a poisoned mutex instead of panicking. The guarded
    // state is plain device state (event_idx, mem, the kill eventfd) with no enforced
    // cross-field invariant, so continuing with the last-written value after a panic
    // in another holder is sound and keeps a guest-driven path from turning a
    // transient poison into a hard crash.
    fn lock_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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
            };

            // Pre-clone the kill eventfd pair for `exit_event` here (M-HOST-6): the
            // `try_clone` fd-dup can fail under fd exhaustion, and this is the only
            // place that failure is a typed `io::Error` rather than a mid-protocol
            // panic. Both clones `dup` the same underlying eventfd, so a
            // `kill_notifier.notify()` still wakes this consumer.
            let exit_pair = (
                backend.kill_evt.0.try_clone()?,
                backend.kill_evt.1.try_clone()?,
            );

            Ok(VhostUserFsBackendHandler {
                backend: Mutex::new(backend),
                exit_event: Mutex::new(Some(exit_pair)),
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
            lock_recover(&self.backend).event_idx = enabled
        }

        fn update_memory(
            &mut self,
            mem: GuestMemoryAtomic<GuestMemoryMmap>,
        ) -> std::io::Result<()> {
            lock_recover(&self.backend).mem = Some(mem);
            Ok(())
        }

        fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
            // Hand out the pre-cloned kill eventfd pair (cloned fallibly at
            // construction, so no fd-exhaustion `.expect()` panic here — M-HOST-6).
            // Taken once; a later worker gets `None`, which is safe as shutdown is
            // also driven by the caller's `kill_notifier`.
            lock_recover(&self.exit_event).take()
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

            // `handle_event` is driven by the guest kicking a virtqueue, so a
            // malformed `device_event`/`vrings` pairing is guest-reachable and must
            // never panic. Return a typed error instead of `expect`.
            let mut vring_state = match device_event {
                HIPRIO_QUEUE_EVENT => vrings
                    .first()
                    .ok_or_else(|| std::io::Error::other("hiprio vring missing"))?
                    .get_mut(),
                REQ_QUEUE_EVENT => vrings
                    .get(1)
                    .ok_or_else(|| std::io::Error::other("request vring missing"))?
                    .get_mut(),
                _ => {
                    return Err(std::io::Error::other("HandleEventUnknownEvent"));
                }
            };

            if lock_recover(&self.backend).event_idx {
                loop {
                    // Masking notifications is an interrupt-rate optimization around the drain loop. If the
                    // mask does not take, the loop simply runs with notifications enabled — slower, never
                    // incorrect — and `enable_notification` below is the arm whose value IS read.
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "notification masking is an interrupt-rate optimization; the enable_notification below is the arm whose value is read"
                    )]
                    let _ = vring_state.disable_notification();
                    lock_recover(&self.backend).process_queue(&mut vring_state)?;
                    if !vring_state.enable_notification().unwrap_or(false) {
                        break;
                    }
                }
            } else {
                lock_recover(&self.backend).process_queue(&mut vring_state)?;
            }

            Ok(())
        }
    }

    pub(crate) fn start_in_process_virtiofsd(
        socket_path: &std::path::Path,
        host_path: &std::path::Path,
        read_only: bool,
    ) -> std::io::Result<(std::thread::JoinHandle<()>, EventNotifier)> {
        let vfs = Vfs::new(VfsOptions {
            no_open: false,
            no_opendir: false,
            ..Default::default()
        });

        // fuse-backend-rs PassthroughFs does not have a config option for readonly,
        // so we must handle it manually or acknowledge it.
        // TODO: Enforce read_only flag inside the VFS layer or via bind mounts.
        if read_only {
            return Err(std::io::Error::other(
                "Read-only mode requested but in-process virtiofsd does not fully support it natively yet.",
            ));
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

        let backend_handler = VhostUserFsBackendHandler::new(Arc::new(vfs))?;
        let kill_notifier = lock_recover(&backend_handler.backend)
            .kill_evt
            .1
            .try_clone()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let backend = Arc::new(RwLock::new(backend_handler));
        let mut listener =
            Listener::new(socket_path, true).map_err(|e| std::io::Error::other(e.to_string()))?;

        let socket_path_str = socket_path.to_string_lossy().into_owned();
        // The worker reports its construction result and then signals readiness over
        // this channel. Building the daemon inside the worker keeps the daemon off
        // the thread boundary (it is not required to be `Send`), but a construction
        // failure is no longer an `expect` panic: the previous code panicked here,
        // and because `Listener::new` had already created the socket file, a
        // socket-existence readiness check reported a *dead* daemon as ready
        // (M-FS-2). Now the caller waits for an explicit ready/err signal, so
        // readiness reflects an actually-constructed, serving daemon.
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<std::io::Result<()>>(1);
        let handle = std::thread::spawn(move || {
            tracing::info!(
                "in-process virtiofsd: thread started, listening on {:?}",
                socket_path_str
            );
            let mut vu_daemon = match VhostUserDaemon::new(
                String::from("in-process-virtiofsd"),
                backend,
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            ) {
                Ok(daemon) => daemon,
                Err(e) => {
                    // Report the failure instead of panicking, so the caller
                    // returns a typed error rather than a false-ready daemon.
                    // The readiness receiver is `recv_timeout`-bounded below. If it already timed out there
                    // is no one to hand the construction error to, and the caller has already turned the
                    // timeout into its own typed error.
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the readiness receiver is bounded by recv_timeout; a send that fails means the caller already reported the timeout"
                    )]
                    let _ = ready_tx.send(Err(std::io::Error::other(format!(
                        "failed to construct vhost-user daemon: {e:?}"
                    ))));
                    return;
                }
            };
            // The daemon is constructed; signal readiness immediately before the
            // (blocking) serve loop. Waiting for `start` to return would deadlock,
            // as the frontend only connects after `VirtioFsDaemon::start_paced` returns —
            // this is the same readiness point as the external daemon's listening
            // socket (bound, about to accept).
            #[expect(
                clippy::let_underscore_must_use,
                reason = "same bounded readiness channel: a receiver that already timed out has reported its own typed error"
            )]
            let _ = ready_tx.send(Ok(()));
            if let Err(e) = vu_daemon.start(&mut listener) {
                tracing::error!("in-process virtiofsd: serve loop failed: {e:?}");
            }
            // The serve loop above has already returned and its failure was logged. This `wait` only
            // reaps the daemon's internal workers on the way out of a detached thread that has no
            // caller to answer.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "post-serve-loop reap on a detached thread: the serve loop's own failure was already logged above"
            )]
            let _ = vu_daemon.wait();
        });

        // Bound the wait so a worker that fails to construct or never reaches the
        // serve loop surfaces as a typed error instead of hanging the caller.
        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "in-process virtiofsd worker did not start: {e}"
                )));
            }
        }

        Ok((handle, kill_notifier))
    }

    #[cfg(test)]
    mod tests {
        // `super::*` brings the parent module's imports (incl. the
        // `VhostUserBackendMut` trait needed for `handle_event` method resolution,
        // `EventSet`, `VringMutex`) and the queue-event consts into scope.
        use super::*;

        fn new_handler() -> VhostUserFsBackendHandler {
            let vfs = Vfs::new(VfsOptions::default());
            VhostUserFsBackendHandler::new(Arc::new(vfs)).expect("construct backend handler")
        }

        // A guest can kick a queue whose vring is not present in `vrings`. The
        // dispatch path must return a typed error, not panic (which the previous
        // `vrings.first().expect(...)` / `vrings.get(1).expect(...)` did). This test
        // goes RED on that inverse: an `expect` on the empty slice unwinds and the
        // `#[test]` fails on the panic.
        #[test]
        fn handle_event_empty_vrings_errors_not_panics() {
            let mut handler = new_handler();
            let no_vrings: &[VringMutex] = &[];

            let hiprio = handler.handle_event(HIPRIO_QUEUE_EVENT, EventSet::IN, no_vrings, 0);
            assert!(
                hiprio.is_err(),
                "hiprio kick with no vrings must error, got {hiprio:?}"
            );

            let req = handler.handle_event(REQ_QUEUE_EVENT, EventSet::IN, no_vrings, 0);
            assert!(
                req.is_err(),
                "request kick with no vrings must error, got {req:?}"
            );
        }

        // An unknown device event is also guest-reachable and must be a typed error.
        #[test]
        fn handle_event_unknown_event_errors() {
            let mut handler = new_handler();
            let no_vrings: &[VringMutex] = &[];
            let res = handler.handle_event(42, EventSet::IN, no_vrings, 0);
            assert!(res.is_err(), "unknown device event must error, got {res:?}");
        }

        // M-HOST-6: `exit_event` must NOT re-`try_clone` the kill eventfd (an fd-dup
        // that panicked via `.expect()` under EMFILE). The pair is cloned once at
        // construction and handed out at most once. This asserts the take-once
        // behavior (a second call yields `None`) and, by never panicking, that the
        // fd-exhaustion `.expect()` is gone. Goes RED if `exit_event` reverts to
        // per-call cloning (a second call would then yield `Some`, not `None`).
        #[test]
        fn exit_event_hands_out_prebuilt_pair_once_no_panic() {
            let handler = new_handler();
            assert!(
                handler.exit_event(0).is_some(),
                "first exit_event must yield the pre-cloned kill eventfd pair"
            );
            assert!(
                handler.exit_event(0).is_none(),
                "exit_event must not re-clone; a second call yields None, never a panic"
            );
        }
    }
}
