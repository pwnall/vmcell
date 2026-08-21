//!
//! In-process virtio-fs daemon implementation using vhost-user.
//!
#[cfg(feature = "experiment-fuse")]
pub(crate) mod backend {
    use fuse_backend_rs::abi::fuse_abi::{CreateIn, Opcode, stat64, statvfs64};
    use fuse_backend_rs::abi::virtio_fs::{RemovemappingOne, SetupmappingFlags};
    use fuse_backend_rs::api::filesystem::{
        Context, DirEntry, Entry, FileLock, FileSystem, FsOptions, GetxattrReply, IoctlData,
        ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
    };
    use fuse_backend_rs::api::{
        BackFileSystem, BackendFileSystem, Vfs, VfsOptions, server::Server,
    };
    use fuse_backend_rs::passthrough::{Config, PassthroughFs};
    use fuse_backend_rs::transport::{FsCacheReqHandler, Reader, VirtioFsWriter};
    use std::ffi::CStr;
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

    // ===============================================================================================
    // §4.5 read-only enforcement for the in-process backend.
    //
    // WHY A VFS-LAYER DECORATOR AND NOT A BIND MOUNT. The deferral marker this replaced named both
    // routes.
    // Bind mounts lose on three counts, each independently fatal:
    //   * `mount --bind` + `remount,ro,bind` needs `CAP_SYS_ADMIN`, which the **unprivileged**
    //     operating mode (KVM group only, no `CAP_*` — §3.2) does not have. That mode is the one
    //     the in-process backend exists to serve, so an enforcement mechanism unavailable there
    //     enforces nothing where it matters.
    //   * A mount is namespace-global. This daemon is a *thread* of the orchestrator process, so a
    //     bind mount is visible to every VM, every share and the orchestrator itself; scoping it
    //     would need a mount-namespace unshare, which is per-thread state that neither the serve
    //     thread nor the `openat`-based fds `PassthroughFs::import` already holds would inherit.
    //   * It is not the layer the decision lives at: the same host directory can back a read-only
    //     share for one cell and a read-write share for another in the same process.
    // The decorator is available in both modes, is per-share by construction, and needs no
    // privilege at all.
    //
    // `fuse-backend-rs` 0.14's `passthrough::Config` has no read-only knob (`seal_size` covers only
    // size changes), which is what that marker recorded — so the refusal has to be a wrapper around
    // the `FileSystem` trait. `Vfs::mount` takes a `BackFileSystem`, so the wrapper mounts exactly
    // where the passthrough used to.
    // ===============================================================================================

    /// What a read-only share does with one FUSE opcode.
    ///
    /// **The one law** (AGENTS.md "One law, one predicate"): [`read_only_disposition`] classifies
    /// *every* opcode `fuse-backend-rs` defines, and every refusal in [`ReadOnlyFs`] cites the
    /// opcode it answers through [`refuse_read_only`]. Two gates keep the halves together:
    ///
    /// * the classifier is an **exhaustive `match` with no wildcard arm**, so a `fuse-backend-rs`
    ///   bump that adds an opcode is a *compile error* here rather than a silently-permitted
    ///   operation — the completeness the enumeration needs, made structural;
    /// * the `read_only_completeness_gate` scan below reads this file and requires the set of
    ///   opcodes classified [`OpKind::Mutating`]/[`OpKind::WriteIntent`] to equal the set cited at
    ///   refusal sites, so a newly-classified opcode with no refusing method reddens too.
    ///
    /// A partial enumeration is worse than none — it reads as enforcement while leaving a hole —
    /// which is why neither half is a hand-maintained roster.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum OpKind {
        /// Mutates host state unconditionally. A read-only share answers `EROFS`, exactly as the
        /// kernel's own `MS_RDONLY` check (`mnt_want_write`) does for the same operation.
        Mutating,
        /// Mutates only when the request carries write intent — `open` flags, the `access` mask,
        /// `setupmapping` flags. Refused with `EROFS` exactly then, delegated otherwise.
        WriteIntent,
        /// Reads, or is otherwise state-neutral (locking, `fsync`, `forget`, `statfs`). Delegated
        /// to the wrapped filesystem unchanged, so a read-only share stays *usable*.
        ReadOnly,
        /// `Server::handle_message` never routes this opcode to a [`FileSystem`] method: it is a
        /// sentinel (`MaxOpcode`, the two byte-order-probe reserved values), handled inside the
        /// server (`Interrupt`), or simply undispatched (`CopyFileRange`, which the server answers
        /// `ENOSYS` itself). There is no method here to refuse it in — and every one of them still
        /// needs a writable handle this wrapper never grants, because [`ReadOnlyFs::open`] and
        /// [`ReadOnlyFs::create`] are the only doors to one.
        NotDispatched,
    }

    /// Classifies one FUSE opcode for a read-only share.
    ///
    /// Exhaustive over [`Opcode`] **without a wildcard arm** on purpose: see [`OpKind`].
    pub(crate) const fn read_only_disposition(op: Opcode) -> OpKind {
        match op {
            // Unconditional mutations. `Ioctl` is here deliberately: its command word is opaque, so
            // a read-only share cannot tell `FS_IOC_GETFLAGS` from `FS_IOC_SETFLAGS` and refuses
            // the class. That is strictly narrower than a real read-only mount (which permits the
            // read-only ioctls) and never wider, and the wrapped `PassthroughFs` implements no
            // ioctl at all, so nothing that works today is lost.
            Opcode::Setattr
            | Opcode::Symlink
            | Opcode::Mknod
            | Opcode::Mkdir
            | Opcode::Unlink
            | Opcode::Rmdir
            | Opcode::Rename
            | Opcode::Rename2
            | Opcode::Link
            | Opcode::Create
            | Opcode::Write
            | Opcode::Fallocate
            | Opcode::Setxattr
            | Opcode::Removexattr
            | Opcode::Ioctl => OpKind::Mutating,
            // Refused only when the request itself asks for write access.
            Opcode::Open | Opcode::Access | Opcode::SetupMapping => OpKind::WriteIntent,
            // Reads and state-neutral operations: delegated, so the share still works.
            Opcode::Lookup
            | Opcode::Forget
            | Opcode::BatchForget
            | Opcode::Getattr
            | Opcode::Readlink
            | Opcode::Read
            | Opcode::Statfs
            | Opcode::Release
            | Opcode::Flush
            | Opcode::Fsync
            | Opcode::Getxattr
            | Opcode::Listxattr
            | Opcode::Init
            | Opcode::Destroy
            | Opcode::Opendir
            | Opcode::Readdir
            | Opcode::Readdirplus
            | Opcode::Releasedir
            | Opcode::Fsyncdir
            | Opcode::Getlk
            | Opcode::Setlk
            | Opcode::Setlkw
            | Opcode::Bmap
            | Opcode::Poll
            | Opcode::NotifyReply
            | Opcode::Lseek
            | Opcode::RemoveMapping => OpKind::ReadOnly,
            // Not routed to a `FileSystem` method by `Server::handle_message`.
            Opcode::Interrupt
            | Opcode::CopyFileRange
            | Opcode::MaxOpcode
            | Opcode::CuseInitBswapReserved
            | Opcode::InitBswapReserved => OpKind::NotDispatched,
        }
    }

    /// The one refusal a read-only share ever issues: `EROFS`, the errno a `MS_RDONLY` mount
    /// returns, naming the opcode it answers.
    ///
    /// Every refusing method in [`ReadOnlyFs`] goes through here, which is what lets
    /// the `read_only_completeness_gate` scan read the enforcement back out of the source and
    /// compare it against [`read_only_disposition`].
    fn refuse_read_only(op: Opcode) -> std::io::Error {
        debug_assert!(
            matches!(
                read_only_disposition(op),
                OpKind::Mutating | OpKind::WriteIntent
            ),
            "a read-only share refused {op:?}, which read_only_disposition does not classify as mutating"
        );
        // Bounded cardinality (one enum variant), and refusals are rare by construction — a guest
        // that keeps writing to a read-only share is worth one `debug` line per attempt.
        tracing::debug!(?op, "read-only share: refusing with EROFS");
        std::io::Error::from_raw_os_error(libc::EROFS)
    }

    /// Whether `open` flags ask for write access.
    ///
    /// The kernel's own read-only-mount rule, not an approximation of it: the access mode, plus the
    /// three flags that mutate on their own (`O_TRUNC` truncates, `O_APPEND` is a write mode,
    /// `O_CREAT` creates). `O_TRUNC` matters even though [`ReadOnlyFs::setattr`] already refuses a
    /// size change, because `FsOptions::ATOMIC_O_TRUNC` (on by default in [`VfsOptions`]) folds the
    /// truncate into the `open` and no `setattr` is ever sent.
    const fn open_flags_imply_write(flags: u32) -> bool {
        // `libc`'s open-flag constants are non-negative `c_int` bit masks, so the widening cast is
        // value-preserving; the FUSE wire carries them as `u32`.
        let accmode = libc::O_ACCMODE as u32;
        let mutating =
            (libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_APPEND | libc::O_CREAT) as u32;
        // O_RDONLY is 0, so the access mode is "write" exactly when it has a bit set.
        (flags & accmode) != 0 || (flags & mutating) != 0
    }

    /// Whether an `access` mask asks about write permission. A read-only mount answers `EROFS` to
    /// `access(W_OK)` rather than reporting the underlying file's mode, and so does this.
    const fn access_mask_implies_write(mask: u32) -> bool {
        // Non-negative `c_int` bit mask; see `open_flags_imply_write`.
        let w_ok = libc::W_OK as u32;
        (mask & w_ok) != 0
    }

    /// Whether a `setupmapping` request asks for a **writable** DAX window. A read mapping of a
    /// read-only share is legitimate; a write mapping would hand the guest a bypass around every
    /// other refusal here.
    const fn setupmapping_flags_imply_write(flags: u64) -> bool {
        (flags & SetupmappingFlags::WRITE.bits()) != 0
    }

    /// A read-only view of another [`FileSystem`].
    ///
    /// Every mutating FUSE operation is answered `EROFS` — the errno a `MS_RDONLY` mount returns —
    /// and every other operation is delegated to `inner` unchanged, so a read-only share is still a
    /// working share. Which is which is [`read_only_disposition`]'s single answer.
    ///
    /// **Not** a second partial mechanism: `VfsOptions::seal_size` would also block size changes,
    /// and is deliberately left off, because a half-overlapping second enforcement point is exactly
    /// the duplicate-law shape AGENTS.md forbids. The one knob that *is* set alongside this
    /// wrapper — [`vfs_options`]'s `no_open` — is not a second refusal but the precondition for
    /// this one: it is what keeps `open` reaching [`ReadOnlyFs::open`] at all.
    ///
    /// The guest still *mounts* the share `rw` unless it passes `-o ro`: FUSE's `statfs` reply
    /// (`Kstatfs`) has no flag word, so `ST_RDONLY` cannot be reported and faking it in the
    /// [`statvfs64`] this returns would be a claim that reaches nobody. Enforcement is per
    /// operation, which is where it binds.
    pub(crate) struct ReadOnlyFs<F> {
        inner: F,
    }

    impl<F> ReadOnlyFs<F> {
        /// Wraps `inner` so that every mutating operation is refused with `EROFS`.
        pub(crate) const fn new(inner: F) -> Self {
            Self { inner }
        }
    }

    impl<F: FileSystem> FileSystem for ReadOnlyFs<F> {
        type Inode = F::Inode;
        type Handle = F::Handle;

        // ---- delegated: reads and state-neutral operations ----------------------------------

        fn init(&self, capable: FsOptions) -> std::io::Result<FsOptions> {
            // The write-enabling negotiation is cut in `vfs_options`, not here: `Vfs::init` calls
            // this with its own already-masked `out_opts` and discards what we return, so masking
            // at this seam would be a no-op dressed as a control.
            self.inner.init(capable)
        }

        fn destroy(&self) {
            self.inner.destroy();
        }

        fn lookup(
            &self,
            ctx: &Context,
            parent: Self::Inode,
            name: &CStr,
        ) -> std::io::Result<Entry> {
            self.inner.lookup(ctx, parent, name)
        }

        fn forget(&self, ctx: &Context, inode: Self::Inode, count: u64) {
            self.inner.forget(ctx, inode, count);
        }

        fn batch_forget(&self, ctx: &Context, requests: Vec<(Self::Inode, u64)>) {
            self.inner.batch_forget(ctx, requests);
        }

        fn getattr(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Option<Self::Handle>,
        ) -> std::io::Result<(stat64, std::time::Duration)> {
            self.inner.getattr(ctx, inode, handle)
        }

        fn readlink(&self, ctx: &Context, inode: Self::Inode) -> std::io::Result<Vec<u8>> {
            self.inner.readlink(ctx, inode)
        }

        fn read(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            w: &mut dyn ZeroCopyWriter,
            size: u32,
            offset: u64,
            lock_owner: Option<u64>,
            flags: u32,
        ) -> std::io::Result<usize> {
            self.inner
                .read(ctx, inode, handle, w, size, offset, lock_owner, flags)
        }

        fn flush(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            lock_owner: u64,
        ) -> std::io::Result<()> {
            self.inner.flush(ctx, inode, handle, lock_owner)
        }

        fn fsync(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            datasync: bool,
            handle: Self::Handle,
        ) -> std::io::Result<()> {
            self.inner.fsync(ctx, inode, datasync, handle)
        }

        fn release(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            flags: u32,
            handle: Self::Handle,
            flush: bool,
            flock_release: bool,
            lock_owner: Option<u64>,
        ) -> std::io::Result<()> {
            self.inner
                .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
        }

        fn statfs(&self, ctx: &Context, inode: Self::Inode) -> std::io::Result<statvfs64> {
            self.inner.statfs(ctx, inode)
        }

        fn getxattr(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            name: &CStr,
            size: u32,
        ) -> std::io::Result<GetxattrReply> {
            self.inner.getxattr(ctx, inode, name, size)
        }

        fn listxattr(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            size: u32,
        ) -> std::io::Result<ListxattrReply> {
            self.inner.listxattr(ctx, inode, size)
        }

        fn opendir(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            flags: u32,
        ) -> std::io::Result<(Option<Self::Handle>, OpenOptions)> {
            // A directory open carries no write intent of its own — the operations that would
            // mutate through it (`create`, `mkdir`, `unlink`, …) are each refused at their own
            // method.
            self.inner.opendir(ctx, inode, flags)
        }

        fn readdir(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            size: u32,
            offset: u64,
            add_entry: &mut dyn FnMut(DirEntry) -> std::io::Result<usize>,
        ) -> std::io::Result<()> {
            self.inner
                .readdir(ctx, inode, handle, size, offset, add_entry)
        }

        fn readdirplus(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            size: u32,
            offset: u64,
            add_entry: &mut dyn FnMut(DirEntry, Entry) -> std::io::Result<usize>,
        ) -> std::io::Result<()> {
            self.inner
                .readdirplus(ctx, inode, handle, size, offset, add_entry)
        }

        fn fsyncdir(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            datasync: bool,
            handle: Self::Handle,
        ) -> std::io::Result<()> {
            self.inner.fsyncdir(ctx, inode, datasync, handle)
        }

        fn releasedir(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            flags: u32,
            handle: Self::Handle,
        ) -> std::io::Result<()> {
            self.inner.releasedir(ctx, inode, flags, handle)
        }

        fn removemapping(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            requests: Vec<RemovemappingOne>,
            vu_req: &mut dyn FsCacheReqHandler,
        ) -> std::io::Result<()> {
            // Tearing a mapping down never writes to the share.
            self.inner.removemapping(ctx, inode, requests, vu_req)
        }

        fn lseek(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            offset: u64,
            whence: u32,
        ) -> std::io::Result<u64> {
            self.inner.lseek(ctx, inode, handle, offset, whence)
        }

        fn getlk(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            owner: u64,
            lock: FileLock,
            flags: u32,
        ) -> std::io::Result<FileLock> {
            self.inner.getlk(ctx, inode, handle, owner, lock, flags)
        }

        fn setlk(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            owner: u64,
            lock: FileLock,
            flags: u32,
        ) -> std::io::Result<()> {
            // A lock is not a write: a `MS_RDONLY` mount takes them too, and a write lock on a
            // handle this wrapper only ever opened `O_RDONLY` is the kernel's problem, not ours.
            self.inner.setlk(ctx, inode, handle, owner, lock, flags)
        }

        fn setlkw(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            owner: u64,
            lock: FileLock,
            flags: u32,
        ) -> std::io::Result<()> {
            self.inner.setlkw(ctx, inode, handle, owner, lock, flags)
        }

        fn bmap(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            block: u64,
            blocksize: u32,
        ) -> std::io::Result<u64> {
            self.inner.bmap(ctx, inode, block, blocksize)
        }

        fn poll(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            khandle: Self::Handle,
            flags: u32,
            events: u32,
        ) -> std::io::Result<u32> {
            self.inner.poll(ctx, inode, handle, khandle, flags, events)
        }

        fn notify_reply(&self) -> std::io::Result<()> {
            self.inner.notify_reply()
        }

        fn id_remap(&self, ctx: &mut Context) -> std::io::Result<()> {
            self.inner.id_remap(ctx)
        }

        // ---- refused: unconditional mutations -----------------------------------------------

        fn setattr(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _attr: stat64,
            _handle: Option<Self::Handle>,
            _valid: SetattrValid,
        ) -> std::io::Result<(stat64, std::time::Duration)> {
            // Covers chmod/chown/utimes AND truncate — `SetattrValid::SIZE` is how a non-atomic
            // `O_TRUNC` and every `ftruncate` arrive.
            Err(refuse_read_only(Opcode::Setattr))
        }

        fn symlink(
            &self,
            _ctx: &Context,
            _linkname: &CStr,
            _parent: Self::Inode,
            _name: &CStr,
        ) -> std::io::Result<Entry> {
            Err(refuse_read_only(Opcode::Symlink))
        }

        fn mknod(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _name: &CStr,
            _mode: u32,
            _rdev: u32,
            _umask: u32,
        ) -> std::io::Result<Entry> {
            Err(refuse_read_only(Opcode::Mknod))
        }

        fn mkdir(
            &self,
            _ctx: &Context,
            _parent: Self::Inode,
            _name: &CStr,
            _mode: u32,
            _umask: u32,
        ) -> std::io::Result<Entry> {
            Err(refuse_read_only(Opcode::Mkdir))
        }

        fn unlink(
            &self,
            _ctx: &Context,
            _parent: Self::Inode,
            _name: &CStr,
        ) -> std::io::Result<()> {
            Err(refuse_read_only(Opcode::Unlink))
        }

        fn rmdir(&self, _ctx: &Context, _parent: Self::Inode, _name: &CStr) -> std::io::Result<()> {
            Err(refuse_read_only(Opcode::Rmdir))
        }

        fn rename(
            &self,
            _ctx: &Context,
            _olddir: Self::Inode,
            _oldname: &CStr,
            _newdir: Self::Inode,
            _newname: &CStr,
            flags: u32,
        ) -> std::io::Result<()> {
            // `Server::handle_message` routes BOTH `Opcode::Rename` and `Opcode::Rename2` here, so
            // this one method answers the pair. The flag word (`RENAME_NOREPLACE`/`EXCHANGE`/
            // `WHITEOUT`, all `rename2`-only) picks which opcode the refusal *names*; both are
            // refused identically, and citing each at a real call site is what keeps the
            // completeness scan honest about the alias.
            if flags == 0 {
                return Err(refuse_read_only(Opcode::Rename));
            }
            Err(refuse_read_only(Opcode::Rename2))
        }

        fn link(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _newparent: Self::Inode,
            _newname: &CStr,
        ) -> std::io::Result<Entry> {
            Err(refuse_read_only(Opcode::Link))
        }

        fn create(
            &self,
            _ctx: &Context,
            _parent: Self::Inode,
            _name: &CStr,
            _args: CreateIn,
        ) -> std::io::Result<(Entry, Option<Self::Handle>, OpenOptions, Option<u32>)> {
            Err(refuse_read_only(Opcode::Create))
        }

        fn write(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _handle: Self::Handle,
            _r: &mut dyn ZeroCopyReader,
            _size: u32,
            _offset: u64,
            _lock_owner: Option<u64>,
            _delayed_write: bool,
            _flags: u32,
            _fuse_flags: u32,
        ) -> std::io::Result<usize> {
            // Refused BEFORE the reader is touched: a partial drain followed by an error would
            // desynchronize the virtio descriptor chain the caller still has to complete.
            Err(refuse_read_only(Opcode::Write))
        }

        fn fallocate(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _handle: Self::Handle,
            _mode: u32,
            _offset: u64,
            _length: u64,
        ) -> std::io::Result<()> {
            Err(refuse_read_only(Opcode::Fallocate))
        }

        fn setxattr(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _name: &CStr,
            _value: &[u8],
            _flags: u32,
        ) -> std::io::Result<()> {
            Err(refuse_read_only(Opcode::Setxattr))
        }

        fn removexattr(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _name: &CStr,
        ) -> std::io::Result<()> {
            Err(refuse_read_only(Opcode::Removexattr))
        }

        fn ioctl(
            &self,
            _ctx: &Context,
            _inode: Self::Inode,
            _handle: Self::Handle,
            _flags: u32,
            _cmd: u32,
            _data: IoctlData,
            _out_size: u32,
        ) -> std::io::Result<IoctlData<'_>> {
            // See `read_only_disposition`: the command word is opaque, so the class is refused.
            Err(refuse_read_only(Opcode::Ioctl))
        }

        // ---- refused on write intent ----------------------------------------------------------

        fn open(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            flags: u32,
            fuse_flags: u32,
        ) -> std::io::Result<(Option<Self::Handle>, OpenOptions, Option<u32>)> {
            // The choke point. `write`/`fallocate`/`ioctl` all need a handle, and this and
            // `create` are the only two methods that mint one.
            if open_flags_imply_write(flags) {
                return Err(refuse_read_only(Opcode::Open));
            }
            self.inner.open(ctx, inode, flags, fuse_flags)
        }

        fn access(&self, ctx: &Context, inode: Self::Inode, mask: u32) -> std::io::Result<()> {
            if access_mask_implies_write(mask) {
                return Err(refuse_read_only(Opcode::Access));
            }
            self.inner.access(ctx, inode, mask)
        }

        fn setupmapping(
            &self,
            ctx: &Context,
            inode: Self::Inode,
            handle: Self::Handle,
            foffset: u64,
            len: u64,
            flags: u64,
            moffset: u64,
            vu_req: &mut dyn FsCacheReqHandler,
        ) -> std::io::Result<()> {
            if setupmapping_flags_imply_write(flags) {
                return Err(refuse_read_only(Opcode::SetupMapping));
            }
            self.inner
                .setupmapping(ctx, inode, handle, foffset, len, flags, moffset, vu_req)
        }
    }

    impl<F: BackendFileSystem + 'static> BackendFileSystem for ReadOnlyFs<F> {
        fn mount(&self) -> std::io::Result<(Entry, u64)> {
            self.inner.mount()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// The [`VfsOptions`] the in-process daemon mounts a share with.
    ///
    /// A function rather than an inline literal because two of these fields are load-bearing for
    /// §4.5 read-only enforcement and one of them inverts a default:
    ///
    /// * `no_open` / `no_opendir` **must stay `false`** (the [`VfsOptions`] defaults are `true`).
    ///   `true` makes the `Vfs` answer `open` with `ENOSYS`, which the kernel reads as
    ///   `FsOptions::ZERO_MESSAGE_OPEN` and then services opens *itself* — [`ReadOnlyFs::open`]'s
    ///   write-intent check would never run and the guest would hold a writable handle the share
    ///   never granted. This is the precondition the refusals rest on, not a second refusal.
    /// * `no_writeback` is `true` on a read-only share, which drops `FsOptions::WRITEBACK_CACHE`
    ///   from the negotiation. That option exists so the guest kernel can defer writes; a
    ///   read-only share has none to defer.
    ///
    /// The read-write path gets exactly the options it had before this function existed.
    fn vfs_options(read_only: bool) -> VfsOptions {
        VfsOptions {
            no_open: false,
            no_opendir: false,
            no_writeback: read_only,
            ..Default::default()
        }
    }

    pub(crate) fn start_in_process_virtiofsd(
        socket_path: &std::path::Path,
        host_path: &std::path::Path,
        read_only: bool,
    ) -> std::io::Result<(std::thread::JoinHandle<()>, EventNotifier)> {
        let vfs = Vfs::new(vfs_options(read_only));

        let cfg = Config {
            root_dir: host_path.to_string_lossy().to_string(),
            do_import: false,
            ..Default::default()
        };

        let fs = PassthroughFs::<()>::new(cfg).map_err(|e| std::io::Error::other(e.to_string()))?;
        fs.import()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        // §4.5: `fuse-backend-rs`'s passthrough has no read-only knob, so a read-only share mounts
        // through `ReadOnlyFs` — the one place the read-only decision is made. This is what the
        // long-standing deferral marker here asked for; `fs::VirtioFsDaemon::start_paced` no longer refuses
        // a read-only share with a typed `Unsupported` because of it.
        let mounted: BackFileSystem = if read_only {
            Box::new(ReadOnlyFs::new(fs))
        } else {
            Box::new(fs)
        };
        vfs.mount(mounted, "/")
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

    /// §4.5 read-only enforcement, driven against a **real host directory**.
    ///
    /// KVM-free and VM-free on purpose, and not a fake: [`ReadOnlyFs`] wraps a real
    /// [`PassthroughFs`] doing real `openat`/`mkdirat`/`unlinkat` syscalls, so every leg asserts on
    /// the **data plane** — the refused operation returns `EROFS` *and* the host tree is unchanged,
    /// and the positive control performs the same operation on a writable share and finds the
    /// change on disk. `test-unprivileged`'s live suite cannot reach this backend at all (no recipe
    /// selects `experiment-fuse`), which is exactly why the enforcement is proven at the layer that
    /// makes the decision rather than through a proxy signal.
    #[cfg(test)]
    mod read_only_tests {
        use super::*;
        use fuse_backend_rs::api::filesystem::ROOT_ID;
        use fuse_backend_rs::file_buf::FileVolatileSlice;
        use fuse_backend_rs::file_traits::FileReadWriteVolatile;
        use std::ffi::CString;
        use std::path::{Path, PathBuf};

        /// A seeded host directory that removes itself on drop — on the **panic** path as much as
        /// the success one, because a test's own fixtures are residue too (AGENTS.md).
        struct Fixture {
            dir: PathBuf,
        }

        impl Fixture {
            fn seeded(tag: &str) -> Self {
                let dir = std::env::temp_dir().join(format!(
                    "vmcell-rofs-{tag}-{}-{}",
                    std::process::id(),
                    uuid::Uuid::new_v4()
                ));
                std::fs::create_dir_all(dir.join("seed_dir")).expect("create fixture tree");
                std::fs::write(dir.join("seed.txt"), SEED).expect("seed a file");
                std::fs::write(dir.join("victim.txt"), SEED).expect("seed a rename/link victim");
                Self { dir }
            }

            fn path(&self) -> &Path {
                &self.dir
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "fixture teardown in Drop has no caller to report to; the next run's directory name is unique anyway"
                )]
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        const SEED: &[u8] = b"hello world";

        /// One read-only share and one writable share, over two identically seeded directories.
        ///
        /// Two directories rather than one so a control's mutation can never be what a refusal leg
        /// observes: the "host tree unchanged" assertion is on the read-only fixture alone.
        struct Pair {
            ro_dir: Fixture,
            rw_dir: Fixture,
            ro: ReadOnlyFs<PassthroughFs<()>>,
            rw: PassthroughFs<()>,
        }

        fn passthrough_over(dir: &Path) -> PassthroughFs<()> {
            let cfg = Config {
                root_dir: dir.to_string_lossy().to_string(),
                do_import: false,
                // The production config leaves `xattr` off; the xattr legs need it on so the
                // positive control is a real `setxattr` rather than a blanket `ENOSYS` that would
                // pass for the wrong reason.
                xattr: true,
                ..Default::default()
            };
            let fs = PassthroughFs::<()>::new(cfg).expect("build passthrough fs");
            fs.import().expect("import passthrough root");
            fs
        }

        fn pair(tag: &str) -> Pair {
            let ro_dir = Fixture::seeded(&format!("{tag}-ro"));
            let rw_dir = Fixture::seeded(&format!("{tag}-rw"));
            let ro = ReadOnlyFs::new(passthrough_over(ro_dir.path()));
            let rw = passthrough_over(rw_dir.path());
            Pair {
                ro_dir,
                rw_dir,
                ro,
                rw,
            }
        }

        fn cstr(s: &str) -> CString {
            CString::new(s).expect("a test name with no interior NUL")
        }

        fn assert_erofs(err: &std::io::Error, what: &str) {
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EROFS),
                "{what} on a read-only share must be EROFS (what a MS_RDONLY mount returns), got {err:?}"
            );
        }

        /// Resolves `name` under the share root, returning its inode.
        fn ino<F: FileSystem<Inode = u64, Handle = u64>>(fs: &F, name: &str) -> u64 {
            fs.lookup(&Context::new(), ROOT_ID, &cstr(name))
                .unwrap_or_else(|e| panic!("lookup {name}: {e:?}"))
                .inode
        }

        /// A `ZeroCopyReader` over an in-memory buffer that counts how many times the filesystem
        /// asked it for bytes — so a refusal leg can assert the refusal happened **before** the
        /// descriptor chain was drained.
        struct CountingReader {
            data: Vec<u8>,
            pos: usize,
            reads: std::cell::Cell<usize>,
        }

        impl CountingReader {
            fn new(data: &[u8]) -> Self {
                Self {
                    data: data.to_vec(),
                    pos: 0,
                    reads: std::cell::Cell::new(0),
                }
            }
        }

        impl std::io::Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = buf.len().min(self.data.len() - self.pos);
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        impl ZeroCopyReader for CountingReader {
            fn read_to(
                &mut self,
                f: &mut dyn FileReadWriteVolatile,
                count: usize,
                off: u64,
            ) -> std::io::Result<usize> {
                self.reads.set(self.reads.get() + 1);
                let end = self.data.len().min(self.pos + count);
                let mut chunk = self.data[self.pos..end].to_vec();
                // SAFETY: `FileVolatileSlice::from_mut_slice` requires the slice to stay valid and
                // unaliased for the lifetime of the returned value. `chunk` is a local `Vec` that
                // outlives `slice` (dropped at the end of this function, after the call returns),
                // and no other reference to it exists while the call is in flight.
                let slice = unsafe { FileVolatileSlice::from_mut_slice(&mut chunk) };
                let n = f.write_at_volatile(slice, off)?;
                self.pos += n;
                Ok(n)
            }
        }

        /// A `ZeroCopyWriter` collecting into a `Vec`, so a read through the wrapper can be
        /// compared against the bytes actually on disk.
        struct CollectingWriter {
            data: Vec<u8>,
        }

        impl std::io::Write for CollectingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.data.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl ZeroCopyWriter for CollectingWriter {
            fn write_from(
                &mut self,
                f: &mut dyn FileReadWriteVolatile,
                count: usize,
                off: u64,
            ) -> std::io::Result<usize> {
                let mut buf = vec![0_u8; count];
                // SAFETY: same obligation as `CountingReader::read_to` — `buf` is a local `Vec`
                // that outlives the `FileVolatileSlice` built from it, and nothing else aliases it
                // while `read_at_volatile` is in flight.
                let slice = unsafe { FileVolatileSlice::from_mut_slice(&mut buf) };
                let n = f.read_at_volatile(slice, off)?;
                self.data.extend_from_slice(&buf[..n]);
                Ok(n)
            }

            fn available_bytes(&self) -> usize {
                // An unbounded sink: the collector grows to whatever the read returns.
                usize::MAX
            }
        }

        /// The DAX-window stub `setupmapping` needs. Records whether the filesystem ever asked for
        /// a mapping, which is how the delegated (read) leg proves it reached the inner fs.
        struct RecordingFsCache {
            maps: usize,
        }

        impl FsCacheReqHandler for RecordingFsCache {
            fn map(
                &mut self,
                _foffset: u64,
                _moffset: u64,
                _len: u64,
                _flags: u64,
                _fd: std::os::unix::io::RawFd,
            ) -> std::io::Result<()> {
                self.maps += 1;
                Ok(())
            }

            fn unmap(&mut self, _requests: Vec<RemovemappingOne>) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn zeroed_stat() -> stat64 {
            // SAFETY: `stat64` is a `#[repr(C)]` aggregate of integer fields with no niche and no
            // pointer, so the all-zero bit pattern is a valid inhabitant.
            unsafe { std::mem::zeroed::<stat64>() }
        }

        // ---- unconditional mutations: refused, with the writable share as positive control ----

        #[test]
        fn mkdir_refused_read_only_permitted_read_write() {
            let p = pair("mkdir");
            let ctx = Context::new();
            let err =
                p.ro.mkdir(&ctx, ROOT_ID, &cstr("made"), 0o755, 0)
                    .expect_err("a read-only share must refuse mkdir");
            assert_erofs(&err, "mkdir");
            assert!(
                !p.ro_dir.path().join("made").exists(),
                "the read-only host tree must be untouched"
            );

            p.rw.mkdir(&ctx, ROOT_ID, &cstr("made"), 0o755, 0)
                .expect("positive control: a writable share permits mkdir");
            assert!(
                p.rw_dir.path().join("made").is_dir(),
                "positive control must reach the same target on disk"
            );
        }

        #[test]
        fn create_refused_read_only_permitted_read_write() {
            let p = pair("create");
            let ctx = Context::new();
            let args = CreateIn {
                flags: libc::O_RDWR as u32,
                mode: 0o644,
                umask: 0,
                fuse_flags: 0,
            };
            let err =
                p.ro.create(&ctx, ROOT_ID, &cstr("fresh.txt"), args)
                    .expect_err("a read-only share must refuse create");
            assert_erofs(&err, "create");
            assert!(
                !p.ro_dir.path().join("fresh.txt").exists(),
                "the read-only host tree must be untouched"
            );

            p.rw.create(&ctx, ROOT_ID, &cstr("fresh.txt"), args)
                .map(|_| ())
                .expect("positive control: a writable share permits create");
            assert!(
                p.rw_dir.path().join("fresh.txt").is_file(),
                "positive control must reach the same target on disk"
            );
        }

        #[test]
        fn unlink_refused_read_only_permitted_read_write() {
            let p = pair("unlink");
            let ctx = Context::new();
            let err =
                p.ro.unlink(&ctx, ROOT_ID, &cstr("seed.txt"))
                    .expect_err("a read-only share must refuse unlink");
            assert_erofs(&err, "unlink");
            assert!(
                p.ro_dir.path().join("seed.txt").is_file(),
                "the refused unlink must leave the file on disk"
            );

            p.rw.unlink(&ctx, ROOT_ID, &cstr("seed.txt"))
                .expect("positive control: a writable share permits unlink");
            assert!(
                !p.rw_dir.path().join("seed.txt").exists(),
                "positive control must reach the same target on disk"
            );
        }

        #[test]
        fn rmdir_refused_read_only_permitted_read_write() {
            let p = pair("rmdir");
            let ctx = Context::new();
            let err =
                p.ro.rmdir(&ctx, ROOT_ID, &cstr("seed_dir"))
                    .expect_err("a read-only share must refuse rmdir");
            assert_erofs(&err, "rmdir");
            assert!(p.ro_dir.path().join("seed_dir").is_dir());

            p.rw.rmdir(&ctx, ROOT_ID, &cstr("seed_dir"))
                .expect("positive control: a writable share permits rmdir");
            assert!(!p.rw_dir.path().join("seed_dir").exists());
        }

        /// Both `rename` and `rename2` (a non-zero flag word) land on the one method, and both are
        /// refused. Red on the inverse in which only the zero-flag spelling is answered.
        #[test]
        fn rename_and_rename2_refused_read_only_permitted_read_write() {
            let p = pair("rename");
            let ctx = Context::new();
            for flags in [0_u32, libc::RENAME_NOREPLACE] {
                let err =
                    p.ro.rename(
                        &ctx,
                        ROOT_ID,
                        &cstr("victim.txt"),
                        ROOT_ID,
                        &cstr("moved.txt"),
                        flags,
                    )
                    .expect_err("a read-only share must refuse rename");
                assert_erofs(&err, "rename");
            }
            assert!(p.ro_dir.path().join("victim.txt").is_file());
            assert!(!p.ro_dir.path().join("moved.txt").exists());

            p.rw.rename(
                &ctx,
                ROOT_ID,
                &cstr("victim.txt"),
                ROOT_ID,
                &cstr("moved.txt"),
                0,
            )
            .expect("positive control: a writable share permits rename");
            assert!(p.rw_dir.path().join("moved.txt").is_file());
        }

        #[test]
        fn symlink_refused_read_only_permitted_read_write() {
            let p = pair("symlink");
            let ctx = Context::new();
            let err =
                p.ro.symlink(&ctx, &cstr("seed.txt"), ROOT_ID, &cstr("alias"))
                    .expect_err("a read-only share must refuse symlink");
            assert_erofs(&err, "symlink");
            assert!(!p.ro_dir.path().join("alias").exists());

            p.rw.symlink(&ctx, &cstr("seed.txt"), ROOT_ID, &cstr("alias"))
                .expect("positive control: a writable share permits symlink");
            assert!(
                p.rw_dir
                    .path()
                    .join("alias")
                    .symlink_metadata()
                    .expect("the control symlink must exist")
                    .file_type()
                    .is_symlink()
            );
        }

        #[test]
        fn link_refused_read_only_permitted_read_write() {
            let p = pair("link");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");
            let err =
                p.ro.link(&ctx, ro_ino, ROOT_ID, &cstr("hard"))
                    .expect_err("a read-only share must refuse link");
            assert_erofs(&err, "link");
            assert!(!p.ro_dir.path().join("hard").exists());

            let rw_ino = ino(&p.rw, "seed.txt");
            p.rw.link(&ctx, rw_ino, ROOT_ID, &cstr("hard"))
                .expect("positive control: a writable share permits link");
            assert!(p.rw_dir.path().join("hard").is_file());
        }

        /// `mknod` of a FIFO, which needs no privilege — so the positive control is real rather
        /// than an `EPERM` that would pass for the wrong reason.
        #[test]
        fn mknod_refused_read_only_permitted_read_write() {
            let p = pair("mknod");
            let ctx = Context::new();
            let mode = libc::S_IFIFO | 0o644;
            let err =
                p.ro.mknod(&ctx, ROOT_ID, &cstr("pipe"), mode, 0, 0)
                    .expect_err("a read-only share must refuse mknod");
            assert_erofs(&err, "mknod");
            assert!(!p.ro_dir.path().join("pipe").exists());

            p.rw.mknod(&ctx, ROOT_ID, &cstr("pipe"), mode, 0, 0)
                .expect("positive control: a writable share permits mknod of a FIFO");
            assert!(p.rw_dir.path().join("pipe").exists());
        }

        /// `setattr` is how every `chmod`/`chown`/`utimes` **and** every non-atomic `truncate`
        /// arrives, so the leg asserts on the size change specifically.
        #[test]
        fn setattr_truncate_refused_read_only_permitted_read_write() {
            let p = pair("setattr");
            let ctx = Context::new();
            let mut attr = zeroed_stat();
            attr.st_size = 0;

            let ro_ino = ino(&p.ro, "seed.txt");
            let err =
                p.ro.setattr(&ctx, ro_ino, attr, None, SetattrValid::SIZE)
                    .expect_err("a read-only share must refuse setattr");
            assert_erofs(&err, "setattr");
            assert_eq!(
                std::fs::read(p.ro_dir.path().join("seed.txt")).expect("read back"),
                SEED,
                "the refused truncate must leave the bytes on disk"
            );

            let rw_ino = ino(&p.rw, "seed.txt");
            p.rw.setattr(&ctx, rw_ino, attr, None, SetattrValid::SIZE)
                .map(|_| ())
                .expect("positive control: a writable share permits truncate");
            assert!(
                std::fs::read(p.rw_dir.path().join("seed.txt"))
                    .expect("read back")
                    .is_empty(),
                "positive control must reach the same target on disk"
            );
        }

        /// The refusal must precede any drain of the caller's reader: a partial drain followed by
        /// an error desynchronizes the virtio descriptor chain the caller still has to complete.
        #[test]
        fn write_refused_read_only_before_touching_the_reader() {
            let p = pair("write");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");
            let mut reader = CountingReader::new(b"CLOBBER");
            let err =
                p.ro.write(&ctx, ro_ino, 0, &mut reader, 7, 0, None, false, 0, 0)
                    .expect_err("a read-only share must refuse write");
            assert_erofs(&err, "write");
            assert_eq!(
                reader.reads.get(),
                0,
                "the refusal must land before the descriptor chain is drained"
            );
            assert_eq!(
                std::fs::read(p.ro_dir.path().join("seed.txt")).expect("read back"),
                SEED,
                "the refused write must leave the bytes on disk"
            );

            // Positive control: the same call on a writable share moves the bytes to disk.
            let rw_ino = ino(&p.rw, "seed.txt");
            let (handle, ..) =
                p.rw.open(&ctx, rw_ino, libc::O_RDWR as u32, 0)
                    .expect("control: open the writable share for writing");
            let handle = handle.expect("the passthrough fs returns a handle when no_open is off");
            let mut control = CountingReader::new(b"CLOBBER");
            let written =
                p.rw.write(&ctx, rw_ino, handle, &mut control, 7, 0, None, false, 0, 0)
                    .expect("positive control: a writable share permits write");
            assert_eq!(written, 7);
            assert!(
                std::fs::read(p.rw_dir.path().join("seed.txt"))
                    .expect("read back")
                    .starts_with(b"CLOBBER"),
                "positive control must reach the same bytes on disk"
            );
        }

        #[test]
        fn fallocate_refused_read_only_permitted_read_write() {
            let p = pair("fallocate");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");
            let err =
                p.ro.fallocate(&ctx, ro_ino, 0, 0, 0, 4096)
                    .expect_err("a read-only share must refuse fallocate");
            assert_erofs(&err, "fallocate");
            assert_eq!(
                std::fs::metadata(p.ro_dir.path().join("seed.txt"))
                    .expect("stat")
                    .len(),
                SEED.len() as u64
            );

            let rw_ino = ino(&p.rw, "seed.txt");
            let (handle, ..) =
                p.rw.open(&ctx, rw_ino, libc::O_RDWR as u32, 0)
                    .expect("control: open for writing");
            let handle = handle.expect("a handle");
            p.rw.fallocate(&ctx, rw_ino, handle, 0, 0, 4096)
                .expect("positive control: a writable share permits fallocate");
            assert_eq!(
                std::fs::metadata(p.rw_dir.path().join("seed.txt"))
                    .expect("stat")
                    .len(),
                4096,
                "positive control must reach the same target on disk"
            );
        }

        #[test]
        fn setxattr_and_removexattr_refused_read_only_permitted_read_write() {
            let p = pair("xattr");
            let ctx = Context::new();
            let key = cstr("user.vmcell");
            let ro_ino = ino(&p.ro, "seed.txt");
            let rw_ino = ino(&p.rw, "seed.txt");

            // The control runs FIRST, so the leg proves the facility exists before asserting the
            // refusal — an `EOPNOTSUPP` filesystem would otherwise make the negative vacuous.
            p.rw.setxattr(&ctx, rw_ino, &key, b"1", 0)
                .expect("positive control: a writable share permits setxattr");
            assert!(matches!(
                p.rw.getxattr(&ctx, rw_ino, &key, 64)
                    .expect("control: read the xattr back"),
                GetxattrReply::Value(v) if v == b"1"
            ));

            let err =
                p.ro.setxattr(&ctx, ro_ino, &key, b"1", 0)
                    .expect_err("a read-only share must refuse setxattr");
            assert_erofs(&err, "setxattr");
            assert!(
                p.ro.getxattr(&ctx, ro_ino, &key, 64).is_err(),
                "the refused setxattr must leave no attribute on disk"
            );

            let err =
                p.ro.removexattr(&ctx, ro_ino, &key)
                    .expect_err("a read-only share must refuse removexattr");
            assert_erofs(&err, "removexattr");

            p.rw.removexattr(&ctx, rw_ino, &key)
                .expect("positive control: a writable share permits removexattr");
            assert!(
                p.rw.getxattr(&ctx, rw_ino, &key, 64).is_err(),
                "positive control must reach the same target on disk"
            );
        }

        /// `ioctl` is refused as a class: the command word is opaque, so a read-only share cannot
        /// tell a getter from a setter. The control shows the refusal is ours — the writable share
        /// answers `ENOTTY` (the passthrough implements no ioctl), never `EROFS`.
        #[test]
        fn ioctl_refused_read_only_and_not_refused_read_write() {
            let p = pair("ioctl");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");
            let err =
                p.ro.ioctl(&ctx, ro_ino, 0, 0, 0, IoctlData::default(), 0)
                    .err()
                    .expect("a read-only share must refuse ioctl");
            assert_erofs(&err, "ioctl");

            let rw_ino = ino(&p.rw, "seed.txt");
            let control =
                p.rw.ioctl(&ctx, rw_ino, 0, 0, 0, IoctlData::default(), 0)
                    .err()
                    .expect("the passthrough implements no ioctl");
            assert_ne!(
                control.raw_os_error(),
                Some(libc::EROFS),
                "positive control: a writable share does not answer EROFS, so the refusal above is this wrapper's"
            );
        }

        // ---- write intent: refused exactly when the request asks for write --------------------

        /// The choke point. Every flag combination that implies write intent is refused, and
        /// `O_RDONLY` through the **same wrapper** is the positive control — so the leg cannot pass
        /// by refusing everything.
        #[test]
        fn open_refuses_write_intent_and_permits_read_only() {
            let p = pair("open");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");

            for flags in [
                libc::O_WRONLY,
                libc::O_RDWR,
                libc::O_RDONLY | libc::O_TRUNC,
                libc::O_RDONLY | libc::O_APPEND,
                libc::O_RDONLY | libc::O_CREAT,
                libc::O_WRONLY | libc::O_TRUNC,
            ] {
                let err =
                    p.ro.open(&ctx, ro_ino, flags as u32, 0)
                        .err()
                        .unwrap_or_else(|| panic!("open flags {flags:#o} must be refused"));
                assert_erofs(&err, &format!("open flags {flags:#o}"));
            }
            assert_eq!(
                std::fs::read(p.ro_dir.path().join("seed.txt")).expect("read back"),
                SEED,
                "no refused open may have truncated the file"
            );

            let (handle, ..) = p
                .ro
                .open(&ctx, ro_ino, libc::O_RDONLY as u32, 0)
                .expect("positive control: O_RDONLY through the same wrapper must be permitted");
            assert!(
                handle.is_some(),
                "the wrapper must pass a real handle through, not swallow the open"
            );
        }

        /// A read-only share is still a *working* share: the delegated read path returns the bytes
        /// on disk. Without this leg an implementation that refused everything would pass.
        #[test]
        fn read_through_the_wrapper_returns_the_bytes_on_disk() {
            let p = pair("read");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");
            let (handle, ..) =
                p.ro.open(&ctx, ro_ino, libc::O_RDONLY as u32, 0)
                    .expect("a read-only share permits O_RDONLY");
            let handle = handle.expect("a handle");
            let mut sink = CollectingWriter { data: Vec::new() };
            let n =
                p.ro.read(
                    &ctx,
                    ro_ino,
                    handle,
                    &mut sink,
                    SEED.len() as u32,
                    0,
                    None,
                    0,
                )
                .expect("a read-only share must serve reads");
            assert_eq!(n, SEED.len());
            assert_eq!(sink.data, SEED, "the wrapper must not alter the data plane");
        }

        /// `access(W_OK)` is `EROFS` on a read-only mount, and `R_OK`/`X_OK` through the same
        /// wrapper is the positive control.
        #[test]
        fn access_refuses_w_ok_and_permits_r_ok() {
            let p = pair("access");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");

            for mask in [libc::W_OK, libc::R_OK | libc::W_OK] {
                let err =
                    p.ro.access(&ctx, ro_ino, mask as u32)
                        .expect_err("access(W_OK) must be refused");
                assert_erofs(&err, "access(W_OK)");
            }
            p.ro.access(&ctx, ro_ino, libc::R_OK as u32)
                .expect("positive control: access(R_OK) through the same wrapper is permitted");
        }

        /// A **writable** DAX mapping would be a bypass around every other refusal here; a read
        /// mapping is legitimate and is delegated (the passthrough answers it on its own terms).
        #[test]
        fn setupmapping_refuses_write_mappings_and_delegates_read_mappings() {
            let p = pair("setupmapping");
            let ctx = Context::new();
            let ro_ino = ino(&p.ro, "seed.txt");
            let mut cache = RecordingFsCache { maps: 0 };

            let err =
                p.ro.setupmapping(
                    &ctx,
                    ro_ino,
                    0,
                    0,
                    4096,
                    SetupmappingFlags::WRITE.bits(),
                    0,
                    &mut cache,
                )
                .expect_err("a writable DAX mapping must be refused");
            assert_erofs(&err, "setupmapping(WRITE)");
            assert_eq!(
                cache.maps, 0,
                "the refusal must land before the DAX window is programmed"
            );

            // Positive control: a read-only mapping is NOT refused as read-only. It reaches the
            // inner filesystem, which decides on its own terms (the passthrough needs an open
            // handle), so the assertion is on the refusal *identity*, not on success.
            let control = p.ro.setupmapping(
                &ctx,
                ro_ino,
                0,
                0,
                4096,
                SetupmappingFlags::READ.bits(),
                0,
                &mut cache,
            );
            assert_ne!(
                control.err().and_then(|e| e.raw_os_error()),
                Some(libc::EROFS),
                "a read mapping must be delegated, not refused as read-only"
            );
        }

        // ---- the predicates themselves, including their inverses -----------------------------

        #[test]
        fn open_flag_predicate_separates_write_intent_from_read() {
            assert!(!open_flags_imply_write(libc::O_RDONLY as u32));
            assert!(!open_flags_imply_write(
                (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u32
            ));
            for flags in [
                libc::O_WRONLY,
                libc::O_RDWR,
                libc::O_RDONLY | libc::O_TRUNC,
                libc::O_RDONLY | libc::O_APPEND,
                libc::O_RDONLY | libc::O_CREAT,
            ] {
                assert!(
                    open_flags_imply_write(flags as u32),
                    "flags {flags:#o} imply write"
                );
            }
        }

        #[test]
        fn access_and_setupmapping_predicates_separate_write_intent() {
            assert!(access_mask_implies_write(libc::W_OK as u32));
            assert!(access_mask_implies_write((libc::R_OK | libc::W_OK) as u32));
            assert!(!access_mask_implies_write(libc::R_OK as u32));
            assert!(!access_mask_implies_write(libc::F_OK as u32));

            assert!(setupmapping_flags_imply_write(
                SetupmappingFlags::WRITE.bits()
            ));
            assert!(setupmapping_flags_imply_write(
                (SetupmappingFlags::WRITE | SetupmappingFlags::READ).bits()
            ));
            assert!(!setupmapping_flags_imply_write(
                SetupmappingFlags::READ.bits()
            ));
            assert!(!setupmapping_flags_imply_write(0));
        }

        /// `vfs_options`' read-only arm. `no_open`/`no_opendir` staying `false` is the precondition
        /// every write-intent refusal rests on — `true` hands opens to the guest kernel via
        /// `ZERO_MESSAGE_OPEN` and `ReadOnlyFs::open` never runs — and the `VfsOptions` defaults
        /// are `true`, so this is an inversion that must not regress silently.
        #[test]
        fn vfs_options_keep_open_reaching_the_wrapper() {
            for read_only in [false, true] {
                let opts = vfs_options(read_only);
                assert!(
                    !opts.no_open,
                    "no_open must stay false or the write-intent check is bypassed"
                );
                assert!(
                    !opts.no_opendir,
                    "no_opendir must stay false for the same reason"
                );
            }
            assert!(
                vfs_options(true).no_writeback,
                "a read-only share drops WRITEBACK_CACHE: there is nothing to write back"
            );
            assert!(
                !vfs_options(false).no_writeback,
                "the read-write path keeps exactly the options it had before"
            );
        }

        /// The disposition law answers every question the wrapper asks of it, and the four classes
        /// are actually distinguished — a classifier that collapsed to one class would pass a
        /// per-opcode spot check but not this.
        #[test]
        fn read_only_disposition_distinguishes_all_four_classes() {
            assert_eq!(read_only_disposition(Opcode::Write), OpKind::Mutating);
            assert_eq!(read_only_disposition(Opcode::Rename2), OpKind::Mutating);
            assert_eq!(read_only_disposition(Opcode::Open), OpKind::WriteIntent);
            assert_eq!(read_only_disposition(Opcode::Read), OpKind::ReadOnly);
            assert_eq!(read_only_disposition(Opcode::Setlk), OpKind::ReadOnly);
            assert_eq!(
                read_only_disposition(Opcode::CopyFileRange),
                OpKind::NotDispatched
            );
        }

        /// `EROFS` is the errno, not "some error": a guest that gets `ENOSYS` back treats the
        /// operation as unimplemented and may retry differently, and one that gets `EPERM` reports
        /// a permission problem the share does not have.
        #[test]
        fn the_refusal_is_erofs_and_names_its_opcode() {
            let err = refuse_read_only(Opcode::Mkdir);
            assert_eq!(err.raw_os_error(), Some(libc::EROFS));
        }
    }

    /// The completeness gate for §4.5 read-only enforcement.
    ///
    /// Two halves, neither of which the other can cover:
    ///
    /// * **The compiler** holds the roster. [`read_only_disposition`] is an exhaustive `match` over
    ///   `fuse-backend-rs`'s `Opcode` with **no wildcard arm**, so a dependency bump that adds an
    ///   opcode fails to compile until somebody classifies it. That is what makes the enumeration
    ///   the assignment demands structural rather than remembered.
    /// * **This scan** holds the wiring. Classifying an opcode `Mutating`/`WriteIntent` and then
    ///   forgetting the method that refuses it is *not* a compile error — the `FileSystem` trait
    ///   supplies a default for every method — so the scan reads both halves back out of this
    ///   file's own source and requires them to be the same set: every opcode the law calls
    ///   mutating is cited at a `refuse_read_only(Opcode::…)` call site, and no opcode the law
    ///   calls read-only is.
    ///
    /// Vacuity: both scanned sets must be **non-empty**. A scan that matched nothing — a rename, a
    /// normalizer that ate the file, a marker that moved — is a *misconfigured gate*, never a pass,
    /// because two empty sets are trivially equal. [`the_scanner_reports_nothing_on_empty_source`]
    /// is the leg that proves that arm reachable.
    #[cfg(test)]
    mod read_only_completeness_gate {
        use std::collections::BTreeSet;

        /// This file's own source text. `include_str!` resolves relative to this file's directory,
        /// so a rename or a move is a compile error here rather than a silently empty scan.
        const SOURCE: &str = include_str!("in_process.rs");

        /// The law's declaration, as the scanner finds it.
        const LAW: &str = "const fn read_only_disposition";

        /// The one refusal helper every refusing method routes through.
        const REFUSAL: &str = "refuse_read_only(Opcode::";

        /// `source`'s production text: everything before its first test module, comments dropped
        /// and whitespace collapsed.
        ///
        /// Dropping comments keeps prose that *names* an opcode from scanning as a call site;
        /// collapsing whitespace keeps a rustfmt line break from hiding half of one.
        fn production_code(source: &str) -> String {
            let cut = ["#[cfg(test)]", "#[cfg(all(test"]
                .iter()
                .filter_map(|marker| source.find(marker))
                .min()
                .unwrap_or(source.len());
            source[..cut]
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with("//"))
                .collect::<Vec<_>>()
                .join(" ")
        }

        /// The body of [`LAW`] within `code`, from its declaration to the `match`'s and the
        /// function's closing braces.
        fn law_body(code: &str) -> &str {
            let Some(start) = code.find(LAW) else {
                return "";
            };
            let tail = &code[start..];
            match tail.find("} }") {
                Some(end) => &tail[..end],
                None => tail,
            }
        }

        /// Every `Opcode::X` named in `text`.
        fn opcode_names(text: &str) -> Vec<&str> {
            const NEEDLE: &str = "Opcode::";
            text.match_indices(NEEDLE)
                .map(|(at, _)| {
                    let tail = &text[at + NEEDLE.len()..];
                    let end = tail
                        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .unwrap_or(tail.len());
                    &tail[..end]
                })
                .collect()
        }

        /// The opcodes [`LAW`] maps to `OpKind::<kind>`, read out of its match arms.
        ///
        /// The arms are split on the `=> OpKind::` that ends each pattern list, so arm `j`'s
        /// patterns are what precedes separator `j` (minus the previous arm's result token).
        fn classified_as<'a>(law: &'a str, kind: &str) -> BTreeSet<&'a str> {
            const SEP: &str = "=> OpKind::";
            let parts: Vec<&str> = law.split(SEP).collect();
            let mut out = BTreeSet::new();
            for j in 0..parts.len().saturating_sub(1) {
                let next = parts[j + 1];
                let result = &next[..next
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(next.len())];
                if result != kind {
                    continue;
                }
                let patterns = if j == 0 {
                    parts[0]
                } else {
                    // Drop the previous arm's `OpKind::<Result>,` prefix.
                    match parts[j].find(',') {
                        Some(comma) => &parts[j][comma + 1..],
                        None => "",
                    }
                };
                out.extend(opcode_names(patterns));
            }
            out
        }

        /// Every opcode cited at a [`REFUSAL`] call site in `code`.
        fn refused_opcodes(code: &str) -> BTreeSet<&str> {
            code.match_indices(REFUSAL)
                .map(|(at, _)| {
                    let tail = &code[at + REFUSAL.len()..];
                    let end = tail
                        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .unwrap_or(tail.len());
                    &tail[..end]
                })
                .collect()
        }

        /// The law, as a predicate over two scanned rosters: the opcodes classified as mutating are
        /// exactly the opcodes refused, and neither roster is empty.
        fn enforcement_matches_classification(
            classified: &BTreeSet<&str>,
            refused: &BTreeSet<&str>,
        ) -> bool {
            !classified.is_empty() && !refused.is_empty() && classified == refused
        }

        #[test]
        fn every_mutating_opcode_has_a_refusal_and_no_read_only_opcode_does() {
            let code = production_code(SOURCE);
            let law = law_body(&code);
            let mut classified = classified_as(law, "Mutating");
            classified.extend(classified_as(law, "WriteIntent"));
            let refused = refused_opcodes(&code);

            assert!(
                !classified.is_empty(),
                "gate misconfigured: scanned zero mutating opcodes out of `{LAW}`. The law was \
                 renamed, moved, or the normalizer ate it — an empty scan is never a pass."
            );
            assert!(
                !refused.is_empty(),
                "gate misconfigured: scanned zero `{REFUSAL}…)` call sites. Either the refusal \
                 helper was renamed or every refusal is gone."
            );
            assert!(
                enforcement_matches_classification(&classified, &refused),
                "§4.5: the opcodes `read_only_disposition` classifies Mutating/WriteIntent must be \
                 exactly the opcodes refused via `{REFUSAL}…)`.\n  classified only: {:?}\n  \
                 refused only: {:?}\nA classified-but-unrefused opcode is a HOLE: the `FileSystem` \
                 trait supplies a default for every method, so forgetting one is not a compile \
                 error. A refused-but-unclassified opcode means the law and the code disagree \
                 about what mutates.",
                classified.difference(&refused).collect::<Vec<_>>(),
                refused.difference(&classified).collect::<Vec<_>>(),
            );

            // Non-vacuity beyond emptiness: the read-only class must be populated too, or a law
            // that called EVERYTHING mutating would satisfy the equality above.
            let read_only = classified_as(law, "ReadOnly");
            assert!(
                read_only.len() > classified.len(),
                "gate misconfigured or the law collapsed: {} read-only vs {} mutating opcodes — a \
                 classifier that refuses everything is not enforcement, it is a broken share",
                read_only.len(),
                classified.len()
            );
        }

        /// The gate's red-on-inverse, on synthetic sources so it fails for the reason it names.
        #[test]
        fn the_predicate_rejects_a_hole_a_stray_refusal_and_an_empty_scan() {
            let mutating: BTreeSet<&str> = ["Mkdir", "Write"].into_iter().collect();

            // The defect this gate exists for: classified mutating, no refusing method.
            let hole: BTreeSet<&str> = ["Mkdir"].into_iter().collect();
            assert!(!enforcement_matches_classification(&mutating, &hole));

            // The opposite drift: a refusal for something the law calls read-only.
            let stray: BTreeSet<&str> = ["Mkdir", "Write", "Read"].into_iter().collect();
            assert!(!enforcement_matches_classification(&mutating, &stray));

            // Two empty sets are equal; the vacuity guard is what makes that a failure.
            assert!(!enforcement_matches_classification(
                &BTreeSet::new(),
                &BTreeSet::new()
            ));
            assert!(!enforcement_matches_classification(
                &mutating,
                &BTreeSet::new()
            ));

            // And the shape that must pass.
            assert!(enforcement_matches_classification(&mutating, &mutating));
        }

        /// The scanner reads code, not prose, and reads arms whole across rustfmt line breaks.
        /// Goes red if the normalizer stops stripping comments — this file's own commentary names
        /// several opcodes.
        #[test]
        fn the_scanner_reads_arms_and_call_sites_not_prose() {
            let synthetic = "\
                // Opcode::Mknod is named in a comment and must NOT scan.\n\
                const fn read_only_disposition(op: Opcode) -> OpKind {\n\
                    match op {\n\
                        Opcode::Mkdir\n\
                        | Opcode::Write => OpKind::Mutating,\n\
                        Opcode::Open => OpKind::WriteIntent,\n\
                        Opcode::Read => OpKind::ReadOnly,\n\
                        Opcode::Interrupt => OpKind::NotDispatched,\n\
                    }\n\
                }\n\
                fn a() { Err(refuse_read_only(Opcode::Mkdir)) }\n\
                fn b() { Err(refuse_read_only(Opcode::Write)) }\n\
                fn c() { Err(refuse_read_only(Opcode::Open)) }\n\
                #[cfg(test)]\n\
                mod t { fn x() { refuse_read_only(Opcode::Read); } }\n";
            let code = production_code(synthetic);
            let law = law_body(&code);

            let mut classified = classified_as(law, "Mutating");
            classified.extend(classified_as(law, "WriteIntent"));
            assert_eq!(
                classified.iter().copied().collect::<Vec<_>>(),
                ["Mkdir", "Open", "Write"],
                "the multi-line arm and the single-line arm must both be read whole"
            );
            assert_eq!(
                classified_as(law, "ReadOnly")
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
                ["Read"],
                "the comment naming Opcode::Mknod must not scan, and arm boundaries must hold"
            );
            assert_eq!(
                classified_as(law, "NotDispatched")
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
                ["Interrupt"]
            );
            assert_eq!(
                refused_opcodes(&code).iter().copied().collect::<Vec<_>>(),
                ["Mkdir", "Open", "Write"],
                "the refusal inside the test module must be cut away with it"
            );
            assert!(enforcement_matches_classification(
                &classified,
                &refused_opcodes(&code)
            ));
        }

        /// The zero-file leg, stated rather than implied: an empty source yields empty rosters,
        /// which is why the non-empty assertions above are what make a misconfigured gate red
        /// instead of green.
        #[test]
        fn the_scanner_reports_nothing_on_empty_source() {
            assert!(law_body(&production_code("")).is_empty());
            assert!(classified_as(law_body(&production_code("")), "Mutating").is_empty());
            assert!(refused_opcodes(&production_code("")).is_empty());
            // A file that is nothing BUT tests scans as empty production code, too.
            let all_tests = "#[cfg(test)] mod t { fn x() { refuse_read_only(Opcode::Mkdir); } }";
            assert!(refused_opcodes(&production_code(all_tests)).is_empty());
            assert!(!enforcement_matches_classification(
                &classified_as(law_body(&production_code(all_tests)), "Mutating"),
                &refused_opcodes(&production_code(all_tests))
            ));
        }
    }
}
