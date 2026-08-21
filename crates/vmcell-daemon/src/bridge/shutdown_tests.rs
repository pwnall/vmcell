//! KVM-free gates for the bridge's **liveness** contract — the three ways a forwarded request or a
//! forwarded VM could otherwise be lost:
//!
//! - `shutdown_all_waits_for_the_in_flight_dispatch_jobs` — a `ShutdownAll` that returns while a
//!   `create` is still between `launch` and the registry insert orphans that VMM on the *graceful*
//!   path (finding `shutdown-all-returns-while-dispatch-jobs-run`).
//! - `broker_death_fails_in_flight_requests_rather_than_hanging` — the EOF drain in
//!   [`BrokerClientEngine::new`] is the only thing that resolves a pending `oneshot` when the broker
//!   dies; deleting it hangs every in-flight HTTP request forever, and nothing tested it.
//! - `a_stalled_broker_call_is_bounded_by_its_deadline` — the drain cannot see a broker that is
//!   alive and simply never answers; the per-call deadline can.
//! - `an_undecodable_request_is_answered_with_a_typed_error_frame` — the request-side mirror of the
//!   reply-side fallback: replying *nothing* wedges the id the parent is waiting on.

use super::*;
use crate::dto::{CreateVmRequest, ExecRequestDto, VmInfo, VmState};
use std::sync::atomic::AtomicUsize;

/// The sentinel `created_at_shutdown` holds until `shutdown_all` runs.
const NEVER_RAN: usize = usize::MAX;

/// A fake engine with no KVM whose `create` takes `create_delay` to complete and records itself,
/// and whose `shutdown_all` records **how many creates had completed when it ran** — the exact
/// ordering M4 is about.
struct ProbeEngine {
    create_delay: std::time::Duration,
    /// Fires when a `create` starts, so a test can send its next frame knowing the dispatch job is
    /// genuinely in flight (a `tokio::test` runs on one thread — spawning is not running).
    create_entered: tokio::sync::Notify,
    created: AtomicUsize,
    created_at_shutdown: AtomicUsize,
}

impl ProbeEngine {
    fn new(create_delay: std::time::Duration) -> Self {
        Self {
            create_delay,
            create_entered: tokio::sync::Notify::new(),
            created: AtomicUsize::new(0),
            created_at_shutdown: AtomicUsize::new(NEVER_RAN),
        }
    }
}

fn vminfo(id: &str) -> VmInfo {
    VmInfo {
        id: VmId(id.to_string()),
        state: VmState::Ready,
        vmid: 7,
        kernel: "vmlinux".to_string(),
        rootfs: "rootfs.erofs".to_string(),
        vcpus: 1,
        mem_mib: 128,
    }
}

#[async_trait]
impl VmEngine for ProbeEngine {
    async fn create(&self, _req: CreateVmRequest) -> DaemonResult<CreateVmResponse> {
        // Stands in for `MicroVmLauncher::launch` → `MicroVm::start`: the VM exists (its VMM is
        // running) only once this returns and the registry has inserted it.
        self.create_entered.notify_one();
        tokio::time::sleep(self.create_delay).await;
        self.created.fetch_add(1, Ordering::SeqCst);
        Ok(CreateVmResponse {
            vm: vminfo("vm-1"),
            exec: None,
        })
    }
    async fn list(&self) -> DaemonResult<Vec<VmInfo>> {
        Ok(vec![vminfo("vm-1")])
    }
    async fn get(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Ok(vminfo(&id.0))
    }
    async fn exec(&self, _id: &VmId, _req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        Ok(ExecOutcomeDto::from_bytes(0, b"", b""))
    }
    async fn stats(&self, _id: &VmId) -> DaemonResult<ResourceUsageDto> {
        Err(DaemonError::Unsupported("stats".to_string()))
    }
    async fn pause(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Ok(vminfo(&id.0))
    }
    async fn resume(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Ok(vminfo(&id.0))
    }
    async fn snapshot(&self, _id: &VmId, _prefix: &str) -> DaemonResult<SnapshotInfo> {
        Err(DaemonError::Unsupported("snapshot".to_string()))
    }
    async fn destroy(&self, _id: &VmId) -> DaemonResult<()> {
        Ok(())
    }
    async fn is_artifact_in_use(&self, _name: &str) -> DaemonResult<bool> {
        Ok(false)
    }
    async fn delete_artifact_if_unused(&self, _name: &str) -> DaemonResult<()> {
        Ok(())
    }
    async fn shutdown_all(&self) {
        self.created_at_shutdown
            .store(self.created.load(Ordering::SeqCst), Ordering::SeqCst);
    }
}

// M4 (`shutdown-all-returns-while-dispatch-jobs-run`): a `ShutdownAll` that arrives while a `create`
// is in flight must not run the teardown until that create has completed — otherwise the VM it just
// booted is in no table when `shutdown_all` walks it and the broker `_exit`s, leaving an orphaned
// VMM. Asserted on the ORDER (`created_at_shutdown == 1`), and on the create still getting its
// reply. RED on the inverse (`tokio::spawn(job)` with no drain before the shutdown arm):
// `shutdown_all` runs immediately and records 0.
#[tokio::test]
async fn shutdown_all_waits_for_the_in_flight_dispatch_jobs() {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let probe = Arc::new(ProbeEngine::new(std::time::Duration::from_millis(300)));
    let engine: Arc<dyn VmEngine> = probe.clone();
    let served = tokio::spawn(serve_engine(engine, broker_sock));
    let client = BrokerClientEngine::new(client_sock);

    let creating = {
        let c = client.clone();
        tokio::spawn(async move {
            c.create(CreateVmRequest::create("vmlinux", "rootfs.erofs"))
                .await
        })
    };
    // Wait until the broker has actually DISPATCHED the create (not merely until the task was
    // spawned), then ask for the graceful shutdown: the 300 ms create is provably still running
    // when the ShutdownAll frame is read.
    probe.create_entered.notified().await;
    client.shutdown_all().await;
    served
        .await
        .expect("serve_engine returns after ShutdownAll");

    let created = creating
        .await
        .expect("join")
        .expect("the in-flight create still receives its reply");
    assert_eq!(created.vm.id.0, "vm-1");
    assert_eq!(
        probe.created.load(Ordering::SeqCst),
        1,
        "the create must have completed"
    );
    assert_eq!(
        probe.created_at_shutdown.load(Ordering::SeqCst),
        1,
        "shutdown_all must run AFTER the in-flight create registered its VM, or that VMM is an \
         orphan on the graceful path"
    );
}

// M12: the reader task's post-loop drain is the ONLY thing that resolves a pending `oneshot` when
// the broker dies. Without it `rx.await` never completes and every in-flight HTTP request hangs
// forever. RED on deleting the drain loop: the 5 s wall-clock guard fires instead of the typed
// error (the per-call deadline is minutes, so it does not mask this).
#[tokio::test]
async fn broker_death_fails_in_flight_requests_rather_than_hanging() {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let client = BrokerClientEngine::new(client_sock);
    // A "broker" that accepts the request and then dies without replying. It reads the frame first,
    // so the parent's pending entry is guaranteed to be registered before the EOF.
    tokio::spawn(async move {
        let (mut rd, _wr) = broker_sock.into_split();
        read_frame(&mut rd).await.expect("the request frame");
        // Both halves drop here => EOF on the parent's reply reader.
    });

    let err = tokio::time::timeout(std::time::Duration::from_secs(5), client.list())
        .await
        .expect("a dead broker must FAIL the in-flight request, not hang it")
        .expect_err("a dead broker cannot answer");
    assert_eq!(err.kind().status_code(), 500, "{}", err.message());
    assert!(
        err.message().contains("broker connection closed"),
        "the EOF drain's typed error must reach the caller, got: {}",
        err.message()
    );
    assert!(
        client
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "the drain must clear the multiplex table"
    );
}

// M12 (second half): a broker that is ALIVE but never replies is invisible to the EOF drain — the
// socket stays open forever. The per-call deadline bounds it. RED on the inverse (a bare `rx.await`
// with no `timeout_at`): the 5 s guard fires instead of the typed timeout error.
#[tokio::test]
async fn a_stalled_broker_call_is_bounded_by_its_deadline() {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    // Held, never read from, never replied to: a stalled broker, not a dead one.
    let _broker = broker_sock;
    let client = BrokerClientEngine::with_call_budget(
        client_sock,
        Some(std::time::Duration::from_millis(100)),
    );

    let start = std::time::Instant::now();
    let err = tokio::time::timeout(std::time::Duration::from_secs(5), client.list())
        .await
        .expect("a stalled broker must not hang the request forever")
        .expect_err("a stalled call must surface a typed error");
    assert_eq!(err.kind().status_code(), 500, "{}", err.message());
    assert!(
        err.message().contains("timed out"),
        "the error must name the stall: {}",
        err.message()
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "the CALL's deadline must end it, not the test's outer guard (took {:?})",
        start.elapsed()
    );
    assert!(
        client
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "a timed-out call must not leak its pending entry"
    );
}

// m33: an undecodable REQUEST frame is answered with a typed `Err` for its id — the mirror of the
// reply-side fallback. Dropping it silently wedges the parent's `call` for that id until its
// deadline. RED on the inverse (`continue` without replying): the read below times out.
#[tokio::test]
async fn an_undecodable_request_is_answered_with_a_typed_error_frame() {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let engine: Arc<dyn VmEngine> = Arc::new(ProbeEngine::new(std::time::Duration::from_millis(0)));
    tokio::spawn(serve_engine(engine, broker_sock));
    let (mut rd, mut wr) = client_sock.into_split();

    // Well-framed, correctly length-prefixed, but not an `EngineRequest`.
    let bogus = serde_json::to_vec(&(77u64, serde_json::json!({ "NoSuchOp": null })))
        .expect("encode the bogus request");
    write_frame(&mut wr, &bogus).await.expect("write");

    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), read_frame(&mut rd))
        .await
        .expect("the broker must ANSWER an undecodable request, not drop it")
        .expect("a reply frame");
    let (id, reply): (u64, EngineReply) = serde_json::from_slice(&frame).expect("decode the reply");
    assert_eq!(id, 77, "the typed error must carry the request's id");
    match reply {
        EngineReply::Err(w) => {
            assert_eq!(w.kind, ErrorKind::Internal);
            assert!(
                w.message.contains("decode"),
                "the error must name the cause: {}",
                w.message
            );
        }
        other => panic!("expected a typed Err reply, got {other:?}"),
    }

    // Positive control: the broker keeps serving — a well-formed request still round-trips.
    let good = serde_json::to_vec(&(78u64, EngineRequest::List)).expect("encode List");
    write_frame(&mut wr, &good).await.expect("write");
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), read_frame(&mut rd))
        .await
        .expect("the broker keeps serving")
        .expect("a reply frame");
    let (id, reply): (u64, EngineReply) = serde_json::from_slice(&frame).expect("decode the reply");
    assert_eq!(id, 78);
    assert!(
        matches!(reply, EngineReply::List(_)),
        "the good request must be served normally"
    );
}
