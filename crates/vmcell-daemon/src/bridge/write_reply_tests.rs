//! KVM-free gates for the reply-write fallback (M8, `bridge-reply-drop-wedges-request`): a broker
//! reply that cannot be sent as-is must reach the parent as a typed `Err` frame for the same id, so
//! the HTTP request fails with a 500 instead of hanging on a `rx.await` that has no timeout.
//!
//! Its own module (beside [`super::tests`], the round-trip/multiplex/codec battery) because the
//! end-to-end leg needs a fake engine whose `exec` reply deliberately overflows
//! [`MAX_BRIDGE_FRAME_BYTES`].

use super::*;
use crate::dto::{CreateVmRequest, ExecRequestDto, VmInfo, VmState};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A fake engine whose `exec` reply is deliberately over the frame cap — the reachable production
/// shape (an `exec` reply carries the guest command's whole captured stdout/stderr, base64'd).
/// Every other op is a minimal stub; `super::tests::FakeEngine` covers the round-trip surface.
struct OverCapEngine;

/// The captured-output payload that pushes the framed reply over the cap. Exactly
/// [`MAX_BRIDGE_FRAME_BYTES`] of base64 already exceeds it once the JSON envelope is added, so this
/// is the smallest payload the real constant admits — it costs ~0.5 GiB transiently (the string plus
/// its serialization), which is the price of gating against the shipped cap rather than a test-only
/// one.
fn over_cap_stdout_b64() -> String {
    "A".repeat(MAX_BRIDGE_FRAME_BYTES)
}

fn vminfo() -> VmInfo {
    VmInfo {
        id: VmId("vm-1".to_string()),
        state: VmState::Ready,
        vmid: 7,
        kernel: "vmlinux".to_string(),
        rootfs: "rootfs.erofs".to_string(),
        vcpus: 1,
        mem_mib: 128,
    }
}

#[async_trait]
impl VmEngine for OverCapEngine {
    async fn create(&self, _req: CreateVmRequest) -> DaemonResult<CreateVmResponse> {
        Ok(CreateVmResponse {
            vm: vminfo(),
            exec: None,
        })
    }
    async fn list(&self) -> DaemonResult<Vec<VmInfo>> {
        Ok(vec![vminfo()])
    }
    async fn get(&self, _id: &VmId) -> DaemonResult<VmInfo> {
        Ok(vminfo())
    }
    async fn exec(&self, _id: &VmId, _req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        Ok(ExecOutcomeDto {
            code: 0,
            stdout_b64: over_cap_stdout_b64(),
            stderr_b64: String::new(),
        })
    }
    async fn stats(&self, _id: &VmId) -> DaemonResult<ResourceUsageDto> {
        Err(DaemonError::Unsupported("stats".to_string()))
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
    async fn shutdown_all(&self) {}
}

/// A writer that fails its first write and buffers everything after it — the "the reply frame could
/// not be written" shape, without materializing a half-gigabyte payload. The fallback frame is a
/// *second* `write_frame` call, so it lands in `buf`.
#[derive(Default)]
struct FailFirstWriter {
    failed_once: bool,
    buf: Vec<u8>,
}

impl tokio::io::AsyncWrite for FailFirstWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.failed_once {
            self.failed_once = true;
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "peer gone",
            )));
        }
        self.buf.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Decodes the single length-prefixed frame in `buf`.
fn decode_one_frame(buf: &[u8]) -> (u64, EngineReply) {
    assert!(buf.len() > 4, "expected one framed reply, got {buf:?}");
    let (len_buf, body) = buf.split_at(4);
    let len = u32::from_be_bytes(len_buf.try_into().expect("4-byte length prefix")) as usize;
    assert_eq!(len, body.len(), "the length prefix must match the payload");
    serde_json::from_slice(body).expect("a decodable (id, reply) frame")
}

// Guards M8 (`bridge-reply-drop-wedges-request`) end to end: an `exec` whose reply exceeds
// `MAX_BRIDGE_FRAME_BYTES` must surface as a typed `DaemonError::Internal` on the parent, not hang.
// Inverse (the shipped bug): `let _ = write_frame(...)` drops the over-cap error, the reply never
// arrives, and the `rx.await` inside `call` never resolves — the timeout below reddens.
#[tokio::test]
async fn over_cap_exec_reply_surfaces_internal_instead_of_hanging() {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let engine: Arc<dyn VmEngine> = Arc::new(OverCapEngine);
    tokio::spawn(serve_engine(engine, broker_sock));
    let client = BrokerClientEngine::new(client_sock);

    let err = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.exec(
            &VmId("vm-1".into()),
            ExecRequestDto::new(vec!["/bin/cat".into(), "/dev/urandom".into()]),
        ),
    )
    .await
    .expect("an unsendable reply must not hang the request (M8)")
    .expect_err("an over-cap reply must surface as an error");

    assert_eq!(
        err.kind().status_code(),
        500,
        "an unsendable reply is an internal error: {}",
        err.message()
    );
    assert!(
        err.message().contains("exceeds cap"),
        "the fallback must name the frame-cap cause, got: {}",
        err.message()
    );
}

// Guards the fallback itself (M8): when the reply frame cannot be written, a compact typed `Err`
// frame for the SAME id is written in its place. Inverse: the dropped-reply code writes nothing and
// the buffer stays empty.
#[tokio::test]
async fn unwritable_reply_is_replaced_by_a_typed_error_frame_for_the_same_id() {
    let wr = Mutex::new(FailFirstWriter::default());
    write_reply(&wr, 4242, EngineReply::Destroyed).await;

    let buf = wr.into_inner().buf;
    let (id, reply) = decode_one_frame(&buf);
    assert_eq!(id, 4242, "the fallback must carry the ORIGINAL request id");
    match reply {
        EngineReply::Err(w) => {
            assert_eq!(w.kind, ErrorKind::Internal);
            assert!(
                w.message.contains("could not be written"),
                "the fallback names the cause: {}",
                w.message
            );
        }
        other => panic!("expected a typed Err fallback, got {other:?}"),
    }
}

// Guards the trigger the fallback exists for: `write_frame` rejects an over-cap payload BEFORE
// writing (the mirror of `read_frame`'s pre-allocation reject). The buffer is never touched, so this
// costs a lazily-zeroed mapping, not 256 MiB of resident memory.
#[tokio::test]
async fn write_frame_rejects_an_over_cap_payload() {
    let payload = vec![0u8; MAX_BRIDGE_FRAME_BYTES + 1];
    let mut sink: Vec<u8> = Vec::new();
    let err = write_frame(&mut sink, &payload)
        .await
        .expect_err("an over-cap payload must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        sink.is_empty(),
        "nothing may be written for a rejected frame"
    );
}
