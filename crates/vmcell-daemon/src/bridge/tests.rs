//! KVM-free gates for the setup-broker bridge (design §12.4, Layer 3 — the setup broker (network
//! surface never holds caps); v27 §20.5 / §12.23): the `VmEngine` RPC
//! round-trips over a real socketpair, errors preserve their HTTP status across the boundary, the
//! multiplex serves concurrent requests, and the framed codec rejects an over-cap length.

use super::*;
use crate::dto::{CreateVmRequest, ExecRequestDto, VmInfo, VmState};

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

/// A fake engine with no KVM. `slow_get` sleeps so a concurrency test can prove the multiplex; a
/// `get` of `"nope"` returns a typed `NotFound` so the error path round-trips.
struct FakeEngine {
    slow_get_ms: u64,
}

#[async_trait]
impl VmEngine for FakeEngine {
    async fn create(&self, _req: CreateVmRequest) -> DaemonResult<CreateVmResponse> {
        Ok(CreateVmResponse {
            vm: vminfo("vm-1"),
            exec: None,
        })
    }
    async fn list(&self) -> DaemonResult<Vec<VmInfo>> {
        Ok(vec![vminfo("vm-1"), vminfo("vm-2")])
    }
    async fn get(&self, id: &VmId) -> DaemonResult<VmInfo> {
        if self.slow_get_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.slow_get_ms)).await;
        }
        if id.0 == "nope" {
            Err(DaemonError::NotFound(format!("no vm {}", id.0)))
        } else {
            Ok(vminfo(&id.0))
        }
    }
    async fn exec(&self, _id: &VmId, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        Ok(ExecOutcomeDto::from_bytes(
            0,
            req.argv.join(" ").as_bytes(),
            b"",
        ))
    }
    async fn stats(&self, _id: &VmId) -> DaemonResult<ResourceUsageDto> {
        Ok(ResourceUsageDto {
            mem_peak_mib: 1,
            mem_current_mib: 1,
            cpu_usec: 1,
            io_read_bytes: 0,
            io_write_bytes: 0,
            mem_limit_enforced: true,
            mem_read_ok: true,
            cpu_read_ok: true,
            io_read_ok: true,
        })
    }
    async fn snapshot(&self, _id: &VmId, prefix: &str) -> DaemonResult<SnapshotInfo> {
        Ok(SnapshotInfo {
            artifact_prefix: prefix.to_string(),
            files: vec!["config.json".to_string()],
        })
    }
    async fn destroy(&self, _id: &VmId) -> DaemonResult<()> {
        Ok(())
    }
    async fn is_artifact_in_use(&self, name: &str) -> DaemonResult<bool> {
        Ok(name == "pinned")
    }
    async fn delete_artifact_if_unused(&self, name: &str) -> DaemonResult<()> {
        if name == "pinned" {
            Err(DaemonError::InUse(format!(
                "artifact {name:?} is pinned by a live VM; destroy the VM first"
            )))
        } else {
            Ok(())
        }
    }
    async fn shutdown_all(&self) {}
}

fn serve_fake(slow_get_ms: u64) -> BrokerClientEngine {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let engine: Arc<dyn VmEngine> = Arc::new(FakeEngine { slow_get_ms });
    tokio::spawn(serve_engine(engine, broker_sock));
    // `BrokerClientEngine::new` spawns the reply reader — must be inside a runtime (we are).
    Arc::try_unwrap(BrokerClientEngine::new(client_sock))
        .map_err(|_| ())
        .expect("sole owner")
}

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)): every op forwards to the broker and its reply round-trips over the real
// socketpair. Inverse: a codec / reply-matching bug reddens on the wrong value or a hang.
#[tokio::test]
async fn engine_rpc_round_trips_every_op() {
    let client = serve_fake(0);

    let created = client
        .create(CreateVmRequest::create("vmlinux", "rootfs.erofs"))
        .await
        .expect("create");
    assert_eq!(created.vm.id.0, "vm-1");

    assert_eq!(client.list().await.expect("list").len(), 2);
    assert_eq!(
        client.get(&VmId("vm-9".into())).await.expect("get").id.0,
        "vm-9"
    );

    let out = client
        .exec(
            &VmId("vm-1".into()),
            ExecRequestDto::new(vec!["echo".into(), "hi".into()]),
        )
        .await
        .expect("exec");
    assert_eq!(out.stdout().expect("decode"), b"echo hi");

    assert!(
        client
            .stats(&VmId("vm-1".into()))
            .await
            .expect("stats")
            .mem_limit_enforced
    );
    assert_eq!(
        client
            .snapshot(&VmId("vm-1".into()), "snap1")
            .await
            .expect("snapshot")
            .artifact_prefix,
        "snap1"
    );
    client.destroy(&VmId("vm-1".into())).await.expect("destroy");

    assert!(client.is_artifact_in_use("pinned").await.expect("in-use"));
    assert!(
        !client
            .is_artifact_in_use("other")
            .await
            .expect("not-in-use")
    );

    // The atomic delete-in-use guard round-trips too: an unpinned artifact deletes (Ok →
    // `ArtifactDeleted`), and a pinned one refuses with its 409 status intact across the boundary.
    client
        .delete_artifact_if_unused("other")
        .await
        .expect("unpinned delete");
    let pinned = client
        .delete_artifact_if_unused("pinned")
        .await
        .expect_err("a pinned artifact must refuse deletion");
    assert_eq!(
        pinned.kind().status_code(),
        409,
        "InUse must survive the boundary as a 409"
    );
}

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)): a typed error crosses the boundary with its HTTP status intact (a `NotFound`
// stays a 404 with its message), so the parent maps it to the correct HTTP response. Inverse: a
// WireError that dropped the kind would surface as a 500.
#[tokio::test]
async fn error_round_trips_with_status_and_message() {
    let client = serve_fake(0);
    let err = client
        .get(&VmId("nope".into()))
        .await
        .expect_err("a missing vm must error");
    assert_eq!(
        err.kind().status_code(),
        404,
        "NotFound status must survive the boundary"
    );
    assert!(
        err.message().contains("no vm nope"),
        "message must survive: {}",
        err.message()
    );
}

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)) (the multiplex): a slow op does NOT block a fast one — a `get` that sleeps 300 ms
// runs concurrently with a `list` that must return promptly. Inverse: a single-Mutex channel would
// serialize them and the fast `list` would wait behind the slow `get`.
#[tokio::test]
async fn concurrent_requests_are_multiplexed_not_serialized() {
    let client = Arc::new(serve_fake(300));
    let c1 = client.clone();
    let slow = tokio::spawn(async move { c1.get(&VmId("slow".into())).await });

    // The fast list must complete well before the 300 ms slow get, proving they are in flight
    // together rather than serialized on one channel.
    let start = std::time::Instant::now();
    let list = client.list().await.expect("list");
    let elapsed = start.elapsed();
    assert_eq!(list.len(), 2);
    assert!(
        elapsed < std::time::Duration::from_millis(200),
        "the fast list must not wait behind the slow get (multiplexed), took {elapsed:?}"
    );

    assert_eq!(slow.await.expect("join").expect("slow get").id.0, "slow");
}

// Guards the framed codec's over-cap reject BEFORE allocation: a length prefix larger than the cap
// is rejected without allocating that many bytes.
#[tokio::test]
async fn read_frame_rejects_over_cap_length() {
    let bogus = (MAX_BRIDGE_FRAME_BYTES + 1) as u32;
    let buf = bogus.to_be_bytes();
    let mut cursor = &buf[..];
    let err = read_frame(&mut cursor)
        .await
        .expect_err("an over-cap length must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
