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

/// The `CreateVmRequest`s a [`FakeEngine`] received, in order — the parent→broker direction's
/// only observation point.
///
/// The fake used to take `_req: CreateVmRequest` and discard it, so **no test in the tree proved
/// that any `CreateVmRequest` field survived the bridge**: `engine_rpc_round_trips_every_op` would
/// have stayed green if `BrokerClientEngine::create` had forwarded a freshly built default request
/// instead of the caller's. Capturing it is what makes a field-for-field comparison possible.
pub(super) type CreateLog = Arc<std::sync::Mutex<Vec<CreateVmRequest>>>;

/// A fake engine with no KVM. `slow_get` sleeps so a concurrency test can prove the multiplex; a
/// `get` of `"nope"` returns a typed `NotFound` so the error path round-trips. Shared with the
/// sibling deadline gates rather than copied (one fake, one behavior to reason about).
pub(super) struct FakeEngine {
    slow_get_ms: u64,
    /// Every `create` this engine was handed (see [`CreateLog`]).
    creates: CreateLog,
}

#[async_trait]
impl VmEngine for FakeEngine {
    async fn create(&self, req: CreateVmRequest) -> DaemonResult<CreateVmResponse> {
        self.creates.lock().expect("create log").push(req);
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

/// A [`FakeEngine`] served over a real socketpair, with the parent-side client wired to the
/// **derived** per-request budget (`BrokerClientEngine::new`, i.e. `call_budget`) — not an override.
pub(super) fn serve_fake(slow_get_ms: u64) -> BrokerClientEngine {
    serve_fake_capturing(slow_get_ms).0
}

/// [`serve_fake`], also handing back the log of every `CreateVmRequest` that reached the far
/// (broker) side of the socketpair — the observation point a field-forwarding gate needs.
pub(super) fn serve_fake_capturing(slow_get_ms: u64) -> (BrokerClientEngine, CreateLog) {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let creates: CreateLog = Arc::default();
    let engine: Arc<dyn VmEngine> = Arc::new(FakeEngine {
        slow_get_ms,
        creates: creates.clone(),
    });
    tokio::spawn(serve_engine(engine, broker_sock));
    // `BrokerClientEngine::new` spawns the reply reader — must be inside a runtime (we are).
    let client = Arc::try_unwrap(BrokerClientEngine::new(client_sock))
        .map_err(|_| ())
        .expect("sole owner");
    (client, creates)
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

// §18 delta 10 / Appendix A reversal 10 — the first of the two unobserved hops on a request field's
// path, now observed: what the HTTP parent sends arrives at the cap-holding broker child
// **field-for-field**, over the real socketpair and the real length-prefixed JSON codec.
//
// This is the gate `engine_rpc_round_trips_every_op` above could never be. It sends an all-defaults
// request and its fake discarded the argument entirely, so it stayed green for any forwarding bug —
// including a `create` that rebuilt the request from `kernel`+`rootfs` and dropped everything else.
//
// The legs populate the new fields ASYMMETRICALLY (init `Some` + placement `Some`; placement `Some`
// + init `None`; both `None`). A `#[serde(default)]` presence attribute collapses in ONE direction,
// so a both-`Some` fixture cannot see it — the postcard trap the JSON choice exists to avoid, on the
// codec it actually ships over.
//
// RED on the inverse (run before accepting): forward a rebuilt request from
// `BrokerClientEngine::create` —
// `self.call(EngineRequest::Create(CreateVmRequest::create(&req.kernel, &req.rootfs)))` — and every
// leg's `assert_eq!` fails on the dropped fields.
#[tokio::test]
async fn a_create_requests_fields_survive_the_bridge_field_for_field() {
    let (client, creates) = serve_fake_capturing(0);

    let sent = [
        // init `Some`, placement `Some`: the delta's whole point.
        CreateVmRequest::create("vmlinux", "rootfs.erofs")
            .with_service_init(
                "/vmcell-tools/mini-init",
                crate::dto::StewardPlacementDto::Service { port: 5100 },
            )
            .with_kernel_arg("mitigations=off"),
        // placement `Some`, init `None` — the asymmetric sibling.
        CreateVmRequest::create("vmlinux", "rootfs.erofs")
            .with_steward_placement(crate::dto::StewardPlacementDto::Pid1),
        // init `Some`, placement `None` — the shape the registry refuses; it must still ARRIVE
        // intact, or the refusal would be the bridge's accident rather than the rule.
        CreateVmRequest {
            init: Some("/sbin/init".to_string()),
            ..CreateVmRequest::create("vmlinux", "rootfs.erofs")
        },
        // both `None`: the old client, unchanged.
        CreateVmRequest::create("vmlinux", "rootfs.erofs"),
    ];
    for req in &sent {
        client.create(req.clone()).await.expect("create");
    }

    let got = creates.lock().expect("create log").clone();
    assert_eq!(
        got.len(),
        sent.len(),
        "every create reached the broker side"
    );
    for (i, (want, have)) in sent.iter().zip(got.iter()).enumerate() {
        // Field-for-field on the WHOLE value, never a byte compare: a field dropped on the first
        // encode is dropped identically on the second, so bytes stay green while the value changed.
        assert_eq!(have, want, "leg {i} did not survive the bridge intact");
    }
    // Non-vacuity: the asymmetry the legs were built for actually reached the far side.
    assert_eq!(
        got[0].steward_placement,
        Some(crate::dto::StewardPlacementDto::Service { port: 5100 })
    );
    assert_eq!(got[0].init.as_deref(), Some("/vmcell-tools/mini-init"));
    assert_eq!(
        got[1].init, None,
        "the sibling stayed absent across the wire"
    );
    assert_eq!(got[2].steward_placement, None);
    assert_eq!(got[3].init, None);
    assert_eq!(got[3].steward_placement, None);
}
