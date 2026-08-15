#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_daemon::dto::{CreateVmRequest, ExecRequestDto, SnapshotRequest};

// The daemon's REST request bodies: `POST /v1/vms` (`CreateVmRequest`), `POST /v1/vms/{id}/exec`
// (`ExecRequestDto`) and `POST /v1/vms/{id}/snapshot` (`SnapshotRequest`).
//
// WHO SUPPLIES THE BYTES: an authenticated REST client's HTTP body — arbitrary JSON, up to the
// route's `DefaultBodyLimit::max(max_artifact_bytes)` (multi-megabyte).
//
// PRODUCTION PRECONDITION MIRRORED: axum's `Json<T>` extractor runs `serde_json` over the body
// bytes, which is exactly what this calls. The body limit is not re-checked here because libFuzzer
// inputs are orders of magnitude below it; the harness therefore covers the DECODE, not the cap.
//
// HONEST SCOPE: most of what this exercises is `serde_json` + serde-derive, both fuzzed upstream.
// Its vmcell-specific value is (a) the `#[serde(default = "default_vcpus")]` / `default_mem_mib`
// arms and the recursion the nested `Vec<ExtraDiskSpec>` / `Vec<String>` allow, and (b) the
// PROPERTY below.
//
// PROPERTY: every decoded request must survive a re-encode/re-decode unchanged. These DTOs carry
// `#[serde(skip_serializing_if)]` / `#[serde(default)]` presence attributes and are forwarded
// verbatim across the broker bridge, which is precisely the class Appendix A reversal 10 records —
// a presence-attribute type must round-trip on the codec it actually ships over, and JSON is that
// codec. Today the guard is one hand-written unit test; this drives it over arbitrary shapes.
fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<CreateVmRequest>(data) {
        let enc = serde_json::to_vec(&req).expect("a decoded CreateVmRequest must re-encode");
        let back = serde_json::from_slice::<CreateVmRequest>(&enc)
            .expect("a self-encoded CreateVmRequest must re-decode");
        assert_eq!(req, back, "CreateVmRequest did not round-trip over JSON");
    }
    if let Ok(req) = serde_json::from_slice::<ExecRequestDto>(data) {
        let enc = serde_json::to_vec(&req).expect("a decoded ExecRequestDto must re-encode");
        let back = serde_json::from_slice::<ExecRequestDto>(&enc)
            .expect("a self-encoded ExecRequestDto must re-decode");
        assert_eq!(req, back, "ExecRequestDto did not round-trip over JSON");
    }
    if let Ok(req) = serde_json::from_slice::<SnapshotRequest>(data) {
        let enc = serde_json::to_vec(&req).expect("a decoded SnapshotRequest must re-encode");
        let back = serde_json::from_slice::<SnapshotRequest>(&enc)
            .expect("a self-encoded SnapshotRequest must re-decode");
        assert_eq!(req, back, "SnapshotRequest did not round-trip over JSON");
    }
});
