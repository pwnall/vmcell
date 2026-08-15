#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_daemon::bridge::{fuzz_decode_engine_reply, fuzz_decode_engine_request};

// The broker BRIDGE's JSON RPC — the same privilege crossing `broker_frame` guards for the postcard
// channel, one layer up and in a different codec, which `broker_frame` does not touch.
//
// WHO SUPPLIES THE BYTES: the cap-DROPPED, network-facing HTTP parent writes these frames; the
// CAP-HOLDING broker child (`serve_engine`, which owns the `Registry` and keeps CAP_NET_ADMIN /
// CAP_SYS_ADMIN / CAP_DAC_OVERRIDE) decodes them. The DTO *values* inside are client-chosen even
// when the parent is honest — `EngineRequest::Create(CreateVmRequest)` and `Exec(VmId,
// ExecRequestDto)` carry the REST client's JSON verbatim. The reply arm runs the same decode in the
// opposite direction, in the parent's reader task.
//
// PRODUCTION PRECONDITION MIRRORED: `read_frame` rejects a length prefix over
// `MAX_BRIDGE_FRAME_BYTES` (256 MiB — the largest single allocation anywhere in the tree) BEFORE
// the `vec![0u8; len]`, and only then hands the payload to `serde_json`. This target covers the
// DECODE, not the cap: libFuzzer inputs are many orders of magnitude below 256 MiB, so mirroring
// the cap as a `return` would filter nothing. It is stated here rather than silently skipped.
//
// Both decode arms the serve loop runs are driven: the typed one, and the PERMISSIVE id-recovery
// decode that re-parses the very same hostile bytes a second time when the typed one fails.
//
// PROPERTY: a decoded frame must survive re-encode/re-decode with BOTH its bytes and its value
// intact. The bridge speaks JSON precisely because the forwarded DTOs use
// `#[serde(skip_serializing_if)]` / `default` and postcard corrupts those (Appendix A reversal 10),
// so the presence-attribute round-trip belongs on the codec it actually ships over. The entry points
// hand back `(re-serialized bytes, the decoded value's Debug render)` rather than the value itself,
// which keeps `EngineRequest`/`EngineReply` private outside their crate. Comparing only the BYTES
// would be a weaker check that a real defect walks straight through: a field dropped on the first
// encode is dropped identically on the second, so the byte comparison stays green while the value
// silently changed. The Debug render is what catches that, and it is what goes red on the inverse.
//
// SEED CORPUS: `fuzz/corpus/daemon_bridge_frame/seed-*` ships real frames for both directions,
// because a byte fuzzer cannot synthesize serde field names (`"extra_kernel_args"`, `"ephemeral"`)
// inside a 300 s window — measured cov 1575 cold versus cov 3719 seeded, and the round-trip property
// is unreachable without them, i.e. a green run would have proven nothing.
//
// WHAT WOULD BE A FINDING: a panic in the cap-holding child, or a decoded value that does not
// round-trip (a field silently dropped or added on the way across the privilege boundary).
fuzz_target!(|data: &[u8]| {
    // NOTE there is deliberately no `assert!(data.len() <= MAX_BRIDGE_FRAME_BYTES)` here. An earlier
    // draft had one; it can never fail (256 MiB is six orders of magnitude above any libFuzzer
    // input), and an assertion that cannot go red is this repo's defining anti-pattern — worse here
    // than useless, because a reader skimming the target would count the cap as covered when nothing
    // exercises it. The cap is documented above as the production precondition this target does NOT
    // cover; the caps that DO execute under fuzz are `broker_frame`'s and `protocol_decode`'s.
    if let Some(encoded) = fuzz_decode_engine_request(data) {
        let (first, rendered) =
            encoded.expect("a decoded bridge request must re-encode on its own codec");
        let (again, rendered_again) = fuzz_decode_engine_request(&first)
            .expect("a self-encoded bridge request must re-decode")
            .expect("a self-encoded bridge request must re-encode");
        assert_eq!(first, again, "EngineRequest did not re-encode identically");
        assert_eq!(
            rendered, rendered_again,
            "an EngineRequest field did not survive the JSON round trip"
        );
    }

    if let Some(encoded) = fuzz_decode_engine_reply(data) {
        let (first, rendered) =
            encoded.expect("a decoded bridge reply must re-encode on its own codec");
        let (again, rendered_again) = fuzz_decode_engine_reply(&first)
            .expect("a self-encoded bridge reply must re-decode")
            .expect("a self-encoded bridge reply must re-encode");
        assert_eq!(first, again, "EngineReply did not re-encode identically");
        assert_eq!(
            rendered, rendered_again,
            "an EngineReply field did not survive the JSON round trip"
        );
    }

    // The serve loop's recovery arm: when the typed decode fails, the SAME bytes are parsed again
    // as `(u64, Value)` to recover an id to answer to, so hostile input is parsed twice.
    let _ = serde_json::from_slice::<(u64, serde_json::Value)>(data);
});
