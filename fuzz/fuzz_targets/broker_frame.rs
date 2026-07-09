#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_broker::{BrokerRequest, MAX_BROKER_FRAME_BYTES};

// The cross-privilege decode surface the broker introduces (rubric B10). The broker CHILD holds the
// three caps; the HTTP parent forwards each request to it as one length-prefixed frame, and the
// child decodes the payload as a postcard `BrokerRequest`. `read_frame` rejects any frame longer
// than `MAX_BROKER_FRAME_BYTES` BEFORE allocating, so we mirror that precondition and fuzz exactly
// the payload the PRIVILEGED process feeds to postcard.
//
// (`vmcell_broker` has no `decode_frame` — the honest entry point is the framed postcard
// `BrokerRequest`, which is what the shipped `recv_msg` decodes; this mirrors the same doc→reality
// adaptation `protocol_decode.rs` made for the guest wire.)
//
// Contract under fuzz: decoding arbitrary bytes must reject cleanly — a returned `Err` is fine. A
// panic, an abort, an integer-narrowing truncation, or an allocation past the frame cap is a
// finding, and here it would be a crash in the cap-holding process. libFuzzer captures the reproducer.
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_BROKER_FRAME_BYTES {
        return;
    }
    let _ = postcard::from_bytes::<BrokerRequest>(data);
});
