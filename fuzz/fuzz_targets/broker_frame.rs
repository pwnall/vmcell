#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vmcell_broker::{BrokerRequest, MAX_BROKER_FRAME_BYTES, recv_msg};

// The cross-privilege decode surface the broker introduces (rubric B10). The broker CHILD holds the
// three caps; the HTTP parent forwards each request to it as one length-prefixed frame, and the
// child decodes the payload as a postcard `BrokerRequest`.
//
// WHO SUPPLIES THE BYTES: the cap-dropped, network-facing HTTP parent — the process that parses
// attacker HTTP. A panic here is a crash in the process that still holds CAP_NET_ADMIN /
// CAP_SYS_ADMIN / CAP_DAC_OVERRIDE.
//
// PRODUCTION PRECONDITION MIRRORED — and this is the honesty upgrade over the original target:
// step (1) drives the SHIPPED `recv_msg`, so the real `read_frame` length-prefix parse and its
// pre-allocation `MAX_BROKER_FRAME_BYTES` check (vmcell-broker/src/lib.rs) execute on every input.
// The previous body hand-mirrored that cap with `if data.len() > MAX_… { return; }` and called
// postcard directly, which meant the over-cap rejection path the target exists to protect was never
// executed even once. Step (2) keeps the direct payload decode so the postcard deserializer is
// still reached on inputs the fuzzer has not yet taught to carry a well-formed 4-byte prefix.
//
// (`vmcell_broker` has no `decode_frame` — the honest entry points are `recv_msg` and the framed
// postcard `BrokerRequest`; this mirrors the same doc→reality adaptation `protocol_decode.rs` made
// for the guest wire.)
//
// WHAT WOULD BE A FINDING: a panic, an abort, an integer-narrowing truncation, or an allocation
// past the frame cap. A returned `Err` is the expected outcome for arbitrary bytes.
fuzz_target!(|data: &[u8]| {
    // (1) The whole production receive path: 4-byte big-endian prefix, cap check BEFORE the
    // `vec![0u8; len]`, then postcard.
    let _ = recv_msg::<BrokerRequest>(&mut Cursor::new(data));

    // (2) The payload decode on its own, so the deserializer is reached even before the fuzzer
    // learns the framing. The cap is the same one `read_frame` enforces above.
    if data.len() <= MAX_BROKER_FRAME_BYTES {
        let _ = postcard::from_bytes::<BrokerRequest>(data);
    }
});
