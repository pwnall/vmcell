#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vmcell_broker::{BrokerReply, MAX_BROKER_FRAME_BYTES, recv_msg};

// The broker channel's REPLY direction — the half `broker_frame` does not cover. AGENTS.md requires
// window-filling payloads "in both directions"; this is the decode side of that rule.
//
// WHO SUPPLIES THE BYTES: the cap-holding broker child, read back by the cap-DROPPED HTTP parent
// (`BrokerClient::request` → `recv_msg::<BrokerReply>`). The privilege gradient runs downhill here,
// so the attacker gain is lower than the request direction — it matters once the child is already
// compromised. It earns its slot on cost and on shape: `BrokerReply::SweepDone` carries four
// `Vec<String>` fields, and the 1 MiB frame cap is the only thing between a hostile length varint
// and an unbounded allocation in the parent.
//
// PRODUCTION PRECONDITION MIRRORED: step (1) drives the shipped `recv_msg`, so `read_frame`'s
// length-prefix parse and its pre-allocation `MAX_BROKER_FRAME_BYTES` check run for real rather
// than being restated in the harness. Step (2) decodes the payload directly so postcard is reached
// before the fuzzer learns the framing.
//
// WHAT WOULD BE A FINDING: a panic, an abort, or an allocation sized from the wire past the cap.
// A returned `Err` is the expected outcome.
fuzz_target!(|data: &[u8]| {
    let _ = recv_msg::<BrokerReply>(&mut Cursor::new(data));

    if data.len() <= MAX_BROKER_FRAME_BYTES {
        let _ = postcard::from_bytes::<BrokerReply>(data);
    }
});
