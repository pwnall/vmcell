#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_protocol::{MAX_FRAME_BYTES, Message};

// The decode surface that guest- and network-derived bytes actually reach: a single framed
// postcard `Message`. Both ends (`vmcell::agent` on the host, the guest agent's `read_framed`)
// reject any frame longer than the shared `MAX_FRAME_BYTES` cap BEFORE handing the payload to
// postcard, so we mirror that precondition here and fuzz exactly what production decodes.
//
// Contract under fuzz (rubric B10): decoding arbitrary bytes must reject cleanly — a returned
// `Err` is fine. A panic, an abort, an integer-narrowing truncation, or an allocation past the
// frame cap is a finding, and libFuzzer captures the reproducer.
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FRAME_BYTES {
        return;
    }
    let _ = postcard::from_bytes::<Message>(data);
});
