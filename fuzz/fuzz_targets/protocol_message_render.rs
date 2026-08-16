#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_protocol::{
    DEBUG_TRUNCATED_MARKER, MAX_DEBUG_RENDER_BYTES, MAX_FRAME_BYTES, Message, capped_debug,
};

// The RENDER surface downstream of the guest wire: every desync diagnostic on the control plane
// quotes a decoded (or undecodable) frame through `capped_debug`.
//
// WHO SUPPLIES THE BYTES: the guest. Five production sites render guest-chosen frames
// (`vmcell::steward`'s connect prologue, the raw Ready frame, an unexpected decoded `Message`, an
// unexpected exec-stream frame, and the session reader), and the steward renders HOST frames
// the same way onto the PERSISTED serial-console artifact — so an uncapped render is a flood
// written into an artifact every later run reads.
//
// PRODUCTION PRECONDITION MIRRORED: the same `MAX_FRAME_BYTES` cap `protocol_decode` mirrors, since
// the value being rendered is always a frame that already passed it. Kept as a separate target from
// `protocol_decode` deliberately: this one's corpus converges on DECODABLE frames (only those reach
// the renderer), where `protocol_decode`'s is reject-dominated.
//
// PROPERTY, not just no-panic: `capped_debug`'s rustdoc promises the render is bounded at
// `MAX_DEBUG_RENDER_BYTES` plus the marker, whatever the peer sent. The concrete panic surface is
// `CappedSink::write_str`'s char-boundary walk and its `s.get(..end)` — a multi-byte payload
// straddling the 256-byte cap is exactly what aims at it. An unmarked render must additionally be
// the WHOLE value, so a silent truncation cannot masquerade as a complete quote.
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FRAME_BYTES {
        return;
    }
    let Ok(msg) = postcard::from_bytes::<Message>(data) else {
        return;
    };

    let rendered = capped_debug(&msg);
    assert!(
        rendered.len() <= MAX_DEBUG_RENDER_BYTES + DEBUG_TRUNCATED_MARKER.len(),
        "capped_debug rendered {} bytes, past its own {MAX_DEBUG_RENDER_BYTES}-byte cap plus marker",
        rendered.len()
    );

    // Strictly under the cap ⇒ the formatter was never stopped, so the render is the complete
    // `{:?}`. (Exactly AT the cap is ambiguous: a value whose Debug ends flush with the cap
    // finishes without the marker, which is correct.)
    if rendered.len() < MAX_DEBUG_RENDER_BYTES {
        assert!(
            !rendered.ends_with(DEBUG_TRUNCATED_MARKER),
            "an under-cap render must not claim truncation"
        );
        assert_eq!(
            rendered,
            format!("{msg:?}"),
            "an untruncated capped_debug must equal the full Debug render"
        );
    }
});
