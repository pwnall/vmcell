#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_artifact_validator::classify::{
    BootKind, SERIAL_TAIL_LINES, SERIAL_TAIL_MAX_BYTES, classify_serial_of, explain_boot_failure_of,
};

// The guest-console classifier and its renderer — `explain_boot_failure_of`, which fans into
// `classify_serial_of`, the tail extractor and its per-line cap.
//
// WHO SUPPLIES THE BYTES: the guest. It owns every byte on `/dev/console` (= `ttyS0`), and PID 1's
// stdout/stderr land there too. `checks::explain_boot_failure_at` reads the VMM's capture of that
// console and hands the text straight here, from every Core/Extended/Full arm that reports a failed
// start or handshake. The rendered message becomes a persisted artifact, and this is a DOWNSTREAM
// CONTRACT crate, so a panic here is visible to an out-of-repo consumer.
//
// PRODUCTION PRECONDITION MIRRORED: the caller reads the log with `tokio::fs::read_to_string`, whose
// `Err` arm (invalid UTF-8) diverts to `explain_without_serial` — so the classifier only ever sees
// VALID UTF-8. The harness gates on `str::from_utf8`, NOT `from_utf8_lossy`, so it cannot manufacture
// inputs the real path rejects.
//
// PROPERTY: the rendered message's guest-controlled tail must respect the byte bounds the rustdoc
// promises. A line COUNT bounds nothing on its own — one un-newlined multi-megabyte line satisfies
// any line count — so the assertion is over BYTES: the whole tail section, header included, is at
// most `SERIAL_TAIL_MAX_BYTES` of quoted text plus one `"\n    "` indent per quoted line. The fixed
// preamble (base + contract clause + symbols, or the checklist pointer plus the restored-console
// note) is all constant strings, so it is bounded by a constant that cannot scale with the log; if
// any guest text were ever interpolated there, that assertion goes red immediately.
//
// The concrete panic surface underneath is `cap_line`'s char-boundary walk and its `line.get(..end)`
// slice — a multi-byte character straddling the 512-byte per-line cap is what aims at it, which is
// why the harness feeds real UTF-8 rather than ASCII.
//
// WHAT WOULD BE A FINDING: a panic on a mid-character truncation, or a message whose guest-derived
// part outgrows the promised bound (a flood into a persisted artifact).

const BASE: &str = "the VM did not reach agent-ready within its budget";
const TAIL_HEADER: &str = "\n  serial tail:";
const LINE_INDENT: &str = "\n    ";
const NO_OUTPUT_NOTE: &str = " (the serial console produced no output)";
/// Ceiling on the fixed preamble between `BASE` and the tail header: every byte of it is a compile-
/// time literal (a clause, its symbol list, the checklist pointer, the restored-console note), so
/// this is generous by construction and can only be exceeded by interpolating something that is not
/// constant — which is the defect it guards.
const PREAMBLE_CEILING: usize = 4096;

fuzz_target!(|input: (bool, &[u8])| {
    let (restored, data) = input;
    let Ok(log) = std::str::from_utf8(data) else {
        return;
    };
    let kind = if restored {
        BootKind::Restored
    } else {
        BootKind::Fresh
    };

    // The classifier itself, on the same input the renderer walks.
    let _ = classify_serial_of(kind, log);

    let msg = explain_boot_failure_of(kind, log, BASE);
    assert!(
        msg.starts_with(BASE),
        "the rendered message must begin with the check's own sentence"
    );

    let tail_at = msg
        .find(TAIL_HEADER)
        .expect("the renderer always emits the serial-tail header");
    assert!(
        tail_at - BASE.len() <= PREAMBLE_CEILING,
        "the fixed preamble grew to {} bytes — something that is not a constant string is being \
         interpolated into it",
        tail_at - BASE.len()
    );

    let tail = &msg[tail_at..];
    let tail_ceiling = TAIL_HEADER.len()
        + NO_OUTPUT_NOTE
            .len()
            .max(SERIAL_TAIL_MAX_BYTES + SERIAL_TAIL_LINES * LINE_INDENT.len());
    assert!(
        tail.len() <= tail_ceiling,
        "the guest-controlled serial tail rendered {} bytes, past its own {tail_ceiling}-byte \
         bound — a guest can flood a persisted artifact",
        tail.len()
    );
});
