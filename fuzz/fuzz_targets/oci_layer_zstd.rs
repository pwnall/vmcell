#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Read};
use vmcell::artifact::tar2erofs::tar_to_erofs;

// The zstd arm of the OCI layer ingest — the decoder composition `build_rootfs_with` performs for
// `application/vnd.oci.image.layer.v1.tar+zstd`, feeding the same packer `oci_layer_tar` covers.
//
// WHO SUPPLIES THE BYTES: an OCI registry, same publisher as `oci_layer_tar` — but this arm reaches
// LINKED C CODE. `zstd` → `zstd-safe` → `zstd-sys` is the C libzstd, the only non-Rust parser in
// this repo that sees off-host bytes. (The gzip arm is `flate2` over `miniz_oxide`, pure Rust and
// far lower yield, so it does not get its own target.)
//
// PRODUCTION PRECONDITION MIRRORED: the composition is reproduced exactly as
// `crates/vmcell/src/artifact/rootfs/oci.rs` builds it — `zstd::stream::read::Decoder::new(blob)`
// pushed straight into `tar::Archive` and handed to the packer. The production function that does
// this is a private `async fn`, so the target reproduces the two-line composition rather than
// calling it; that is the same doc→reality adaptation `protocol_decode.rs` and `broker_frame.rs`
// already made. The blob is digest-verified before the decoder is constructed, which is why the
// harness feeds a whole in-memory blob rather than a truncated stream.
//
// TWO DELIBERATE HARNESS CHOICES, both stated because either could otherwise look like a bug:
//   1. A SEED CORPUS ships with the repo, in `fuzz/corpus/oci_layer_zstd/seed-*` (re-included by
//      `fuzz/.gitignore` against the blanket corpus ignore, and picked up because `cargo fuzz run`
//      uses that directory by default). Without it every random input dies on the frame magic and
//      the target burns its whole window inside libzstd's first four bytes: measured cov 759 cold
//      versus cov 1286 with one real `.tar.zst`. A target that cannot reach the parser it names is
//      exactly the "reports success while covering nothing" defect, in fuzz-target form.
//   2. The decompressed stream is bounded with `Read::take`. A zstd frame is a legitimate
//      compression bomb — a few KiB of input can expand without bound — and production's exposure
//      to that is a property of the pinned image, not a parser defect. Without the bound the target
//      would OOM on ordinary inputs and stop fuzzing anything.
// The bytes themselves are fed VERBATIM: no synthetic frame header, so the magic, the frame header
// descriptor and the window descriptor are all fuzzed exactly as a registry would deliver them.
//
// WHAT WOULD BE A FINDING: a crash inside libzstd — the only non-Rust parser in this repo that sees
// off-host bytes — or a panic in the tar/packer stage downstream of it.
//
// HOW MUCH SANITIZER ACTUALLY COVERS THE C, checked rather than assumed: `cargo fuzz build` puts
// `-Zsanitizer=address` in RUSTFLAGS but sets no `CFLAGS`, and `nm` over the built
// `zstd-sys/*/out/*.o` finds ZERO `asan` symbols — the C objects are NOT instrumented. What still
// holds is ASan's process-wide malloc/free interception: a heap overflow that crosses a redzone, a
// double free or a use-after-free inside libzstd is still caught. What is NOT caught is an
// intra-allocation overflow, or a stack/global overflow, inside the uninstrumented C. Exporting
// `CFLAGS=-fsanitize=address -fno-omit-frame-pointer` (and `CXXFLAGS`) in the nightly workflow's env
// would close that gap; the workflow is owned elsewhere, so this is recorded here rather than
// silently assumed away.

/// Ceiling on the DECOMPRESSED stream handed to the tar reader — see harness choice 2 above.
const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(decoder) = zstd::stream::read::Decoder::new(Cursor::new(data)) else {
        return;
    };

    let _ = tar_to_erofs(
        vec![tar::Archive::new(decoder.take(MAX_DECOMPRESSED_BYTES))],
        vec![],
        vec![],
        vec![],
        false,
    );
});
