#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::path::Component;
use vmcell::artifact::tar2erofs::{fuzz_node_paths, tar_to_erofs};

// The OCI layer ingest: every tar header field of a pulled image layer is consumed here and folded
// into the merged tree that becomes the guest's rootfs.
//
// WHO SUPPLIES THE BYTES: an OCI registry — whoever publishes the pinned base image (Debian, a
// downstream consumer's registry). The digest pin proves INTEGRITY, not benignity: it fixes WHICH
// third-party bytes arrive, it does not make them ours, and the `VMCELL_PINS` overlay (contract
// surface) lets a consumer name any image with any digest. Production reaches this through
// `pull_rootfs_from_oci` → the verified blob → a gzip/zstd decoder → `pack_erofs_with_injection` →
// `tar_to_erofs`.
//
// PRODUCTION PRECONDITION MIRRORED: `require_libc6 = false` and empty injection vectors — the
// `--agent-musl` pack configuration. `true` would short-circuit on the missing-libc6 check before
// the interesting tail (whiteouts, hardlink materialization, parent synthesis) is ever reached, and
// an arbitrary archive never carries `libc.so.6`. The injection vectors are empty because a
// non-empty one names host files the packer would READ, which a fuzz target must not do.
//
// PROPERTY: every key of the merged tree is CONFINED — relative, and free of any `..`, root or
// prefix component. `normalize_path` POPS a parent component rather than escaping with it, so an
// archive member named `../../etc/passwd` must fold to `etc/passwd`; a key that escaped would be a
// path the packer addresses outside the image root. An EMPTY key is deliberately allowed: an
// ordinary `./`-prefixed layer entry normalizes to one, so asserting non-empty would report a
// shape production accepts every day.
//
// Then the full `tar_to_erofs`, which is what production actually calls — the packer/EROFS builder
// past the node map is covered only by that second call.
//
// HARNESS NOTES worth knowing when reading a crash:
//   * A SEED CORPUS ships in `fuzz/corpus/oci_layer_tar/seed-*` (re-included by `fuzz/.gitignore`
//     against the blanket corpus ignore; `cargo fuzz run` reads that directory by default). It
//     carries one archive with every arm this packer branches on — regular file, directory,
//     symlink, hardlink, `.wh.` whiteout and `.wh..wh..opq` opaque marker — because a tar header
//     carries a CHECKSUM and a fuzzer that has to solve one before it can branch spends its window
//     on that instead. It also lifts libFuzzer's `-max_len`, which with no explicit flag is guessed
//     from the largest corpus unit: the 10 KiB seed puts it well past the 4096-byte default (eight
//     tar blocks), which is what reaches the whiteout/hardlink/parent-synthesis tail.
//   * KEEP the default `-rss_limit_mb`. The hardlink arm clones the target member's whole `data`
//     per link with no aggregate budget, so a self-amplifying archive outrunning the RSS limit is a
//     real finding, not a harness artifact.
//
// WHAT WOULD BE A FINDING: a panic, an OOM from an input far smaller than the allocation it drove,
// or an escaping merged-tree key.
fuzz_target!(|data: &[u8]| {
    if let Ok(paths) = fuzz_node_paths(vec![tar::Archive::new(Cursor::new(data))]) {
        for p in &paths {
            assert!(
                p.is_relative(),
                "merged-tree key {p:?} is absolute: it addresses a path outside the image root"
            );
            assert!(
                !p.components().any(|c| matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )),
                "merged-tree key {p:?} escapes the image root"
            );
        }
    }

    // The shipped entry point, including the EROFS pack itself.
    let _ = tar_to_erofs(
        vec![tar::Archive::new(Cursor::new(data))],
        vec![],
        vec![],
        vec![],
        false,
    );
});
