//! Dev utility: emit a valid pipeline `CacheMetadata` JSON for the prebuilt
//! `vmlinux`, so the kernel stage is treated as a cache hit instead of being
//! rebuilt (a from-scratch kernel build is broken under gcc-15 / C23 — design
//! v17 §1506). The kernel is unchanged, so reusing it is correct.
//!
//! This calls the REAL `KernelStage::cache_key` (with the same `label: None,
//! fragments: None` as `vmcell build`) instead of re-deriving the hash by hand, so
//! the emitted key cannot drift from the pipeline (M-BIN-5: the old hand-rolled copy
//! had `STAGE_VERSION = 1` vs the real `2`, no `\x1f` field separators, and never
//! folded the label — every one a silent mismatch that made the cache miss).
//!
//! Usage: cargo run --example blake3_cache_key --features pipeline -- \
//!            <pins.json> <vmlinux_path>
//! Prints the CacheMetadata JSON to stdout.
use std::io::Read;

use vmcell::artifact::kernel::{KernelStage, ReqwestClient};
use vmcell::artifact::{Stage, StageInputs};

fn main() {
    let mut args = std::env::args().skip(1);
    let pins_path = args.next().expect("pins.json path");
    let vmlinux_path = args.next().expect("vmlinux path");

    let pins = std::fs::read_to_string(&pins_path).expect("read pins.json");
    let json: serde_json::Value = serde_json::from_str(&pins).expect("parse pins.json");
    let k = json.get("kernel").expect("kernel section");
    let url = k["source_url"].as_str().expect("source_url");
    let sha = k["source_sha256"].as_str().expect("source_sha256");
    let cfg = k["microvm_config"].as_str().expect("microvm_config");

    // Build the exact stage `vmcell build` uses (the default, unlabelled kernel with
    // no config fragments) and feed it the resolved pins under the same keys
    // `ResolvePinsStage` publishes. Calling the tracked `cache_key` guarantees the
    // emitted key matches whatever the pipeline would compute — no re-implementation.
    let stage = KernelStage {
        http_client: std::sync::Arc::new(ReqwestClient),
        label: None,
        fragments: None,
    };
    let mut inputs = StageInputs::default();
    inputs.pins.insert("kernel_source_url".into(), url.into());
    inputs
        .pins
        .insert("kernel_source_sha256".into(), sha.into());
    inputs
        .pins
        .insert("kernel_microvm_config".into(), cfg.into());
    let key = stage.cache_key(&inputs).0;

    // Mirror hash_file(vmlinux).
    let mut file = std::fs::File::open(&vmlinux_path).expect("open vmlinux");
    let mut h = blake3::Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).expect("read vmlinux");
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let payload_hash = h.finalize().to_hex().to_string();

    print!(
        r#"{{"key":"{key}","hash":"{payload_hash}","pins":{{}},"artifacts":{{"kernel":"{vmlinux_path}"}}}}"#
    );
}
