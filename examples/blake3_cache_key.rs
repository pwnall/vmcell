//! Dev utility: emit a valid pipeline `CacheMetadata` JSON for the prebuilt
//! `vmlinux`, so the kernel stage is treated as a cache hit instead of being
//! rebuilt (the from-scratch kernel build is broken under gcc-15 / C23 — see
//! implementation-notes.md). The kernel is unchanged, so reusing it is correct.
//!
//! Replicates `KernelStage::cache_key` (blake3 over STAGE_VERSION + the three
//! kernel pins) and `hash_file` (blake3 of the artifact) exactly.
//!
//! Usage: cargo run --example blake3_cache_key --features pipeline -- \
//!            <pins.json> <vmlinux_path>
//! Prints the CacheMetadata JSON to stdout.
use std::io::Read;

const KERNEL_STAGE_VERSION: u32 = 1;

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

    // Mirror KernelStage::cache_key.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&KERNEL_STAGE_VERSION.to_le_bytes());
    hasher.update(url.as_bytes());
    hasher.update(sha.as_bytes());
    hasher.update(cfg.as_bytes());
    let key = format!("kernel-{}", hasher.finalize().to_hex());

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
