use criterion::{Criterion, black_box, criterion_group, criterion_main};
use imp_testing::agent::protocol::{ExecRequest, Message};
use imp_testing::artifact::{Stage, StageInputs, kernel::KernelStage};
use std::net::Ipv4Addr;

#[cfg(feature = "am-fs-erofs")]
use imp_testing::artifact::tar2erofs::tar_to_erofs;

fn bench_protocol_codec(c: &mut Criterion) {
    let msg = Message::Exec(
        ExecRequest::new(vec!["ls".to_string(), "-l".to_string()])
            .with_env(vec![("PATH".to_string(), "/bin".to_string())])
            .with_cwd("/root"),
    );

    c.bench_function("protocol_encode", |b| {
        b.iter(|| {
            let bytes = postcard::to_stdvec(black_box(&msg)).unwrap();
            black_box(bytes);
        })
    });

    let encoded = postcard::to_stdvec(&msg).unwrap();
    c.bench_function("protocol_decode", |b| {
        b.iter(|| {
            let decoded: Message = postcard::from_bytes(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });
}

fn bench_cache_key(c: &mut Criterion) {
    let stage = KernelStage {
        http_client: std::sync::Arc::new(imp_testing::artifact::kernel::ReqwestClient),
    };
    let mut inputs = StageInputs::default();
    inputs.pins.insert(
        "kernel_source_url".into(),
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.tar.xz".into(),
    );
    inputs
        .pins
        .insert("kernel_source_sha256".into(), "dummy_sha256".into());
    inputs.pins.insert(
        "kernel_microvm_config".into(),
        "CONFIG_KVM=y\nCONFIG_VIRTIO=y\n".into(),
    );

    c.bench_function("cache_key_generation", |b| {
        b.iter(|| {
            let key = stage.cache_key(black_box(&inputs));
            black_box(key);
        })
    });
}

fn bench_math_30(c: &mut Criterion) {
    c.bench_function("math_30_ipv4_parse", |b| {
        b.iter(|| {
            let vmid = black_box(42u32);
            let ip: Ipv4Addr = format!("10.200.{}.1", vmid).parse().unwrap();
            black_box(ip);
        })
    });
}

#[cfg(feature = "am-fs-erofs")]
fn bench_tar_to_erofs(c: &mut Criterion) {
    // Create a dummy empty tar in memory
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        builder.finish().unwrap();
    }

    c.bench_function("in_memory_tar2erofs_empty", |b| {
        b.iter(|| {
            // tar_to_erofs expects an iterator over archives
            let reader = std::io::Cursor::new(tar_data.clone());
            let archive = tar::Archive::new(reader);
            let image = tar_to_erofs(vec![archive], vec![], vec![]).unwrap();
            black_box(image);
        })
    });
}

#[cfg(not(feature = "am-fs-erofs"))]
fn bench_tar_to_erofs(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_protocol_codec,
    bench_cache_key,
    bench_math_30,
    bench_tar_to_erofs
);
criterion_main!(benches);
