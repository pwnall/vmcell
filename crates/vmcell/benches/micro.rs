use criterion::{Criterion, black_box, criterion_group};
use vmcell::agent::protocol::{ExecRequest, Message};
use vmcell::artifact::{Stage, StageInputs, kernel::KernelStage};

#[cfg(feature = "am-fs-erofs")]
use vmcell::artifact::tar2erofs::tar_to_erofs;

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
        http_client: std::sync::Arc::new(vmcell::artifact::kernel::ReqwestClient),
        label: None,
        fragments: None,
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
    // CLI-2: bench the REAL production `/30` helper (`net::ip_math`), which applies
    // `(vmid % 254) + 1` and formats the guest `/30` CIDR. The old hand-rolled
    // `format!("10.200.{vmid}.1").parse()` was a strawman: it used a different octet
    // and skipped the modular math, so a regression in the tracked helper could never
    // move this "math_30_ipv4_parse" number. `black_box` both the vmid input and the
    // `(host, guest, cidr)` output so the optimizer can't fold the call away.
    c.bench_function("math_30_ipv4_parse", |b| {
        b.iter(|| {
            let vmid = black_box(42u32);
            let addrs = vmcell::net::ip_math(vmid).expect("vmid 42 is in the valid /30 range");
            black_box(addrs);
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
            // require_libc6=false: the bench packs a synthetic tar without an injected agent.
            let image = tar_to_erofs(vec![archive], vec![], vec![], false).unwrap();
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

// Custom entry point (instead of `criterion_main!`) so the micro-benchmarks run
// under the same CPU-frequency pin as the macro harness (design §14, Hard-won lessons). The guard
// pins every online CPU to `performance` (turbo off) for the run and restores the
// prior settings on drop. It is a logged no-op without CAP_DAC_OVERRIDE, so to
// actually pin run `cargo bench` through `vmcell-test-runner` or as root.
fn main() {
    // Report the freq-pin status to stderr (criterion owns stdout) so a run is not
    // silently un-pinned (L-BIN-6): without CAP_DAC_OVERRIDE the pin is a logged
    // no-op, and with no subscriber installed that warning is invisible — leaving
    // "not freq-pinned" a convention rather than observed evidence. Mirrors the
    // macro harness (`bench-vm`), which prints `is_pinned()`/`pinned_cpus()`.
    let _freq_pin =
        match vmcell::cpufreq::CpuFreqPin::engage(vmcell::cpufreq::SysfsCpuFreq::system()) {
            Ok(pin) if pin.is_pinned() => {
                eprintln!(
                    "cpufreq: pinned {} CPU(s) to `performance` + turbo off (restored on exit)",
                    pin.pinned_cpus()
                );
                Some(pin)
            }
            Ok(pin) => {
                eprintln!(
                    "cpufreq: NOT pinned (need CAP_DAC_OVERRIDE via vmcell-test-runner) — \
                 micro-bench numbers carry CPU-scaling noise"
                );
                Some(pin)
            }
            Err(e) => {
                eprintln!("cpufreq: pin unavailable: {e}");
                None
            }
        };
    benches();
    Criterion::default().configure_from_args().final_summary();
}
