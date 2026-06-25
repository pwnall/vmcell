# Benchmark Results

This document compiles the performance results for the `imp-testing` framework, tracking both hot-path overheads (micro-benchmarks) and KVM lifecycle latencies (macro-benchmarks) across different hypervisor backends.

## Micro-Benchmarks
These micro-benchmarks were gathered using `criterion` (100 samples, ~5 seconds each). They measure the raw CPU performance of critical, hot-path framework components.

| Benchmark | Description | Latency (p50) |
| --- | --- | --- |
| `protocol_encode` | `postcard` length-delimited serialization of `Message::Exec` | ~53 ns |
| `protocol_decode` | `postcard` length-delimited deserialization | ~89 ns |
| `cache_key_generation` | Hashing struct variants and configurations | ~198 ns |
| `math_30_ipv4_parse` | Host VM IP `/30` parsing (`10.200.<vmid>.1`) | ~31 ns |
| `in_memory_tar2erofs_empty` | EROFS node-tree packing of an empty tar stream in-memory | ~1.27 µs |

## Macro-Benchmarks (Cold Boot)
These metrics measure the time taken from issuing the VMM boot command until the `imp-guest-agent` successfully completes the vsock handshake and replies with `Ready`. Page caches are dropped on the host before every iteration to ensure a "cold" start.

| Backend | Sample Size | p50 | p95 | p99 | Max |
| --- | --- | --- | --- | --- | --- |
| **Cloud Hypervisor** | 3 | **293 ms** | 329 ms | 329 ms | 329 ms |
| **Firecracker** | 3 | **778 ms** | 788 ms | 788 ms | 788 ms |
| **QEMU** (`q35`) | 3 | **1125 ms** | 1130 ms | 1130 ms | 1130 ms |

### Backend Notes:
- **Cloud Hypervisor** proves to be exceptionally fast (under 300ms) for our use-case, partly due to how seamlessly it mounts `virtio-blk` with EROFS and passes through network devices.
- **Firecracker** takes slightly longer (~780ms), which includes its specific multi-stage configuration API overhead (configuring machine, boot source, drives, and vsock over the REST API prior to the `InstanceStart` action).
- **QEMU** is the slowest at ~1.1 seconds. This is expected due to QEMU's more heavyweight PC architecture initialization, despite using the modernized `q35` machine type with memory backends and stripped defaults.
