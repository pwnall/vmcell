# Benchmark Results

This document compiles the performance results for the `imp-testing` framework, tracking both hot-path overheads (micro-benchmarks) and KVM lifecycle latencies (macro-benchmarks) across different hypervisor backends.

## Micro-Benchmarks
These micro-benchmarks were gathered using `criterion` (100 samples, ~5 seconds each). They measure the raw CPU performance of critical, hot-path framework components.

| Benchmark | Description | Latency (p50) |
| --- | --- | --- |
| `protocol_encode` | `postcard` length-delimited serialization of `Message::Exec` | ~57.34 ns |
| `protocol_decode` | `postcard` length-delimited deserialization | ~84.11 ns |
| `cache_key_generation` | Hashing struct variants and configurations | ~195.10 ns |
| `math_30_ipv4_parse` | Host VM IP `/30` parsing (`10.200.<vmid>.1`) | ~31.03 ns |
| `in_memory_tar2erofs_empty` | EROFS node-tree packing of an empty tar stream in-memory | ~1.25 µs |

## Macro-Benchmarks (Cold Boot)
These metrics measure the time taken from issuing the VMM boot command until the `imp-guest-agent` successfully completes the vsock handshake and replies with `Ready`. Page caches are dropped on the host before every iteration to ensure a "cold" start.

| Backend | Sample Size | p50 | p95 | p99 | Max |
| --- | --- | --- | --- | --- | --- |
| **Cloud Hypervisor** | 10 | **324 ms** | 343 ms | 343 ms | 343 ms |
| **Firecracker** | 10 | **781 ms** | 790 ms | 790 ms | 790 ms |
| **QEMU** (`q35`) | 9 | **1126 ms** | 1180 ms | 1180 ms | 1180 ms |

## Macro-Benchmarks (Warm Restore)
These metrics measure the time taken to restore a VM from a snapshot (using `TestVm::restore`), connect to the guest agent, and receive a response, recording the latency distribution.

| Backend | Sample Size | p50 | p95 | p99 | Max |
| --- | --- | --- | --- | --- | --- |
| **Cloud Hypervisor** | 10 | **47 ms** | 58 ms | 58 ms | 58 ms |
| **Firecracker** | 10 | **35 ms** | 46 ms | 46 ms | 46 ms |
| **QEMU** (`q35`) | N/A | **N/A** | N/A | N/A | N/A |

### Backend Notes:
- **Cloud Hypervisor** proves to be exceptionally fast (around 320ms cold boot) for our use-case, partly due to how seamlessly it mounts `virtio-blk` with EROFS and passes through network devices. Its warm restore latency is also extremely low (~47ms).
- **Firecracker** takes slightly longer for cold boot (~780ms), which includes its specific multi-stage configuration API overhead (configuring machine, boot source, drives, and vsock over the REST API prior to the `InstanceStart` action). However, its warm restore latency is the fastest of all at **~35ms**.
- **QEMU** is the slowest at ~1.1 seconds cold boot. This is expected due to QEMU's more heavyweight PC architecture initialization, despite using the modernized `q35` machine type with memory backends and stripped defaults. QEMU does not support snapshot/restore under the rootless vsock control plane due to statelessness of the external `vhost-device-vsock` daemon.

