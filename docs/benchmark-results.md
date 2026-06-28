# Benchmark Results

Performance results for the `imp-testing` framework: hot-path overheads (micro-benchmarks) and
KVM lifecycle/density/size metrics (macro-benchmarks). Per design §13.7 these are **tracked metrics,
not pass/fail gates** — absolute numbers are hardware-bound and only meaningful with their substrate.

## Substrate (this measurement pass — 2026-06-28)

- **Host:** Intel Core Ultra 7 258V (Lunar Lake), 8 cores / 8 threads; **base 2.2 GHz, turbo
  4.7 GHz**. 30 GiB RAM (~13 GiB free). Root FS ext4 on NVMe; **`/tmp` is tmpfs**.
- **Pinned tools:** Cloud Hypervisor v52.0.0, Firecracker v1.16.0, QEMU 10.2.1, virtiofsd 1.13.3,
  mmdebstrap 1.5.7; **guest kernel Linux 6.12.94** (the committed pin, distro-aligned with Trixie);
  rootfs base `debian@…` (trixie). Built from scratch via `imp-testing build` under gcc 15.2.0.
- **mm:** THP `madvise`, **KSM on**. Macro runs go through the capability runner under
  `systemd-run --user --scope`, and are **CPU-frequency-pinned** (`performance` + turbo off →
  numbers sit at the **sustained 2.2 GHz base**, representative of dense/all-core operation).
- **Caveats:** "Cold" boot is **warm-cache** (`drop_caches` needs real `euid==0`, and tmpfs artifacts
  are immune). Micro-benchmarks run via `cargo bench` and are **not** freq-pinned. Shared-host load
  adds run-to-run variance — quote central tendency, not tails/SLAs.

## Micro-Benchmarks (`criterion`, in-process; not freq-pinned)

| Benchmark | Description | p50 |
| --- | --- | --- |
| `protocol_encode` | `postcard` encode of `Message::Exec` | 55.9 ns |
| `protocol_decode` | `postcard` decode | 82.9 ns |
| `cache_key_generation` | hashing struct variants + configs for the artifact cache key | 218 ns |
| `math_30_ipv4_parse` | `/30` host-IP parse (`10.200.<vmid>.1`) | 29.3 ns |
| `in_memory_tar2erofs_empty` | erofs node-tree pack of an empty tar, in-memory | 1.23 µs |

The control-plane codec and per-VM address/cache math are tens-to-hundreds of ns — far below the
multi-second VM lifecycle.

## Macro — Cold boot & Warm restore (start → guest agent `Ready`)

N=20, warmup=3, mem=256 MiB. Cold = warm-cache (see caveats). All ms.

| Backend | Cold p50 / p95 / max | Warm restore p50 / p95 / max |
| --- | --- | --- |
| **Cloud Hypervisor** | 635 / 669 / 669 | **169 / 179 / 179** |
| **Firecracker** | 1022 / 1038 / 1038 | **128 / 138 / 138** |
| **QEMU** (`q35`) | 1405 / 1732 / 1732 | N/A (`snapshot_restore=false`) |

- Warm restore is **~3.7× faster than cold** on CH and **~8× on Firecracker** — the per-test lever
  holds. **Firecracker now restores (128 ms) and *wins* restore over CH (169 ms)** while losing cold
  boot — exactly the density/snapshot-tier role the design assigns it. (FC warm restore was broken by
  a vsock-UDS `EADDRINUSE` bug, since fixed.)
- **Kernel-bump cost:** on the prior 6.6.9 pin these were CH ~571 ms cold / ~76 ms restore (pinned).
  The distro-aligned 6.12.94 boots ~10–15% slower and, notably, **restores ~2× slower** (76→169 ms) —
  a real cost of the larger 6.12 kernel on the hot path, worth weighing against the §6 distro-kernel
  preference and the gcc-15 build fix (a minimal 6.6.143 bump would avoid the restore regression).
- **Design §13.1 reference** (research-era figures): CH 324 ms cold / 47 ms restore — hardware- and
  pin-dependent; the *relative* invariants reproduce, the absolute ms do not.

## Macro — Eager vs lazy restore (CH, `prefault`)

N=20, warmup=3, mem=256 MiB. Warm restore → agent response (ms).

| restore-mode | p50 | p95 | max |
| --- | --- | --- | --- |
| `eager` (`prefault=on`) | 258 | 274 | 274 |
| `lazy` (`prefault=off`, userfaultfd) | 176 | 188 | 188 |
| `default` (CH default ≈ lazy) | 169 | 179 | 179 |

Lazy resumes **~82 ms faster** (it defers guest-page fault-in to first touch); eager pays the full
prefault up front. The resume-latency win **understates** lazy's true cost, which reappears as
in-guest first-touch page faults during execution.

## Macro — Guest-RAM footprint & density (CH, 8 concurrent, 256 MiB)

| Metric | Baseline (shared) | `--ksm-mergeable` (opt-in) |
| --- | --- | --- |
| guest RAM per guest | ≈58 MiB (`RssShmem`, memfd) | ≈59 MiB (`RssAnon`, private) |
| marginal per added guest | ≈58 MiB (dead-linear) | ≈59 MiB |
| shared CH binary/libs (`RssFile`) | ≈6 MiB/guest (≈flat) | ≈6 MiB/guest |
| **KSM dedup over the run** | **0** (KSM can't merge shared pages) | **≈394 MiB** (`pages_sharing`=100,993 → 11,814 canonical) |
| guest agent (PID 1) RSS | ≈2.4 MiB | ≈2.4 MiB |
| guest `MemTotal` / `MemAvailable` | 211 / 194 MiB | 211 / 194 MiB |
| **Implied density ceiling** | ≈13 GiB / 58 MiB ≈ **~230 idle** (~52 if each faults full 256 MiB) | KSM collapses ~84% of identical-guest RAM |

Guest RAM is demand-paged (each guest touches ~58 of 256 MiB). The opt-in `ksm_mergeable` lever
(CH `mergeable=on` + `shared=off`) makes KSM dedup the bulk of identical-guest RAM — a large density
win for N-identical-guest workloads, traded against vhost-user incompatibility (`shared=off`) and KSM
scan CPU. **Off by default.**

## Macro — Suspend-state size on disk (CH & FC)

| Backend | mem | total | memory-file share |
| --- | --- | --- | --- |
| CH | 256 / 512 MiB | 268.5 / 536.9 MB | 100% (`memory-ranges`) + ~52 KiB state |
| FC | 256 / 512 MiB | 268.4 / 536.9 MB | 100% (`mem_file`) + ~14 KiB vmstate |

Snapshot size **tracks guest RAM exactly** and is **flat in rootfs size**. Memory files are dense →
sparse-snapshot (`SEEK_HOLE`) is the lever for warm-pool density.

## Macro — Per-test critical-path budget (CH, n=12)

| Phase | COLD p50 / share | RESTORE p50 / share |
| --- | --- | --- |
| create (`start` \| `restore`+`resume`) | 41 ms / 6% | 54 ms / 27% |
| connect (vsock + handshake [+resync]) | **591 ms / 89%** | **115 ms / 58%** |
| exec (`/bin/true`) | 5 ms / 1% | 1 ms / 1% |
| teardown (reap-VMM-first) | 29 ms / 4% | 27 ms / 14% |
| **TOTAL** | **≈671 ms** | **≈196 ms** |

Cold is ~89% guest-boot wait (`connect`); restore collapses it ~3.4×. On 6.12.94 the post-restore
`connect` phase (reconnect + clock/RNG resync) is itself ~115 ms — the bulk of the restore regression
vs 6.6.9. Teardown is a real ~27 ms (reap-VMM-first no-leak ordering, on the budget by design).

## Macro — Datapath: vsock exec round-trip (CH, 200×)

**p50 719 µs, p95 1183 µs, p99 1479 µs, max 2414 µs** (incl. in-guest fork/exec/reap) — a
sub-millisecond control-plane floor at the base clock; not an `exec` bottleneck.

## Artifact sizes (§13.6) — OCI base vs mmdebstrap *(kernel-independent; unchanged)*

Packed **erofs** (the booted artifact; the pipeline ships **uncompressed** — `am-fs-erofs` emits no
compressed nodes):

| Base | erofs uncompressed (shipped) | erofs lz4 | erofs zstd |
| --- | --- | --- | --- |
| **OCI** `debian:trixie` slim | **79.2 MB** | 50.2 MB | 44.7 MB |
| **mmdebstrap `--variant=minbase`** (bookworm) | 165.0 MB | 101.6 MB | 89.6 MB |
| mmdebstrap minbase (trixie) | 120.2 MB | — | — |

The OCI base is **~52% smaller** (the official image strips locale/doc/man via `dpkg path-exclude`),
**inverting** the §13.6 hypothesis. Build wall-clock: mmdebstrap minbase 13–18 s; OCI assemble 0.4 s.

## Guest agent: musl vs glibc (§13.3) *(unchanged)*

| Variant | stripped | linkage | rootfs-independent |
| --- | --- | --- | --- |
| glibc-dynamic (default) | 1,479,512 B | dynamic PIE (needs libc6) | No |
| musl-static | 1,571,424 B | static-pie (self-contained) | Yes |

musl-static is **6.2% larger**, builds without `musl-gcc` (pure-Rust agent). Real deciding axis is
toolchain-availability + rootfs-independence, not size → keep glibc-dynamic default.

---
*Full analysis, methodology, and the open-question resolutions are in `implementation-notes.md`
("Benchmark results — resolving the §13 / §15 open questions" and the later fix sections). The detailed
in-notes §13 tables were the first pass on the then-pinned 6.6.9 kernel; this doc is the canonical
re-run on the committed 6.12.94 pin.*
