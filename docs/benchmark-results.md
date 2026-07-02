# Benchmark Results

Performance results for the `vmcell` framework: hot-path overheads (micro-benchmarks) and
KVM lifecycle/density/size metrics (macro-benchmarks). Per design §13.7 these are **tracked metrics,
not pass/fail gates** — absolute numbers are hardware-bound and only meaningful with their substrate.

> **Canonical numbers: the 2026-07-02 post-investigation matrix** (directly below) — the
> 2026-07-01 profile-matrix baseline plus the `docs/45` experiment pass (EXP-A…E, incl. the
> Firecracker warm-restore unlock). The historical pass sections further down record how the
> system got here (CH cold 642→330 ms, CH restore 166→84→60 ms); the detailed sub-analyses
> (kernel sweep, eager/lazy, footprint, suspend-size) were measured **pre-pass**: their
> *relative* conclusions still hold, but their absolute cold/restore ms are superseded by the
> tables below.

## Post-investigation matrix (2026-07-02 — after the docs/45 experiment pass) — CANONICAL

The docs/45 investigation (EXP-A…E) landed on top of the 2026-07-01 baseline below. Same
substrate/method. What changed: readiness-poll unification (EXP-A), `cryptomgr.notests
raid=noautodetect` cmdline trims (EXP-B), event-driven guest accept via poll(2) (EXP-C),
teardown grace deadline-before-RPC + adaptive poll step (EXP-D), and **Firecracker warm restore
unlocked** (EXP-E: capability now honestly `true`; plus the AGENT-2 guest reaper-race fix that
was the real cause of the historical "Agent … timed out" flake — QEMU now drops zero bench
iterations).

**Time-to-ready (latency mode), p50 / p95 ms — Δ vs the 07-01 baseline below:**

| Backend | `default` cold | `default` restore | `low_latency` restore |
| --- | --- | --- | --- |
| **Cloud Hypervisor** | 316 / 331 (≈) | **58 / 67** (−8) | 54 / 66 (≈) |
| **Firecracker** | 764 / 792 (−14) | **24 / 33** (NEW — was N/A; fastest restore tier) | **23 / 28** |
| **QEMU** (`q35`) | **965 / 995** (−38, and 20/20 iterations vs 16–17/20) | N/A (`snapshot_restore=false`) | N/A |

**End-to-end lifecycle (phase-budget TOTAL), p50 ms, `throughput` profile — Δ vs baseline:**

| Backend × path | baseline | post-experiments |
| --- | --- | --- |
| CH cold | 405 | **361** (teardown 95→56) |
| CH restore | 161 | **120** |
| **FC restore** | N/A | **64** (create 13 + connect 13 + exec 10 + teardown 31) |
| FC cold | 860 | **848** |
| QEMU cold | 1112 | ~1080 (n=14) |

Per-experiment attribution, mechanisms, bug-risk analysis, and the FC-restore unlock narrative:
`docs/45-claude-perf-investigation.md`; deviations: `docs/implementation-notes.md`.

## Profile-matrix re-run (2026-07-01, HEAD `37c5067`) — the docs/45 baseline

Same substrate as below; N=20 (latency) / N=12 (phase-budget), warmup=3, mem=256 MiB,
freq-pinned, warm-cache. This is the canonical backend × `Timeouts`-preset matrix.

**Time-to-ready (latency mode: start|restore → agent `Ready`), p50 / p95 ms:**

| Backend | `default` cold | `low_latency` cold | `default` restore | `low_latency` restore |
| --- | --- | --- | --- | --- |
| **Cloud Hypervisor** | 318 / 332 | **290 / 308** | 66 / 74 | **54 / 66** |
| **Firecracker** | 778 / 806 | 760 / 775 | N/A (`snapshot_restore` off, §3.2) | N/A |
| **QEMU** (`q35`) | 1003 / 1138 | 993 / 1097 | N/A | N/A |

**End-to-end lifecycle (phase-budget TOTAL: create+connect+exec+graceful teardown), p50 ms:**

| Backend × path | `default` | `throughput` |
| --- | --- | --- |
| CH cold | 604 | **405** |
| CH restore | 359 | **161** |
| FC cold | 1063 | **860** |
| QEMU cold | 1311 | 1112 † |

- The `low_latency` preset buys **−28 ms CH cold / −12 ms CH restore** (tighter guest accept poll
  5 ms + host cadences); FC/QEMU move only ~2% because their cold path is guest-boot-bound.
- The `throughput` preset (50 ms shutdown grace) cuts **~200 ms** off every graceful lifecycle;
  CH restore e2e lands at **161 ms**. (RAII `Drop` consumers pay ~27 ms teardown regardless.)
- † QEMU intermittently loses iterations to the known environmental agent-timeout flake
  (`docs/perf-experiments-log.md` "Flake investigation"): latency-mode counts were 17/20 and
  16/20, and the throughput phase-budget needed retries to complete a full n=12 pass (a
  failure breaks the phase loop). CH/FC dropped zero iterations across the whole matrix.
- vsock exec RTT floor re-confirmed: **p50 711 µs / p95 852 µs / p99 1013 µs** (CH, 200×).

## Substrate (this measurement pass — 2026-06-28 base; 2026-07-01 optimization pass)

- **Host:** Intel Core Ultra 7 258V (Lunar Lake), 8 cores / 8 threads; **base 2.2 GHz, turbo
  4.7 GHz**. 30 GiB RAM (~13 GiB free). Root FS ext4 on NVMe; **`/tmp` is tmpfs**.
- **Pinned tools:** Cloud Hypervisor v52.0.0, Firecracker v1.16.0, QEMU 10.2.1, virtiofsd 1.13.3,
  mmdebstrap 1.5.7; **guest kernel Linux 6.12.94** (the committed pin, distro-aligned with Trixie);
  rootfs base `debian@…` (trixie). Built from scratch via `vmcell build` under gcc 15.2.0.
- **mm:** THP `madvise`, **KSM on**. Macro runs go through the capability runner under
  `systemd-run --user --scope`, and are **CPU-frequency-pinned** (`performance` + turbo off →
  numbers sit at the **sustained 2.2 GHz base**, representative of dense/all-core operation).
- **Caveats:** "Cold" boot is **warm-cache** (`drop_caches` needs real `euid==0`, and tmpfs artifacts
  are immune). Micro-benchmarks run via `cargo bench` and are **not** freq-pinned. Shared-host load
  adds run-to-run variance — quote central tendency, not tails/SLAs.

## Micro-Benchmarks (`criterion`, in-process; not freq-pinned)

| Benchmark | Description | p50 (2026-07-01 re-run) |
| --- | --- | --- |
| `protocol_encode` | `postcard` encode of `Message::Exec` | 54.8 ns |
| `protocol_decode` | `postcard` decode | 86.2 ns |
| `cache_key_generation` | hashing struct variants + configs for the artifact cache key | 260 ns |
| `math_30_ipv4_parse` | `/30` host-IP parse (`10.200.<vmid>.1`) | 23.2 ns |
| `in_memory_tar2erofs_empty` | erofs node-tree pack of an empty tar, in-memory | 1.26 µs |

The control-plane codec and per-VM address/cache math are tens-to-hundreds of ns — far below the
multi-second VM lifecycle.

## Macro — Cold boot & Warm restore (start → guest agent `Ready`) — historical (opt-pass era)

N=20, warmup=3, mem=256 MiB. Cold = warm-cache (see caveats). All ms. **As measured right after
the 2026-07-01 optimization pass** (pre native-resync / pre shared-cmdline-builder; canonical
current numbers are in the profile-matrix section above):

| Backend | Cold p50 / p95 | Warm restore p50 / p95 |
| --- | --- | --- |
| **Cloud Hypervisor** | **330 / 346** | **84 / 94** (now 66 with native resync) |
| **Firecracker** | **776 / 787** | N/A (`snapshot_restore` gated off, §3.2) |
| **QEMU** (`q35`) | ~1400 (pre shared-cmdline; now ~1003) | N/A (`snapshot_restore=false`) |

- Warm restore is **~3.9× faster than cold** on CH — the per-test lever holds, now at **84 ms**. The
  optimization pass cut CH cold **642→330 ms** and CH restore **166→84 ms** with no invariant relaxed;
  FC cold dropped **1019→776 ms**. The two biggest levers were the verbose serial console (a
  `loglevel=6` cmdline that drops the KERN_INFO probe flood) and the guest's coarse vsock accept poll
  (100→20 ms) — details under "Latency optimization pass" below.
- **Kernel version is NOT the lever** (see the kernel-version sweep below). An earlier cross-session
  comparison suggested 6.12.94 restored ~2× slower than 6.6.9 (≈76 ms), but that was **not
  apples-to-apples** — the 6.6.9 figure came from a quieter earlier session. A **direct, interleaved
  6.6.143-vs-6.12.94 sweep** (same harness, same session) shows warm restore within **~2%** (CH 168 vs
  171 ms; FC 138 vs 134 ms) — so the gap was host-load noise, not a kernel cost. The §6 distro-aligned
  6.12.94 pin carries no measurable hot-path penalty.
- **Design §13.1 reference** (research-era figures): CH 324 ms cold / 47 ms restore — hardware- and
  pin-dependent; the *relative* invariants reproduce, the absolute ms do not. The optimization pass
  narrows the gap to those figures substantially (330 ms cold / 84 ms restore here).

## Latency optimization pass (2026-07-01)

The correct-but-slower code (vs earlier buggy-fast versions) carried recoverable latency in a few
conservative constants and one always-on grace sleep. This pass recovered it **without relaxing an
invariant** (fail-loud, the desync flag, the mandatory post-restore clock resync, re-bind-after-
restore, ordered teardown all preserved). Per-experiment deltas + bug-risk analysis:
`docs/perf-experiments-log.md`; the deviations: `docs/implementation-notes.md`.

| Metric (CH, p50) | baseline | final | Δ |
| --- | --- | --- | --- |
| cold boot → ready | 642 | **330** | −49% |
| warm restore → ready | 166 | **84** | −49% |
| phase COLD `connect` | 613 | **284** | −54% |
| phase RESTORE `connect` | 110 | **36** | −67% |
| graceful `shutdown()` teardown | 531 | **283** | −47% |

What changed (each measured independently, all kept):

1. **Quieter guest kernel boot** — `loglevel=6 random.trust_cpu=on random.trust_bootloader=on` on the
   cmdline (all backends). Full-verbosity printk to the byte-at-a-time 8250 UART was the single largest
   cold-boot tax; `loglevel=6` drops the `KERN_INFO` (6) device-probe flood — the bulk — while keeping
   `NOTICE`/`WARN`/`ERR` (a debuggable serial log, incl. the "Linux version" banner the `boot.rs`
   integration test asserts on, and every oops/panic line `contains_panic` relies on). The largest
   single lever: **CH cold −270 ms / FC −180 ms** at the more-aggressive `quiet loglevel=3` first tried,
   of which `loglevel=6` keeps all but ~43 ms (CH) — the ~43 ms is the cost of the retained
   notice/warn lines, paid to keep the serial log non-empty for debugging + panic capture. (An empty
   serial log broke `boot.rs` and would blind a boot-failure post-mortem; §12.10 panic capture depends
   on it.)
2. **Guest vsock accept poll `ACCEPT_POLL` 100→20 ms** (+ `REBIND_IDLE` 1 s→250 ms). The 100 ms poll
   sat directly on the critical path — the host blocks for `Ready` between its completed CONNECT/OK
   handshake and the guest's next `accept()`. **CH restore −71 ms (the single biggest restore win),
   cold −74 ms.**
3. **Graceful-`shutdown()` teardown** — new `VmInstance::has_exited()` poll + `SHUTDOWN_GRACE`
   500→250 ms, so `shutdown()` returns when the guest actually powers off instead of always sleeping
   the full window. **−246 ms.** (The fast `Drop` force-kill teardown, ~27 ms, is unchanged — see the
   budget note below.)
4. **Tighter host connect cadence** — backoff floor/cap 50/500→20/100 ms + reset-on-UDS-connect,
   OK-read timeout 500→150 ms, CH api-socket poll 20→5 ms. Marginal on CH (**−4 cold / −6 restore**),
   but confirms the connect slack is guest-side and improves worst-case robustness.

## Tunable config knobs + native resync (2026-07-01 follow-up, design 44)

Made the pass's constants per-VM tunable and removed the last restore subprocess cost. Details +
bug-risk per change: `docs/perf-experiments-log.md` (Phases 1–2); deviations: `docs/implementation-notes.md`.

| Result (CH, p50) | value | note |
| --- | --- | --- |
| **warm restore** (native in-agent resync) | 84 → **60 ms** | restore `connect` phase 36 → **16 ms** (3 subprocess execs incl. the multi-MB `ip` binary → one native `Resync` round-trip) |
| **QEMU cold boot** (shared cmdline builder → QEMU gains `loglevel=6`) | ~1400 → **996 ms** | fixed the triplication divergence where QEMU omitted `loglevel=` |
| **`throughput` profile teardown** (`shutdown_grace` 250→50 ms) | 283 → **96 ms** | graceful-`shutdown()` path; `Drop` stays ~27 ms |
| **`low_latency` profile cold** (guest `accept_poll` 5 ms + tight host cadence) | 327 → **309 ms** | guest poll now tuned via `vmcell_accept_poll_ms=` cmdline token |
| **logging VM-exit cost** (`verbose` vs `balanced` cold) | 330 → **561 ms** | +231 ms = the 8250-UART PIO-exit cost of `KERN_INFO` (answers "does logging cause VM exits": yes) |

**Restore, full journey:** 166 (original) → 84 (opt pass) → **60 ms** (native resync) = **−64%**.
`KernelVerbosity` (Quiet/Balanced/Verbose/Debug) + `Timeouts { …, low_latency(), throughput() }` are on
`VmConfig`; guest-side polls travel on the cmdline (`vmcell_accept_poll_ms=`/`vmcell_rebind_idle_ms=`,
clamped guest-side). `perf kvm stat` for a direct exit count is blocked by `perf_event_paranoid=4` on
this host, so the `verbose`-vs-`balanced` A/B is the exit evidence.

## Console transport knob — virtio-console vs UART (2026-07-02, design 44 §1b)

`ConsoleMode` (default `Uart`=`ttyS0`; opt-in `VirtioConsole`=`hvc0`) on `VmConfig`. UART is a per-byte
PIO VM-exit; virtio-console batches over a virtqueue. Measured (CH cold, freq-pinned):

| console × verbosity | cold p50 | restore p50 |
| --- | --- | --- |
| uart × balanced | 316 | 75 |
| **virtio-console × balanced** | **291** | 67 |
| uart × **verbose** (`loglevel=7`) | **558** | 75 |
| **virtio-console × verbose** | **299** | 70 |

**Virtio-console makes boot ~independent of log verbosity** (291→299 ms balanced→verbose) where UART
scales with it (316→558 ms): `virtio-console + verbose` = **299 vs 558 ms UART (−46%)** — full kernel
logs without the UART VM-exit tax. Restore works (67-70 ms → validates the CH `console.file` restore
rewrite end-to-end); QEMU virtio-console boots (validates that wiring). Default is `Uart` because
virtio-console (`hvc0`) only exists after virtio-pci probe → loses early-boot + pre-virtio panic capture
(a correctness floor); **Firecracker has no virtio-console** → `VirtioConsole` is rejected loud+early
(`Error::Unsupported{feature:"virtio_console"}`). Use `Uart` for panic/kernel-log tests, `VirtioConsole`
for guest-code tests wanting a cheaper boot / cheap verbose logs.

Validation for this whole follow-up: `just ci` green (semver: `vmcell` 0.2→0.3 for the intentional
`AgentClient::connect` arity change); unit 253/0; the full `just test-privileged` is green under
`retries=2`+`kind(test)` (see the flake section below — the intermittent CH-vsock reset is environmental,
absorbed by fresh-VM retries).

## Macro — Kernel-version sweep (6.6.143 vs 6.12.94)

Direct, **interleaved** comparison (same harness/session, freq-pinned, N=20) built with the
multi-kernel pipeline (`vmcell build-kernels`; `bench-vm --kernel <label>`). One shared rootfs.

| Metric | 6.6.143 | 6.12.94 | Δ |
| --- | --- | --- | --- |
| Cold boot p50 — CH / FC / QEMU (ms) | 607 / 996 / 1579 | 642 / 1022 / 1411 | +6% / +3% / −11% |
| **Warm restore p50 — CH / FC (ms)** | **168 / 138** | **171 / 134** | **+2% / −3% (noise)** |
| Eager / lazy restore p50 — CH (ms) | 257 / 170 | 262 / 173 | +2% / +2% |
| Footprint per-guest RAM (MiB) | 56 | 58 | +2 |
| KSM dedup steady-state (MiB) | ~381 | ~393 | ≈ equal |
| Phase: RESTORE connect / total (ms) | 109 / 186 | 118 / 200 | +8% / +7% |
| vsock-rtt p50 (µs) | 705 | 718 | +2% |
| suspend-size (256 MiB guest) | 256.0 MiB | 256.0 MiB | flat |

**Verdict: the guest kernel version does not materially change boot, restore, footprint, or
datapath.** Warm restore is within ~2% on both backends, the restore-`connect` phase the earlier
session flagged is only ~8% higher on 6.12 (not 2×), and per-guest RAM differs by ~2 MiB. The
**earlier 6.6.9-vs-6.12.94 ~2× restore gap was cross-session host-load noise**, not a real kernel
effect — exactly what making the kernel a first-class dimension was built to settle. The
distro-aligned (§6) 6.12.94 pin is free of any measurable hot-path cost; 6.6.143 is kept in the
registry as a tracked alternative.

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

## Macro — Per-test critical-path budget (CH, n=12) — 2026-07-01 re-run

Default profile (graceful `shutdown()` teardown); throughput-profile totals in the
profile-matrix section above.

| Phase | COLD p50 / share | RESTORE p50 / share |
| --- | --- | --- |
| create (`start` \| `restore`+`resume`) | 44 ms / 7% | 54 ms / 14% |
| connect (vsock + handshake [+resync]) | **279 ms / 45%** | **22 ms / 6%** |
| exec (`/bin/true`) | 4 ms / 1% | 5 ms / 1% |
| teardown (graceful `shutdown()`) | 285 ms / 47% | 279 ms / 78% |
| **TOTAL** | **≈604 ms** | **≈359 ms** |

Cold is now guest-boot-bound but ~50% smaller (`connect` 591→284 ms after the `loglevel=6` cmdline +
accept-poll levers); restore `connect` collapsed to **~36 ms** (was 115 ms) after the guest accept
poll dropped to 20 ms — the resync (clock/RNG/MAC) execs now dominate that small residue.

**Teardown caveat.** This budget measures the *graceful* `MicroVm::shutdown()` (`request_shutdown`
→ poll `has_exited` up to the 250 ms grace → force-kill), so its ~283 ms is the grace ceiling, not a
leak. The **fast per-test teardown is the `Drop` path** (force-kill the VMM process group + reap,
**~27 ms**, §12.10) — a consumer that lets the `MicroVm` drop (RAII) pays that, not the graceful
grace. The optimization pass halved the graceful path (531→283 ms) and left the fast `Drop` path
untouched.

## Macro — Datapath: vsock exec round-trip (CH, 200×)

**p50 711 µs, p95 852 µs, p99 978 µs, max 1042 µs** (post-pass re-run; incl. in-guest fork/exec/reap)
— a sub-millisecond control-plane floor at the base clock, unchanged by the optimization pass (the
poll-cadence levers touch connect/accept, not the established-stream exec RTT); not an `exec`
bottleneck.

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
