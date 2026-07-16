# Benchmark Results

Performance results for the `vmcell` framework: hot-path overheads (micro-benchmarks) and
KVM lifecycle/density/size metrics (macro-benchmarks). Per design §16 (Performance) these are **tracked metrics,
not pass/fail gates** — absolute numbers are hardware-bound and only meaningful with their substrate.

> **Canonical numbers: the 2026-07-15 full backend×mode matrix** (directly below) — the re-run
> after the QEMU suspend/resume + session-persistence + security-hardening rounds, which adds the
> first QEMU restore/suspend numbers and confirms no latency regression on CH/FC. The
> **2026-07-04** matrix beneath it is the prior canonical (it confirmed the 2026-07-02
> post-investigation matrix and filled the FC/QEMU coverage gaps); the 2026-07-02 section is below
> that, then the 2026-07-01 profile-matrix baseline plus the `docs/45` experiment pass (EXP-A…E,
> incl. the Firecracker warm-restore unlock). The historical pass sections further down record how
> the system got here (CH cold 642→330 ms, CH restore 166→84→60 ms); the detailed sub-analyses
> (kernel sweep, eager/lazy) were measured **pre-pass**: their *relative* conclusions still hold,
> but their absolute cold/restore ms are superseded by the tables below.

## Full backend×mode matrix (2026-07-15, HEAD `7497b26`) — CANONICAL

Re-run of the whole `scripts/perf-matrix.sh` after the development rounds since the 2026-07-04
matrix (`c6eeefc..HEAD`, 15 commits): **session persistence**, **CoW cloning**, the **mandatory
VMM seccomp + jailer** (`vmm/seccomp.rs`, `vmm/jail.rs` — new; every spawn now
`fork → apply_jail → execve`, and QEMU gained `-sandbox`), daemon security, dep bumps, and — the
headline — **QEMU suspend/resume** (in-kernel `vhost-vsock` transport + `migrate`/`-incoming`).
Same substrate/method as the 2026-07-04 matrix: freq-pinned at the 2.2 GHz base via the blessed
runner under a delegated cgroup scope, warm-cache, mem=256 MiB, `default` profile. N=20 (latency) /
N=12 (phase-budget) / N=200 (vsock-rtt) / 8 concurrent (footprint). Suspect deltas were
re-measured, and the no-regression call was cross-checked against the `c6eeefc..HEAD` diff.

**Verdict: no latency regression in any measured area.** Every CH (primary) and FC headline p50
lands within run-to-run noise of 2026-07-04. The new spawn-path security layer is **negligible by
construction, not just by measurement**: `JailConfig::default()` is `hardened` with
`seccomp_deny_list=false`, so `apply_jail` compiles no BPF and adds only three async-signal-safe
child syscalls (`setrlimit(RLIMIT_CORE=0)` + `prctl(DUMPABLE=0)` + `prctl(NO_NEW_PRIVS=1)`) in the
already-existing pre-`exec` fork window. CH's `--seccomp true` and FC's built-in filter were
**already the 2026-07-04 default** (`vmm_seccomp_args("firecracker", …)` returns an empty vec), so
the seccomp *centralization* adds nothing to CH/FC; the only genuinely-new VMM confinement is
QEMU's `-sandbox` (off→on), a few-ms one-time filter compile that is below the benchmark's
resolution and left QEMU cold p50 within its documented cross-session band. What is genuinely new
is all-QEMU: warm restore, suspend-size, and better cold-boot robustness.

**Time-to-ready (latency mode), p50 / p95 ms** (Δ vs 2026-07-04):

| Backend | cold | restore |
| --- | --- | --- |
| **Cloud Hypervisor** | 317 / 335 (≈) | **49 / 64** (−8, ≈noise) |
| **Firecracker** | 761 / 789 (≈) | **26 / 33** (=) |
| **QEMU** (`q35`) | **1002** / 1078 (p50 ≈; **20/20 iters, 0 dropped** vs 18/20) | **462 / 476** (NEW — was `snapshot_restore=false`) |

- **QEMU warm restore ≈462 ms** is the new capability. It is slower than CH (49) / FC (26) because
  QEMU restore streams the **full memory image** through `migrate-incoming` (`file:`) — no
  demand-paged/UFFD lazy backend (`lazy_restore=false`, §17). The restore rotates the host-global
  guest CID, so concurrent QEMU zygote fan-out is sound (`restore_rotates_host_paths=true`).
- **QEMU cold-boot is now flake-free by count**: 20/20 iterations completed (baseline dropped 2/20).
  The new `verify_control_plane` health-gate + re-spawn loop (`CONTROL_PLANE_PROBE_BUDGET=4 s`,
  `MAX_CONTROL_PLANE_RESPAWNS=4`) *recovers* the ~11 % external-`vhost-device-vsock` bring-up flake
  instead of dropping the iteration; the cost is a rare (~1/20) ~5 s p99 tail on the recovered boot
  (4 s probe budget + ~1.3 s re-spawn). p50 is unchanged (~1002 ms, re-measured 1004) — the
  health-gate pays the guest-boot wait once, then `agent()` re-connects cheaply.

**Phase-budget, p50 ms (`default` profile: create + connect + graceful `shutdown()` teardown):**

| Backend | path | create | connect | exec | teardown | TOTAL |
| --- | --- | --- | --- | --- | --- | --- |
| **CH** | COLD | 39 | 267 | 3 | 264 | **~579** |
| **CH** | RESTORE | 52 | 3 | 5 | 257 | **~321** |
| **FC** | COLD | 41 | 725 | 5 | 278 | **~1057** |
| **FC** | RESTORE | 15 | 13 | 9 | 43 | **~78** |
| **QEMU** | COLD † | 118 | 870 | 5 | 303 | **~1303** |
| **QEMU** | RESTORE | **448** | 8 | 9 | 328 | **~798** (NEW) |

- **QEMU RESTORE phase-budget is `create`-bound (448 ms / 56 %)** — the `migrate-incoming`
  full-memory load, consistent with the 462 ms restore-latency figure. `connect` collapses to 8 ms
  (the guest is already booted in the stream), the mirror of the cold path's boot-bound 870 ms.
- † **QEMU COLD phase-budget is not a like-for-like comparison** with 2026-07-04. Snapshot-taking
  modes (phase-budget, suspend, restore) select the in-kernel `vhost-vsock` transport, whereas the
  2026-07-04 QEMU cold row used the external daemon. So the +33 ms TOTAL is a transport change, not
  a regression, and the n=12 completing on the **1st attempt** (baseline needed 3) reflects the
  deterministic in-kernel device removing the external-daemon race — *not* the re-spawn recovery
  (which is a no-op on the in-kernel endpoint). QEMU cold *latency* above (1002 ms) is the
  like-for-like external-daemon comparison and is within band. CH/FC phase-budget are like-for-like
  and flat-or-improved.

**Datapath — vsock exec round-trip (`/bin/true`), µs** (re-measured; central tendency):

| Backend | p50 | p95 | p99 |
| --- | --- | --- | --- |
| **Cloud Hypervisor** | 697–723 | 832 | 936 |
| **Firecracker** | 728 | 823 | 965 |
| **QEMU** | **723** | 837 | 901 |

Sub-millisecond floor on all three, unchanged. A single QEMU matrix sample read p50 915 µs; two
re-measurements returned 820 then **723 µs** with CH/FC controls at 728 µs the same session —
**shared-host load, not a regression**; QEMU remains the fastest backend, as at baseline. exec RTT
is in-guest fork/exec/reap-dominated and the transport/`-sandbox` do not touch it.

**Suspend-state size on disk (256 MiB guest):**

| Backend | total | memory-file share | note |
| --- | --- | --- | --- |
| **CH** | 268.5 MB | 100 % | dense: full memory-file (`memory-ranges`) |
| **FC** | 268.4 MB | 100 % | dense: full `mem_file` |
| **QEMU** | **52.2 MB** | 100 % | **sparse**: `migrate file:` streams only populated/non-zero pages |

- **QEMU snapshots are sparse for free** (~52 MB vs CH/FC's dense 256 MB): QEMU migration skips zero
  pages, so a snapshot tracks the guest's touched working set (~52–59 MB here, matching footprint),
  not the full RAM allotment. For CH/FC, sparse-snapshot (`SEEK_HOLE`) remains the warm-pool-density
  lever; QEMU gets it inherently from the migration stream. The small size is an optimization, not a
  truncation — the restore connects + execs every iteration.

**Guest-RAM footprint & density (8 concurrent, 256 MiB), per-guest resident** — unchanged vs
2026-07-04: CH ≈57 MiB `RssShmem` (memfd), FC ≈57 MiB `RssAnon` (private), QEMU ≈59 MiB `RssShmem`
+ ≈21 MiB `RssAnon` VMM overhead (heaviest resident VMM). CH `--ksm-mergeable` still dedups the bulk
of identical-guest RAM. Dead-linear per added guest on every backend.

**Coverage caveat — what this matrix does *not* reach.** The core modes are scoped to **single-VM,
no-network (`NetConfig::None`), library-direct (no `vmcelld`/broker), one-shot `AgentClient`**
lifecycle. They *do* bound the changed spawn path (seccomp/jailer land on the measured `create` phase
for all three backends) and the rewritten connect/handshake law (measured by the `connect` phase +
vsock-rtt on both the Unix and Vsock arms). The **follow-up probes below** (added 2026-07-15,
collected every run) cover the surfaces this pass flagged as unreached — round 1: unprivileged
smoltcp NAT egress (`net-egress`), CoW / zygote fan-out (`zygote`), the daemon HTTP + broker bridge
(`perf-daemon.sh`); round 2: **privileged** networked start (netns + tap + 1 `nft` spawn + tproxy,
via `net-egress --net-mode privileged` under the blessed runner's `CAP_NET_ADMIN`), the **TLS-MITM
egress proxy** per-connection cert mint + handshake (`--net-mode tls`/`privileged`), interactive
**sessions** (`--mode session`: the `SessionMux` second handshake + per-session open), and the daemon
**`restore_cow`** tree-copy (`perf-daemon.sh` `restore`). The **only** surface left deliberately
unmeasured is the MITM proxy→origin (upstream) TLS handshake: hudsucker pins `with_webpki_roots()` on
the upstream leg, so a hermetic self-signed local origin is rejected and measuring it would require a
webpki-trusted public origin over the host's internet (WAN latency + external dependency) — out of
scope for a controlled probe. Every other changed latency surface is now bounded.

### Follow-up probes — egress, zygote fan-out, daemon API (2026-07-15)

Three probes for the changed-but-unmeasured paths above, shipped in `scripts/perf-matrix.sh` so
they run every matrix: `bench-vm --mode net-egress` and `--mode zygote` (per backend, self-skipping
where unsupported) and the standalone `scripts/perf-daemon.sh`. Same freq-pinned substrate as the
matrix above, **except the daemon probe** (a plain backgrounded process — read its `list` bridge
floor and deltas, not its absolute create).

**Networked egress (`net-egress`; CH + QEMU — Firecracker has no unprivileged vhost-user-net, skips).**
Unprivileged smoltcp NAT + `Egress::Open` to an in-process host endpoint; the guest curls it through
the NAT and a real returned byte is asserted (data-plane, not a proxy signal).

| Backend | NET-START p50 / p95 (boot WITH NAT) | egress RTT p50 / p95 (in-guest curl→NAT→host) |
| --- | --- | --- |
| **CH** | 309 / 331 ms | **36.8 / 41.7 ms** |
| **QEMU** | 1062 / 1079 ms | **36.6 / 37.7 ms** |

- NET-START vs the network-disabled cold boot (CH 317 ms, QEMU 1002 ms) is the **smoltcp NAT setup
  cost on the boot path** — small on both (the NAT threads start concurrently with the guest boot).
  The egress RTT (~37 ms on both) is ~50× a vsock exec (~0.7 ms): a full in-guest `curl` process +
  TCP through the **userspace** smoltcp NAT + host round-trip — the realistic cost a guest workload
  pays to reach a host service, which the vsock control-plane floor does not capture. It is backend-
  independent (the datapath is the shared smoltcp NAT, not the VMM).
- **Discovered: smoltcp bring-up flake.** ~10 % of networked boots the smoltcp `vhost-user-net`
  daemon never binds its socket in time (the daemon thread intermittently errors on start — sibling
  to the recorded ~11 % external-`vhost-device-vsock` flake). Latent because the egress *tests* boot
  one VM; this volume probe (13+ networked boots/run) exposes it. The probe retries a transient boot
  on a fresh VM (bounded, and prints `recovered N …` so it is surfaced, not hidden). Two fixes landed
  with it: (1) `spawn_qemu` now waits for the smoltcp socket before launch — QEMU's `-chardev socket`
  is a no-retry client that otherwise raced the lazy bind and crashed (`wait_for_socket` gained an
  `Option<&mut Child>` for the process-less thread producer; the same gate the vsock daemon already
  had). The root-cause fix (synchronous bind in `SmoltcpProcess::start`) is recorded open in
  `implementation-notes.md`.

**Zygote CoW fan-out (`zygote`; CH + QEMU concurrent, Firecracker single-clone control).**
Snapshot a base once, then time `Zygote::spawn_clones` restoring + resuming N=8 CoW clones
concurrently, plus time-to-agent-ready across all.

| Backend | fan-out to N total p50 / p95 | per-clone p50 | agent-ready-all p50 | CoW |
| --- | --- | --- | --- | --- |
| **CH** (N=8) | 440 / 467 ms | ~55 ms | 4 ms | FullCopy |
| **QEMU** (N=8) | 522 / 526 ms | ~65 ms | 9 ms | FullCopy |
| **FC** (N=1 control) | 125 / 132 ms | ~125 ms | 9 ms | FullCopy |

- **CoW is `FullCopy` on this host**: `restore_cow` reflinks the master snapshot dir, but the copy
  lands under `$TMPDIR` (tmpfs) with the master under `target/` (ext4) — neither is a reflink-capable
  fs (XFS/Btrfs/bcachefs), so `FICLONE` falls back to a full byte copy. The per-clone figure is
  therefore the **non-reflink ceiling** (the whole snapshot is byte-copied); on a reflink fs it would
  collapse to the restore+resume alone. The probe prints `cow=Reflink`/`FullCopy` so it is never
  misread. **Fan-out is sub-linear**: CH's 8-clone total (440 ms) is only ~1.3× its 3-clone total
  (~348 ms) — the concurrent CoW copies + restores overlap, so per-clone drops from ~116 ms (n=3) to
  ~55 ms (n=8). QEMU's per-clone (~65 ms) beats its single-boot restore (~462 ms) because the sparse
  52 MB migrate stream copies far less than CH's dense 256 MB. agent-ready across all clones is a few
  ms — they are already resumed by `spawn_clones`; the fan-out cost is the CoW copy + restore + resume.

**Daemon API (`perf-daemon.sh`; CH).** vmcelld HTTP + broker-bridge overhead over the raw VMM op,
via `curl -w %{time_total}` (daemon-side request latency, excluding curl startup). NOT freq-pinned.

| Op | p50 / p95 | what it isolates |
| --- | --- | --- |
| **list** | **0.6 / 0.9 ms** | pure HTTP + broker bridge, NO VMM work — the **bridge floor** |
| **exec** | **2.9 / 3.8 ms** | bridge + in-guest vsock exec (~2 ms over the raw vsock-rtt ~0.7 ms) |
| **create** | 199 / 207 ms | full cold-boot-to-agent-ready THROUGH the HTTP + broker (defaults vcpus=2/mem=512) |
| **destroy** | 262 / 273 ms | teardown THROUGH the daemon (graceful grace, like the ~260 ms `shutdown()` path) |

- **`list` (~0.6 ms) is the clean bridge floor**: every daemon op forwards parent→broker over a
  length-prefixed JSON frame on top of HTTP routing/auth; with no VMM work behind it, that ~0.6 ms is
  the per-op tax the daemon adds. `exec` shows it on top of the vsock datapath (~2 ms over the
  library-direct vsock-rtt); `create`/`destroy` are dominated by the VM lifecycle they wrap, so their
  absolute figures are boot/teardown-bound (and not freq-pinned) — read the bridge delta, not the
  total. Percentiles are nearest-rank (matching `bench-vm`'s `pcts`).

### Follow-up probes, round 2 — privileged net, TLS-MITM, sessions, daemon restore (2026-07-15)

The four surfaces round 1 left unmeasured, now collected every run: `bench-vm --mode net-egress
--net-mode {tls,privileged}`, `--mode session`, and a snapshot+restore loop in `scripts/perf-daemon.sh`.

**Filtered / TLS-MITM egress (`net-egress --net-mode tls` and `--net-mode privileged`).** The guest
makes an HTTPS request through the `Egress::Filtered` proxy, which mints a per-connection leaf cert
(rcgen) and completes the guest↔proxy TLS handshake; a `TestDouble` short-circuits the origin (no real
upstream). A fresh unique `*.probe.local` host per iteration forces a cache-miss → **fresh cert mint
every request**. `tls` rides the unprivileged smoltcp NAT (CH+QEMU; FC has no vhost-user-net, skips);
`privileged` rides tap + netns + nft (all backends, via the runner's `CAP_NET_ADMIN`).

| Variant | NET-START p50 / p95 | MITM egress RTT p50 / p95 (cert mint + guest↔proxy TLS handshake) |
| --- | --- | --- |
| **CH `tls`** (smoltcp + proxy) | 318 / 343 ms | **166 / 169 ms** |
| **CH `privileged`** (tap+nft + proxy) | 334 / 349 ms | **79 / 79 ms** |
| **QEMU `tls`** | 1042 / 1077 ms | 168 / 171 ms |
| **QEMU `privileged`** | 1040 ms (5.3 s p95 tail †) | 79 / 80 ms |
| **FC `privileged`** | 798 / 812 ms | 80 / 82 ms |

- **The MITM RTT is dominated by per-connection cert minting** (RSA keygen + sign in rcgen): the smoltcp
  `tls` path is ~**166 ms** vs the plain-NAT HTTP egress (~37 ms) — a large tax paid once per *new*
  upstream host (a repeated host hits the moka authority cache and skips the mint; this probe measures
  the worst-case fresh-mint path by design).
- **`privileged` MITM (~79 ms) is ~2× faster than `tls` MITM (~166 ms)** — backend-independent on both
  (the cert mint is fixed; the datapath differs). The multi-round-trip TLS handshake pays the userspace
  smoltcp NAT's per-packet cost on `tls` but rides the in-kernel tap on `privileged`. The ~87 ms delta
  is the smoltcp-NAT overhead compounded over the handshake — a concrete argument for the kernel tap
  path where egress latency matters.
- **NET-START** for `privileged` (netns-create + tap-setup + 1 `nft` spawn + tproxy routing + in-netns
  proxy) and `tls` (smoltcp + proxy) both sit within ~30 ms of the plain cold boot — the net setup runs
  concurrently with the guest boot. † QEMU `privileged` shows the same rare ~5 s external-vsock
  bring-up tail seen in the cold-latency table; p50 is unaffected.
- **Out of scope: the proxy→origin (upstream) TLS handshake.** hudsucker pins `with_webpki_roots()` on
  the upstream leg, so a hermetic self-signed local origin is rejected; the real second handshake needs
  a webpki-trusted public origin over the host's internet (WAN latency + external dependency). The probe
  measures the mint + client-handshake path.

**Interactive sessions (`session`; all three backends, no capability gate).** The `SessionMux` layer the
one-shot `AgentClient` (measured by vsock-rtt) never exercises — a **second** vsock connection + its own
`Ready` handshake, plus per-session open→guest-spawn→exit. (No resume-by-id API: "persistence" means
long-lived sessions, not reattach; the connect handshake is the closest analogue.)

| Backend | session-connect p50 / p95 (2nd vsock handshake) | session-open p50 / p95 (open→spawn→exit) |
| --- | --- | --- |
| **CH** | 142 / 215 µs | 621 / 681 µs |
| **FC** | 161 / 247 µs | 632 / 683 µs |
| **QEMU** | 201 / 475 µs | 788 / 1334 µs |

- **session-connect (~140–200 µs)** is the mux's own second vsock connect + `Ready` handshake — the
  interactive layer's setup cost, distinct from the cached one-shot client vsock-rtt reuses.
  **session-open (~620–790 µs)** is the per-command open (no ack; timed to the terminal exit) —
  right on the vsock exec RTT floor (~0.7 ms), since it is the same in-guest fork/exec/reap round-trip
  plus session-registry bookkeeping. Sub-millisecond on all three; QEMU is marginally higher (its
  vsock/agent path).

**Daemon restore (`perf-daemon.sh` `restore`; CH; not freq-pinned).** Snapshot one VM once, then time N
restores via `POST /v1/vms` with `restore_from` — the `restore_cow` reflink tree-copy path.

| Op | p50 / p95 | vs |
| --- | --- | --- |
| **restore** | **269 / 282 ms** | daemon `create` 180 ms; library-direct CH restore ~49 ms |

- Daemon `restore` (269 ms) is **slower than the daemon `create`** (180 ms) here because `restore_cow`
  byte-copies the whole memory image (**FullCopy** — the store dir is not on a reflink fs, same as the
  zygote/CoW finding) before restoring, whereas cold create boots fresh. On a reflink fs the copy is
  near-instant and restore would beat create. The gap over the library-direct restore (~49 ms) is the
  FullCopy + the larger default geometry (512 MiB / 2 vCPU) + the HTTP/broker hop.

## Full backend×mode matrix (2026-07-04, HEAD `c6eeefc`) — PRIOR CANONICAL

Every applicable metric on every backend, run via `scripts/perf-matrix.sh` (a superset of
`perf-baseline.sh`; backends self-skip modes they cannot serve). Same substrate/method as the
2026-07-02 matrix: freq-pinned at the 2.2 GHz base via the blessed runner under a delegated cgroup
scope, warm-cache, mem=256 MiB, `default` profile. N=20 (latency) / N=12 (phase-budget) / N=200
(vsock-rtt) / 8 concurrent (footprint). **Purpose:** re-validate after the v20/v21 wave (artifact
validator, builder extraction, `vmcelld` daemon + client, magic-resource-naming removal) and fill
the coverage gaps (FC phase-budget, FC/QEMU vsock-rtt + footprint, FC suspend-size, QEMU metrics).
**Verdict: those changes did not move the hot path** — they are build tooling, a control-plane layer
over the same `MicroVm`, and a rename; no lifecycle-path code changed, and every headline p50 lands
within noise of 2026-07-02.

**Time-to-ready (latency mode), p50 / p95 ms:**

| Backend | cold | restore |
| --- | --- | --- |
| **Cloud Hypervisor** | 308 / 325 | **57 / 64** |
| **Firecracker** | 774 / 786 | **26 / 30** |
| **QEMU** (`q35`) | **960 / 1078** (18/20 — flake dropped 2, below) | N/A (`snapshot_restore=false`) |

**Phase-budget, p50 ms (`default` profile: create + connect + graceful `shutdown()` teardown):**

| Backend | path | create | connect | exec | teardown | TOTAL |
| --- | --- | --- | --- | --- | --- | --- |
| **CH** | COLD | 44 | 275 | 4 | 263 | **~583** |
| **CH** | RESTORE | 53 | 3 | 5 | 261 | **~320** |
| **FC** | COLD | 47 | 733 | 5 | 281 | **~1063** |
| **FC** | RESTORE | 16 | 9 | 8 | **43** | **~76** |
| **QEMU** | COLD | 126 | 849 | 5 | 293 | **~1270** (n=12, 3rd attempt) |

- **FC restore e2e (~76 ms) beats CH restore e2e (~320 ms) on the `default` profile, entirely on
  teardown** (FC 43 ms vs CH 261 ms). The FC guest actually powers off within the grace window, so
  `has_exited()` reaps it early; the CH guest does not exit within the 250 ms default grace, so CH
  pins at the grace ceiling and force-kills. This is a profile artifact, not a CH defect — the
  `throughput` profile (50 ms grace) collapses CH teardown to ~96 ms (see the throughput table).
- Cold path is guest-boot-bound on every backend (`connect` dominates: CH 47%, FC 69%, QEMU 67%).
  QEMU's `create` (126 ms) is ~3× CH/FC — the QEMU launch + `q35` machine model setup.

**Datapath — vsock exec round-trip (`/bin/true`), µs:**

| Backend | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- |
| **Cloud Hypervisor** | 853 | 1028 | 1455 | 2338 |
| **Firecracker** | 734 | 839 | 1046 | 1341 |
| **QEMU** | **711** | 818 | 868 | 1347 |

A sub-millisecond control-plane floor on all three backends (incl. in-guest fork/exec/reap). p50s
sit within ~140 µs of each other; the CH tail this run reflects shared-host load (the 07-01 CH
figure was p50 711 / p99 1013).

**Suspend-state size on disk (256 MiB guest):** CH 268.5 MB and FC 268.4 MB, both **100%
memory-file** (state ~52 KiB CH / ~14 KiB FC). Snapshot size tracks guest RAM exactly. QEMU skips
(`snapshot_restore=false`).

**Guest-RAM footprint & density (8 concurrent, 256 MiB), per-guest resident:**

| Backend | guest RAM (per guest) | VMM overhead (per guest) | KSM dedup over run |
| --- | --- | --- | --- |
| **CH** (shared memfd) | ≈57 MiB `RssShmem` | ≈0–1 MiB `RssAnon` | **0** (shared pages can't merge) |
| **CH `--ksm-mergeable`** | ≈58 MiB `RssAnon` (private) | — | **≈382 MiB** (`pages_sharing` +97,935) |
| **FC** (private anon) | ≈57 MiB `RssAnon` | (in the anon line) | 0 (not mergeable) |
| **QEMU** (memfd + heavier VMM) | ≈59 MiB `RssShmem` | **≈21 MiB `RssAnon`** | 0 |

Guest RAM is demand-paged (~57–59 of 256 MiB touched) and dead-linear per added guest on every
backend. QEMU carries the heaviest resident VMM overhead (~21 MiB/guest vs CH/FC ~0–6). The opt-in
CH `ksm_mergeable` lever still dedups the bulk of identical-guest RAM (~382 MiB here); it is CH-only
(needs `mergeable=on` + `shared=off`) and off by default.

### Firecracker restore-teardown exit line is benign (diagnosed 2026-07-04)

Every FC **restore** iteration prints one `Error: RunWithApi(MicroVMStoppedWithError(GenericError))`
to the console (exactly warmup+iterations lines per restore run; **zero** for cold, CH, or QEMU).
It is **not a fault**: FC's stderr is inherited (`firecracker.rs`, deliberate — surfaces real FC
panics/errors loud), and this is FC's own `main()` returning `Err(..)` as it exits. The graceful
`SendCtrlAltDel` teardown drives the restored guest to reset; FC reports that reset with exit code
`GenericError`(=1) where a cold guest's clean power-off yields `Ok`. Evidence it is benign: restore
produces fully valid samples (agent connects + exec succeeds every iteration; 26 ms p50), FC's `main`
returns the error and the **process exits on its own** (a Rust `Error:` print, not our uncatchable
SIGKILL — so `has_exited()` reaps it, `kill()` is skipped), and a single cold+restore run leaves
**zero residue** (no leaked `firecracker` processes, no leaked netns, scratch cleaned). Not
suppressed, because muting FC stderr would also hide real FC failures. It correlates with FC's fast
43 ms restore teardown above (the guest exits promptly rather than sitting at the grace ceiling).

### QEMU agent-timeout flake — root-caused and fixed (2026-07-04)

CH and FC dropped **zero** iterations across the entire matrix; **QEMU** did not (latency 2/20;
phase-budget, which `break`s its loop on the first timeout, needed 3 attempts for a clean n=12;
footprint aborted once on guest 0). Investigated with a purpose-built repro harness
(`crates/vmcell/tests/qemu_vsock_flake_repro.rs`) and reproduced at **~11% (13/120 boots)**.

**Root cause (mechanism, evidence-backed).** QEMU's vsock rides an **external `vhost-device-vsock`
daemon** over a **`vhost-user-vsock`** virtqueue (CH/FC terminate vsock *inside* the VMM — hence
QEMU-only). That bring-up **races**: on ~11% of boots the data path comes up **wedged for the VM's
entire life** — the daemon is alive and *accepts* the host `CONNECT`, but never reaches the guest
listener (a raw CONNECT probe returns `<no reply within 500ms>`, persistently), while the guest is
healthy (boots, no panic under `panic=1`, agent running). Because it is persistent-per-instance, the
host's 10 s of retries all fail. Ruled out with evidence: not the guest agent, not a guest hang, not
the re-bind idle window, not the host-facing UDS.

**Fix.** A post-boot **control-plane health-gate** in `MicroVm::start`
(`VmInstance::verify_control_plane`; QEMU override, default no-op for CH/FC). After boot it probes the
vsock path with a bounded budget (reusing `AgentClient::connect`, so the handshake lives in one
place); a wedged VM is **re-spawned** on the same per-VM resources (up to 4×, then fails loud) instead
of being handed back to time out ~10 s later at `agent()`. `spawn_qemu` pre-cleans stale sockets so
re-spawn is safe. **Validated 120/120 QEMU boots green** post-fix (P of that by luck without the fix
≈ 8e-7); full privileged suite 72/72 across all backends. The repro test is the committed red→green
gate (`#[ignore]`d; runs in `just test-privileged` via `--run-ignored all`, not in the KVM-free
`just ci`). *Measurement note:* QEMU `start()` now waits for the control plane to come live, so in a
future phase-budget re-run its cost shifts from `connect` into `create` (TOTAL unchanged).

## Post-investigation matrix (2026-07-02 — after the docs/45 experiment pass) — PRIOR CANONICAL

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
| **Firecracker** | 778 / 806 | 760 / 775 | N/A (`snapshot_restore` off, §2.3 — Firecracker — the density tier and the fastest restore) | N/A |
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
| **Firecracker** | **776 / 787** | N/A (`snapshot_restore` gated off, §2.3 — Firecracker — the density tier and the fastest restore) |
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
  171 ms; FC 138 vs 134 ms) — so the gap was host-load noise, not a kernel cost. The §5.1 (The base and the pin) distro-aligned
  6.12.94 pin carries no measurable hot-path penalty.
- **Design §16 reference** (Performance; research-era figures): CH 324 ms cold / 47 ms restore — hardware- and
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
   serial log broke `boot.rs` and would blind a boot-failure post-mortem; §13 — Cross-cutting invariants — panic capture depends
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
distro-aligned (§5.1 — The base and the pin) 6.12.94 pin is free of any measurable hot-path cost; 6.6.143 is kept in the
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
**~27 ms**, §13 — Cross-cutting invariants) — a consumer that lets the `MicroVm` drop (RAII) pays that, not the graceful
grace. The optimization pass halved the graceful path (531→283 ms) and left the fast `Drop` path
untouched.

## Macro — Datapath: vsock exec round-trip (CH, 200×)

**p50 711 µs, p95 852 µs, p99 978 µs, max 1042 µs** (post-pass re-run; incl. in-guest fork/exec/reap)
— a sub-millisecond control-plane floor at the base clock, unchanged by the optimization pass (the
poll-cadence levers touch connect/accept, not the established-stream exec RTT); not an `exec`
bottleneck.

## Artifact sizes (§16 — Performance) — OCI base vs mmdebstrap *(kernel-independent; unchanged)*

Packed **erofs** (the booted artifact; the pipeline ships **uncompressed** — `am-fs-erofs` emits no
compressed nodes):

| Base | erofs uncompressed (shipped) | erofs lz4 | erofs zstd |
| --- | --- | --- | --- |
| **OCI** `debian:trixie` slim | **79.2 MB** | 50.2 MB | 44.7 MB |
| **mmdebstrap `--variant=minbase`** (bookworm) | 165.0 MB | 101.6 MB | 89.6 MB |
| mmdebstrap minbase (trixie) | 120.2 MB | — | — |

The OCI base is **~52% smaller** (the official image strips locale/doc/man via `dpkg path-exclude`),
**inverting** the §16 (Performance) hypothesis. Build wall-clock: mmdebstrap minbase 13–18 s; OCI assemble 0.4 s.

## Guest agent: musl vs glibc (§16 — Performance) *(unchanged)*

| Variant | stripped | linkage | rootfs-independent |
| --- | --- | --- | --- |
| glibc-dynamic (default) | 1,479,512 B | dynamic PIE (needs libc6) | No |
| musl-static | 1,571,424 B | static-pie (self-contained) | Yes |

musl-static is **6.2% larger**, builds without `musl-gcc` (pure-Rust agent). Real deciding axis is
toolchain-availability + rootfs-independence, not size → keep glibc-dynamic default.

---
*Full analysis, methodology, and the open-question resolutions are in `implementation-notes.md`
("Benchmark results — resolving the §16 (Performance) / §15 (Testing strategy) open questions" and the later fix sections). The detailed
in-notes §16 (Performance) tables were the first pass on the then-pinned 6.6.9 kernel; this doc is the canonical
re-run on the committed 6.12.94 pin.*
