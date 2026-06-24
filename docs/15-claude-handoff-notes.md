# Imp Testing — Designer Handoff Notes

*For a future Claude continuing this project. You already have the latest **requirements**, **design doc** (`imp-testing-design.md`), and **implementation notes**. These notes are the layer that isn't in those: the reasoning behind settled decisions, what's still open, what has burned us, and how to work with this person. Read this first, then the design doc.*

---

## 1. Orientation

Imp Testing is a Rust library that runs each integration test for the **Imp** agentic harness inside its own micro-VM (structural isolation, hermetic state, production fidelity). The person you're working with, Victor, is building Imp; this project tests it.

**Document map.** Inputs arrive as numbered files (`1-…`, `2-…`, …) in rough chronological order: research reports (often a Gemini/Claude pair on the same question), fact-checks of those reports, design-doc revisions, and implementation notes from an agent building against the design. The **design doc is the single source of truth**; everything else is provenance. The design doc carries inline "**(observed)**" call-outs wherever a finding came from an actual implementation pass — preserve that convention so the empirical parts stay distinguishable from the reasoned parts.

**Where things stand.** The architecture is stable and has survived three implementation passes and a dependency study without being overturned. Two pure-Rust substitution experiments have graduated into the baseline (rootless networking, erofs build); two were rejected/postponed; one is underway. No code skeleton exists yet — there's a `Cargo.toml` sketch (also embedded in design §5.5) but `src/` hasn't been written.

---

## 2. The decision ledger — settled, don't reopen without new evidence

These are load-bearing and were each chosen for a reason. If you find yourself "helpfully reconsidering" one, check the reason first — most reversals would be re-litigating a closed question. New evidence can reopen any of them; a vague sense that there might be a cleaner way cannot.

- **VMM = Cloud Hypervisor, run as a subprocess over its REST socket.** Not embedded — it has no embeddable library crate, and it's the only option that does virtio-fs + vsock + nested virt + snapshot *simultaneously*. Firecracker is an optional dense backend (no virtio-fs, no nesting). QEMU is the fallback nester. The `Vmm`/`VmInstance` trait is the boundary.
- **Rootfs = erofs, read-only, shared across all VMs with no per-VM copy; tmpfs overlay for writes.** This killed two v1 bugs at once (ext4 journal-recovery panic on RO mount; concurrent-mount corruption), composes with snapshot (a plain block device, not vhost-user), and recovers some of the page-cache-sharing density that DAX would have given (DAX is gone — see open threads).
- **Rootfs source = `mmdebstrap` minbase, NOT OCI.** Preserves apt signing-chain verification (`InRelease`/`Release.gpg` + rPGP) and timestamp-reproducibility via snapshot.debian.org. The OCI alternative is postponed; the full reasoning (including that OCI-as-build-source would be performance-neutral, so the real trade is signing vs convenience) is in design §10 Exp 4 — read it before anyone reopens OCI.
- **Rootfs build = `am-fs-erofs`, in-memory tar→erofs (graduated); `mkfs.erofs` fallback.** Runs unprivileged (no device nodes / root uids on the host).
- **Control plane = vsock + a Rust guest agent as PID 1**, postcard framing, accept-in-a-loop, reconnect-after-restore. NO SSH except as a human debugging fallback.
- **Agent linking = dynamic-glibc by default; static-musl optional.** The "no libraries early" worry that motivates static-musl applies to initramfs, not to a rootfs-as-init that already ships `libc6`. Static-musl needs `musl-tools`, which isn't installable unprivileged in some CI.
- **Networking = two modes behind `NetConfig`.** Privileged: netns + tap + `/30` + nftables TPROXY. Rootless: in-process `smoltcp` + `vhost-user-backend` NAT (graduated). **passt is dead** — it's CH-incompatible because its C seccomp filter drops the `accept4` CH's vhost-user connection needs, with no opt-out. Don't propose passt.
- **nftables rules applied via the `nft` *binary*, not a crate.** `rustables` is GPL-3.0 (disqualified); no permissive crate covers the TPROXY + `socket` expressions. This is Exp 2, rejected.
- **Snapshot/restore sequencing is exact** (all observed against CH): `snapshot` = pause → snapshot → resume; restore = launch `--restore` → `resume`, **never** create/boot (CH returns 500 "VM is already created"). On restore, rotate identity (CID/MAC), reseed entropy, resync the clock, and **reconnect the vsock** (CH re-creates the host socket, severing the old connection; the agent must survive the EOF and re-accept).
- **Source layout = one package, 2024 edition**, lib + CLI bin + a feature-gated lean guest-agent bin. `cargo-deny` is the license gate and the *source of truth* on licensing (not hand-written labels).

---

## 3. Open threads — likely to come up next

- **`am-fs-erofs` license is UNVERIFIED.** It's obscure enough that a web search couldn't confirm its license. It's been adopted as the default erofs builder, so **run it through `cargo-deny` before trusting it**; `mkfs.erofs` is the fallback if it's copyleft or unmaintained. This is the most important loose end.
- **`fuse-backend-rs` experiment (Exp 1) is not concluded.** Scaffolded behind `experiment-fuse`, virtiofsd as fallback. Open question is whether in-process virtio-fs delivers the density win without destabilizing the data path. Note it does **not** fix the snapshot↔virtio-fs fork for an external CH (CH still sees a vhost-user device; the fix needs CH-internal adoption, CH #7250).
- **The snapshot↔virtio-fs fork (highest-risk unknown).** The erofs-block rootfs snapshots cleanly, but whether virtio-fs *data* shares can be re-attached to a snapshotted VM on the pinned CH/virtiofsd is **unvalidated**. This gates the M8↔M3 interaction. Build both paths (virtiofsd data shares vs extra erofs/block data images) and pick per tier from measurement.
- **No performance numbers are validated.** Don't quote boot times (<100 ms vs ~200 ms are both in the inputs and unreconciled), density, or restore latency as fact — they must be benchmarked on real kernel/rootfs/hardware. With snapshot/restore, cold-boot numbers fall off the per-test critical path anyway.
- **No code yet.** The natural next build step is the M0–M2 skeleton: `Cargo.toml` (sync it with §5.5), the `Vmm`/`VmInstance` traits, the vsock handshake state machine, the kernel config fragment as a real file, a `FakeVmm`, and `deny.toml`.
- **Two CH-version-dependent claims to re-check on the pin:** DAX availability (treated as unavailable per the Claude fact-check's primary-source quote — re-check `docs/fs.md`) and userfaultfd lazy restore in v52 (claimed, unconfirmed).

---

## 4. Landmines — things that have actually burned us

- **Crate licenses: verify, never trust the label.** `rustables` presented as MIT/Apache in an earlier draft; it's GPL-3.0. The `cargo-deny` allow-list is the gate. Apply the same suspicion to every obscure crate (currently `am-fs-erofs`).
- **The Gemini-research optimism pattern.** Across rounds, Gemini reports have recommended obscure single-author crates (`herolib-virt`, `jip-nftables`), overclaimed maturity (erofs writers, DAX), and underweighted implementation cost (smoltcp framed as easy). Cross-check Gemini claims against primary sources before folding them in.
- **"Most recent ≠ most correct."** A *later* Gemini fact-check re-introduced the DAX error that an *earlier* Claude fact-check had already refuted with a verbatim source quote. Don't defer to recency; defer to the better-sourced claim, and flag conflicts explicitly.
- **Subprocess supervision is silently fatal if sloppy.** A misconfigured `virtiofsd` exits immediately, but if you only poll for its socket, CH hangs forever. Always surface the child's exit/stderr and bound the socket-wait with a timeout. (And the flag is `--readonly`, not `--read-only`.)
- **OCI: keep build-source and runtime-mechanism distinct.** Conflating them produces a wrong performance answer (design §10 Exp 4 has the full reasoning).
- **Don't reverse a graduated/settled decision to chase tidiness.** If a substitution was rejected (e.g., pure-Rust nftables) or a tool kept (mmdebstrap), the reason is recorded; re-proposing it without new evidence wastes the person's time.

---

## 5. How to maintain the artifacts

- **The design doc is living, edited via `str_replace`.** Keep section numbers stable — cross-references use `§N` throughout, and renumbering breaks them. Before a big restructure, grep for references to the sections you're moving.
- **Two copies of the `Cargo.toml` exist:** the standalone artifact and the embedded copy in design §5.5. They can drift — when you change one, change both (and re-verify; e.g., confirm the standalone copy has the `rustables` removal and the smoltcp/am-fs-erofs/fuse additions).
- **A `deny.toml` was offered but may not be written yet.** It's the concrete form of the license gate; creating it is low-effort, high-value.
- **When new inputs arrive** (research or implementation notes): assess critically *first* — verify the load-bearing, checkable facts (especially crate licenses/versions) with a search when the stakes are real — *then* fold conclusions in, *then* offer the handoff. For experiments, classify each as graduated / rejected / postponed / underway and reflect adopted ones in the main body, not just the experiments section.

---

## 6. Working with Victor

- **Calibrate deep.** He's a senior systems engineer (ex-Google/Fuchsia, low-level virtio driver work, strong Rust, IOI-level competitive programming). Don't over-explain fundamentals; do show your reasoning on trade-offs.
- **Preferences, consistently expressed:** terse reference documentation; primary-source grounding; **honest trade-offs with explicit caveats over reassuring-but-unvalidated recommendations**; permissive licensing only for linked crates (MIT/Apache/BSD — no copyleft); no flattery or filler.
- **He runs a tight loop:** parallel research → fact-check → design → an agent implements → notes back → refine. He sends research specifically to be assessed — be critically honest and name what's wrong (he responded well to the `rustables`-license catch and to the OCI performance reframe). Matching his rigor is the job; agreeing pleasantly is not.
- **Disposition that has worked here:** verify before asserting; flag what's unvalidated rather than papering over it; keep the design robust to the *conservative* reading of contested facts; push back with reasons when a proposal has a real problem. When something is genuinely uncertain (a crate's license, a performance number), say so and say how to resolve it, rather than guessing confidently.
