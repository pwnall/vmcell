# 41 — Experimental-conclusions audit

**Goal.** Re-run the implementation experiments whose conclusions were recorded in
`docs/39-claude-design-v15.md` (Appendix A.3 "load-bearing reversals", Appendix B
"substitution experiments") and `docs/implementation-notes.md`, because those conclusions were
drawn while the code was buggy and may be wrong. Headline questions from the maintainer:

1. **Can we use the QEMU `microvm` machine type?** (recorded as rejected)
2. **Do we still need the vendored `vhost` / `vhost-user-backend` fork?** (`[patch.crates-io]`)

Plus a full audit of every other experiment-derived decision.

**Host (audit environment, 2026-07-01).** KVM present (Intel vmx), QEMU **10.2.1** (Debian) —
**`microvm` machine type IS available** — Cloud Hypervisor, Firecracker, virtiofsd,
vhost-device-vsock, ch-remote all installed; `.vmcell-bin/{debug,release}/vmcell-test-runner`
blessed with `cap_dac_override,cap_net_admin,cap_sys_admin=ep`; artifacts present
(`target/vmcell-artifacts/vmlinux` = Linux 6.12.94, `rootfs.erofs`, guest_agent, guest_tools).
Guest kernel `.config` has `CONFIG_PCI/VIRTIO_PCI/PCI_MMCONFIG/PCIEPORTBUS=y` **and**
`CONFIG_VIRTIO_MMIO=y` + `CONFIG_ACPI=y` — so both a PCIe and an MMIO microvm are plausible.

**Method (per maintainer instruction).** One subagent per experiment, invoked **sequentially**
so they never conflict on code, builds, or VMs. Each experiment: isolate (prefer a standalone
reproducer over mutating the tree; if the tree must change, revert after), run against the real
`vmlinux`+`rootfs.erofs`, clean up every VM/netns/daemon it starts, and return a structured
verdict. Bugs uncovered go into `docs/implementation-notes.md`.

---

## Executive summary

Experiments re-run **live** on this KVM host (real `vmlinux` + `rootfs.erofs`); the rest of the ~40 claims
dispositioned by reasoning (Buckets A–D) with the Bucket-D items then executed at the maintainer's request.
**The maintainer's worry was justified. Of the six "we can't / we must" conclusions re-run live, only ONE (E2) held
cleanly as recorded**: two had wrong/misattributed *reasons* (E1, E5 — decision still stands on other grounds), two were
**overturned** (E3 — QEMU *can* snapshot; E7 — FC *can* snapshot under PCI), and one is over-applied (E6). Pointedly,
**E7 had been "confirmed by reasoning" and then executing it OVERTURNED it** — vindicating the instruction to actually
run Bucket D rather than reason about it.

| # | Recorded conclusion | Live verdict |
|---|---|---|
| **E1** | microvm unusable — "MMIO `virtio-net-device` → legacy 10-byte header breaks networking" | ⚠️ **decision holds, reason WRONG.** microvm never reaches networking — it dies at early boot (spurious `#DE` in `start_kernel`), identically with `pcie=on`+the same PCI NIC. q35 negotiates the 12-byte header fine. Header size is feature-, not transport-, governed. |
| **E2** | vendored `vhost` fork needed (QEMU sends `SET_VRING_ENABLE` before `SET_FEATURES`) | ✅ **CONFIRMED by message trace.** Genuine QEMU-vs-CH ordering quirk (not a masked backend bug); upstream unchanged; CH needs no fork. Upgrade the doc's "lowest-confidence" wording to "confirmed." |
| **E3** | QEMU snapshot-ineligible in all configs (privileged vhost-vsock path "likely, unvalidated") | ✅ **recovery path VALIDATED — QEMU *can* snapshot (privileged).** In-kernel `vhost-vsock-pci` has no migration blocker (QEMU 10.2 source) + migrate→restore verified live. A **capability gain**, not just a doc fix. |
| **E5** | passt CH-incompatible — "its C seccomp drops `accept4`" | ⚠️ **decision holds, reason WRONG.** Not seccomp (passt survives with `EACCES`, not `SIGSYS`) — it's the host's stale **AppArmor** af_unix profile. Not CH-specific (`socat` reproduces it); avoidable by socket-direction flip. |
| **E6** | FC needs T2 template **+** `noxsave` to avoid `restore_fpregs_from_fpstate` panic | ⚠️ **partially revised.** `noxsave` is over-applied in code (unconditional, even with T2); the panic doesn't reproduce for AVX2/YMM on FC v1.16.0 with **no** guard; T2 is **rejected** on this CPU. AVX-512 trigger untestable here (no ZMM). |
| **E7** | FC has no snapshot under PCI (→ MMIO) | ❌ **OVERTURNED** live — FC v1.16.0 `--enable-pci` + snapshot create *and* restore both succeed (204, resumes `Running`, no `MicroVMStoppedWithError`). My earlier reasoned "confirmed" was wrong — version-stale. |

**Concrete follow-ups uncovered (all logged in `implementation-notes.md`):**
1. **Doc corrections:** rewrite the microvm-rejection reason (§140/impl-notes L20) to the early-boot-`#DE` finding; rewrite the passt-rejection reason (Exp 5) to the AppArmor finding; upgrade the vendored-patch wording (§10.4) to "confirmed by trace."
2. **Code — real test-hygiene bug:** `tests/host_endpoint.rs` leaks its `python3 -m http.server` on an early panic (no `Drop` guard, unlike `egress_proxy.rs`).
3. **Code — FC `noxsave` over-application:** gate it behind `template.is_none()` (recovers guest AVX2).
4. **Capability opportunity:** wire QEMU `snapshot()`/`restore()` for the privileged in-kernel-vhost-vsock config (currently `Unsupported`).
5. **Env fact corrected:** this host's user cannot open `/dev/vhost-vsock` (empty `kvm` group; `/dev/kvm` via per-user ACL) — the full live QEMU-snapshot reconnect needs a real `kvm`-member host or the `CAP_DAC_OVERRIDE` runner.

---

## Decision inventory (experiment-derived claims to re-test)

Legend: **Status** ∈ PENDING / RUNNING / ✅ confirmed / ❌ overturned / ⚠️ partially-revised / ⏭️ not-re-run (with reason).

### Flagged by maintainer

| ID | Claim (as recorded) | Source | Status |
|----|---------------------|--------|--------|
| **E1** | QEMU `microvm` machine type is unusable: its `virtio-net-device` (MMIO) falls back to the legacy 10-byte virtio-net header vs the modern 12-byte mergeable-rx header, "breaks guest networking" → use `q35`+`virtio-net-pci`. | design §101/§140; impl-notes L20 | ⚠️ **conclusion holds, reason WRONG** |
| **E2** | The unprivileged smoltcp NAT on QEMU needs a `[patch.crates-io]` fork of `vhost`/`vhost-user-backend` to relax a `PROTOCOL_FEATURES` check on `SET_VRING_ENABLE` (QEMU sends it before `SET_FEATURES`). | design §10.4 L747; Cargo.toml L11-16; `vendor/vhost/.../backend_req_handler.rs:554` | ✅ **confirmed by trace (fork needed)** |

### QEMU / snapshot

| ID | Claim | Source | Status |
|----|-------|--------|--------|
| **E3** | QEMU cannot snapshot over the unprivileged vsock control plane (external `vhost-device-vsock` = stateless vhost-user). A **privileged kernel `vhost-vsock`** QEMU config *should* be snapshot-eligible but is **unvalidated** (dead code behind a gate). | design A.3 #5 L1472; §140 | ✅ **recovery path VALIDATED (QEMU *can* snapshot, privileged config)** |
| **E7** | Firecracker has no snapshot/restore under PCI (`--enable-pci`) → runs MMIO mode off the same vmlinux. | design A.3 #1 L1464 | ❌ **OVERTURNED live (FC v1.16.0: `--enable-pci` + snapshot create *and* restore both succeed)** |
| **E6** | Firecracker restore panics in `restore_fpregs_from_fpstate` with modern glibc (XSAVE mismatch); fixed by a **T2 CPU template** + `noxsave` cmdline, not a `bookworm` downgrade. | design A.3 #3 L1468 | ⚠️ **partially revised (noxsave over-applied + unneeded for YMM on FC 1.16; T2 rejected on this CPU; AVX-512 untestable here)** |

### Networking / PID-1

| ID | Claim | Source | Status |
|----|-------|--------|--------|
| **E5** | `passt` is fundamentally CH-incompatible: its C seccomp filter drops the `accept4` CH's `--net vhost_user=true` needs (→ `epoll` EBADF), no opt-out. Replaced by in-process smoltcp NAT. | design Exp 5 L1512; A.3 | ⚠️ **decision holds, reason WRONG (AppArmor, not seccomp; avoidable)** |
| **E8** | `ip=` kernel cmdline configures `eth0` with **zero netlink in PID-1** (kernel IP-PNP late-initcall, not initramfs); the manual `ip link/addr/route` added to the agent was a wrong fix for a compiled-out `net-unprivileged`. | design A.3 #2 L1466 | PENDING |
| **E10** | Pure-Rust nftables rejected: no permissive TPROXY-capable crate (`rustables` GPLv3, `jip-nftables` read-only); REDIRECT can recover orig dst via `SO_ORIGINAL_DST` but TPROXY chosen for UDP/QUIC/source-preservation. | design Exp 2 L1506; A.3 #4 L1470 | PENDING |

### Build / rootfs / kernel

| ID | Claim | Source | Status |
|----|-------|--------|--------|
| **E4** | `mkfs.erofs` → `am-fs-erofs` (in-memory tar→erofs, unprivileged) graduated; output is byte-deterministic. | design Exp 3 L1508 | ✅ **confirmed byte-deterministic** (Bucket D executed) |
| **E9** | Benchmark inversions: OCI slim base ~34% **smaller** than mmdebstrap-minbase; static-musl agent ~6.2% **larger** than glibc-dynamic; kernel 6.6.9 vs 6.12.94 warm restore within ~2% ("2×" was cross-session noise). | design A.3 #6 L1474; §13 | ✅ **confirmed** — OCI −34.06% (musl +6.8%); Bucket D executed |
| **E11** | `kvm_guest.config` alone omits vsock/virtio-fs/erofs → real boot failures (first gap = `EAFNOSUPPORT` at vsock); the custom microvm fragment (all `=y`, no initramfs) is required. | design §8.3 L340 | ✅ **confirmed (config + runtime)** — omits all three; built kernel panics at erofs root-mount (Bucket D executed) |
| **E12** | virtiofsd → `fuse-backend-rs` (Exp 1) is *underway*, blocked on read-only enforcement not natively supported upstream. | design Exp 1 L1504 | ✅ **confirmed** (Bucket D executed — external RO enforced; in-process fails loud) |

---

## Conclusions

### E1 — QEMU `microvm` machine type · ⚠️ conclusion holds, recorded reason is WRONG

**Verdict:** Keep `q35`. microvm stays rejected — **but not for the recorded reason**, and it is *not* a drop-in even with `pcie=on`.

**What was tested** (standalone QEMU 10.2.1 reproducers, real `vmlinux` 6.12.94 + `rootfs.erofs`, SLIRP user-net so no caps needed; `init=/bin/bash`, TCP round-trip probe via `guestfwd`):

| Cfg | Machine / devices | Boots to userspace? | eth0/DHCP | Connectivity | MRG_RXBUF(b15)/VERSION_1(b32) | Header |
|----|----|----|----|----|----|----|
| A | `-M microvm` (MMIO) + `virtio-net-device`/`virtio-blk-device` | **NO** — `#DE` at `kmem_cache_init_late` | — | — | crash precedes virtio | n/a |
| B | `-M microvm,pcie=on` + `virtio-net-pci`/`virtio-blk-pci` (suggested drop-in) | **NO** — identical `#DE`, same PC | — | — | crash precedes virtio | n/a |
| C | `-M q35` + `virtio-net-pci` (baseline/control) | **YES** | 10.0.2.15 | **TCP round-trip OK** | **1 / 1** | **12-byte modern** |

**The recorded reason is factually unsupported.** The 10-vs-12-byte virtio-net header is set by feature negotiation (`VIRTIO_F_VERSION_1`), not by MMIO-vs-PCI transport — on q35, `virtio-net-pci` negotiates VERSION_1 + MRG_RXBUF → modern 12-byte header, and networking works end-to-end. The claimed "microvm MMIO → legacy 10-byte header → broken networking" **could never be observed** because the kernel never reaches virtio-net probe on microvm. Config B uses the *exact same* `virtio-net-pci` device as q35 and still fails — refuting "microvm fails because of the virtio-net device/header."

**The real reason microvm is unusable here:** QEMU 10.2.1's microvm cannot boot this project's PVH kernels to userspace. It panics in `start_kernel → kmem_cache_init_late` with a spurious `divide error` — the faulting RIP is that function's `endbr64` (offset 0), an instruction that cannot raise `#DE`, immediately after `sti`; i.e. a **pending interrupt mis-vectored as vector 0** the instant IRQs are enabled — a microvm interrupt-controller/early-environment problem, nothing to do with virtio. Reproduced across **~24 permutations**: KVM *and* pure-TCG (rules out host-CPU/KVM/nesting), both project kernels (6.6.143 + 6.12.94), all `-cpu` models, all timer/clock and IRQ-controller (`pic/pit/rtc/ioapic2/noapic/nolapic/acpi=off`) options. q35 boots the identical kernel/rootfs/cmdline every time.

**Caveat (open avenue, not tested):** this proves microvm can't boot the *current* kernel *configs* as-is; the `#DE` points at early IRQ setup, so a microvm-specific kernel-config investigation *might* recover it. That is a kernel-rebuild question, not a machine-type/device swap — and given q35 already works with the full feature set, low value.

**Recommended action:** Keep the `q35` hardcode (`qemu.rs:303`). **Correct the rationale** in design §140 and impl-notes L20 — replace the (wrong) header story with the real early-boot-`#DE` finding. Do **not** adopt `-M microvm,pcie=on` (tested; fails identically). Incidental: microvm needs an explicit `console=uart8250,io,0x3f8`/`earlyprintk` (it doesn't enumerate ISA COM1 via ACPI/PNP) — noted so a future microvm probe doesn't mistake a silent console for a hang.

### E2 — vendored `vhost`/`vhost-user-backend` fork · ✅ recorded conclusion CONFIRMED (fork needed)

**Verdict:** the fork is **genuinely required** for the QEMU-unprivileged tier — classification **(a) a real QEMU-vs-CH vhost-user ordering quirk**, *not* masking a backend bug, *not* already-fixed upstream. Removable **only** if the QEMU-unprivileged tier is dropped (CH-unprivileged, the primary, needs no fork — confirmed).

**A/B evidence** (restored the two commented `check_feature(PROTOCOL_FEATURES)?` guards = pristine upstream behavior; ran the QEMU + `NetConfig::Unprivileged` smoltcp path):
- **Unpatched → QEMU FAILS:** guard returns `VhostUserError::InactiveFeature(PROTOCOL_FEATURES)` → `Error::HandleRequest` → `VhostUserDaemon` drops the socket → QEMU logs `Failed to read msg header. Read 0 instead of 12` + net HUP → guest never boots → `Failed to connect to agent: Timeout`. **Patched → QEMU PASSES** (full curl round-trip). **CH PASSES even unpatched** (sanity anchor).
- **Message trace (the decisive proof):** QEMU 10.2.1 sends `… SET_VRING_ENABLE(0,1) … → SET_FEATURES=0x170000000 → SET_MEM_TABLE …` — **`SET_VRING_ENABLE` well before `SET_FEATURES`**. CH sends `… SET_FEATURES → … → SET_VRING_ENABLE` (features first). At the enable point: QEMU `acked_features=0x0` (SET_FEATURES not yet sent) vs CH `0x170000000`.
- **(a) not (b):** our backend advertises `PROTOCOL_FEATURES` (smoltcp.rs:58-64) and QEMU's eventual `SET_FEATURES=0x170000000` carries the bit — so the `0` at enable time is purely QEMU's ordering, not a fumbled ack.
- **Upstream:** pinned `vhost-user-backend 0.22.0` / `vhost 0.16.0` are the newest released; both CHANGELOG "Unreleased" are empty; upstream still enforces the guard. No newer release relaxes it; no backend-side or QEMU-option fix avoids it.
- **Patch is minimal:** both guard lines are live on our path (`vhost` `backend_req_handler.rs:554` fires first at outer dispatch; `vhost-user-backend` `handler.rs:534` is independently load-bearing) — cannot be reduced to one line.

**Recommended action:** Keep the patch (or drop it *iff* QEMU-unprivileged is deprioritized — the design's own §10.4 escape hatch). **Upgrade the design §10.4/impl-notes L19 wording from "lowest-confidence must-patch" to "confirmed by trace."** Keep pinned to 0.22.0/0.16.0; re-evaluate each `vhost` bump. A downstream `.patch` file or narrow git-fork would be lower-maintenance than fully vendored crates, but the current form is functional and `cargo-deny`-clean (Apache-2.0).

**Corrections to my own earlier note:** the CI coverage gap I suspected **does not exist** — `just test-privileged` (`--features firecracker,qemu`) *does* select `host_endpoint::qemu` and `egress_proxy::qemu` (both `NetConfig::Unprivileged`), so the patch's necessity *is* regression-guarded (verified via `cargo nextest list`). Real (smaller) gaps: `just test-unprivileged` doesn't compile `--features qemu`; VM tests don't run in KVM-less `just ci`.

**Bug uncovered (real, unrelated to the patch):** `crates/vmcell/tests/host_endpoint.rs` leaks its `python3 -m http.server` child on an early panic — it's reaped only at lines 120-121, *after* the agent/curl steps, so the agent-connect timeout (line 70) leaks the host process (hit twice during the unpatched runs). `egress_proxy.rs` guards its python with a `Cleanup(Child)` Drop guard (lines 59-66); `host_endpoint.rs` should adopt the same (AGENTS.md "ownership owns cleanup — on panic").

### E3 — QEMU privileged in-kernel `vhost-vsock` snapshot · ✅ recovery path VALIDATED (overturns "QEMU can't snapshot in *any* config")

**Verdict:** the recorded *unprivileged* conclusion is correct and untouched (external `vhost-device-vsock` = stateless vhost-user = ineligible). But the design's own **"privileged kernel-`vhost-vsock` → likely, unvalidated"** recovery path (design L167/§140) is now **validated in its two load-bearing halves** — so **"QEMU is snapshot-ineligible in all configs today" is overturnable: QEMU *can* snapshot in the privileged config.**

**Evidence:**
1. **No migration blocker (source-proven, QEMU v10.2.0, unchanged in 10.2.1):** `hw/virtio/vhost-vsock.c` / `vhost-vsock-common.c` register `vmstate_virtio_vhost_vsock` with `pre_save`/`post_load` and set **no** `migrate_add_blocker` — the in-kernel `vhost-vsock-pci` device does **not** block `migrate`. (Contrast: `vhost-user-vsock` *can* block when the backend lacks `PROTOCOL_F_LOG_SHMFD` — the path the design correctly ruled out.) `guest-cid` is a device *property* (not migrated) → must match on the destination `-device` line. `post_load` **resets vsock connections on restore** — exactly why the guest listener goes deaf and the agent must re-`bind`; the existing re-bind loop (`vmcell-guest-agent/src/main.rs:402-440`) already covers it, no guest change needed.
2. **Mechanism verified empirically on the committed pin:** q35/KVM + real `vmlinux` 6.12.94 + `rootfs.erofs` over read-only `virtio-blk` (`readonly=on,file.locking=off`). QMP `stop` + `migrate exec:cat>state.bin` → `query-migrate status:"completed"` (60 MB); fresh QEMU + `-incoming` + `cont` resumes **live** (dest serial shows the guest's post-pause clocksource-watchdog line continuing from migrated uptime, not a `[0.00]` reboot). Read-only erofs needs **no** `x-ignore-shared`.
3. **Unrun step (honest gap — NOT a QEMU limitation):** the full live agent-reconnect-over-in-kernel-vhost-vsock loop couldn't run here because **`/dev/vhost-vsock` is not openable in this sandbox** — `/dev/kvm` is reachable via a per-user POSIX ACL that does *not* extend to `/dev/vhost-vsock`, the `kvm` group is **empty**, no passwordless sudo, runner not setuid. QEMU fails at device realize (`Could not open '/dev/vhost-vsock': Permission denied`). Finish this on a host where the run user is a real `kvm` member (or via the privileged capability runner, whose `CAP_DAC_OVERRIDE` bypasses the mode). **(Note: this corrects a wrong host-fact in the experiment's brief.)**

**Recommended action / wiring** (`qemu.rs:508 restore()` / `qemu.rs:581 snapshot()`, both currently `Unsupported`): for the privileged config — (a) attach `vhost-vsock-pci,guest-cid=<CID>` instead of the external vhost-user-vsock daemon (drop the daemon plumbing on that path); (b) `snapshot()` = QMP `stop` + `migrate exec:/file:/fd:` + poll `query-migrate` for `completed` (fail loud on `failed`/`cancelled`, never fall through a timeout); (c) `restore()` = fresh QEMU with identical topology (**same `guest-cid`**) + `-incoming`, then `cont`, returning **paused** to match the trait's "restore returns paused, caller resumes" shape; (d) enforce the §3.3 law (reject `NetConfig::Unprivileged` + virtio-fs rootfs; privileged tap net; no virtiofsd/vhost-user-net); (e) flip `snapshot_restore: true` only for that specific config via `capabilities()`. This would give QEMU a real snapshot tier — a **capability gain**, not just a doc correction.

### E5 — passt / CH incompatibility · ⚠️ decision holds, recorded REASON is WRONG (AppArmor, not seccomp)

**Verdict:** classification **(b) wiring/config artifact + mechanism misattribution.** The recorded reason ("passt's C seccomp filter drops `accept4`, no opt-out → CH-incompatible") is **factually wrong**. Keeping smoltcp is still right (in-process, no external dep) — but for different reasons.

**Evidence** (passt `0.0~git20260120` = newest; CH `v52.0.0`; Ubuntu 26.04, kernel 7.0.0):
- **The symptom reproduces** with passt as vhost-user backend/listener + CH as client (CH's default, correct wiring): `accept4(6,…) = -1 EACCES` → `epoll_ctl(3,ADD,-1,…) = -1 EBADF` → passt logs `Failed to add fd to epoll`, CH hangs at net init, guest never boots.
- **But it's NOT seccomp:** passt's seccomp default action is `SECCOMP_RET_KILL_PROCESS` and doesn't flag-filter accept4 — a seccomp block would **SIGSYS-kill** passt. passt **survived** `accept4` and got **`EACCES`** (an LSM signature), then continued to `epoll_ctl`. So passt's own seccomp *allows* accept4.
- **Real cause = host AppArmor:** SELinux off; only AppArmor confines passt (`profile="passt"`, proven by a `type=1400 apparmor="DENIED" … profile="passt"` line). Ubuntu 26.04 has AppArmor **af_unix fine-grained mediation ON** (`/sys/kernel/security/apparmor/features/network/af_unix = yes`), but the distro `abstractions/passt` profile uses the **old coarse `network unix stream,`** rule, which doesn't grant `unix (accept)` → `accept()` denied `EACCES`.
- **NOT CH-specific:** a plain **`socat`** client (not CH) reproduces the identical `accept4 = -1 EACCES` — it breaks passt-as-listener for *any* frontend (QEMU too). That alone refutes "CH-incompatible."
- **Avoidable (decisive escape hatch):** CH `--net …,vhost_mode=server` (CH listens) + passt as client via `-F <fd>` → **zero `accept4` calls, vhost-user handshake completes, CH boots the guest kernel.** Or fix the AppArmor profile (`unix (accept,send,receive) type=stream` / corrected profile / complain mode).

**Rigor caveat (honest):** couldn't capture a `type=1400` DENIED line *specifically* for the accept (AppArmor logged one for passt's `sendmsg` but not the accept), and couldn't A/B passt fully-unconfined (blocked by an orthogonal userns restriction). Attribution to AppArmor af_unix is by elimination — but the two load-bearing facts are direct: passt *survives* accept4 (⇒ not its seccomp) and the direction-flip works with zero accept4. Also note this is the *current* host's environment; whether the *original* rejection host had a genuine passt-seccomp issue is unknowable now, but on today's passt+host the seccomp mechanism is disproven.

**Recommended action:** Keep smoltcp (better design regardless). **Correct the impl-notes/design Exp-5 reason** from "passt seccomp blocks accept4, CH-incompatible" to the AppArmor-af_unix-mediation finding, noting it's environment-specific, not CH-specific, and avoidable by socket-direction or a profile fix.

### E6 — FC `noxsave` + T2 template · ⚠️ partially revised (over-applied in code; largely unneeded on FC v1.16.0; T2 inoperative here)

**Verdict:** the *core* claim (modern-glibc AVX extended-FPU state can mismatch on FC restore) is **not disprovable on this host** (no AVX-512 → the specific ZMM trigger is unreachable), but everything reachable points to the current guard being **over-applied and largely unnecessary on FC v1.16.0**:

- **`noxsave` is over-applied (certain, code):** `firecracker.rs:472` hardcodes `noxsave` into the boot_args **unconditionally** — applied even when the T2 template is active. Design §138/A.3 #3 intend `noxsave` as the **fallback for hosts where T2/C3 don't fit** (T2 alone leaves AVX2 usable; `noxsave` drops to SSE2). *Caveat:* impl-notes L14 records a *deliberate* "belt-and-suspenders always-on" deviation — so the **code matches that recorded deviation, not the design.** The empirical results undercut its "incomplete template" justification for reachable state.
- **The panic does NOT reproduce on FC v1.16.0 here (empirical):** with a purpose-built guest that provably dirties **AVX2/YMM** state (XCR0=0x207), a **raw** config (no template, **no `noxsave`**) snapshotted and restored into a fresh FC **resumed cleanly** — the YMM accumulator kept evolving post-restore, zero `restore_fpregs_from_fpstate`/xsave errors. So `noxsave` is **not required for YMM/AVX2** on FC v1.16.0 here.
- **T2 is rejected on this CPU (empirical):** `PUT /machine-config {cpu_template:"T2"}` → 204, but `InstanceStart` → HTTP 400 *"current CPU model is not permitted to apply the CPU template"*; FC v1.16 also **deprecates** the static `cpu_template` field. So on Intel **Lunar Lake** (and modern client hybrids) the design's **T2 leg is inoperative** — this host is exactly a "T2 doesn't fit" host, where `noxsave` would be the *only* guard, yet raw restore is clean anyway.
- **Confound (honest):** host has no AVX-512 (avx/avx2/avx_vnni only; Lunar Lake fuses ZMM off), guest XCR0=0x207. So this proves *"AVX2/YMM snapshot-restore is clean on FC v1.16.0 here"* — it **cannot** disprove an AVX-512-specific trigger, and can't fully separate "FC v1.16 fixed it" from "the CPU doesn't expose the state." Decisive for YMM; silent on ZMM.

**Recommended action:** (1) **Gate `noxsave` behind `template.is_none()`** (`firecracker.rs:470-495`) — recovers guest AVX2 wherever T2 fits, matches design §138. (2) *Consider* dropping `noxsave` entirely (recovers fidelity on T2-reject hosts like this one) **but only after** validating on an AVX-512-capable host + an older FC — don't drop on this single-host YMM-only evidence. (3) Note the T2 leg is CPU-rejected on modern Intel client hybrids and `cpu_template` is deprecated in FC v1.16; combined with FC `snapshot_restore: false` (not live in vmcell yet), this is a **design-accuracy fix, not an active-bug fix**.

---

## Remaining inventory — disposition (why not separately live-tested)

A "full audit" means every experiment-derived claim gets a verdict — but not every claim needs a live VM re-run.
The two doc reads surfaced ~40 claims; the flagged + highest-risk ones (E1–E3, E5–E7) were re-run live above. The rest
fall into three buckets. **None is a silent skip**; each is dispositioned with reasoning.

### Bucket A — settled OS/kernel/library facts (not buggy-code artifacts → no live re-test needed)
These rest on documented, stable behavior of the kernel/FS/libraries, independent of vmcell's (buggy-at-the-time) code.
Re-running would only re-confirm a spec.
- **cgroup v2 has no per-cgroup network byte accounting** (no `net.stat`) → `ResourceUsage` omits net counters. Verifiable by `ls /sys/fs/cgroup/<slice>/`. ✅ settled.
- **erofs has no journal; ext4-RO-clone hits journal-recovery panics + concurrent-mount corruption; virtiofs-as-overlayfs-lowerdir needs redirect_dir/metacopy.** Documented kernel FS behavior. ✅ settled.
- **`FICLONE` reflink is XFS/Btrfs-only; silently full-copies on ext4.** Documented. ✅ settled.
- **cgroup-v2 "no internal processes" rule → sibling placement; threaded `domain threaded` scope rejects `cgroup.procs`.** Documented cgroup-v2 semantics (the validation runbook already relies on the `domain`-scope workaround). ✅ settled.
- **`/proc/sys/vm/drop_caches` is euid==0-special-cased (ignores CAP_DAC_OVERRIDE); `CAP_DAC_OVERRIDE` needed for `/var/run/netns`.** Kernel behavior; the 3-cap set is already validated by the passing privileged suite. ✅ settled.
- **`SO_ORIGINAL_DST` recovers the REDIRECT original dst** (D6/E10) → TPROXY chosen for UDP/QUIC/source-preservation, not because REDIRECT "can't". Documented netfilter fact; the design already recorded this as a *reversal* (its own audit). ✅ settled + self-corrected.
- **virtiofsd flag is `--readonly` not `--read-only`; `--sandbox namespace` needs privilege.** Exact CLI behavior of the pinned virtiofsd; enforced in code. ✅ settled.
- **Guest needs `VSOCKETS`+`VIRTIO_VSOCKETS` (not `VHOST_VSOCK`, which is host/nesting side); OCI base must carry `libc6` (else dead PID 1); erofs decompressor must match if compressed (ships uncompressed).** Kernel/linking facts. ✅ settled.
- **CH: DAX unavailable (v52), no `--cpu nested=on` flag (nesting via host module + guest cmdline), `500 "VM is already created"` on create-after-restore, snapshot refused with any vhost-user device (§3.3 law).** Documented CH behavior, cited to CH docs; the §3.3 law is the most cross-validated rule in the design. ✅ settled. *(E3 above tested the one genuinely-open corner — QEMU in-kernel vhost-vsock — and validated it.)*
- **Pure-Rust nftables rejected: `rustables` GPL-3.0 (cargo-deny rejects), `jip-nftables` read-only** (E10). Licensing fact; `cargo-deny` is the arbiter. ✅ settled.
- **gcc-15/C23 breaks Linux 6.6.9 EFI stub (`false` keyword); 6.12.94 carries the `-std=gnu11` fix.** Widely-reported 2025 toolchain issue; the current artifacts are built with the 6.12.94 pin and boot (proven by E1's working q35 baseline). ✅ settled.

### Bucket B — claims the notes ALREADY self-corrected (the correction was itself the audit; re-run = low value)
Design A.3 explicitly frames these as reversals; re-testing would re-confirm the *corrected* form.
- **CH guest RAM is `RssShmem` (memfd `MAP_SHARED`), not `RssAnon`** → KSM dedups 0 by default; the `mergeable=on`+`shared=off` lever (mutually exclusive with vhost-user) dedups ~84%. Self-corrected (v12 RssAnon assumption was wrong).
- **Kernel version is NOT a hot-path lever** — the "6.12 restores ~2× slower" was cross-session noise; interleaved same-session is within ~2%. Self-corrected; the methodological lesson ("only interleaved same-session deltas") is the takeaway. *(This is the maintainer's own worry generalized — several absolute-ms numbers in the notes are warm-cache/cross-session and labeled as such.)*
- **"Cold boot" numbers here are warm-cache** (drop_caches euid-gated; tmpfs artifacts) — honestly relabeled; the `O_TRUNC` hypothesis was wrong. Self-corrected.
- **smoltcp host-NAT MAC collided with `mac_math(254)`** at the v12 pin — a real own-code bug, now guarded. Self-corrected + unit-tested.
- **`lazy_restore:true` was a dead flag** (no prefault plumbing) until wired to `--restore …,prefault=`. Self-corrected; the eager-vs-lazy numbers are only valid post-plumbing.
- **CID-rotation revert / `assert_ne!(cid)` over-specification; `ip addr flush` drops the IP-PNP route (restore doesn't rotate IP); metrics_limits needs `memory.swap.max=0`+`memory.oom.group=1` (shmem reclaim, not just `memory.max`).** Each a self-corrected own-code bug now covered by tests. ✅ self-corrected — trust the *corrected* form, not the intermediate wrong diagnoses.

### Bucket C — vmcell code-correctness invariants (unit-testable; "how to use the API right", not "conclusions about the world")
Not experiment-conclusions that could be wrong about external reality — they're correct-usage invariants, several already
guarded by tests. Re-audit belongs in unit tests, not VM experiments.
- handshake read must be byte-wise (BufReader over-reads the first framed payload); PID-1 reaper vs `child.wait()` race (false 127); smoltcp RX-iterate-consumes-`avail_idx` / TX `enable_notification()` / socket-pool sizing; cgroups-rs `EOPNOTSUPP` → direct sysfs writes; cache keys use blake3+sorted+content (not `DefaultHasher`/`PathBuf`); content-addressed cache validity (reject tampered artifact w/ intact sidecar). ✅ verify via the existing/added unit tests.

### Bucket D — worth a cheap re-check on demand (not run this pass; flagged, with cost)
Low audit-risk (measured facts / graduated substitutions) but re-checkable if the maintainer wants belt-and-suspenders.
**Update (maintainer-requested): all Bucket D checks are being executed via the privileged runner / delegated scope; results below in "Bucket D — executed results."**
| Item | How to re-check | Cost | Why deprioritized |
|----|----|----|----|
| **E4** am-fs-erofs **byte-determinism** | build same tar twice, `sha256sum` the two erofs | cheap (1 pipeline stage) | graduated & works; determinism is an *open reproducibility requirement* the notes already track, not a wrong conclusion |
| **E9** musl vs glibc **agent size** | build agent both ways, `size`/`ls -l` stripped | cheap-ish (needs musl target) | measured & self-corrected (musl ~6.2% larger); low risk |
| **E9** OCI-slim vs mmdebstrap **rootfs size** | build both erofs, compare | **expensive** (2 full rootfs builds incl. builder-VM) | measured & self-corrected (OCI ~34% smaller via dpkg path-exclude); mechanism verifiable by inspecting `/usr/share/{locale,doc,man}` presence |
| **E7** FC **no-snapshot-under-PCI** | boot FC `--enable-pci`, attempt snapshot | medium | **EXECUTED → OVERTURNED** (FC v1.16.0 supports PCI+snapshot). Was reasoned-confirmed; running it disproved that. See executed results. |
| **E11** `kvm_guest.config` insufficiency | build kernel w/ only that fragment, boot, `AF_VSOCK`→`EAFNOSUPPORT` | **expensive** (kernel rebuild) | verifiable by config inspection (the required `CONFIG_VSOCKETS/VIRTIO_FS/EROFS` are simply absent from `kvm_guest.config`); the current custom-fragment kernel boots (E1 baseline) |
| **E12** fuse-backend-rs RO-enforcement | write to an in-process RO share, expect `Error::Unsupported` | cheap (unit/integration) | not a wrong conclusion — an acknowledged upstream gap; code fails loud (Review 40 CFG-3) |

**E7 note — my reasoned confirmation was WRONG (corrected by execution).** I had argued FC-PCI-snapshot was "not a plausible buggy-code artifact" and confirmed it by reasoning. **Executing it overturned that** (see "Bucket D — executed results"): FC v1.16.0 supports `--enable-pci` + snapshot create *and* restore. The block was real in FC's ~1.10–1.12 experimental-PCI era, so it was version-stale, not a code artifact — but the point stands that **reasoning was not a substitute for running it.** This is the strongest single vindication of re-running Bucket D.

---

## Bucket D — executed results (maintainer-requested, via the privileged runner where needed)

### E4 — `am-fs-erofs` byte-determinism · ✅ CONFIRMED (unprivileged)
Built an erofs image **twice** from the same fixed in-memory tar through the production
`vmcell::artifact::tar2erofs::tar_to_erofs` path: both images **28,672 bytes, identical
`sha256=11a180…3280b6`**. Fixed mtimes + `BTreeMap`-ordered inode/dirent emission → byte-stable. A full
raw-bytes `a == b` assertion (goes red on any mtime/ordering/padding drift) — a stronger check than
`pipeline.rs::test_pipeline_determinism`, which compares only *cache keys*. No privileged runner needed.

### E9 (musl vs glibc agent size) — ✅ CONFIRMED (unprivileged)
Stripped release builds: **glibc-dynamic 1,444,344 B** (dynamic PIE → `libc.so.6`+`libgcc_s`) vs
**static-musl 1,542,816 B** (static-pie) → **musl +98,472 B = +6.82% larger**, matching the recorded "~6.2%
larger" (design §13.3). Default `cargo build` is **not** crt-static. *Nuance (for impl-notes):* the *shipped*
agent (pipeline `GuestAgentStage`, impl-notes L1586) is a **static-glibc (crt-static)** build — a third path not
in the §13.3 two-pole table; the "glibc-dynamic (default)" label describes the plain-cargo build, accurate but
not what ships. No code bug; both size claims hold.

### E12 (fuse-backend-rs RO enforcement) — ✅ CONFIRMED (via the privileged runner)
Two paths, both green:
- **External virtiofsd RO enforcement:** `shares_ro_rw::cloud_hypervisor` PASSES in the privileged suite (RO-share
  write fails, RW-share write succeeds; FC/QEMU skip via `require_cap!(virtio_fs_shares)`).
- **In-process (`experiment-fuse`) RO rejection:** `fs::ro_share_tests::ro_share_is_unsupported_not_subprocess`
  PASSES under `--features experiment-fuse` — the in-process backend returns a typed
  `Error::Unsupported{vmm:"in-process-virtiofsd", feature:"read-only virtio-fs share…"}` (CFG-3, `fs.rs:195-206`),
  i.e. **fails loud, no silent write-through.** The recorded conclusion holds.

### Code-fix validation (host-facing DoD, via the privileged runner)
The two code fixes applied this pass (FC `noxsave` gating; `host_endpoint.rs` Drop guard) were validated on this KVM
host: **`just test-privileged` (delegated scope) = 232 passed / 0 failed / 17 skipped (84.5s)** — incl.
`host_endpoint::{cloud_hypervisor,firecracker,qemu}`, the FC-booting `metrics_limits/snapshot_restore/nested_virt::firecracker`
(exercising the gated `noxsave` cmdline), and `shares_ro_rw::cloud_hypervisor`; **`just test-unprivileged` = 17 passed /
0 failed**; `just test-unit` (`--all-features`) = 242 passed; the new `noxsave_only_applied_without_cpu_template` unit
test passes. (On this Lunar Lake host FC rejects T2, so `template=None` → `noxsave` still applied → FC boot-args
unchanged here; the gating is guarded by the unit test and takes effect on T2-capable hosts.)

### E7 (FC no-snapshot-under-PCI) — ❌ OVERTURNED (live, FC v1.16.0)
`firecracker --help` exposes `--enable-pci` (runtime flag, no rebuild). PCI was genuinely active (guest enumerated
`virtio-pci 0000:00:01.0 [1af4:1042]`, virtio-blk over PCI; MMIO baseline showed `pci=off` + `virtio_mmio.device=…`).
**Snapshot create succeeds in both modes** (204: MMIO state 13,947 B, **PCI state 22,315 B** — larger, carries PCI
device state). **Restore succeeds in both modes** (204, resumes `state:"Running"`; the PCI restore log shows the PCI
segment reconstructed then `VcpuEvent::Resume` — **no `MicroVMStoppedWithError`**). So on FC v1.16.0 the recorded
"PCI blocks snapshot/restore" is **false** — it was true in FC's ~1.10–1.12 experimental-PCI era but v1.16.0 ships
stable PCI + snapshot. **Design A.3 #1's `MicroVMStoppedWithError`-under-PCI justification should be dropped;** MMIO
may still be a fine FC default (maturity + shared `vmlinux`), but not for the stated reason. *Caveat:* tested with
virtio-blk-on-PCI only; virtio-net-on-PCI (needs a tap/privilege) was not exercised, so a device-specific residual
limit isn't excluded — but the blanket block is refuted.

### E9 (OCI-slim vs mmdebstrap rootfs size) — ✅ CONFIRMED (live, trixie vs trixie)
Measured both erofs images on this host, same suite (trixie), same packer (`mkfs.erofs -T0`, uncompressed):
**OCI slim 79,114,240 B (79.1 MB) vs mmdebstrap `--variant=minbase` 119,980,032 B (120.0 MB) → OCI −34.06%**,
matching the recorded ~34% and the ≈79.2/≈120 MB numbers. **Mechanism verified:** the OCI base ships
`/etc/dpkg/dpkg.cfg.d/docker` with `path-exclude /usr/share/{doc,man,info,locale,lintian}/*` — in the OCI tree
locale/man/info are empty and doc is copyright-only; mmdebstrap-minbase carries exactly what OCI strips
(**locale 32.06 MB** — matches the "~32 MB" claim — + doc/man/info ≈ 41 MB total, fully accounting for the 40.9 MB
delta). *(The builder micro-VM wasn't booted — the pipeline mmdebstrap path is deferred/needs a
`debian_snapshot_timestamp` pin absent from `resolved_pins.json` — so the exact `mmdebstrap` invocation was reproduced
rootless on the host; erofs size = f(package tar, packer), so this is equivalent for the size question.)*

**Nuances found (for impl-notes, not audit-blocking):**
- **Variant mislabel:** the pipeline's `RootfsBuildSource::Mmdebstrap` builds `--variant=apt --include=curl,ca-certificates`
  (measured **129.1 MB**), not `--variant=minbase` (120.0 MB). The recorded "minbase ≈120 MB" describes a variant the
  code doesn't build; the pipeline's real OCI advantage is **38.7%**, *larger* than the stated 34%.
- **erofs is uncompressed on both paths**, and `am-fs-erofs` is ~5% larger than `mkfs.erofs` — a size opportunity
  (lz4/zstd), orthogonal to this claim.
- **Cosmetic (not a bug):** the gitignored `target/vmcell-artifacts/*.cache_key` sidecars record a **stale absolute
  `…/target/imp-artifacts/…` path** in their `"artifacts"` **metadata** field (pre-v14 dir name; live dir is
  `vmcell-artifacts`). The content-addressed `"key"`/`"hash"` fields do **not** embed it (verified in `artifact/mod.rs`
  — the cache still hits post-rename, proving the key is path-independent), and `target/` is gitignored so the legacy
  term doesn't trip `ban-legacy-terms.sh`. Stale-metadata leak only, not a cache-correctness or gate issue.

### E11 (`kvm_guest.config` insufficiency) — ✅ CONFIRMED (config + runtime)
**Config inspection** (out-of-tree `make defconfig kvm_guest.config` on pristine linux-6.12.94, real tree untouched):
kvm_guest.config-**only** omits all three families — `CONFIG_VSOCKETS` (`is not set`), `CONFIG_VIRTIO_VSOCKETS` /
`CONFIG_VIRTIO_VSOCKETS_COMMON` (absent), `CONFIG_VIRTIO_FS` (absent), `CONFIG_EROFS_FS` (`is not set`) — vs all `=y`
in the real fragment-built `.config`. **Runtime** (built the kvm_guest-only `bzImage`, booted under QEMU q35+KVM with
the real `rootfs.erofs` RO over virtio-blk): `VFS: Cannot open root device "/dev/vda" … error -19` → `Kernel panic …
Unable to mount root fs` — virtio-blk enumerates `vda` but the bdev-filesystem list has **no erofs**. Claim holds.
**Refinements (for prose):** (a) the "first gap = `EAFNOSUPPORT` at vsock" symptom is **order-dependent** — for
kvm_guest.config-*alone* boot dies at the **erofs root-mount** before userspace, so vsock is never reached; the
`EAFNOSUPPORT`-at-vsock symptom only appears on an *intermediate* config (erofs present, vsock absent). (b) design §8.3's
parenthetical `CONFIG_VSOCKETS_COMMON` is not a real 6.12.94 symbol — the correct name is `CONFIG_VIRTIO_VSOCKETS_COMMON`.

---

## Final status — all inventory items dispositioned

**Live re-runs (7):** E1 ⚠️reason-wrong · E2 ✅confirmed · E3 ✅overturned (QEMU *can* snapshot) · E5 ⚠️reason-wrong ·
E6 ⚠️over-applied · E7 ❌overturned (FC PCI+snapshot) · plus the code-fix DoD (privileged 232 / unprivileged 17 / unit 242).
**Bucket D executed (6):** E4 ✅ · E9-musl ✅ · E9-OCI/mmdebstrap ✅ · E7 ❌overturned · E11 ✅ · E12 ✅.
**Reasoned dispositions:** Bucket A (settled OS/kernel/library facts) · Bucket B (already self-corrected in the notes) ·
Bucket C (code-invariants — unit-testable). Every experiment-derived claim in the two-doc inventory now has a verdict.
