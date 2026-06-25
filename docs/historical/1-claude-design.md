# Imp Integration / Evaluation Platform — Micro-VM Design & VMM Research

*Design target: run each integration/eval test in a fresh micro-VM for (1) zero state leakage and (2) production-fidelity environment, driven from Rust, with shared dirs (per-permission), host-served test endpoints, transparently-proxied egress, optional nested virt, on Debian. Researched against current (mid-2026) VMM and rust-vmm ecosystem state.*

---

## 0. Bottom line up front

**Primary recommendation: Cloud Hypervisor (CH) as the default backend, behind a `Vmm` trait, with QEMU-`microvm` as the flexibility fallback and Firecracker as an optional "fast/dense subset" backend.**

CH is the only minimal Rust VMM that satisfies *every* hard requirement on your list simultaneously: `virtio-fs` with independent per-mount permissions, `virtio-vsock`, **nested virtualization**, snapshot/restore for fast iteration, generic-Debian guests, and a clean machine-controllable API. Firecracker is faster to cold-boot and has the smallest attack surface, but it has **no `virtio-fs`** (block devices only) and **cannot expose `/dev/kvm` to the guest** (no nested virt) — two of your requirements it structurally cannot meet. QEMU-`microvm` can do literally everything but is a large C codebase with a bigger attack surface; keep it as the escape hatch and for the most battle-tested nesting.

The single biggest performance lever is **snapshot/restore**, not VMM choice: boot to "agent-ready" once, snapshot, then fork a restored VM per test in single-digit milliseconds, skipping kernel boot entirely. Both Firecracker and CH support this.

The console/driver mechanism that everyone serious converges on is **a tiny static guest agent on `virtio-vsock`, not SSH or TTY scraping**. SSH is a fallback for humans; vsock is the machine interface.

Decision table (hard requirements):

| Requirement | Firecracker | Cloud Hypervisor | crosvm | QEMU `microvm` | libkrun | Kata/Dragonball |
|---|---|---|---|---|---|---|
| Console/driver (vsock) | ✅ vsock (userspace) | ✅ vsock (userspace) | ✅ vsock (vhost) | ✅ vsock (vhost) | ✅ vsock+TSI | ✅ vsock (ttrpc) |
| Shared dirs, separate perms (`virtio-fs`) | ❌ block only | ✅ virtiofsd ×N | ✅ virtio-fs/9p | ✅ virtiofsd | ✅ (weak isolation) | ✅ inline-virtiofs |
| Host-served test endpoints + arbitrary protocols | ✅ tap/vsock | ✅ tap/vsock | ✅ tap/vsock | ✅ tap/vsock | ⚠️ TSI/passt | ✅ |
| Transparent egress proxy | ✅ (tap+nft) | ✅ (tap+nft) | ✅ (tap+nft) | ✅ (tap+nft) | ✅ (TSI is the proxy) | ✅ |
| Generic Debian guest | ⚠️ stripped kernel | ✅ | ✅ | ✅ | ❌ bundled kernel | ✅ (mini-OS) |
| **Nested virtualization** | ❌ | ✅ | ⚠️ partial | ✅ (most proven) | ❌ | ✅ via QEMU/CH |
| Snapshot/restore (fast start) | ✅ | ✅ | ⚠️ limited | ✅ (migrate) | ⚠️ | ⚠️ |
| Rust control surface | SDK→REST | OpenAPI/D-Bus | crates/socket | `qapi` (QMP) | `krun-sys` FFI | in-process lib |
| Cold-boot to userspace | ~125 ms | ~200 ms | ~sub-300 ms | ~sub-300 ms | <200 ms | varies |
| Codebase / attack surface | Rust, tiny (5 devices) | Rust, small (~16 devices) | Rust, medium | C, large | Rust, small | Rust |

(✅ supported, ⚠️ caveats, ❌ not supported. Boot numbers are cold-boot-to-`/sbin/init`; with snapshot/restore all of these drop to single/low-digit ms.)

---

## 1. Requirement → mechanism mapping

Before the VMM bake-off, here's how each of your requirements is actually realized, independent of which VMM you pick. This is the part that determines the architecture.

### 1.1 Drive the console for the test
Use a **statically-linked Rust guest agent on `virtio-vsock`**, launched as the guest's first userspace process (or right after a minimal init). The host opens the VMM's vsock Unix socket and speaks a tiny framed protocol: `Ready` → `Exec{argv, env, cwd}` → streamed `Stdout/Stderr` chunks → `Exit{code}`. This is exactly what production sandboxes do — Kata's agent uses ttrpc-over-vsock; the `mvm` project ships an `mvm-guest-agent` on vsock and explicitly states "**NO SSH ever**."

- Host side: `tokio-vsock` (async `AF_VSOCK`) for CH/Firecracker (userspace vsock, surfaced as a per-port Unix socket on the host). For QEMU/crosvm, vsock is the kernel's `vhost-vsock` (needs the `vhost_vsock` host module loaded).
- Keep SSH as an optional humans-only debugging path (drop an `sshd` + key into the rootfs, reachable over the tap). Don't build your control plane on it.
- A raw serial console (`console=ttyS0` / `hvc0`) is the universal lowest-common-denominator and is invaluable for capturing kernel panics and early-boot failures — wire it to a per-VM log file in addition to vsock.

### 1.2 Shared directories with separate permissions
Use **`virtio-fs`, one mount tag per share, each backed by its own `virtiofsd` instance** pointed at a different host directory with its own mode:

- `imp-in` → host input-data dir, **read-only** (`virtiofsd --readonly` / mount `ro`)
- `imp-bin` → build-system output dir with the Imp binaries, **read-only**, `cache=auto` or `always` (binaries are immutable per run; let the host page cache serve them — big win for repeated launches)
- `imp-out` → results dir, **read-write**, mounted `rw`, ideally a per-test subdir bind so a test can only see its own outputs

`virtiofsd` is itself a rust-vmm project (`gitlab.com/virtio-fs/virtiofsd`), so the whole FS path stays in Rust-adjacent, auditable code. CH wires each with `--fs tag=...,socket=...` and requires `--memory shared=on` for the shared-memory window. **Firecracker can't do this at all** — its only storage is `virtio-block`, so "shared, separate-permission directories" forces you into per-share block images (read-only squashfs for in/bin; a writable ext4 for out that you loopback-read on the host afterward). That's the single most important reason FC isn't the primary.

Permission/identity nuance: `virtio-fs` does no isolation beyond the host FS itself. Run `virtiofsd` (and the VMM) under a dedicated uid with the share dir as the only thing it can reach, and use mount namespaces. crosvm's `fs_runtime_ugid_map` and CH's `virtiofsd` uid/gid mapping handle the host↔guest identity squashing.

### 1.3 Access to HTTP (and other) servers started by the test
Two clean options, and you'll probably want both:

- **vsock for host↔guest control-plane services** (clean, no IP stack, no firewall surprises). If the *test's* HTTP server lives on the host, the guest reaches it via a vsock→TCP shim, or the server listens on vsock directly. Best when "the integration test" is host-side and the guest is the SUT.
- **tap + private subnet for arbitrary protocols** (the general answer). Give the guest a tap NIC on e.g. `10.200.<vmid>.0/30`; host-side test servers listen on the gateway IP `10.200.<vmid>.1`. Arbitrary TCP/UDP/whatever "just works" because it's real IP networking. This is the bonus-points "other protocols" path — gRPC, raw TCP, QUIC, etc., all flow.

A per-VM `/30` (or a dedicated netns per VM) keeps tests from seeing each other and makes teardown trivial (delete the netns/tap).

### 1.4 Web access through a transparent proxy (log + filter)
Default to **tap networking + nftables `TPROXY` → a proxy you control**:

- Prefer the kernel `TPROXY` target over `REDIRECT`. `REDIRECT` does DNAT, which loses the original destination (racy even for TCP, impossible for UDP); `TPROXY` preserves it and works for UDP. (Kernel docs: `socket transparent` match + `tproxy` target, nftables since 4.18.)
- Terminate at **mitmproxy in transparent mode** (Python scripting for log/filter, ready-made) *or* a custom Rust proxy (`hyper` + `rustls` for TLS MITM; a plain L4 splice for log-only). For HTTPS interception you bake your proxy's CA cert into the guest image's trust store.
- A real-world template that mirrors your use case almost exactly: someone sandboxing an AI agent in a **Cloud Hypervisor** micro-VM via `microvm.nix`, with `nftables` egress logging in the `forward` chain, `unbound` logging every DNS query, and a read-only `erofs` rootfs. Steal that topology.

Rootless alternative worth knowing: **usermode networking** (`passt` or `gvproxy`/`gvisor-tap-vsock`) puts the entire guest network stack inside a userspace process you own — a natural, root-free choke point for logging/filtering, no tap or `CAP_NET_ADMIN` needed. libkrun's TSI is the extreme version of this (the VMM *is* the proxy). Trade-off: usermode nets are slower than tap and don't model L2 faithfully, but for an eval harness that's usually fine and the operational simplicity is real.

### 1.5 Nested virtualization (Imp-under-test runs its own VMs)
Requires (a) the **host** to expose nested virt (`kvm-intel nested=1` / `kvm-amd nested=1`; on clouds, bare-metal or a nesting-enabled instance), (b) the **guest kernel** to have KVM built in, and (c) a VMM that passes through the virtualization extensions. CH supports it (recent releases even ship "nested-virtualization control fixes on AMD"); QEMU is the most proven nester; crosvm has partial support. **Firecracker explicitly cannot** (`/dev/kvm` forwarding was requested and closed — issue #1721; FC needs KVM itself and doesn't re-expose it). **libkrun** isn't a nesting story. So the nested-virt requirement on its own eliminates FC and libkrun as the primary.

(Industry note for context: nested virt on regular cloud VMs is finally spreading — AWS announced limited nested virt on C8i/M8i/R8i in early 2026, joining GCP/Azure which had it for years. If your CI runs in the cloud, this matters for where you can host the platform.)

### 1.6 Monitoring (RAM / CPU / disk I/O per VM)
**Make every VMM process its own cgroup v2 slice and read the cgroup** — this is uniform across all VMMs and is the clean answer:

- RAM: `memory.current`, `memory.peak`
- CPU: `cpu.stat` (`usage_usec`, throttling)
- Disk I/O: `io.stat` (per-device bytes/ops)

The jailer / process-per-VM model these VMMs already use makes this natural (Firecracker's jailer literally sets up cgroups; CH is commonly run inside namespaces+cgroups à la Ubicloud). Layer VMM-native metrics on top where useful: **Firecracker emits JSON metrics to a FIFO**; **CH** exposes counters via its API/events; **QEMU** via QMP `query-*`. `virtio-balloon` stats give guest-internal memory pressure if you need inside-the-guest numbers.

### 1.7 The "Imp gets full host access" scenarios
Treat host-exposure as a **per-scenario parameter**, not a global mode. The micro-VM gives you a clean, reproducible base; "full host access" is then modeled by widening what you mount/expose:

- isolated tier: no host mounts beyond in/bin/out, filtered egress, fresh rootfs
- elevated tier: mount more of a **disposable** host tree rw via `virtio-fs`, looser egress
- full-host tier: mount a throwaway host root, or run against a sacrificial nested host

Security reality to bake into the design: when you deliberately hand an agent-under-test full host access, the VM boundary is your safety net being lowered *on purpose*. Keep the egress proxy and per-VM cgroup limits even then, and **never point the "full host access" scenario at the real build/CI host** — use a disposable VM-as-host (this is itself an argument for nested virt: the "host" Imp gets full access to is a nested VM you can discard).

---

## 2. Recommended architecture

```
┌──────────────────────────── Host (Linux + KVM, nested=1) ──────────────────────────┐
│                                                                                     │
│  imp-eval orchestrator (Rust, tokio)                                                │
│   ├─ Vmm trait: start / stop / kill / snapshot / restore / configure / stats        │
│   │    └─ impls: CloudHypervisor (default) · Qemu (fallback) · Firecracker (dense)  │
│   ├─ per-test lifecycle  →  cgroup v2 slice  →  netns + tap (/30)                    │
│   ├─ vsock client (tokio-vsock)  ⇄  guest agent                                      │
│   ├─ virtiofsd ×3  (imp-in ro · imp-bin ro · imp-out rw)                             │
│   └─ egress: nft TPROXY  →  mitmproxy / rust-proxy (CA-injected)  →  WAN (logged)    │
│                                                                                     │
│   artifact cache:  vmlinux (host)  ·  base rootfs.img  ·  warm snapshot/            │
└─────────────────────────────────────────────────────────────────────────────────────┘
         │ restore (≈ms)                              ▲ vsock: Ready/Exec/IO/Exit
         ▼                                            │
   ┌─────────────────────── micro-VM (per test, ephemeral) ───────────────────────┐
   │ kernel: direct boot, virtio + KVM built-in, no initramfs                       │
   │ PID 1: imp-guest-agent (or tiny init → agent)                                  │
   │ mounts: /in (virtiofs ro) · /bin/imp (virtiofs ro) · /out (virtiofs rw)        │
   │ net: eth0 tap → default route → host TPROXY                                    │
   │ [optional] /dev/kvm present → Imp runs its own inner VMs                       │
   └────────────────────────────────────────────────────────────────────────────────┘
```

**Per-test flow:**
1. `restore` a warm snapshot (agent already up) into a fresh cgroup+netns — or cold-boot if the test mutates so much that snapshot state is wrong.
2. Rebind the three `virtiofsd` shares to this test's input/output dirs; the `imp-bin` share is shared/read-only across all tests so the page cache stays hot.
3. Over vsock: `Exec` the test entrypoint; stream stdout/stderr/exit; tail the serial log for panics.
4. Collect outputs from the `imp-out` host dir; collect `memory.peak`/`cpu.stat`/`io.stat` from the cgroup; collect the proxy's request log.
5. `kill` the VMM, delete the netns/tap/cgroup. No teardown of guest state needed — it's discarded by construction (your no-leakage guarantee is *structural*, not hygiene-based).

**Why a `Vmm` trait, not a single VMM:** both `mvm` and Kata abstract over multiple VMMs precisely because each is optimal for a different slice (FC for density, CH for features, QEMU for the weird cases). Modeling the lifecycle as a contract (`start/stop/kill/snapshot/configure/stats`) also matches how you like to structure things — push the unsafe/finicky VMM-specific glue behind a narrow, well-typed boundary and keep the orchestrator idiomatic.

---

## 3. VMM deep-dives

For each: Rust control, config (shared FS + net), artifact building, monitoring, distro needs, and the verdict for Imp.

### 3.1 Cloud Hypervisor — **recommended default**

Rust, on KVM (and Microsoft MSHV), Linux Foundation project, built on rust-vmm crates, current release **v52.0 (May 2026)**, actively maintained (it shipped a `virtio-block` use-after-free fix, CVE-2026-45782, in v52.0 — i.e. security is tracked and patched, which matters for an adversarial-input harness).

- **Device model (~16 devices):** `virtio-{net,block,pmem,fs,vsock,console,rng,balloon,iommu}`, PCI, VFIO passthrough, CPU/memory hotplug. This is the sweet spot: everything you need, nothing baroque.
- **Shared FS:** `virtio-fs` via `virtiofsd`, `--fs tag=imp_in,socket=...` per share, `--memory shared=on`, cache modes `never|auto|always` (use `never` for the rw output share to avoid host-cache footprint, `auto/always` for the read-only binary share to exploit the page cache). Multiple tags = multiple `virtiofsd` = your three separate-permission mounts.
- **vsock:** built-in, stream sockets, Firecracker-derived userspace implementation; each guest port surfaces as `…_<port>` Unix socket on the host. Pairs directly with `tokio-vsock`.
- **Nested virt:** supported; recent releases explicitly fix nested-virt control paths on AMD. Combined with host `nested=1` and a KVM-enabled guest kernel, Imp can run inner VMs.
- **Snapshot/restore + live migration:** yes, including `virtio-fs` migration and vsock-reset-on-restore (v52.0). This is your fast-start path.
- **Rust control:** CH is API-first. Three good options: (a) generate a typed client from its published **OpenAPI** YAML and drive the `--api-socket` REST endpoint; (b) the **D-Bus** API; (c) drive `ch-remote`. `--no-shutdown` keeps the VMM process alive under your management layer when the guest powers off. (CH's internals are a `vmm` crate, but it isn't packaged for clean in-process embedding the way libkrun/Dragonball are — drive it out-of-process.)
- **Artifacts:** direct kernel boot of a `vmlinux` ELF (PVH-enabled) or `bzImage`, or boot via its `hypervisor-fw`/EDK2. Needs guest kernel ≥5.10 for `virtio-fs`. Generic rootfs (see §4).
- **Monitoring:** cgroup v2 (primary) + CH counters via API/events.
- **Distro:** **generic — boots stock Debian.** No specialized distro required.
- **Verdict:** meets every hard requirement; ~200 ms cold boot, ms-scale with snapshots. Make it the default backend.

### 3.2 Firecracker — fastest & smallest, but structurally limited for *your* list

Rust, KVM, AWS, Apache-2.0. ~**125 ms** to `/sbin/init`, **<5 MiB** memory overhead, up to **150 µVMs/s/host** — the density/latency leader, and it descends from crosvm.

- **Device model — only 5 devices:** `virtio-net`, `virtio-block`, `virtio-vsock`, serial console, a partial keyboard (reset only). No PCI. Minimal attack surface by design.
- **Shared FS:** **none.** Block devices only; `virtio-fs` was evaluated and rejected (issue #1180), still not present (confirmed in Jan-2026 write-ups: "only the five emulated virtio devices … no device passthrough"). This breaks your separate-permission shared-dirs requirement unless you accept per-share block images + host-side loopback for outputs.
- **vsock:** yes (userspace) — good for the agent.
- **Nested virt:** **no.** FC needs KVM and does not re-expose `/dev/kvm` to guests (#1721). Breaks your nested requirement.
- **Snapshot/restore:** yes (this is how Lambda gets its speed).
- **Rust control:** healthy SDK ecosystem driving the REST socket — **`fctools`** (most actively maintained, modular, includes an in-process networking backend), the **`firecracker`** crate (async builder, jailer support), `firecracker-rs-sdk` (std/tokio/async-std, start/stop/pause/resume), `firepilot` (older, OpenAPI-generated). Notably there's an **`agentkernel`** crate ("run AI coding agents in secure, isolated microVMs," very recently updated) — directly your problem space, worth reading.
- **Artifacts:** stripped, uncompressed `vmlinux` (x86) / PE `Image` (arm64). FC publishes `.config` files (5.10, 6.1 — dated LTS, minimal); for general workloads you compile your own with more drivers. No initramfs (FC injects an empty 134-byte one).
- **Monitoring:** JSON metrics to a FIFO + cgroup v2 (jailer sets up the cgroups for you).
- **Distro:** needs a FC-compatible kernel; minimal rootfs (Alpine is the common tutorial choice; Debian minbase works).
- **Verdict:** ideal *if* you could drop `virtio-fs` and nesting — which your list won't. Keep it as an **optional third backend** for the subset of tests that need neither shared FS nor nested VMs, to harvest its density and 125 ms boots.

### 3.3 crosvm — culturally closest to you, more glue required

Rust, Google/ChromeOS, BSD-3-Clause; Firecracker forked from it; shares rust-vmm. Given your Fuchsia/Google-systems context this is the one you'll be most at home reading.

- **Device model:** `virtio-{net,block,fs,9p,console,rng,balloon,vsock,gpu,…}`, both PCI and MMIO transports, VFIO. **Has `virtio-fs` *and* 9p.**
- **Shared FS:** `virtio-fs` with `fs_runtime_ugid_map` for host-side uid/gid mapping even without user namespaces — nice for your separate-permission shares.
- **vsock:** on Linux delegates to the kernel `vhost-vsock` (needs `vhost_vsock` host module). (crosvm's own userspace vsock impl is Windows-only.)
- **Sandboxing:** strongest of the bunch by default — **process-per-device + Minijail** (VFS/PID/user/net namespaces, strict seccomp-BPF per device, all caps dropped). If "defense in depth around the device emulators" matters, crosvm leads.
- **Nested virt:** partial/usable in some configs (ChromeOS runs nested guests), but less turnkey and less documented than CH/QEMU — budget verification time.
- **Rust control:** designed to be forked/embedded; control socket for runtime ops (`stop`, `balloon`, …). The catch: upstream crosvm is laced with ChromeOS-specific features you must disable for standalone use, and there's no stable "use crosvm as a library" contract the way libkrun/Dragonball offer.
- **Artifacts/distro:** generic; direct kernel boot; you assemble a rootfs.
- **Monitoring:** cgroup v2 + control socket.
- **Verdict:** excellent engineering and the best per-device sandboxing, but more integration friction (ChromeOS-isms, less-documented nesting) than CH for a from-scratch harness. Strong *secondary* candidate; reach for it if you want crosvm's Minijail model or you end up wanting tight coupling to the Fuchsia/ChromeOS toolchain.

### 3.4 QEMU `microvm` — the flexibility fallback

C, KVM, the most battle-tested option. The `microvm` machine type is explicitly "inspired by Firecracker": no PCI/ACPI, `virtio-mmio`, `qboot` or direct kernel boot, for short-lived guests, tuned for boot time and footprint.

- **Capability:** with standard QEMU you get *everything* — `virtio-fs` (`virtiofsd`), vsock (`vhost-vsock`), **the most proven nested virt**, every protocol/transport, VFIO, migration. If `microvm`'s stripped machine (no PCI, no hotplug) is too lean for a given test, switch that test to `q35` for the full device model. This is your "can always make it work" backend.
- **Boot:** `microvm` + direct kernel boot reaches **sub-300 ms to a fully-networked guest with the QEMU guest agent** (June-2026 measurement); a NetBSD/virtio-mmio guest boots in **31 ms**. Not Firecracker-fast, but close, and the ceiling on flexibility is much higher.
- **Rust control:** the mature **`qapi`** crate (`arcnmx/qapi-rs`, MIT, ~400k downloads/month, tokio-capable) speaks **QMP** (lifecycle, hotplug, `query-*` stats) *and* the **`qemu-guest-agent`** protocol (`qga` feature) for in-guest exec. `virt` (libvirt bindings) if you ever want libvirt's management layer.
- **Artifacts/distro:** generic, boots anything; direct kernel boot means the kernel lives on the host and the guest disk is rootfs-only.
- **Monitoring:** QMP `query-*` + cgroup v2.
- **Trade-off:** large C codebase = bigger attack surface and heavier process than the minimal Rust VMMs. For an eval harness running adversarial inputs, that's a real (if manageable) consideration. Keep it as the documented fallback and the nesting reference.

### 3.5 libkrun — library-first, but isolation-by-default is wrong for adversarial agents

A **dynamic library** VMM (C API, built as a Rust `cdylib`; Rust crates `krun-sys` FFI + `krun-vmm`). Incorporates Firecracker/rust-vmm/CH code; API stable since 1.0 (SemVer). Powers `crun`, Microsandbox, `muvm`, `krunkit`. MMIO-only device model.

- **Appeal:** genuinely library-shaped — `krun_create_ctx` → configure → `krun_start_enter`, no external VMM process to babysit. Has `virtio-fs` (`krun_add_virtiofs`), vsock, and a slick **TSI (Transparent Socket Impersonation)** mode where the VMM transparently proxies the guest's `AF_INET/INET6/UNIX` sockets with no tap device at all — which is *itself* a built-in logging/filtering choke point (your transparent-proxy requirement, for free).
- **The disqualifier for your use case:** libkrun's security model treats **guest and VMM as the same security context** — its own docs say to "think about the guest and the VMM as a single entity," and that `virtio-fs` "provides no isolation beyond what the host OS provides." For a harness whose entire point is isolating possibly-adversarial agent code from tests and (selectively) from the host, that inverts your trust model. You'd have to wrap each VMM in namespaces yourself to get back the boundary that CH/crosvm/QEMU give you by default.
- **Other friction:** the standard variant requires its **bundled kernel** (`libkrunfw`), so running a *stock Debian kernel* is awkward (the distro-kernel-booting EFI variant is macOS-only). No real nested-virt story.
- **Verdict:** great ergonomics, wrong default isolation and wrong kernel story for this project. Worth a hard look only if you later want an *embedded*, library-shaped VMM and you're willing to build the namespace isolation yourself — and even then mainly for the TSI networking idea.

### 3.6 Kata Containers / Dragonball — borrow ideas, don't adopt wholesale

Kata is going **Rust-first**: in 4.0 the Rust `runtime-rs` becomes default and the Go runtime is deprecated (~Q4 2026). `runtime-rs` can drive QEMU, CH, Firecracker, or **Dragonball** (Alibaba's **in-process Rust VMM library**, rust-vmm-based, with `inline_virtio_fs` that folds `virtiofsd` into the VMM address space and bypasses the FUSE socket for lower latency).

- **Why not adopt directly:** Kata is fundamentally an **OCI/CRI/Kubernetes** runtime — it's built around pods/containers and container orchestration, which is more (and differently) opinionated than a bespoke Rust test harness needs. You'd be fighting the container abstraction.
- **What to steal:** (a) **Dragonball** is a legitimately interesting *embeddable* Rust VMM if you want in-process control later; (b) the **agent-over-vsock-via-ttrpc** design and the `agent-ctl`/`kata-ctl` tools are a proven blueprint for your guest agent; (c) `osbuilder` is a reference for building the mini-OS rootfs/initrd/kernel.
- **Honest caveat:** Dragonball's theoretical lightweight-VMM advantages aren't fully realized yet — a 2025 study found it *slower* than QEMU to start containers on ARM64 due to immature ARM adaptation. Don't assume "newer Rust VMM ⇒ faster" without measuring on your target arch.

### 3.7 Roll-your-own on rust-vmm — maximum control, probably overkill

rust-vmm isn't a VMM; it's the **shared crate foundation** under Firecracker, CH, crosvm, libkrun, Dragonball, OpenVMM, and `virtiofsd`. Core pieces you'd assemble: `kvm-ioctls`/`kvm-bindings`, `vm-memory` (IOMMU, `guest_memfd`, Kani-verified), `vm-allocator`, `linux-loader`, `virtio-queue`/`virtio-bindings`, `vhost`/`vhost-user-backend`, `vfio-ioctls`, `vm-superio` (serial/i8042), plus the vhost-user device backends (vsock, virtiofsd, …). (Consolidating into a monorepo as of FOSDEM 2026; RISC-V landing.)

Given your Fuchsia virtio-driver work, building a minimal purpose-built VMM with *exactly* your device model is squarely within reach and would be the most elegant long-term artifact — but it's a large investment versus driving CH out-of-process, and you'd be re-deriving snapshot/restore, jailer, and the API surface. **Recommendation: don't start here.** Ship on CH, and only consider a rust-vmm VMM later if profiling shows CH's out-of-process control or device model is a real bottleneck. (If you do, your isolated-`unsafe` discipline from the virtio work transfers directly.)

### 3.8 macOS aside (vfkit / Virtualization.framework)
You've used `vfkit` before on Apple Silicon. For *this* platform it's almost certainly the wrong host: the requirements (nested virt, full Linux host access, Debian guests, `/dev/kvm`) point to a **Linux+KVM host**. Apple's Virtualization.framework now does nested virt on M3+, and `vfkit`/`libkrun-efi` exist on macOS, but you'd be giving up the KVM ecosystem (CH/Firecracker/crosvm and the whole rust-vmm device set) for a thinner, less controllable stack. Note only if some runners are Macs; build the platform Linux-first.

---

## 4. Guest OS: configuring Debian for a seconds-to-minutes micro-VM

Your direct question — "is server the way to go?" — **no.** The Debian *server* install (the `server` tasksel task / cloud image) carries far more than a short-lived VM needs, and most of what slows VM boot isn't the userland at all; it's firmware, bootloader, initramfs, and module probing. The right model is **"assemble a root filesystem, don't install an OS."**

**Build the rootfs with `mmdebstrap`, not the installer.** `mmdebstrap` is the faster, rootless-capable successor to `debootstrap`. Use a minimal variant (`--variant=minbase` or even `essential`) plus exactly the packages a test needs and your `imp-guest-agent`. Or build it from a Debian OCI base image (the Proxmox `pve-microvm` approach builds rootfs straight from OCI images for Debian/Alpine/Fedora/…). For maximum fidelity to your real **gLinux/Debian** environment, mirror that userland here rather than dropping to Alpine — the environment-match requirement outweighs Alpine's size advantage, and as shown below the distro userland is *not* where the boot-time budget goes.

**Decouple the kernel from the rootfs (direct kernel boot).** The kernel lives on the **host**; the guest disk holds only userland — no `/boot`, no GRUB, no per-guest kernel package, **no initramfs**. One `vmlinux`, built once, shared by every micro-VM, audited/updated in exactly one place. Build it from a stock `defconfig` + a microvm overlay (or start from Firecracker's published `.config`), with these built **in** (`=y`, not modules, so there's nothing to probe and no initramfs needed):

- `virtio` core + `virtio-pci`/`virtio-mmio` (match your VMM's transport), `virtio-blk`, `virtio-net`, `virtio-console`, `virtio-rng`, **`virtio-fs`/`fuse`**, **`vsock`/`vhost_vsock`**
- the rootfs filesystem (`ext4`, or `erofs`/`squashfs` for a read-only base)
- **`KVM` + `kvm-intel`/`kvm-amd`** *if you need nested virt in the guest*
- serial console; drop ACPI on the no-ACPI path for faster boot (Firecracker ships a `5.10-no-acpi` config for exactly this)

Avoiding the initramfs is a measured win — it removes a whole load/unpack stage and shrinks the memory footprint (the Firecracker analysis recommends exactly this; FC substitutes an empty 134-byte initramfs when none is supplied).

**Pick init for speed, not habit.** Three tiers:

1. **Agent as PID 1** (`init=/usr/bin/imp-guest-agent`): absolute minimum boot, no service manager. The agent brings up `eth0`/mounts itself (or you pre-bake them). Best for short, well-scoped tests.
2. **Tiny init → agent** (`tini`/`busybox init`/OpenRC): a few hundred ms, brings up vsock/net/mounts then `exec`s the agent. Good default — a little structure without systemd's weight.
3. **systemd** only if a test genuinely needs systemd semantics (units, cgroup delegation, `systemd-networkd`). Full Ubuntu+systemd is ~2–3 s; a trimmed systemd is sub-second but still heavier than (1)/(2). Reserve for fidelity cases.

**Concrete boot-time data points (mid-2026):**
- Firecracker: ~125 ms to `/sbin/init` (minimal kernel, no initramfs).
- QEMU `microvm` + direct kernel boot: sub-300 ms to a fully-networked guest with the guest agent; a NetBSD/virtio-mmio guest in **31 ms**.
- A *full* Debian-with-Docker image was "ready in under 8 s — and most of that was `apt` during first boot," i.e. **prebuild the rootfs**; don't install at boot.
- **With snapshot/restore, none of this is on the per-test critical path** — you boot once and restore in ms.

**Read-only base + ephemeral writes.** Ship the rootfs read-only (`erofs`/`squashfs`) with a tmpfs or per-VM overlay for writes. That reinforces no-leakage (the base literally can't be mutated), shrinks images, and lets the page cache serve a single shared base across many VMs. (The `microvm.nix` agent-sandbox above uses a read-only `erofs` rootfs for exactly this.)

---

## 5. Build/artifact pipeline (fits your existing build system)

Artifacts to produce and cache:

1. **`vmlinux`** (per arch): one custom kernel, direct-boot, drivers built-in, optional KVM-for-nesting. Versioned, host-side, shared by all VMs. Rebuild only when you change the kernel config.
2. **Base `rootfs.img`** (per profile): `mmdebstrap` minbase + toolchain + `imp-guest-agent`, read-only `erofs`/`squashfs`. The `imp-bin` Imp binaries are **not** baked in — they come from the build system over the `imp-bin` `virtio-fs` share, so a new Imp build doesn't mean a new rootfs.
3. **Warm snapshot/** (per VMM+profile): boot the base to "agent-ready," snapshot. Per-test = restore.
4. **CA cert** for the egress proxy, baked into the rootfs trust store.

Wire these into your build graph as normal outputs with content-addressed caching (your `clonefile`/reflink instincts from the ARM64 VM builder apply: fork the writable overlay per VM via reflink for near-instant, COW per-test disks). The orchestrator consumes (1)+(2)+(3), mounts (binaries) from the build system's output dir, and never rebuilds them per test.

---

## 6. Prior art worth reading before you write code

These are close enough to your design that they'll save you weeks — study the ones marked ★ first:

- ★ **`tinylabscom/mvm`** — a Rust CLI (`mvmctl`) that builds/runs micro-VMs across Firecracker (default, Linux+KVM), Cloud Hypervisor (opt-in, wider device model), Apple Container, and libkrun, with a **vsock-only guest agent ("NO SSH ever")**, BusyBox PID 1, ext4 rootfs, dm-verity sidecar, and per-service isolation (`setpriv`, seccomp). This is essentially a reference implementation of your spec. Read its `Vmm`-backend abstraction and guest-agent protocol.
- ★ **`microvm.nix` agent-sandbox write-up** (sandboxing the "Openclaw" agent on Cloud Hypervisor) — the egress topology you want: `nftables` forward-chain logging, `unbound` DNS logging, read-only `erofs` rootfs, the netlink/`os.networkInterfaces()` gotcha.
- ★ **`pve-microvm`** (Tao of Mac, mid-2026) — QEMU `microvm` as a first-class managed guest; direct-kernel-boot, rootfs-from-OCI, sub-300 ms boots, one shared host kernel. Great reference for the kernel/rootfs split and the build pipeline; author is explicitly chasing "agentic sandbox" use cases.
- **`agentkernel`** crate — "run AI coding agents in secure, isolated microVMs" on Firecracker; very recently updated; your exact problem domain in Rust.
- **`vmexec`** — zero-setup CLI for running commands in throwaway VMs on the rust-vmm stack; minimal end-to-end example of the ephemeral-VM-per-command pattern.
- **Ubicloud** — production architecture: a control plane over bare-metal Linux+KVM servers, **Cloud Hypervisor per VM inside Linux namespaces** for extra isolation, ephemeral clean VMs per CI job. Validates the "CH + namespaces + cgroups, fresh VM per job" model at scale.
- **Kata `agent` / `agent-ctl`** — the agent-over-vsock-via-ttrpc blueprint and tooling.
- **`fctools`** / the **`firecracker`** crate — if/when you add the Firecracker backend, these are the maintained Rust SDKs.

---

## 7. Open decisions for you

1. **Snapshot-restore vs cold-boot as the default.** Restore is dramatically faster but starts every test from identical memory — perfect for determinism, but you must rotate per-VM identity on restore (vsock CID, MAC/IP, entropy reseed) and confirm `virtio-fs`/vsock reconnect cleanly (CH handles vsock-reset-on-restore). Tests that mutate global state in ways the snapshot baked in should cold-boot. Suggest: restore by default, cold-boot opt-in per test.
2. **Transparent proxy: tap+`TPROXY`+mitmproxy/Rust-proxy vs usermode-net (`passt`/`gvproxy`).** Tap+TPROXY = faithful L2, full control, needs root + CA injection. Usermode = rootless, simpler, natural log point, slower and L2-approximate. For an eval harness, usermode's simplicity is attractive; for production-fidelity networking, tap wins. Possibly: tap for "fidelity" scenarios, usermode for "fast" scenarios — another axis on the `Vmm`/scenario config.
3. **How faithfully must "full host access" mirror the real host?** This drives whether you mount a disposable host tree, run a nested host VM, or (least safe) touch a sacrificial real host. Strong lean: nested host VM, which also exercises your nested-virt path.
4. **arm64 vs x86_64 (or both).** Your world spans both (Fuchsia ARM64 work, gLinux). CH/QEMU/Firecracker all do both, but feature/perf parity differs (e.g., Dragonball's weaker ARM64 maturity; CH documents x86/arm64 functional differences). Decide the primary CI arch early; it affects kernel configs and snapshot artifacts.
5. **Per-device sandboxing appetite.** If you want crosvm-grade Minijail isolation around the device emulators (vs CH's process+namespace model), that nudges toward crosvm despite the extra glue. Worth deciding before committing the `Vmm` trait's assumptions.

---

## Sources

VMM features / current state:
- Cloud Hypervisor v52.0 release notes & docs (device model, `fs.md`, `vsock.md`, nested-virt fixes): https://www.cloudhypervisor.org/blog/cloud-hypervisor-v52.0-released/ · https://github.com/cloud-hypervisor/cloud-hypervisor (`docs/device_model.md`, `docs/fs.md`, `docs/vsock.md`)
- Firecracker design/FAQ (5-device model, no virtio-fs, no nested): https://firecracker-microvm.github.io/ · host filesystem sharing #1180 · KVM-in-guest #1721 · `docs/rootfs-and-kernel-setup.md`
- "What is AWS Firecracker" (Jan 2026, boot/overhead numbers, limitations): https://northflank.com/blog/what-is-aws-firecracker
- "Guide to Cloud Hypervisor in 2026" (CH ~200 ms vs FC ~125 ms, 16 devices): https://northflank.com/blog/guide-to-cloud-hypervisor
- crosvm README & API docs (virtio-fs/9p, vhost-vsock, Minijail): https://github.com/google/crosvm · https://crosvm.dev/doc/
- QEMU `microvm` machine type: https://www.qemu.org/docs/master/system/i386/microvm.html · Ubuntu microvm docs: https://ubuntu.com/server/docs/explanation/virtualisation/qemu-microvm/
- libkrun (library VMM, TSI, shared security context caveat): https://github.com/containers/libkrun · https://deepwiki.com/containers/libkrun · crates `krun-sys`/`krun-vmm`
- Kata 4.0 / runtime-rs / Dragonball: https://katacontainers.io/blog/release-4-0-0-preview/ · https://kata-containers.github.io/kata-containers/design/virtualization/ · Dragonball ARM perf study: https://dl.acm.org/doi/full/10.1145/3773365.3773613
- rust-vmm crate inventory + ecosystem ("State of MicroVM Isolation in 2026"): https://emirb.github.io/blog/microvm-2026/

Rust control / SDKs:
- Firecracker SDKs: `fctools` https://github.com/rust-firecracker/fctools · `firecracker` crate https://crates.io/crates/firecracker · `firecracker-rs-sdk` · `firepilot` · `agentkernel`
- QEMU `qapi` (QMP + guest agent): https://github.com/arcnmx/qapi-rs

Networking / egress:
- Kernel transparent proxy (TPROXY vs REDIRECT): https://docs.kernel.org/networking/tproxy.html
- mitmproxy transparent / VM proxying: https://docs.mitmproxy.org/stable/howto/transparent/ · https://docs.mitmproxy.org/stable/howto/transparent-vms/
- microvm.nix agent sandbox (CH + nftables/unbound logging, erofs): https://buduroiu.com/blog/openclaw-microvm/

Guest OS / boot:
- Direct-kernel-boot & rootfs-from-OCI (pve-microvm, sub-300 ms, 31 ms NetBSD, prebuild-don't-apt): https://taoofmac.com/space/blog/2026/06/18/1845
- Firecracker rootfs/kernel setup & no-initramfs analysis: https://github.com/firecracker-microvm/firecracker/blob/main/docs/rootfs-and-kernel-setup.md · https://arxiv.org/pdf/2005.12821

Prior art:
- `mvm` (multi-VMM, vsock-only agent): https://github.com/tinylabscom/mvm
- Nested virt on cloud VMs (AWS C8i/M8i/R8i, 2026): context on where to host the platform

*(Version numbers and feature claims reflect the state found at research time, mid-June 2026; CH was at v52.0, Kata 4.0 in preview. Re-verify nesting/virtiofs flags against the exact VMM build you pin.)*
