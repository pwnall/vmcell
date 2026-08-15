# vmcell

An end-to-end integration-testing and evaluation platform for a hypothetical agentic harness.
Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity.
Driven entirely from a single Rust library, organized as a cargo **workspace**. `vmcell` is the host
library and carries the primary Cloud Hypervisor backend; the three secondary backends live in their
own crates (`vmcell-firecracker`, `vmcell-qemu`, `vmcell-crosvm`), each depending on `vmcell` for the
one `Vmm` trait and the shared jail/seccomp/spawn helpers. Around them sit the lean members —
`vmcell-protocol` (the shared wire enum), `vmcell-guest-agent` (guest PID 1), `vmcell-test-runner`
(the privileged-test capability runner), `vmcell-guest-tools` (the in-rootfs multicall helper:
vmcell's own `ip`/`curl`/`kvm-ok`/`echo-server` applets, symlinked into `/vmcell-tools`, which the
guest agent puts **first** on the guest `PATH` — so an in-guest `curl` is this shim, which
implements a fixed curl-flag subset and *rejects* anything outside it rather than ignoring it),
`vmcell-privilege`, the two in-VM artifact builders, the `vmcell-artifact-validator` conformance kit,
the `vmcell-bench` harness, the CLI, and the control-plane tier (`vmcell-daemon`, `vmcelld`,
`vmcell-daemon-client`, `vmcelld-ctl`, `vmcell-broker`).

## CLI (`vmcell`)

The library API is the product surface; the `vmcell` binary is a thin `clap` wrapper for trying it
out. The binary lives in the `vmcell-cli` crate (`vmcell` itself declares no binary). Build it with
`cargo build` (the default feature set) and run subcommands with
`cargo run -p vmcell-cli --bin vmcell -- <subcommand>`:

| Subcommand | What it does |
|---|---|
| `build` | Build all VM artifacts (kernel, erofs rootfs, proxy CA) from `pins.json`. |
| `build-kernels` | Build every kernel in the `pins.kernels` registry to `vmlinux-<label>`. |
| `oci2-erofs IMAGE@sha256:DIGEST -o out.erofs` | Convert any **digest-pinned** OCI base image into an erofs rootfs (verify blobs → whiteouts → inject agent/CA/tools → pack). Tags are rejected; a libc6-less base fails loud unless `--agent-musl <path>` supplies a static-musl agent. |
| `run --kernel K --rootfs R [-- CMD…]` | Boot a fresh micro-VM, run `CMD` (default `/bin/true`) over vsock, tear down, and exit with the guest's exit code. |
| `create --kernel K --rootfs R` | Boot a micro-VM and confirm the agent is ready, then tear down (a boot smoke test). |
| `snapshot --kernel K --rootfs R --out DIR` | Boot a micro-VM and write a warm snapshot into `DIR` (snapshot-eligible config only). |
| `stats --kernel K --rootfs R` | Boot a micro-VM, sample resource usage, print it as JSON, tear down. |
| `bundle [-o manifest.json]` | Write a digest-pinned fetch-and-verify manifest of the built artifacts (kernel/rootfs/CA/pins.json). |
| `verify-bundle [-m manifest.json]` | Re-hash every artifact in a manifest and fail loud on any mismatch. |
| `exec` / `ls` / `rm` / `destroy` | Deferred to the `vmcelld` daemon (design §11) (need a cross-process VM registry); these fail loud with a typed error naming the `vmcelld-ctl` route. |

## Consuming vmcell as a dependency (the downstream contract)

vmcell has out-of-repo consumers, so the surface they stand on is named here and held still by gates
(design §10.4) — no more "public in the Rust-visibility sense, semi-public in practice".

**The contract surface.** The pins schema + overlay semantics; `Stage`, `Pipeline`,
`ResolvePinsStage`, `StageInputs`/`StageOutputs`, `CacheKey` and the hash helpers; the kernel build
entry points and the resolved-config sidecar; `pack_erofs_with_injection` + `ExtraFile` and the
rootfs-construction contract; the `VMCELL_*` env contract below; and the `vmcell-artifact-validator`
battery + `KconfigValues`. A breaking change to any of it is a **deliberate ledger entry** in the
comment-changelog at the top of `crates/vmcell/Cargo.toml` (pre-1.0 convention: breaking changes are
minor bumps), never something a consumer discovers when their build breaks. `cargo semver-checks`
gates both contract crates (`vmcell` and `vmcell-artifact-validator`), and the out-of-tree
`examples/downstream-kernel/` workspace builds on every push as the living consumer — **reddening
that job is the intended failure mode of contract drift**, so fix the contract or bump it, never the
example.

**The `VMCELL_*` environment contract.**

| Variable | Contract |
|---|---|
| `VMCELL_ARTIFACTS_DIR` | Relocates the artifact cache; all freshness/fingerprint logic runs there unchanged. |
| `VMCELL_KERNEL` | Path redirect only: the kernel is used verbatim and must exist (fail-loud). It does **not** disable any build. |
| `VMCELL_ROOTFS` | The externally-managed-artifacts switch: its presence makes `ensure_test_artifacts` a **full no-op** — not a rootfs-only skip, so the kernel-presence check and the agent/tools rebuilds are skipped too. This is the switch a downstream harness sets. |
| `VMCELL_PINS` | The pins overlay: a JSON file whose top-level keys override the committed baseline key-by-key. An unknown or wrong-shaped top-level key is a hard error naming it, so a typo'd override can never silently resolve from the baseline. |
| `VMCELL_CH_BIN` / `_FC_BIN` / `_QEMU_BIN` / `_CROSVM_BIN` | Backend binary resolvers. |
| `VMCELL_SKIP_MANIFEST` | Where capability-driven test skips are recorded (`SKIP <vmm> <capability>`). |

**The harness getters, downstream.** In a consumer workspace `harness::get_vmlinux()`/`get_rootfs()`
have exactly two behaviors: with `VMCELL_KERNEL` + `VMCELL_ROOTFS` set (the documented downstream
configuration) they return those paths after an existence check; **without** them — including with
`VMCELL_PINS` alone — they **fail loud**, naming the two-step route (build the kernel through the
toolkit, then point `VMCELL_KERNEL`/`VMCELL_ROOTFS` at the outputs). They never quietly try to run
the workspace bootstrap against your cargo checkout, because that bootstrap structurally cannot build
downstream. Build with the overlay; consume through the env contract.

**Git-dep guidance**, each item load-bearing:

1. Pin by `rev`, build `--locked`, and use a toolchain at least the single-source MSRV
   (`rust-toolchain.toml` ≡ `[workspace.package] rust-version`). Understating the MSRV lets
   MSRV-aware resolvers hand you older, vulnerable dependency versions.
2. **If you use QEMU with `NetConfig::Unprivileged`, replicate the `[patch.crates-io]` vendored-vhost
   stanza in your own workspace root.** Cargo honors patch sections only from the *consuming*
   workspace root, so a plain git dep silently drops vmcell's carried `SET_VRING_ENABLE` fix and
   regresses that one path to a cryptic vhost-handshake boot failure:

   ```toml
   [patch.crates-io]
   vhost = { git = "https://github.com/<your-fork-or-vmcell-remote>", rev = "<the rev you pinned>" }
   vhost-user-backend = { git = "https://github.com/<your-fork-or-vmcell-remote>", rev = "<the rev you pinned>" }
   ```

   (The path form works too, but then copy the `vendor/vhost*` trees as well. Every other
   backend/mode needs none of this.)
3. Run `scripts/check-vendored-vhost.sh` in your CI when (2) applies. It is path-independent — it
   greps *your* workspace's `cargo tree` for the patched resolution — and is the same predicate
   vmcell's own CI runs, so the check cannot drift between here and downstream. A workspace that
   never links vhost gets a "not applicable" pass rather than a failure it is told to ignore.
4. Artifacts: build the rootfs with a vmcell checkout (`vmcell build`, or `vmcell oci2-erofs …
   --inject …` for your own files), then point your harness at it with `VMCELL_ROOTFS` +
   `VMCELL_ARTIFACTS_DIR`. Kernels build downstream through the toolkit with `VMCELL_PINS`.
5. **Privileged runs need a capability runner installed in *your* workspace.** `just bless` is a
   vmcell-checkout recipe and `vmcell-test-runner` is not a member of your workspace, so do the four
   steps yourself, once per profile you test under:

   ```sh
   # (a) build the runner from the vmcell checkout you pinned (same rev as the git dep)
   cargo build --locked --release -p vmcell-test-runner   # in the vmcell checkout
   # (b) install it under YOUR workspace, owner-only before it gains caps
   install -D -m 0700 <vmcell-checkout>/target/release/vmcell-test-runner \
       .vmcell-bin/release/vmcell-test-runner
   # (c) grant the blessed capability set to that copy (one sudo)
   sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override,cap_setpcap+ep .vmcell-bin/release/vmcell-test-runner
   # (d) wire cargo/nextest's target runner at it
   CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="$PWD/.vmcell-bin/release/vmcell-test-runner" \
       cargo nextest run --release …
   ```

   **The copy must live in your workspace**, and this is the part not to "simplify" away: the runner
   derives its trusted confinement root from its **own** canonicalized path — the `.vmcell-bin`
   ancestor's parent, then that workspace's `target/` — and refuses to exec anything outside it. A
   runner blessed inside the vmcell checkout would therefore refuse *your* test binaries. Mode `0700`
   is the real security boundary (the runner holds `cap_sys_admin`); on a shared box use a dedicated
   group + `0750`. Writing a file strips its capabilities, so redo (b)–(c) whenever you rebuild the
   runner.

## Development

The suite targets a Linux **x86_64** host with KVM enabled (`/dev/kvm` present). External tooling
falls into four groups: system packages, Cargo-installed subprocess binaries, the externally
distributed VMM binaries (Firecracker, QEMU, and — optional — crosvm), and the developer command
runner (`just`).

### 1. System Packages (Debian / Ubuntu)

```sh
sudo apt update
sudo apt install -y \
    build-essential flex bison bc libelf-dev libssl-dev \
    pkg-config libseccomp-dev libcap-ng-dev libcap2-bin \
    nftables
```

What these are for:

- `build-essential flex bison bc libelf-dev libssl-dev` — the guest kernel is built **on the host**
  with `make` from a pinned, SHA256-verified `linux.tar.xz` that the artifact pipeline downloads.
  There is no host `mmdebstrap`/`debootstrap` step: the Debian rootfs is built either from a
  digest-pinned OCI base image or by running `mmdebstrap` *inside* a builder micro-VM, so no host
  bootstrap tooling (and no `/bin/sh` → `bash` workaround) is required.
- `pkg-config libseccomp-dev libcap-ng-dev` — build dependencies for the Cargo-installed
  `cloud-hypervisor` and `virtiofsd` binaries (§2).
- `libcap2-bin` — provides `setcap`, used to bless the privileged test runner (§6).
- `nftables` — provides `nft`; the transparent egress proxy installs an `nft` TPROXY ruleset.
  (Host networking otherwise uses `rtnetlink` directly, so the `ip` CLI / `iproute2` is not needed.)

### 2. Cargo-installed subprocess binaries

`cloud-hypervisor` (the primary VMM) and `virtiofsd` (the virtio-fs daemon) are installed via Cargo
so they build as optimized release binaries spawned by the orchestration layer. `vhost-device-vsock`
backs the unprivileged vsock control plane on the QEMU backend.

```sh
cargo install --git https://github.com/cloud-hypervisor/cloud-hypervisor.git cloud-hypervisor
cargo install virtiofsd --locked
cargo install vhost-device-vsock --locked
```

All three are required for the full suites, `vhost-device-vsock` included: it is the **default** QEMU
vsock transport (`uses_in_kernel_vsock` returns `cfg.snapshotting` on `Auto`), so every
non-snapshotting QEMU leg spawns it — by bare name, with a deliberately loud failure if it is
missing. Cloud Hypervisor also publishes a static `cloud-hypervisor-static` binary on its GitHub
releases; CI uses that (pinned by digest) instead of the source build above, which is the faster
route if you do not need a local CH build.

Ensure that `~/.cargo/bin` is in your `$PATH` so the test suite can discover these executables.

### 3. Firecracker Binary

Unlike Cloud Hypervisor, Firecracker uses a custom containerized build process (`tools/devtool`) and
is not intended to be built via a standard `cargo install`. Instead, we use the pre-compiled external
binaries from their GitHub releases.

Download and install the latest Firecracker release (e.g. v1.16.0) on Debian/Ubuntu:

```sh
curl -LO https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.0/firecracker-v1.16.0-x86_64.tgz
tar -xzf firecracker-v1.16.0-x86_64.tgz
sudo mv release-v1.16.0-x86_64/firecracker-v1.16.0-x86_64 /usr/local/bin/firecracker
sudo chmod +x /usr/local/bin/firecracker
rm -rf firecracker-v1.16.0-x86_64.tgz release-v1.16.0-x86_64
```

### 4. QEMU Binary

QEMU serves as the fallback VMM backend and is the most proven platform for nested virtualization.
Install the `qemu-system-x86` package which provides the `qemu-system-x86_64` binary.

```sh
sudo apt install -y qemu-system-x86
```

### 5. crosvm Binary (optional, secondary backend)

crosvm (the ChromeOS Rust VMM) is a fourth, secondary backend. Unlike Firecracker there is **no
official prebuilt binary release** and no Debian/Ubuntu package, so it is built from source. crosvm is
only *spawned* as an external binary (never linked as a crate), so — exactly like the QEMU binary — it
does **not** enter the workspace `Cargo.lock`, the `cargo deny` license scan, or the dependency tree.

crosvm's full path (boot, agent-exec, sessions, tap networking, cgroup limits, and **snapshot/restore**)
is validated live via the opt-in `just test-crosvm` matrix — 29/29 on a KVM host with a source-built
crosvm (2026-08-14); that recipe is the number's source, so read it there rather than from here.
virtio-fs and unprivileged-net stay honest-`false`. Snapshot/restore follows the Firecracker
baked-CID pattern (single-lineage, no concurrent fan-out). Its KVM-free gates (unit tests,
capability-honesty pins, seccomp mapping, clippy) run in `just ci`; the live matrix needs KVM, a
crosvm binary, and a blessed runner (§6), and is deliberately **not** part of `just test-privileged`,
so a host without crosvm is unaffected — install this only to run the crosvm backend.

Build from source (Debian / Ubuntu):

```sh
sudo apt install -y build-essential clang libclang-dev libcap-dev libwayland-dev pkg-config protobuf-compiler
git clone https://chromium.googlesource.com/crosvm/crosvm && cd crosvm
git submodule update --init          # pulls minijail — REQUIRED
cargo build --release                # → ./target/release/crosvm
sudo install -m 0755 target/release/crosvm /usr/local/bin/crosvm
```

crosvm pins its own Rust toolchain via its `rust-toolchain` file and should be built `--locked` against
its committed `Cargo.lock`.

The `apt` line above covers the **default** feature build, whose gpu/wayland/audio/video features pull
extra system libraries — `libwayland-dev` is the first (and other default features, e.g. gpu, may pull
further `-dev` packages depending on your target crosvm version). vmcell drives crosvm **headless**
(serial + virtio-block + virtio-net + vsock) and needs none of those features, so the cleaner route is a
slimmed build that skips the whole gpu/wayland/audio dependency chain:

```sh
cargo build --release --no-default-features
```

The test suite discovers the binary via `$VMCELL_CROSVM_BIN` (default: `crosvm` on `$PATH`).

### 6. Privileged Test Runner

To run privileged networking tests (like those requiring TAP interfaces or transparent proxying)
without running the entire `cargo test` suite as `root`, we use a lightweight capability-granting
runner.

Bless it once with `just bless`:

```sh
just bless
```

This builds the runner (its own workspace member crate — no `--features` needed), installs a copy
to a **stable path outside `target/`** (the gitignored `./.vmcell-bin/{debug,release}/vmcell-test-runner`),
and grants *that copy* the blessed capability set:

```sh
sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override,cap_setpcap+ep .vmcell-bin/debug/vmcell-test-runner
sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override,cap_setpcap+ep .vmcell-bin/release/vmcell-test-runner
```

Three of those four are what the privileged mode actually uses and what the runner **delivers** to
the test over the ambient set (`vmcell_privilege::PRIVILEGED_CAPS`: `cap_net_admin` for
netns/tap/nft, `cap_sys_admin` for mount/cgroup, `cap_dac_override` for the root-owned netns bind
mount). The fourth, `cap_setpcap`, is **transient** and is never delivered anywhere: its only use is
`PR_CAPBSET_DROP`, which the kernel gates on it, and the runner drops it back out of both the
bounding set and permitted/effective before it `exec`s the test. Without it that shrink silently
fails and the bounding set stays as wide as the kernel supports, so a child could still gain
capabilities through a file-cap'd or setuid binary. `vmcell-privilege` owns the list
(`BLESSED_FILE_CAPS`), and a unit gate walks the tree for every `setcap` command copy outside
`docs/historical/` — this file's three, the `bless` recipe's one, the design doc's downstream-consumer
one — and asserts each names exactly that set, with the preflight probe's `NEEDED_CAPS` array checked
alongside, so no copy can drift.

**Why the stable path (v15 §12.8):** writing a binary file strips its capabilities, and cargo
rewrites `target/<profile>/vmcell-test-runner` for reasons unrelated to the runner's own source (a
`RUSTFLAGS=-D warnings` re-fingerprint, a feature-set toggle, a profile change). Because cargo only
ever touches `target/`, the blessed copy under `./.vmcell-bin/` keeps its caps across all that churn,
so you almost never need to re-bless. `just bless` is also **idempotent**: it records the runner's
`sha256` in a sibling `.blessed` stamp and skips the `sudo setcap` (no password prompt) until the
runner binary genuinely changes. The stamp keys on the **runner** only — never on the test binaries
it wraps, whose identity is deliberately out of scope (the security boundary is *who may execute the
runner* plus path-confinement, not test-binary content).

The privileged suite points the cargo/nextest target-runner at this stable path; `just
test-privileged` (§7) wires it up for you.

### 7. Developer command runner (`just`) and CI tooling

The lint, test, and dependency gates are driven by [`just`](https://github.com/casey/just) recipes
(`just ci`, `just test-unit`, `just test-unprivileged`, `just test-privileged`, `just bless`). Install `just`
plus the Cargo subcommands those recipes call. All of these are **binary `cargo` subcommands**, not
library dependencies, so they are installed with `cargo install` rather than added to `Cargo.toml`:

```sh
cargo install just --locked                  # the command runner (Debian 13+/Ubuntu 24.04+: `sudo apt install just`)
cargo install cargo-nextest --locked         # test runner used by every `just test-*` recipe
cargo install cargo-hack --locked            # feature-powerset clippy gate in `just ci`
cargo install cargo-deny --locked            # license / advisory gate in `just ci`
cargo install cargo-semver-checks --locked   # public-API semver gate (CI runs it on PRs)
```

As with the binaries above, ensure `~/.cargo/bin` is in your `$PATH` so `cargo` and `just` can
discover them.

Common recipes:

- `just test-unit` — fast unit, codec, and property tests (no KVM, no privileges).
- `just ci` — `cargo fmt`, clippy, feature-powerset clippy, `cargo deny`, the global-state ban, and
  the unit suite.
- `just test-unprivileged` — the unprivileged (smoltcp NAT) KVM integration tier.
- `just test-privileged` — the privileged KVM integration tier (run `just bless` once first; see §6).
- `just test-daemon` — the `vmcelld` integration tier (same blessed runner, under a delegated cgroup
  scope).
- `just test-crosvm` — the opt-in crosvm live matrix (§5).
- `just skip-manifest-show` — the capability-driven skips this run recorded; review them.

#### What CI runs, and what only you can run

CI (`.github/workflows/ci.yml`) runs on **GitHub-hosted runners only** — there is no self-hosted
runner, and nothing here depends on one. Four jobs:

| Job | Covers |
| --- | --- |
| `lint` | everything in `just ci` except the test run: fmt, clippy, feature-powerset, `cargo deny`, rustdoc, the ban scripts, shellcheck/actionlint/zizmor/machete/typos, and (on PRs) `cargo semver-checks` |
| `test-unit` | `just test-unit` — unit, codec and property tests, no KVM |
| `example-downstream` | the downstream toolkit contract's KVM-free legs |
| `test-integration` | `just test-unprivileged`, `just bless`, `just test-privileged`, `just test-daemon`, and the downstream example's live leg — **real VMs, on `ubuntu-24.04`** |

`test-integration` boots real guests on a hosted runner: `/dev/kvm` is present there and made
openable with a udev rule, `kvm_intel.nested = Y` so the nested-virt legs are real, and the suites
run inside `systemd-run --user --scope -p Delegate=yes` because a hosted runner's own cgroup is not
delegated. It installs Cloud Hypervisor, Firecracker, `virtiofsd` and `vhost-device-vsock` itself,
so you do **not** need a KVM host to get integration coverage on a pull request.

Two things CI cannot run, and which therefore need a local run before you trust them:

- **`just test-crosvm`** — the crosvm live matrix. crosvm has no prebuilt binary release and no
  Debian package (§5), so it is built from source and the matrix is opt-in. Its KVM-free honesty
  pins do run in `test-unit`.
- **`just test-usb-passthrough`** — needs a *designated physical USB device*
  (`VMCELL_TEST_USB_DEVICE`). Without one the privileged suite records a capability skip, which you
  will see in `just skip-manifest-show`.

Everything else that runs locally also runs in CI. If you are changing guest-side code, remember the
artifacts are baked: rebuild with `vmcell build --kernel-source host-make` (§8) before believing a
local live run.

Built VM artifacts (kernel, rootfs, proxy CA) default to `target/vmcell-artifacts`, overridable via
`VMCELL_ARTIFACTS_DIR` (with `VMCELL_KERNEL` / `VMCELL_ROOTFS` overriding the individual kernel/rootfs paths).

### 8. Building the VM artifacts

The KVM integration suites need built artifacts (guest kernel, erofs rootfs, proxy CA) in the
artifacts dir. Build them once with the CLI:

```sh
# Fast: a digest-pinned prebuilt guest kernel (no kernel toolchain needed).
cargo run -p vmcell-cli --bin vmcell -- build

# Full privileged suite: compile the guest kernel on the host (uses the §1 kernel deps).
cargo run -p vmcell-cli --bin vmcell -- build --kernel-source host-make
```

`--kernel-source` (default `prebuilt`) selects the guest-kernel seed. **This is an unprivileged
build — no `sudo` / root step is involved either way.**

> **`build` overwrites the default `vmlinux`.** Both seeds publish the *same* artifact path, so a
> bare `vmcell build` (i.e. `--kernel-source prebuilt`) silently replaces a host-make kernel you
> built earlier — and the next privileged run reddens on the legs below. Re-run `build
> --kernel-source host-make`, or keep the compiled kernel under a label (see the `host-make` bullet).

- **`prebuilt`** downloads a digest-pinned, SHA256-verified `vmlinux` (Kata's) — no kernel toolchain,
  one large one-time download. It boots and runs `just test-unit`, `just test-unprivileged`, and
  `just test-daemon`, plus most of `just test-privileged`. But that image **omits `CONFIG_KVM_INTEL`
  and `CONFIG_HW_RANDOM_VIRTIO`**, so three privileged tests fail on it, once per backend that
  advertises the capability: `nested_virt` and `nested_virt_disabled` need a guest `/dev/kvm` and a
  readable `kvm_{intel,amd}.nested` parameter, and `snapshot_restore`'s post-restore entropy reseed
  needs guest `/dev/hwrng` from virtio-rng.
- **`host-make`** compiles the pinned Linux source on the host (the `build-essential flex bison bc
  libelf-dev libssl-dev` from §1) and appends vmcell's microvm KConfig, which sets both options —
  `just test-privileged` then passes in full. No tally is quoted here — an embedded pass/total moves
  with every suite change and this one had already gone stale twice. Run `just test-privileged` for
  the pass/total and `just skip-manifest-show` for the capability skips. Those are **two different
  quantities**, and they sit one line apart in the same output: nextest's `N skipped` summary field
  counts *deselected* tests (filtered out before running), whereas a **capability** skip is a
  `require_cap!` record written to `$VMCELL_SKIP_MANIFEST`. Reading the first as the second is
  exactly how the number that used to be here was wrong. To keep the fast prebuilt kernel as the
  default artifact and still run those legs, build a host-make kernel under a label with
  `vmcell build-kernels` and point `VMCELL_KERNEL` at the resulting `vmlinux-<label>` for the
  privileged run — a labelled kernel has its own filename, so `build` cannot clobber it.
- **`in-vm`** compiles the pinned source *inside* a builder micro-VM. It needs a kernel to boot the
  builder, so it is a typed refusal on `build`; its route is `vmcell build-kernels --kernel-source
  in-vm`, which stages the bootstrap seed ahead of it.

### 9. Packages supporting experiments

The groups above are everything the product needs to build and run. The packages below are **only**
for the *optional* performance experiments and contested-fact benchmarks behind design §16 and
`docs/benchmark-results.md` (the `bench-vm` macro-harness plus a few out-of-band measurement probes).
None is required to build or run `vmcell` itself — install only the ones for the experiment you
actually want to reproduce.

```sh
# static-musl guest-agent experiment (musl vs glibc on-disk size / RSS / rootfs-independence)
sudo apt install -y musl-tools                 # provides `musl-gcc`
rustup target add x86_64-unknown-linux-musl    # the prebuilt musl libc rustc links against
#   The all-Rust agent links musl *statically without* `musl-gcc`; `musl-gcc` only becomes
#   necessary once the agent gains a C / `*-sys` dependency that has to be cross-compiled.

# rootfs image-size comparison: OCI slim base vs a minimal mmdebstrap build
sudo apt install -y erofs-utils                # provides `mkfs.erofs` for the size/compressor probe.
#   The production pipeline packs erofs in-crate via `am-fs-erofs`; `mkfs.erofs` is only the
#   out-of-band yardstick used to compare lz4/zstd/uncompressed sizes.
sudo apt install -y skopeo                      # pull the digest-pinned OCI base out-of-band.
#   Production pulls via the in-crate `oci-client`; `skopeo` is only for the manual size probe.
sudo apt install -y mmdebstrap                  # build the `--variant=minbase` comparison tree
#   host-side. (Production runs mmdebstrap *inside* a builder micro-VM, so the product itself
#   needs no host mmdebstrap — this is for the size measurement only.)

# benchmark noise-floor discipline: pin the CPU frequency so latency numbers don't drift
sudo apt install -y linux-cpupower             # provides `cpupower` (applying a governor needs root)
```

Benchmarks are *tracked metrics, not pass/fail gates* (design §16), so a missing package degrades
an experiment to "not measured here," never a build or test failure.
