# vmcell

An end-to-end integration-testing and evaluation platform for a hypothetical agentic harness.
Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity.
Driven entirely from a single Rust library, organized as a cargo **workspace**: the `vmcell` library
(plus its CLI) and four lean member crates — `vmcell-protocol` (the shared wire enum),
`vmcell-guest-agent` (guest PID 1), `vmcell-test-runner` (the privileged-test capability runner), and
`vmcell-guest-tools` (the in-rootfs `ip`/`curl`/`kvm-ok` helper).

## CLI (`vmcell`)

The library API is the product surface; the `vmcell` binary is a thin `clap` wrapper for trying it
out. Build it with `cargo build` (the default feature set) and run subcommands with
`cargo run -p vmcell --bin vmcell -- <subcommand>`:

| Subcommand | What it does |
|---|---|
| `build` | Build all VM artifacts (kernel, erofs rootfs, proxy CA) from `pins.json`. |
| `build-kernels` | Build every kernel in the `pins.kernels` registry to `vmlinux-<label>`. |
| `oci2erofs IMAGE@sha256:DIGEST -o out.erofs` | Convert any **digest-pinned** OCI base image into an erofs rootfs (verify blobs → whiteouts → inject agent/CA/tools → pack). Tags are rejected; a libc6-less base fails loud unless `--agent-musl <path>` supplies a static-musl agent. |
| `run --kernel K --rootfs R [-- CMD…]` | Boot a fresh micro-VM, run `CMD` (default `/bin/true`) over vsock, tear down, and exit with the guest's exit code. |
| `create --kernel K --rootfs R` | Boot a micro-VM and confirm the agent is ready, then tear down (a boot smoke test). |
| `snapshot --kernel K --rootfs R --out DIR` | Boot a micro-VM and write a warm snapshot into `DIR` (snapshot-eligible config only). |
| `stats --kernel K --rootfs R` | Boot a micro-VM, sample resource usage, print it as JSON, tear down. |
| `bundle [-o manifest.json]` | Write a digest-pinned fetch-and-verify manifest of the built artifacts (kernel/rootfs/CA/pins.json). |
| `verify-bundle [-m manifest.json]` | Re-hash every artifact in a manifest and fail loud on any mismatch. |
| `exec` / `ls` / `rm` / `destroy` | Deferred to the `vmcelld` daemon (§18) (need a cross-process VM registry); these fail loud with a typed error. |

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
cargo install vhost-device-vsock --locked   # only needed for the QEMU unprivileged-vsock path
```

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
is validated live via the opt-in `just test-crosvm` matrix (21/21 on a KVM host with a source-built
crosvm); virtio-fs and unprivileged-net stay honest-`false`. Snapshot/restore follows the Firecracker
baked-CID pattern (single-lineage, no concurrent fan-out). Its KVM-free gates (unit tests,
capability-honesty pins, seccomp mapping, clippy) run in `just ci`; the live matrix needs KVM **and** a
crosvm binary and is deliberately **not** part of `just test-privileged`, so a host without crosvm is
unaffected — install this only to run the crosvm backend.

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
and grants *that copy* the three capabilities:

```sh
sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep .vmcell-bin/debug/vmcell-test-runner
sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep .vmcell-bin/release/vmcell-test-runner
```

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
- `just test-privileged` — the privileged KVM integration tier (run `just bless` once first; see §5).

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

- **`prebuilt`** downloads a digest-pinned, SHA256-verified `vmlinux` (Kata's) — no kernel toolchain,
  one large one-time download. It boots and runs `just test-unit`, `just test-unprivileged`, and
  `just test-daemon`, plus most of `just test-privileged`. But that image **omits `CONFIG_KVM_INTEL`
  and `CONFIG_HW_RANDOM_VIRTIO`**, so six privileged tests fail on it: `nested_virt` /
  `nested_virt_disabled` (CH + QEMU) need an openable guest `/dev/kvm`, and `snapshot_restore`'s
  post-restore entropy reseed (CH + FC) needs guest `/dev/hwrng` from virtio-rng.
- **`host-make`** compiles the pinned Linux source on the host (the `build-essential flex bison bc
  libelf-dev libssl-dev` from §1) and appends vmcell's microvm KConfig, which sets both options —
  `just test-privileged` then passes in full (102/102 on a KVM host). To keep the fast prebuilt
  kernel as the default artifact and still run those six, build a host-make kernel under a label with
  `vmcell build-kernels` and point `VMCELL_KERNEL` at the resulting `vmlinux-<label>` for the
  privileged run.

### 9. Packages supporting experiments

The groups above are everything the product needs to build and run. The packages below are **only**
for the *optional* performance experiments and contested-fact benchmarks in the design doc §13 (the
`bench-vm` macro-harness plus a few out-of-band measurement probes). None is required to build or run
`vmcell` itself — install only the ones for the experiment you actually want to reproduce.

```sh
# §13.3  static-musl guest-agent experiment (musl vs glibc on-disk size / RSS / rootfs-independence)
sudo apt install -y musl-tools                 # provides `musl-gcc`
rustup target add x86_64-unknown-linux-musl    # the prebuilt musl libc rustc links against
#   The all-Rust agent links musl *statically without* `musl-gcc`; `musl-gcc` only becomes
#   necessary once the agent gains a C / `*-sys` dependency that has to be cross-compiled.

# §13.6  rootfs image-size comparison: OCI slim base vs a minimal mmdebstrap build
sudo apt install -y erofs-utils                # provides `mkfs.erofs` for the size/compressor probe.
#   The production pipeline packs erofs in-crate via `am-fs-erofs`; `mkfs.erofs` is only the
#   out-of-band yardstick used to compare lz4/zstd/uncompressed sizes.
sudo apt install -y skopeo                      # pull the digest-pinned OCI base out-of-band.
#   Production pulls via the in-crate `oci-client`; `skopeo` is only for the manual size probe.
sudo apt install -y mmdebstrap                  # build the `--variant=minbase` comparison tree
#   host-side. (Production runs mmdebstrap *inside* a builder micro-VM, so the product itself
#   needs no host mmdebstrap — this is for the size measurement only.)

# §13.2  benchmark noise-floor discipline: pin the CPU frequency so latency numbers don't drift
sudo apt install -y linux-cpupower             # provides `cpupower` (applying a governor needs root)
```

Benchmarks are *tracked metrics, not pass/fail gates* (design §13.7), so a missing package degrades
an experiment to "not measured here," never a build or test failure.
