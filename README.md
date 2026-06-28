# Imp Testing

An end-to-end integration-testing and evaluation platform for the Imp agentic harness.
Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity.
Driven entirely from a single Rust library.

## Development

The suite targets a Linux **x86_64** host with KVM enabled (`/dev/kvm` present). External tooling
falls into four groups: system packages, Cargo-installed subprocess binaries, the externally
distributed VMM binaries (Firecracker, QEMU), and the developer command runner (`just`).

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
- `libcap2-bin` — provides `setcap`, used to bless the privileged test runner (§5).
- `nftables` — provides `nft`; the transparent egress proxy installs an `nft` TPROXY ruleset.
  (Host networking otherwise uses `rtnetlink` directly, so the `ip` CLI / `iproute2` is not needed.)

### 2. Cargo-installed subprocess binaries

`cloud-hypervisor` (the primary VMM) and `virtiofsd` (the virtio-fs daemon) are installed via Cargo
so they build as optimized release binaries spawned by the orchestration layer. `vhost-device-vsock`
backs the rootless vsock control plane on the QEMU backend.

```sh
cargo install --git https://github.com/cloud-hypervisor/cloud-hypervisor.git cloud-hypervisor
cargo install virtiofsd --locked
cargo install vhost-device-vsock --locked   # only needed for the QEMU rootless-vsock path
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

### 5. Privileged Test Runner

To run privileged networking tests (like those requiring TAP interfaces or transparent proxying)
without running the entire `cargo test` suite as `root`, we use a lightweight capability-granting
runner.

Build the `imp-test-runner` for both `debug` and `release` configurations, then grant it the
necessary capabilities:

```sh
# Build the runner
cargo build --bin imp-test-runner --features test-runner
cargo build --release --bin imp-test-runner --features test-runner

# Bless the binaries with network and system admin capabilities
sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep target/debug/imp-test-runner
sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep target/release/imp-test-runner
```

`just bless` (§6) runs exactly these steps for you.

*Note: You must re-run the `setcap` commands (or `just bless`) anytime the `imp-test-runner` binary is
recompiled, as rebuilding strips file capabilities.*

To use the runner during local development, either execute your test binaries through it directly or
configure your cargo test runner (e.g., in `.cargo/config.toml`) to use it for the privileged suite.

### 6. Developer command runner (`just`) and CI tooling

The lint, test, and dependency gates are driven by [`just`](https://github.com/casey/just) recipes
(`just ci`, `just test-unit`, `just test-rootless`, `just test-priv`, `just bless`). Install `just`
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
- `just test-rootless` — the rootless (unprivileged) KVM integration tier.
- `just test-priv` — the privileged KVM integration tier (run `just bless` once first; see §5).

### 7. Packages supporting experiments

The groups above are everything the product needs to build and run. The packages below are **only**
for the *optional* performance experiments and contested-fact benchmarks in the design doc §13 (the
`bench-vm` macro-harness plus a few out-of-band measurement probes). None is required to build or run
`imp-testing` itself — install only the ones for the experiment you actually want to reproduce.

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
