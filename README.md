# Imp Testing

An end-to-end integration-testing and evaluation platform for the Imp agentic harness.
Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity.
Driven entirely from a single Rust library.

## Development

Required external tools for the host are split into system packages and Rust subprocess binaries.

### 1. System Packages (Debian / Ubuntu)

Install the required system utilities and build dependencies:

```sh
sudo apt update
sudo apt install -y bash mmdebstrap linux-source build-essential iproute2 iptables pkg-config libseccomp-dev libcap-ng-dev libelf-dev libssl-dev debian-archive-keyring
```

**Important Note for Ubuntu Users:**
Building the test rootfs uses `mmdebstrap`, which has a hard-coded assumption that `/bin/sh` points to `bash`. On Ubuntu systems where `/bin/sh` defaults to `dash`, this will cause the build to fail with a `Syntax error: Bad fd number` error.

You must reconfigure your system to use `bash` as the default system shell:
```sh
sudo dpkg-reconfigure dash
```
*(When prompted "Use dash as the default system shell?", please select **No**)*

If `dpkg-reconfigure` does not work or prompt you, you can manually update the symlink:
```sh
sudo ln -sf bash /bin/sh
```

### 2. Rust Subprocess Binaries

We install `cloud-hypervisor` and `virtiofsd` via Cargo. By separating these into a Cargo installation group, we ensure they are built and run as highly-optimized Release binaries, providing maximum performance when spawned as subprocesses by the orchestration layer.

```sh
cargo install --git https://github.com/cloud-hypervisor/cloud-hypervisor.git cloud-hypervisor
cargo install virtiofsd --locked
```

Ensure that `~/.cargo/bin` is in your `$PATH` so the test suite can discover these executables.

### 3. Firecracker Binary

Unlike Cloud Hypervisor, Firecracker uses a custom containerized build process (`tools/devtool`) and is not intended to be built via a standard `cargo install`. Instead, we use the pre-compiled external binaries from their GitHub releases.

Download and install the latest Firecracker release (e.g. v1.16.0) on Debian/Ubuntu:

```sh
curl -LO https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.0/firecracker-v1.16.0-x86_64.tgz
tar -xzf firecracker-v1.16.0-x86_64.tgz
sudo mv release-v1.16.0-x86_64/firecracker-v1.16.0-x86_64 /usr/local/bin/firecracker
sudo chmod +x /usr/local/bin/firecracker
rm -rf firecracker-v1.16.0-x86_64.tgz release-v1.16.0-x86_64
```

### 4. Privileged Test Runner

To run privileged networking tests (like those requiring TAP interfaces or transparent proxying) without running the entire `cargo test` suite as `root`, we use a lightweight capability-granting runner.

Build the `imp-test-runner` for both `debug` and `release` configurations, then grant it the necessary capabilities:

```sh
# Build the runner
cargo build --bin imp-test-runner --features test-runner
cargo build --release --bin imp-test-runner --features test-runner

# Bless the binaries with network and system admin capabilities
sudo setcap cap_net_admin,cap_sys_admin+p target/debug/imp-test-runner
sudo setcap cap_net_admin,cap_sys_admin+p target/release/imp-test-runner
```

*Note: You must re-run the `setcap` commands anytime the `imp-test-runner` binary is recompiled, as rebuilding strips file capabilities.*

To use the runner during local development, either execute your test binaries through it directly or configure your cargo test runner (e.g., in `.cargo/config.toml`) to use it for the privileged suite.
