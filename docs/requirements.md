# Imp Testing

This project is an end-to-end integration testing and evaluation platform for an
AI agentic harness. The agentic harness is named Imp, so this project is named
Imp Testing.

Each integration test will run in its own micro-VM. Desired benefits:

1. Harness and model bugs don't disrupt the host running the tests.

2. No state leakage between tests. Aiming for hermetic tests.

3. The test environment matches the real environment. The harness has use cases
   that require full access to the host system.

## Micro-VM system requirements

### Micro-VM feature checklist

The feature requirements are below.

Non-mandatory requirements can be given up in return for better test
performance.

1. Host OS and CPU architecture for fast development.
    * Mandatory: Linux and x86_64 -- primary CI architecture
    * Good extra: ARM64 / aarch64
    * Nice to have extra: macOS with Apple Silicon -- only for tie-breaking, not
      worth concessions to any of the points below

2. Shared directories -- the VM can access directories in the host filesystem.
    * Mandatory: multiple directory support. The tests will need at least two
      test inputs (data, binaries under test) and one test output
    * Great extra: access permissions, so test inputs are read-only
    * Good extra: host page cache sharing, so read-only data doesn't get
      duplicated in guest RAM

3. The VM can access HTTP servers started by tests on the host.
   * Mandatory: the HTTP servers should not be exposed to other systems on the
     host's network
   * Great extra: the HTTP server configuration should be per-test -- each test
     may involve bringing up zero or more HTTP servers with custom application
     logic
   * Great extra: the HTTP servers can use dynamically assigned ports (so any
     test VM port configuration would have to happen after listening on the
     servers' sockets), to avoid port conflicts
   * Good extra: the VM can access host servers using other protocols

4. The VM's Web access goes through a transparent proxy.
    * Mandatory: tests can filter and log all Web access from the VM
    * Great extra: the proxy is Rust code that allows writing test doubles for
      the Web services accessed by the VM

5. The VM exposes a Linux environment as close as possible to end user systems
   that run Debian or a derivative distribution.
    * Great: environment perfectly matches an installed Debian flavor, such as
      server
    * Good: stripped down Debian installation built using supported methods,
      such as `debootstrap` -- perfectly acceptable in return for performance
      gains
    * Okay: completely custom environment, such as a different distribution
      tailored for micro-VMs

6. The VM exposes a Linux kernel environment as close as possible to end user
   systems.
    * Great: one of the kernel images provided by the distribution installed in
      the micro-VM
    * Good: kernel source code provided by the distribution installed in the
      micro-VM, compiled with custom options -- this extra complexity is
      acceptable if it yields improved performance
    * Okay: kernel source code maintained outside the installed distribution,
      potentially compiled with custom options
    * Unacceptable: developing kernel patches specific to this project

7. Nested virtualization, so the harness can run its own VMs.
    * Great: nested VMs get near-native CPU, networking, disk
    * Nice-to-have extra: passthrough for peripherals (USB2.0, USB3.2, USB4 2.0)
      -- only for tie-breaking, not worth concessions to any of the other points

8. Fully automated (programmable) access to test infrastructure functionality.
    * VM management: create, delete, list
    * VM lifecycle: start, request shutdown, force shutdown
    * VM configuration: shared directories, networking, nested virtualization
    * Performance monitoring: peak and average resource usage
      (CPU, RAM, disk I/O, network I/O)

9. Fully automated (programmable) process for building artifacts used by VM.
    * filesystem / disk images
    * binaries (firmware / kernel)
    * configuration files

10. Programmable access to the VM console.
    * Great: custom protocol over vsock with a Rust implementation of client
      (in test harness) + server (in VM), if the extra complexity is reasonable.
    * Good: TTY emulation
    * Okay: SSH server -- if nothing else works, the micro-VM must support SSH

### Micro-VM non-functional attributes

The micro-VM infrastructure must be optimized for integration tests and
evaluations for an AI agentic harness.

#### Performance: test running time

The integration tests are expected to be organized in a pyramid, where most
tests run for a few seconds to a minute, some tests run for multiple minutes,
and a few tests run for tens of minutes.

Total VM running time is important. We're designing for thousands of tests, and
the tests will run on every software iteration, so shaving off hundreds of
milliseconds per test is worthwhile some extra complexity.

VM running time must include the time it takes to prepare per-test artifacts.
For example, if a micro-VM technology doesn't support shared directories, and
uses some form of networked filesystem (examples: NFS or Plan 9 over vsock), the
VM running time will be extended by the filesystem serving overhead plus the
serving daemon reconfiguration overhead.

micro-VM systems that offer suspend + copy + resume should be evaluated based
on the time it takes to copy artifacts (which can be quite low if Copy-on-Write
is supported) and resume the copied VM, because these are the steps that must be
performed on each test.

#### Performance: RAM consumption / VM density

Since we're designing for thousands of tests, we'll want to reduce total testing
time by running tests in parallel.

The total RAM consumption of each VM will be the most likely limit to system
parallelism.

#### Ergonomics: Rust library support

The micro-VM system needs to be driven entirely from Rust.

Implementation avenues for each aspect that requires programmable access, ranked
by preference:

* Best: the functionality is well documented enough that it's easiest to write
  our own Rust library
* Great: Rust library crate with no unsafe code
* Also great: Rust library crate with properly documented unsafe code
* Good: Rust binary crate providing a programmable interface (HTTP, CLI, etc.)
* Okay: Binary providing a programmable interface available

Rust library crates must be open sourced with permissive licenses (examples: MIT
and Apache).  Rust library crates must not have copyleft licenses (example: GPL)
or restrictive licenses (examples: no commercial use, caps on number of users).

Binaries must be open sourced, and must not have restrictive licenses. Binaries
preferably do not have copyleft licenses, but we can make exceptions if that
unlocks major benefits.

Healthy repositories (actively maintained, somewhat popular) are preferable, for
both Rust library crates and all binaries.

## Software development

### Source code requirements

1. One Rust package that uses the 2024 edition.
2. All functionality in one library crate, which will be used by integration
   tests and evals.
3. Binary crate wrapping the library crate to allow quickly trying out the
   functionality. The binary crate implements CLI argument parsing and output.
4. Fine-grained integration tests. Ideally, one test per requirement or VM
   operation. Example: check that the tool can be used to stop a previously
   started VM.
5. README enumerating all required external tools with installation instructions
   for a Debian development host.
6. Rust best practice compliance vetted by tools such as `clippy` and `rustfmt`.
7. Unit tests for all functions and methods that are testable.
8. Minor architectural accomodations for increasing the unit tests coverage,
   without going overboard.

### System dependency requirements

1. Prefer Rust crates integrated into the tool over orchestrating external
   tools.
2. Use Rust crates with permissive licensing. Absolutely do not use crates
   with copyleft licenses, or crates whose licenses limit availability.
3. Do not use external tools whose licenses limit applicability. (Example: Caps
   on concurrent CPUs or users, forbidding commercial usage.)
4. Prefer external tools with permissive licensing (examples: Apache, MIT) over
   copyleft licensing (examples: LGPL, GPL, AGPL).
6. Prefer external tools with full automation support over friendlier GUIs that
   are less amenable to automation.

## VM artifact production requirements

The VM artifacts are all the images used by the VM. Examples: rootfs image or
directory, custom kernel image, any firmware involved in booting.

1. Producing each artifact is structured as a sequence of stages.
2. The first stage determines the most up to date values for a minimal set of
   version / timestamp pins that can define the VM contents. (Example pin:
   timestamp for Debian package repository snapshot.)
3. All following stages are deterministic / idempotent / repeatable.
   When a deterministic stage succeeds, its output is completely determined by
   its inputs.
4. Each stage is cacheable. The stage is skipped if its outputs already exist.
5. The process supports resetting to a specific stage by removing the outputs of
   all following stages.
6. Minimize access to external servers while testing and iterating. Use
   on-demand caching to avoid downloading a resource multiple times.
7. Split each operation that uses on-demand caching across a record step and a
   replay step. Example: The automated Debian installation process uses a
   package repository.
8. Verify against a signing chain if one exists, and refuse to proceed on
   mismatch.
