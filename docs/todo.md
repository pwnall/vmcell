Designed, need implementing

* Test helper so we can run all tests without `sudo`
* Add OCI registry image support, use it for low-dependency rootfs build;
  redesign the `mmdebootstrap` rootfs building process to work in a micro-VM
  (using our infrastructure); this way, the host doesn't need to be able to
  run `mmdebootstrap` -- we remove the shell problem and maybe some package
  dependencies
* Performance benchmarking
* Trait implementations for the firecracker backend
* Trait implementations for the QEMU backend
* Benchmarks for all backends

Need design

* Introduce term "unprivileged operation" instead of "rootless" (with KVM
  access, no additional caps), and its opposite as "privileged" (with
  capabilities). Explicitly spec tests for unprivileged and for privileged
  operation.
* Resolve open questions based on benchmarks
* Migration to Rust 1.96 for cleanup
* README covering CLI capabilities and benchmark results
* Position as isolated test environment, useful for agentic harnesses and
  generic serverless
* Ensure that the micro-VM execution primitive is reasonably general
