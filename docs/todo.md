Designed, need implementing


Need design

* Benchmarks for learning implications of using musl vs glibc in guest agent
* Add benchmarks for RAM usage
* Add measurements for rootfs image size under OCI vs mmdebootstrap methods
* Add measurements for VM suspend state size on disk
* Resolve open questions based on benchmarks
* Migration to Rust 1.96 for cleanup
* Introduce term "unprivileged operation" instead of "rootless" (with KVM
  access, no additional caps), and its opposite as "privileged" (with
  capabilities). Explicitly spec tests for unprivileged and for privileged
  operation.
* README covering CLI capabilities and benchmark results
* Position as isolated test environment, useful for agentic harnesses and
  generic serverless
* Ensure that the micro-VM execution primitive is reasonably general
