Designed, need implementing


Need design

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
