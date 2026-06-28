Designed, need implementing


Need design

* Migrate all "best-effort" functionality (do something if the capabilties
  exist, move on otherwise) to failing on missing capabiltiies. Implementations
  must document the required capabilities. Callers must ensure they have the
  capabilities need to call into functionality. I am concerned about silent
  failures leading to missed errors.
* Resolve open questions based on benchmarks
* Introduce term "unprivileged operation" instead of "rootless" (with KVM
  access, no additional caps), and its opposite as "privileged" (with
  capabilities). Explicitly spec tests for unprivileged and for privileged
  operation.
* README covering CLI capabilities and benchmark results
* Position as isolated test environment, useful for agentic harnesses and
  generic serverless
* Ensure that the micro-VM execution primitive is reasonably general
