Designed, need implementing

* README covering CLI capabilities and benchmark results

Need design

* Introduce term "unprivileged operation" instead of "rootless" (with KVM
  access, no additional caps), and its opposite as "privileged" (with
  capabilities). Explicitly spec tests for unprivileged and for privileged
  operation.
* Reconsider `imp-test-runner` design for testing privileged operations. We're
  blocked on me running `just bless` too often. Are there approaches that would
  be more resilient to code changes? Alternatively, can we design a more robust
  suite of tests for the `imp-test-runner` binary so that we don't have to get
  it rebuilt as often? Does the binary get rebuilt often because of unrelated
  changes, suggesting we should switch to a cargo workspace?
* Migrate all "best-effort" functionality (do something if the capabilties
  exist, move on otherwise) to failing on missing capabiltiies. Implementations
  must document the required capabilities. Callers must ensure they have the
  capabilities need to call into functionality. I am concerned about silent
  failures leading to missed errors.
* Resolve open questions based on benchmarks
* Position as isolated test environment, useful for agentic harnesses and
  generic serverless
* Ensure that the micro-VM execution primitive is reasonably general
