/plan Please read the following from `docs/`: latest design doc,
implementation notes, latest performance investigation.  Please do not waste
your context reading any other files in docs/.

Please do a code review of the entire implementation and write a code review
report at `docs/46-claude-code-review.md`. Do not attempt to fix any problems.

Please focus on correctness issues, code quality issues, overly complicated API
design, gaps in testing coverage, potential performance wins, insufficient /
incorrect documentation, and deviations from Rust best practices.

Please avoid suggesting improvements that would regress performance, as
documented in `docs/.

Use any tools that would help your review. For example, you may run both
unprivileged and privileged tests, and you can perform (and revert) experiments
that involve code changes.

To avoid overwhelming your context window, please scope out the codebase and
delegate work, such as sub-reviews, to subagents.
