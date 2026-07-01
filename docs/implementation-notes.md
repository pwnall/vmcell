# Implementation Notes

This is the running log of **justified deviations** from the design (per `AGENTS.md`): a place to
record a deliberate divergence, with its reason, at the moment it is made.

**The log is currently empty.** As of the v17 design rewrite (`docs/43-claude-design-v17.md`) every
prior entry has been reconciled into the design document — either folded into the body as the settled,
present-tense state of the system, or dropped as superseded / dated validation bookkeeping. The design
document now reflects the system *as built*, including the deviations that used to live here (for
example: the Firecracker snapshot/restore honest gate-off, the `ResourceUsage` net-counter omission,
the stringly per-subsystem `Error` payloads, the static-glibc guest agent, the `SUDO_UID`-not-`nobody`
virtiofsd choice, and the file-cap runner's inability to shrink its bounding set). See design §12
("The subtle parts") for the cross-cutting invariants and §15 ("Open decisions and known gaps") for
what remains forward work.

**When you make a new deviation,** add a short entry here — *what* you diverged from and *why* — and,
once it stabilizes, fold it into the design document and delete it from this log. Keep this file
small: a growing log means the design doc has drifted from the code.
