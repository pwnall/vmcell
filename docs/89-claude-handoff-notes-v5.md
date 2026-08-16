# vmcell — Handoff notes (v5): the v33 register is closed

Written at `df0dcdd`. Supersedes `docs/88-claude-handoff-notes-v4.md` (written at `c5a01a1`) and,
through it, `docs/87`. Read those two only for archaeology: v4's own §3 contains a factual error this
pass paid for, and several of v3's per-delta blockers were resolved or refuted while landing.

Read `AGENTS.md` first; it is binding and this file does not repeat it. The as-built records — the
durable ones — are in `docs/implementation-notes.md`, one section per delta. The `Cargo.toml` comment
changelogs are the other half.

---

## 1. Where things stand

**The v33 §18 delta register is CLOSED. All ten deltas are landed, pushed and live-validated.**

| Delta | Commit |
|---|---|
| 1–5 | earlier pass |
| 6a — registry core + rootfs kind | `55a0e15` |
| 6b — handler kind | `ff3a4ff` |
| 6c — laziness, declarations, `unpinned_path` | `ae723fc` |
| 7 — xattr policy + external repacking | `2e58f3e` |
| 9 + 10 — systemd proof cell, daemon placement | `05b5512` |
| 8 — ext4 producer | `df0dcdd` |

Contract versions at HEAD: `vmcell` **0.20.0**, `vmcell-protocol` **0.7.0**,
`vmcell-artifact-validator` **0.5.0**, `vmcell-daemon` **0.3.0**.

Deltas 2–7 were **one breaking release spanning five versions** (0.15 → 0.20). That is not sloppiness
and the ledger says so at each step: every landed version becomes `origin/main`'s baseline, and
`cargo semver-checks` measures against the baseline rather than against the release narrative. Do not
fight the tool; ledger the span honestly.

**The live bar to match at `df0dcdd`:**

```
privileged   228/228
unprivileged   4/4
daemon        16/16
validator      4/4
test-systemd   2/2      (opt-in)
skips:  9  — 4 firecracker unprivileged_vhost_user_net
              2 firecracker nested_virt
              1 firecracker virtio_fs_shares
              2 cloud-hypervisor systemd_proof_cell_not_opted_in
```

The two `systemd_proof_cell_not_opted_in` skips are **deliberate and load-bearing**: they are the
evidence that delta 9's opt-in actually holds under `test-privileged`'s filterset. A run that does
*not* record them means the opt-in broke and a 59 MB pull just joined every privileged run.

The reproduction sequence is in §5.

---

## 2. Use workflows and subagents. This is still the single biggest process lesson.

v4 said this first and it was right; this pass leaned harder on it and it scaled. What worked:

**Recon before code, always.** Two read-only fan-outs (4 agents, then 2) produced per-delta surface
maps *before* any edit. Each agent got a disjoint file set, an explicit "you are READ-ONLY", an
explicit **"do NOT run `cargo` or `just`"** (a live suite holds the build lock and a second
invocation deadlocks so quietly it reads as a hung agent), and one instruction that mattered more
than the rest: **"report any contradiction between the design's text and the code's reality rather
than silently resolving it."** That instruction is what found the executable `build-kernels` legs,
the four-way writability contradiction, and the unrealizable `debian-systemd` image.

**Implementation as a sequential chain, not a parallel fan-out.** Cargo's target lock serializes
everything, and two agents editing one crate produce half-written `mod` declarations that block every
build in the workspace. Deltas 6c, 7, 8 and 9/10 each ran as a chain of 2–5 agents, one at a time,
each allowed targeted `cargo` but never `just ci`. That is the shape: **parallel for reading,
sequential for writing.**

**A dedicated follow-up agent after each delta.** Every chain produced a list of "found it, out of my
slice" findings. Collecting those into one more agent, with the orchestrator deciding which to act
on, is where the applet-roster cache bug, the second Firecracker fail-open, and the digest-case
defect were actually fixed. Do not let those lists rot in a scratch file.

**Give agents the decisions, not the questions.** Each prompt carried a short "design decisions
already made (do not re-litigate)" block. Agents that still hit a genuine ambiguity reported it
instead of guessing — which is exactly what you want, and is the reason the `unpinned_path`
entry-key-vs-label question and the `None`-over-REST question came back as decisions rather than as
silent facts in a diff.

**Read reports section by section, on demand.** The recon and impl records ran to ~4 000 and ~6 000
lines. `grep -n '^#' <report>` then `sed -n` the one section you need. A `Read` of the whole thing is
2 000 lines in your context forever.

---

## 3. THE lesson, restated because it earned it again

**Plant the violation. Every time. On every gate.**

v4 §6.5 recorded a gate that passed with its own regression planted. This pass, agents that were
told to construct the buggy implementation and *watch it fail* found, in their own first drafts:

* a gate asserting `pack_options().xattrs == Strip` — which cannot fail, because `Strip` is the
  `Default`, so deleting the line it guards leaves it green. **The agent deleted it and said so in
  the file.**
* two vacuity bugs in a fresh test: pins merge leaf-wise, so an overlay that re-states `default`'s
  image/digest still *inherits* the baseline's declarations — the "declares nothing" leg was not
  declaring nothing; and the fixture helper always wrote `overlay.json`, so two overlays were one
  file.
* a serial-console needle of `"systemd"` — which the *kernel* echoes in
  `Command line: … init=/usr/lib/systemd/systemd …` before systemd runs at all.
* a fuzz target that **could not pass on valid input** after a sibling change, caught only by running
  the real fuzzer (crash on `{}`, an empty document).

None of those is visible by reading. All were caught by inverting and running.

**The corollary this pass adds: a gate on a code path nothing has ever executed is worth writing even
if you expect it to pass.** `RootfsSource::Block` had been consumable since v22, was green in every
static sense, and the first boot found two real defects — one of which let a guest write into an
image N zygote clones share.

---

## 4. What is actually left

The register is closed, so what follows is opportunity, not obligation. Each is recorded in
`docs/implementation-notes.md` or a `Cargo.toml` ledger with more detail.

1. **Graduate the ext4 producer to the crate route.** `am-fs-ext4` 0.4.0 is the named candidate: MIT,
   same author family as the `am-fs-erofs` this tree already trusts, `am-fs-core` already in the
   lock, a complete write API down to `apply_mknod`/`apply_link`/`apply_setxattr`. It was rejected
   at cut only because §17's qualifier ("*if* it passes the mount-and-diff gate") could not be met by
   a gate that did not exist yet. **It exists now** (`crates/vmcell/tests/ext4_cell.rs`), the swap is
   contained to `Ext4Producer`'s body behind the `Stage` boundary, and graduating would remove the
   tarball route's xattr refusal outright. This is Appendix B's substitution-experiment pattern with
   the harness already built — the cheapest high-value item on this list.
2. **Design corrections to fold in on the next reissue** (the design has no standing errata, so these
   belong in the body):
   * §4.7's "workloads that need a **writable**, POSIX-complete root" is false in both halves of its
     subject; the ext4 root ships read-only and the motivation is POSIX-completeness.
   * §4.7's "xattr policy … inherited for free" is true of the *merge* and false of the *image*: the
     `mkfs.ext4 -d <tarball>` route carries only `security.capability`.
   * §4.7 counts "ten node-construction sites"; there are eleven (the hardlink arm).
   * §10.5's registry illustration gives `debian-systemd` the image `docker.io/library/debian`, which
     ships no systemd at any digest. The tree registers `docker.io/jrei/systemd-debian`.
   * §18 delta 9's leg expects a *placement refusal* from a stewardless `Service` cell; it produces a
     *transport timeout*, because `steward_port()` is always `Some` for `Service`.
   * §18 delta 10 says "`Service{port}` with a custom init only" while the gate row demands a
     `None`-rejected-400 arm. The gate row shipped.
   * §15.4 calls delta 9 "the R1+R2+R5+R6+R7 proof cell", which pulls in delta 8 (declared separable)
     and omits R3/R4, which the cell actually exercises.
3. **`Source::Rootfs` carries a filename, not a label.** The design asserts
   `Source::Rootfs("debian-systemd")`; the code builds it from `image.file_name()`. Three landed
   delta-6c gates pin the filename form, so changing the constructor is its own delta with its own
   sweep of those three sites.
4. **The §10.6 kit's under-claim finding.** The `debian-systemd` artifact declares
   `snapshot_restore: false`, but booted the ordinary `Pid1` way it snapshots fine — what cannot
   snapshot is the `Service` *placement*, a per-op eligibility arm rather than an intersection axis.
   The kit correctly reports an under-claim and the test dispositions it. §18 delta 9's two halves are
   in tension; resolving it is a design decision.
5. **Smaller, all recorded:** the `mmdebstrap` rootfs reads no registry entry so it emits no
   declaration sidecar; `oci2-erofs` cannot request `Preserve` (deliberate — the registry entry is
   the one place the policy is declared); the `tracing::warn!` announcing an unpinned resolution is
   unasserted (`vmcell` has no tracing-capture harness); the ext4 feature's OFF arm cannot be
   unit-tested because `vmcell`'s dev-dependency cycle re-enables `default`, so it is a compile gate
   that is currently hand-copied between `justfile` and `ci.yml` — AGENTS rule 3's drift class, and a
   `scripts/check-feature-arms.sh` would close it.

---

## 5. Operational knowledge — corrections and additions to v4 §5

**5.1 `git push`: use SSH on port 443, not the `gh` token.** v4 recommended the HTTPS-token route.
It is **rejected for any commit touching `.github/workflows/*`** ("refusing to allow an OAuth App to
create or update workflow … without `workflow` scope"), which vmcell commits do often. Outbound port
22 is blocked, but 443 is not:

```bash
timeout 180 git push ssh://git@ssh.github.com:443/pwnall/vmcell.git main
```

Always wrap it in a `timeout`.

**5.2 The reproduction sequence.** Run it before writing code, and again before cutting:

```bash
./scripts/review-preflight-priv.sh                      # exit 0 = READY
cargo build --release -p vmcell-cli && ./target/release/vmcell build --kernel-source host-make
just skip-manifest-reset
export VMCELL_TEST_USB_DEVICE=0bda:5634                 # the laptop camera; the USB NICs are driverless
systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged
just test-unprivileged
just test-daemon
systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-validator
systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-systemd
just skip-manifest-show
```

`--kernel-source host-make` is not optional: a bare `vmcell build` swaps in a prebuilt `vmlinux`
lacking `CONFIG_KVM_INTEL` and reddens `nested_virt` and `snapshot_restore`.

**5.3 `typos` runs over `docs/` too, and it will find your prose.** This pass it caught a plural of
"entry" spelled the wrong way in a test name, a run-together "opt in" that reads as "option" in a
module name, and a hyphenated-prefix verb in a note — all in code and documentation this pass
itself wrote. `_typos.toml` is deliberately near-empty; add an entry only for real project
vocabulary (`lov`, from the `lustre.lov` xattr name, was a legitimate addition — a hyphenated prefix
in ordinary prose is not, so reword it instead). **And note that this file cannot quote the
misspellings it is describing**, which is the same reason the config already carries the
deliberate-misspelling fixture exception.

**5.4 A version bump needs three lockfiles' worth of attention.** `cargo update --workspace
--offline` for the main tree, **and** the same inside `examples/downstream-kernel`. That example's
lockfile was found stale by three versions at the start of this pass, which would have reddened the
contract-gate CI job for a reason having nothing to do with the contract — inverting the gate exactly
as §10.4 warns.

**5.5 Poll background jobs on a sentinel you write yourself, and beware the truncation race.** A
`grep -q DONE` against a log file that a *new* run is about to truncate will match the *old* run's
content. Write the sentinel last and check for it, or check file identity too.

**5.6 `just ci` is ~20–25 minutes.** Run it in the background and do non-cargo work. Never two at
once. `rm -rf target/doc` if a hand-run `cargo doc` left a partial tree — CI's rustdoc step then
fails on unrelated files.

---

## 6. A closed fd is not a dead one, in a process that forks

Two unrelated flakes this pass had one cause, and the next author of a socket or binary fixture will
hit it a third time. A file descriptor open in one thread is duplicated into every `fork` another
thread performs in that instant, and stays alive in the child until it reaches `execve` and
`CLOEXEC` closes it. In a multi-threaded test binary whose siblings spawn processes:

* a `drop`ped `UnixListener` can still be **bound and accepting** — measured at 0 anomalies in 96 000
  sequential cycles and 1–4 per 3000 under 24-way concurrency;
* a file being written can still be **`ETXTBSY` for `execve`**.

Both fixtures now *verify* the state they assume rather than assuming it. Neither was a product
defect, and both presented as one. If a fixture's premise is "I closed it, therefore it is gone",
that premise is false here.

---

## 7. Decisions from this pass that bind you

* **The ext4 root is read-only**, and the reasoning lives on `RootfsSource::Block` and
  `root_device_read_only` rather than in a scratch file. Do not re-open it without re-reading §4.7's
  own closing sentence and §18's *Migration* clause.
* **`unpinned_path` is an entry key, not a reserved label** — a reserved label would have to be
  re-reserved on every verb that names one, which is the reserved-suffix defect class re-armed.
* **The `.features` sidecar is its own stage**, because §7.4 requires a declaration-only edit to
  re-emit the sidecar and leave the image key unmoved, and a single-key stage cannot express that.
* **A `PackOptions` field nobody folds is `error[E0027]`** — `fold_rootfs_injection_identity`
  destructures it exhaustively. Keep it that way; it caught a live cache-collision defect.
* **`vmcell build-kernels` requires a selection.** `--all` reproduces the old behavior. The example
  workspace's `ci-check.sh` invokes it for real; changing its interface means changing those legs in
  the same commit, deliberately.
* **A registry entry's unknown key is refused naming the delta that adds it.** With the register
  closed there is no next delta to name, so the next such key is refused naming *nothing* — which is
  the right answer, but say so at the site rather than leaving a dangling forward reference.
