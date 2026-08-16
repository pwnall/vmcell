# vmcell — Handoff notes (v4): the v33 delta register, 6c and 7–10

Written at `c5a01a1`. Supersedes `docs/87-claude-handoff-notes-v3.md`, which was written at
`540d8a3` — read v3 only for its per-delta detail on **7, 8, 9 and 10**, which this file amends
rather than repeats. Everything v3 says about **delta 5 is history**, and several of its premises
turned out to be wrong (§6 below).

Read `AGENTS.md` first; it is binding and this file does not repeat it. The as-built records are in
`docs/implementation-notes.md`.

---

> **FIRST ACTION.** **Deltas 6a and 6b have NOT been live-validated.** They are green on `just ci`
> and `just gates`, but the last live run was at `2198702` (delta 5 part 2). 6a reshaped the pins
> `rootfs` namespace and 6b bumped `GuestToolsStage`'s stage version 2 → 3, so the artifact pipeline
> re-runs. Before writing new code:
>
> ```bash
> ./scripts/review-preflight-priv.sh              # exit 0 = READY
> cargo build --release -p vmcell-cli && ./target/release/vmcell build --kernel-source host-make
> just skip-manifest-reset
> export VMCELL_TEST_USB_DEVICE=0bda:5634
> systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged
> just test-unprivileged
> just test-daemon
> systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-validator
> just skip-manifest-show
> ```
>
> The bar to match: **privileged 162/162, unprivileged 4/4, daemon 14/14, validator 3/3**, and
> exactly seven skips (`unprivileged_vhost_user_net` ×4, `nested_virt` ×2, `virtio_fs_shares` ×1,
> all Firecracker). Anything else is a regression from 6a/6b, not a pre-existing condition.

---

## 1. USE WORKFLOWS AND SUBAGENTS. YOU WILL RUN OUT OF CONTEXT OTHERWISE.

This is the single biggest process lesson of the session that wrote this file, and it is written
first because by the time you feel the need you will already have spent the budget.

**What worked, concretely.** Two `Workflow` fan-outs of 3–4 read-only agents each, run *before*
touching any code, produced the per-delta surface maps that made the actual edits fast. Each agent
got:

* a **disjoint file set** and an explicit "you are READ-ONLY on the repo";
* an explicit **"do NOT run `cargo` or `just`"** — a live suite or a `just ci` holds the cargo build
  lock, and a second invocation deadlocks so quietly it reads as a hung agent;
* the exact rule with its rationale, and **"report any contradiction between the design's text and
  the code's reality rather than silently resolving it"** — which is how the delta-5 recon found
  that `guest_tools_on_path` does not exist, that `serve_vsock`'s line range in v3 was wrong, and
  that `mini-init`/`xattr` were being described in AGENTS.md in the present tense;
* a demand for **exact `file:line` anchors and verbatim quotes** of anything to be copied.

Their output landed in the scratchpad as markdown (`recon5-*.md`, `recon67-*.md`) and was read
section by section on demand, not all at once. That is the pattern: **agents produce a map, you read
the part you need.**

**What to delegate, that this session did not and should have:**

* **The premise re-verification pass** for whichever delta you are about to cut. v3's own §2 was
  built that way and it is why the register's conventions demand it. One agent per delta, each
  decomposing that delta's `*Premise:*` paragraph into clauses and checking every one.
* **The mechanical halves of a delta.** Delta 6a/6b's fixture migrations — ~40 call sites across
  five crates — are exactly the shape a subagent does well with a precise instruction and a
  compile-check loop.
* **A review agent over each large diff before committing.** v3 §3.11 records that the delta-1
  reviewer found vendored-file corruption and broken JS the compiler could not see. This session
  skipped that step and paid for it twice (see §6.4 and §6.5 — two gates that could not fail).
* **Reading a long file you only need three facts from.** `Explore` or a `general-purpose` agent
  returns the three facts; a `Read` returns 2,000 lines into your context forever.

**What does not work**: two agents (or an agent and you) editing the same crate — cargo's target
lock serializes everything and a half-written `mod foo;` blocks every build in the workspace. When
an agent is mid-flight, **stop running cargo**; poll for the file instead.

**Ultracode is on for this project.** Authoring a workflow for every substantive task is the
default, not an escalation. Token cost is not a constraint; your context window is.

---

## 2. Where the pass stands

| Commit | Delta | Live-validated |
|---|---|---|
| `2d5296c` … `540d8a3` | 1–4 | yes (at `540d8a3`) |
| `92c4c50` | 5 part 1 — the steward as a library; placement parameterizes the PID-1 contract | yes (with part 2) |
| `2198702` | 5 part 2 — the service-steward battery | **yes — privileged 162/162** |
| `55a0e15` | 6a — the shared registry law + the `rootfs` map namespace | **no** |
| `ff3a4ff` | 6b — the handler kind | **no** |
| `c5a01a1` | (not a delta) the fail-open baked-vsock guard | **no** |

**Remaining: 6c, 7, 8, 9, 10.**

Contract versions at HEAD, verified: `vmcell` **0.17.0**, `vmcell-artifact-validator` **0.4.0**,
`vmcell-protocol` **0.6.0**, `vmcell-steward` **0.4.0**. Unit suite **1031** tests.
`crates/vmcell/tests/` holds **29** files. `scripts/` holds **33** gate-shaped scripts, all in the
one `gates` recipe (the meta-gate checks both directions).

**Delta 6 is being landed in three commits**, all before delta 7: 6a (done), 6b (done), **6c (next)**.
The register treats delta 6 as one item; splitting it keeps each half reviewable and independently
gated. Say so in the 6c commit so the split reads as a decision.

**The version convention changed, deliberately.** v3 said "extend the 0.15→0.16 entry; do not mint
0.17.0". That was written for delta 5, which broke no `vmcell` API. 6a does
(`constructible_struct_adds_private_field` on `RootfsStage`), and 0.16.0 became `origin/main`'s
baseline the moment delta 5 landed — `cargo semver-checks` measures against the baseline, not against
the release narrative. So `vmcell` is 0.17.0 and the deltas 2–7 release now spans two versions, with
the ledger saying so. **Expect to bump again** if 6c/7 break the surface; do not fight the tool.

---

## 3. Delta 6c — what is left of delta 6

Verified absent at HEAD (grep, not memory): `build-kernels` still takes **no** label filter and no
`--all` (`crates/vmcell-cli/src/main.rs:95-106`); there is no `unpinned` dev-override key (the only
`unpinned` in the tree is `handler::reject_unpinned_digest`, a function name); `render_manifest`
still has **zero production callers** — the `.features` sidecar has consumers
(`orchestrator.rs:2293`, `:2304`) and no producer.

**What 6c owes:**

1. **Laziness (§10.5).** `build-kernels <label>…` / `--all`, replacing "build every label in the
   merged registry". Neither given is an error naming both forms; both given is an error. The gate
   §10.5 names: register a second label pointing at the **same digest** as `default`, build both,
   assert byte-identical outputs **and that `default`'s cache key did not move**; then register a
   third label and assert a build that selects nothing **does not build it** — red-on-inverse by
   removing the laziness. v3's blocker #2 on this is **now wrong in your favour**: it worried that
   any `pins.json` edit moves `ResolvePinsStage::cache_key` via `fold_pins_identity`'s raw
   `include_str!`. True, but scope the assertion to the **stage** keys — `RootfsStage::cache_key`
   folds the *resolved values*, so it stays put if `rootfs.default` resolves to today's pair, which
   6a's `the_default_label_flattens_to_the_pre_v33_keys` already proves it does.
   v3's blocker about `build-kernels` callers needing `--all` is **confirmed stale**: no CI recipe
   and no justfile recipe invokes `build-kernels`. The real edit set is four prose sites
   (`justfile:227`, `README.md:28/:390/:393`, `crates/vmcell/tests/usb_passthrough.rs:203`).
2. **The `unpinned` dev override (F7).** A registration with a path and no digest, under one
   explicitly named key, marking the cell's artifact identity `unpinned` wherever provenance is
   reported, **refused by `bundle`**. Both the rootfs and handler entry parsers currently reject a
   `path` key as unknown — 6c is where it becomes a named, restricted shape.
3. **`features` declarations on registry entries (§7.4).** The rootfs entry parser currently rejects
   `features` naming "delta 6c" — that string is in `crates/vmcell/src/artifact/mod.rs`'s
   `rootfs_registry_entry` and in `crates/vmcell/tests/rootfs_registry.rs`; both move together.
   The JSON `{"snapshot_restore": false}` map must be read through `Feature::parse`
   (`feature.rs:160`), never a second token table (F6).
4. **The `.features` sidecar producer.** v3 §"Delta 6" records the live consequence and it is still
   true: the canonical `rootfs.erofs` has no sidecar → `FeatureDeclaration::baseline` → empty
   stances → nothing removes `Feature::XattrPreserved` → `FeatureSet::has(XattrPreserved)` reports
   **true** for an artifact whose packer strips every xattr. Note the **sidecar naming trap**:
   `load_beside` uses `with_extension("features")`, which eats a trailing dotted component, so
   `rootfs.erofs` → `rootfs.features`. Pick append-vs-replace knowingly (`resolved_config_path`
   deliberately *appends*) and say which.
5. **A `registry_entry` fuzz target.** Directed by the gate spec; needs a `fuzz/Cargo.toml` `[[bin]]`
   plus its `fuzz_targets/<name>.rs` twin or `fuzz.yml` GUARD 5 fails. Precedent: delta 2's
   `feature_manifest`. Also note `fuzz.yml`'s prose header says "15 targets" and there are 16 —
   already stale before you add the 17th.

**What 6c does not owe:** the shared registry core, the collision reject, the sort law and the two
key-composer ban scripts all exist. `ban-rootfs-key-composers.sh` and `ban-handler-key-composers.sh`
are the templates if a third key law appears.

---

## 4. Deltas 7–10 — amendments to v3

v3's per-delta sections are still the best inventory. These are the deltas where **6a/6b moved the
ground under them**:

### Delta 7 (xattr policy + external repacking)

* **v3's blocker #1 is resolved.** It said "the declaration surface belongs to delta 6, which is
  unstarted". The registry now exists, and a rootfs entry's `xattrs` key is **refused naming
  delta 7** — in `rootfs_registry_entry` and pinned by
  `rootfs_registry::an_unknown_entry_key_is_rejected_naming_it`. Delta 7 turns that refusal into the
  honored key. **That is the F1-clean seam: refused here, honored there, never accepted-and-ignored
  between.** Both sites move together.
* **`pack_erofs_with_injection` no longer takes positional parameters.** 6b converted its tail to
  `&PackOptions` (`#[non_exhaustive]`, `new()` + `with_*`), precisely so delta 7 could add `xattrs`
  **without breaking a caller again**. Add a field; do not add a parameter.
* **The eleventh `xattrs:` site is real** — v3's note is confirmed: the hardlink arm
  (`tar2erofs.rs:204-242`) builds `Node::File { xattrs: xattrs.clone() }` from the already-merged
  target, not from its own PAX header. Decide and pin it under `Preserve`.
* v3's blocker #2 (the live gate has no input: the pinned base carries **zero** PAX xattr records)
  stands unchanged. Pick and state a source — the `test_pax_xattrs_are_not_preserved` fixture
  builder at `tar2erofs.rs:818-832` already produces exactly one.
* `OCI_ROOTFS_STAGE_VERSION` is still 4 and still pinned by a literal-value test whose name says
  "delta6_bump" — rename it and its message on your bump, do not delete it.

### Delta 8 (ext4 producer)

Unchanged from v3, and still gated behind 7. Its three blockers stand: no merged **tar** exists (the
tail merges straight into an erofs node map), parent synthesis lives inside the erofs-typed
`tar_to_erofs`, and the design contradicts itself about whether a `Block` root is writable (§4.7
says writable, §5.2 says read-only, and the code sides with read-only — `build_kernel_cmdline` emits
`ro` unconditionally). **Resolve the writability question before writing anything.** The
clone-eligibility hazard v3 names is also unchanged: `clone_ineligible_feature` has no
`RootfsSource` arm, so a writable ext4 root would fan out read-write to N zygote children.

### Delta 9 (systemd proof cell)

Still needs 2–7. Two of v3's five blockers have moved:

* **Blocker 1 is partly discharged.** The rootfs registry now exists, so `debian-systemd` is
  registerable by digest today — `resolve_rootfs_registry` + `--rootfs-label`. What is still missing
  is 7's `xattrs` and the *image*: v3's finding that §10.5's example (`docker.io/library/debian`)
  ships no systemd remains true and unresolved. **Decide provenance before writing the recipe.**
* **Blocker 5 is discharged.** A non-default `Service` port now works end to end — delta 5 landed
  the guest-side `vmcell_steward_port=` parse, and
  `service_steward::a_non_default_declared_port_is_actually_bound_by_the_guest` proves it live. The
  proof cell may use any port.
* Its gate-as-written is still respecified: a `Service` cell with a missing steward produces a
  *transport timeout*, not a placement refusal. And note the new constraint from §6.2 below: **do not
  assert on steward log lines.**
* `mini-init` now exists and is the model for the unit-file shape. `crates/vmcell/tests/service_steward.rs`
  is the closest template — it boots a non-steward init under `Service` placement and drives the
  control plane end to end.

### Delta 10 (daemon placement exposure)

Unchanged from v3 and now **fully unblocked**: its blocker #1 was "the live gate cannot run at full
strength until delta 5", and delta 5 has landed. A REST `Service{port}` cell with a custom init is
now expressible end to end. v3's three "notes that matter" are all still accurate — especially that
`engine_rpc_round_trips_every_op`'s fake **discards the request entirely**, so adding fields and
re-running it is theater; the new test must have the fake capture the request and compare
field-for-field with one field `Some` and a sibling `None`.

**Delta 10 is the cheapest remaining item and it is independent.** If you want a win before the
large ones, take it first.

---

## 5. Operational knowledge (carry forward, plus new)

Everything in v3 §3 still applies. In particular: `just ci | tail` reports `tail`'s exit code, so
capture it explicitly; a source-wide sweep must exclude `vendor/` and `.claude/`; don't rewrite the
Cargo.toml ledgers' history; `typos` reads a deliberate misspelling fixture as the defect. New:

**5.1 `git push` hangs. Use the `gh` token over HTTPS.** Outbound port 22 is blocked here — the
remote is `git@github.com:…` and a bare `git push` (or `ssh -T git@github.com`) hangs until killed.
HTTPS works:

```bash
TOKEN=$(gh auth token)
timeout 120 git -c credential.helper='!f(){ echo "username=x-access-token"; echo "password='"$TOKEN"'"; };f' \
    push https://github.com/pwnall/vmcell.git main
```

Always wrap it in a `timeout`; an un-timed push burns the whole tool budget hanging.

**5.2 `just ci` takes ~25 minutes.** Run it in the background and do other (non-cargo) work. Never
two at once. A `cargo doc` you ran by hand leaves a partial `target/doc` that makes CI's rustdoc step
fail with `No such file or directory` on unrelated files — `rm -rf target/doc` and re-run before
believing that failure.

**5.3 The blessing survives most rebuilds.** `just bless` needs a TTY for sudo and will fail from an
agent. It is usually unnecessary: the blessing is on `vmcell-test-runner`, which only changes when
that crate does. Run `./scripts/review-preflight-priv.sh` — if it says READY, you do not need a
bless.

**5.4 The live suites are fast; the builds are not.** `test-privileged` is ~5 minutes of tests. The
`vmcell build --kernel-source host-make` before it is a cache hit in seconds *if* the kernel is
already built — the recorded trap is that a bare `vmcell build` swaps in a prebuilt `vmlinux`
lacking `CONFIG_KVM_INTEL`.

**5.5 A backgrounded `sleep` does not wait.** `run_in_background: true` returns immediately, so a
poll right after it sees nothing. Either end the turn and let the completion notification wake you,
or run the wait in the foreground with a bounded `until` loop.

---

## 6. Five premises that did not survive contact — and one gate that was theater

The register's convention ("every register so far has carried at least one shipped-fact premise that
was empirically false") earned itself five more times. All five were found by **running** something,
never by reading it.

**6.1 §18 delta 5's subreaper gate does not reproduce.** The design specifies "the double-fork exec
leg red-on-inverse by removing the subreaper call (the test **hangs**)", and §3.5 explains it as
`wait_for` blocking on a status that will never be recorded. Built and run both ways: **it does not
hang, and `exec` returns the right code with the bit removed.** The steward only ever waits on its
own *direct* child, which it reaps in either placement. What `PR_SET_CHILD_SUBREAPER` decides is who
inherits the **grandchild**. The leg is rebuilt on orphan `PPid` re-parenting and *fails* instead of
stalling — a better gate than the specified one.

**6.2 Steward log lines are not observables.** The steward logs at `tracing::info!`, the guest has no
`RUST_LOG`, and `tracing_subscriber`'s default filter keeps everything below `error` off the serial
console. Two assertions rested on output that does not exist. Use `mini-init`'s `println!` output,
the kernel's own lines (`reboot: Power down`), or a data-plane fact (`dial_vsock` to a port that must
have nobody on it). **This will bite delta 9.**

**6.3 A backgrounded payload hangs `exec` forever.** `handle_exec` joins both output pumps before
replying, so a background process that inherits the exec's stdout pipe holds it open for its whole
life. Redirect stdio (`</dev/null >/dev/null 2>&1 &`) on any background job in a live test.

**6.4 Firecracker's baked-vsock guard failed OPEN.** `reject_live_baked_vsock` grouped a probe
*timeout* with a probe *failure* and unlinked on both — so under load it classified a **live**
socket as stale and would have severed a running VM's steward transport. Fixed at `c5a01a1`: an
inconclusive probe now refuses. Pre-existing, found only because its own unit test flaked once.

**6.5 THE GATE FOR 6.4 PASSED WITH THE REGRESSION PLANTED.** It tried to produce a real timeout by
saturating a listener's accept backlog; the backlog is 1024 deep, the loop gave up at 512, every
connect succeeded, the *live-listener* arm fired, and the assertion passed with the fail-open form
restored. **A test that cannot reach the arm it names is theater, and reading it does not show
that.** The fix was to extract the decision into a pure predicate driven directly over all three
inputs. This is the third pass in a row where a first-cut gate was structurally unable to fail.
**Plant the violation. Always. Every time.**

---

## 7. Decisions this session made that bind you

* **Delta 6 lands in three commits** (6a, 6b, 6c), all before delta 7.
* **`rootfs.default` and `handlers.default` flatten to the UN-suffixed pin keys.** That is what makes
  §10.5's byte-identity requirement a property of the data, and what kept `resolve_builder_base` —
  which picks the image that builds *kernels* — working untouched. Do not "tidy" it into
  `rootfs_default_image`; two gates redden, and they are the right two.
* **A registry entry's unknown key is refused naming the delta that adds it.** `xattrs` → delta 7,
  `features` → delta 6c. This is the F1-clean seam between deltas; keep it when you land those.
* **`PackOptions` grows by field.** Delta 7 adds `xattrs` to it; do not add a parameter.
* **`vmcell` will keep bumping.** One breaking release, several versions, ledgered honestly.

---

## 8. Known-stale items not worth blocking on

Carried from v3, re-verified:

* `docs/todo.md` still says "a host `agent::session` multiplexer" (line 21) and "no framing and no
  agent" (line 65) — `docs/` was outside the delta-1 rename sweep.
* `crates/vmcell-artifact-validator/src/classify.rs` fixtures say `init=/sbin/vmcell-steward` while
  `DEFAULT_INIT` is `/usr/sbin/vmcell-steward`, and one says "listening on vsock port 1024".
* ~thirty production comments cite `§18, Delta register … delta N` against the **superseded v27/v30**
  register, so "delta 1" in a comment usually means something else entirely. Two of them
  (`rootfs/mod.rs:60`, `tests/segment.rs:9`) say "delta 7" meaning `echo-server`, which will actively
  mislead you while implementing v33 delta 7.
* `.github/workflows/fuzz.yml`'s prose header says "15 targets"; there are 16. GUARD 5 does not check
  the prose, by design.
* `AGENTS.md` describes `just test-systemd` in the present tense; it does not exist (delta 9's).
