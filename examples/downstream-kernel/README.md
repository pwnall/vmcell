# `downstream-kernel` — the living consumer of the vmcell toolkit contract

This is a small, complete out-of-repo-shaped consumer of vmcell: a workspace that owns a guest-kernel
config fragment, builds a kernel carrying it through the published toolkit, proves the fragment
survived, and validates the result — with **zero vmcell-source edits and no fork of `pins.json`**.

It exists to be a gate. Design §10.4 names the downstream contract surface; this workspace consumes
**every item on that list**, so **a change that breaks it is contract drift**. Four rows are consumed
only as far as a network-free, KVM-free job can reach, and `src/lib.rs`'s table says which and why —
a scoped claim that is true beats a sweeping one that is not. The intended
response to a red `example-downstream` CI job is to reverse the change or version the contract (the
comment ledger at the top of `crates/vmcell/Cargo.toml`) — never to edit this example back to green.
Editing the consumer to match a silently-changed contract inverts the gate.

## What it does

1. **Extends the pins registry through the overlay — all three artifact kinds.**
   `pins-overlay.json` adds `kernel_fragments.IKCONFIG` (this repo's own fragment) and a
   `kernels.ikconfig` entry that declares it. That entry carries **all three** of `source_url`,
   `source_sha256` and `fragments: ["IKCONFIG"]`: a label is buildable only with its own source pins,
   and an entry carrying `fragments` alone is refused fail-loud (the refusal names the two
   `kernels.<label>.…` overlay keys to add — the flattened `kernel_<label>_source_url` spelling is not
   a key any pins document may carry). Since v33 it also adds a `rootfs.acme` entry (§10.5) — the same
   digest-pinned base vmcell's own `default` names, under `"xattrs": "preserve"` plus one
   hand-declared `features` stance — and a `handlers.acme` entry registered **by digest** with its own
   `applets` roster, because a path is an override and never a registration (F7). The overlay is
   layered over vmcell's committed baseline key by key: the resolved rosters are the *union*
   (`[acme, debian-systemd, default]`), so nothing is forked and nothing of vmcell's is taken away.
2. **Builds `vmlinux-ikconfig` through the library entry point** —
   `vmcell::artifact::build_labelled_kernel(label, target_dir, overlay)` — the entry a git-dep
   consumer calls from its own harness. (The CLI entry points — `vmcell build-kernels <label>…
   --pins <file>`, `--all` for the whole registry, and v33's `vmcell build
   --rootfs-label/--handler-label` selectors, §10.5 — from a vmcell checkout, are exercised by
   `ci-check.sh` on their fail-fast boundaries.)
3. **Asserts against the result, not the fragment.** `make olddefconfig` silently drops any symbol
   whose dependencies are unmet, so the assertion reads the resolved-config sidecar
   (`vmlinux-ikconfig.config`) through `vmcell_artifact_validator::kconfig::KconfigValues`.
4. **Runs the toolkit's own stage model.** A `Pipeline` of `ResolvePinsStage` → this consumer's own
   `Stage` proves Stage 0's pins arrive in `StageInputs` and that a downstream stage's `CacheKey`
   folds its input's **content** (through the exported `hash_file`), never a path.
5. **Emits and reads back the §7.4 feature-manifest sidecar.** `RootfsFeaturesStage::labelled`,
   behind Stage 0, writes `rootfs-acme.features`; `FeatureDeclaration::load_beside` reads it. Both
   the hand-declared stance and the `xattr_preserved` stance vmcell **derives** from the entry's
   `xattrs` policy have to survive the round trip — the derivation is the half no consumer can see in
   its own JSON.
6. **Runs both batteries.** `vmcell_artifact_validator::validate` for the level checks, and the
   two-directional conformance kit (`run_battery`) for the declarations: the KVM-free legs drive the
   whole five-state verdict law — including v33's `Warn` (an under-claim) and `Unverified` (an
   absence nothing can decide) — through a scripted probe, with the paired positive control, both
   directions of the expected-warning lifecycle and the battery-wide budget. The live leg runs the
   same battery through the shipped `LiveProbe`.
7. **Proves it on the data plane.** The booted guest exposes `/proc/config.gz` — a file that exists
   *only* if `CONFIG_IKCONFIG_PROC` survived — and its content round-trips the sidecar. This is also
   the differential the kit itself cannot make: `proc_config_gz` has no data-plane probe, so the
   battery answers `Unverified` and this consumer decides it another way.

The fragment choice is the point: `IKCONFIG` is **mechanism, not consumer content** (invariant G1).
It is self-proving, tiny, and owned by vmcell as an example. vmcell ships no consumer fragments.

## What this workspace deliberately does **not** reach

Named here and in `src/lib.rs`'s table, so the claim above stays checkable:

| Contract row | What is pinned here | What is out of reach, and why |
|---|---|---|
| the labelled rootfs / handler build entry points | the selectors, their unknown-label refusals naming the merged roster, the flag-vs-source refusal, and the labelled **declaration** producer | finishing a labelled *image* needs an OCI pull; finishing a labelled *handler* needs its digest-pinned fetch. Both are network work, and this job has no network |
| `pack_erofs_with_injection` + `ExtraFile` + `XattrPolicy` + `RootfsFormat` | the options composition (which handler binary the tail bakes, which artifact key the image registers under), the reserved-dest law both ways, the erofs door's typed refusal of a format it does not pack, and the filename laws with their inverse | a completed pack needs a pulled base **and** a built steward; the ext4 emitter additionally needs the external producer binary (§4.7) |
| `VMCELL_SKIP_MANIFEST` | — | it is read only by vmcell's own `require_cap!` test helper and has no consumer-callable API, so there is nothing here to consume |
| the conformance battery's live absence probes | the whole verdict law, KVM-free, through a scripted probe — which is the form §10.6 asks for | a live absence probe boots and snapshots, so the live leg declares only what this consumer's own artifacts actually claim rather than a fixture that would redden for fixture reasons |

## Layout

| Path | What it is |
|---|---|
| `Cargo.toml` | its **own** workspace root, its own `[patch.crates-io]`, its own lockfile |
| `pins-overlay.json` | this consumer's pins overlay: the `IKCONFIG` fragment, the `ikconfig` kernel, the `acme` rootfs and the `acme` handler |
| `src/lib.rs` | the contract surface this consumer stands on (the item-by-item table lives here), its registry readers, its declaration/pack compositions and its survival predicates |
| `src/main.rs` | `downstream-kernel getters` / `… bins` (the two env-contract probes) and `… live` (the full loop) |
| `tests/contract.rs` | the KVM-free legs: overlay + registry resolution, the declaration sidecar through the pipeline, a consumer's own `Stage`, the pack surface, the five-state conformance law, predicates — each with its inverse |
| `ci-check.sh` | the whole KVM-free gate, including the documented CLI legs and the vendor-assertion trio |

## Consumer shape, and the one deliberate exception

Everything here is shaped like a real git-dep consumer: its own `[workspace]` root (vmcell's root
`Cargo.toml` `exclude`s this directory, so `cargo build --workspace` / nextest / `cargo hack` in
vmcell never compile it), its own `Cargo.lock`, its own pins overlay, its own artifacts directory,
and no reach from the crate into the vmcell workspace.

The **one** exception: the `vmcell` and `vmcell-artifact-validator` dependencies are **path** deps,
not `git = "…", rev = "…"`. A git dep would pin a commit and therefore stop reddening on the
same-commit contract drift this example exists to catch — and could not run on a pull request at
all, since the rev would not exist yet. A real consumer pins by `rev` and builds `--locked`.

`ci-check.sh` does invoke the `vmcell` CLI out of the surrounding checkout. That is not a leak: the
documented route for the CLI half of the contract is *"from a vmcell checkout"* (design §5.6), which
is exactly what the script does.

## Running it

```sh
# The KVM-free contract gate (what the `example-downstream` CI job runs):
cd examples/downstream-kernel && ./ci-check.sh

# The live loop. Needs /dev/kvm, a `cloud-hypervisor` binary, and an externally built rootfs —
# the documented downstream configuration (build artifacts with a vmcell checkout, then point the
# env contract at them). A first run compiles a kernel with host `make`, which takes minutes.
VMCELL_ARTIFACTS_DIR="$PWD/target/vmcell-artifacts" \
VMCELL_ROOTFS=/path/to/rootfs.erofs \
cargo run --locked --bin downstream-kernel -- live
```

`VMCELL_PINS` is not needed for the `live` run: the consumer passes its overlay explicitly to
`build_labelled_kernel`. Setting it is equivalent (an explicit path wins over the environment — the
one flag-beats-env law).

## The vendored-vhost positive control

This workspace's feature set resolves `vhost` / `vhost-user-backend`, and its manifest replicates
vmcell's `[patch.crates-io]` stanza. That makes it the **positive control** for
`scripts/check-vendored-vhost.sh`: `ci-check.sh` runs the real predicate here (green), then reddens
it against this same workspace's resolution with the vendored source annotations stripped, and
confirms the not-applicable verdict for a workspace that never links vhost. Drop either the stanza
or the feature set and the green leg's own non-vacuity check reddens.
