# `downstream-kernel` — the living consumer of the vmcell toolkit contract

This is a small, complete out-of-repo-shaped consumer of vmcell: a workspace that owns a guest-kernel
config fragment, builds a kernel carrying it through the published toolkit, proves the fragment
survived, and validates the result — with **zero vmcell-source edits and no fork of `pins.json`**.

It exists to be a gate. Design v30 §10.4 names the downstream contract surface; this workspace
consumes every item on that list, so **a change that breaks it is contract drift**. The intended
response to a red `example-downstream` CI job is to reverse the change or version the contract (the
comment ledger at the top of `crates/vmcell/Cargo.toml`) — never to edit this example back to green.
Editing the consumer to match a silently-changed contract inverts the gate.

## What it does

1. **Extends the pins registry through the overlay.** `pins-overlay.json` adds
   `kernel_fragments.IKCONFIG` (this repo's own fragment) and a `kernels.ikconfig` entry that
   declares it. The overlay is layered over vmcell's committed baseline key by key; nothing is
   forked.
2. **Builds `vmlinux-ikconfig` through the library entry point** —
   `vmcell::artifact::build_labelled_kernel(label, target_dir, overlay)` — the entry a git-dep
   consumer calls from its own harness. (The CLI entry point, `vmcell build-kernels --pins <file>`
   from a vmcell checkout, is exercised by `ci-check.sh`.)
3. **Asserts against the result, not the fragment.** `make olddefconfig` silently drops any symbol
   whose dependencies are unmet, so the assertion reads the resolved-config sidecar
   (`vmlinux-ikconfig.config`) through `vmcell_artifact_validator::kconfig::KconfigValues`.
4. **Runs the conformance battery** (`vmcell_artifact_validator::validate`) against its own
   kernel + rootfs pair.
5. **Proves it on the data plane.** The booted guest exposes `/proc/config.gz` — a file that exists
   *only* if `CONFIG_IKCONFIG_PROC` survived — and its content round-trips the sidecar.

The fragment choice is the point: `IKCONFIG` is **mechanism, not consumer content** (invariant G1).
It is self-proving, tiny, and owned by vmcell as an example. vmcell ships no consumer fragments.

## Layout

| Path | What it is |
|---|---|
| `Cargo.toml` | its **own** workspace root, its own `[patch.crates-io]`, its own lockfile |
| `pins-overlay.json` | this consumer's pins overlay: the `IKCONFIG` fragment + the `ikconfig` label |
| `src/lib.rs` | the contract surface this consumer stands on, and its survival predicates |
| `src/main.rs` | `downstream-kernel getters` (the env-contract probe) and `… live` (the full loop) |
| `tests/contract.rs` | the KVM-free legs: overlay resolution, sidecar naming, predicates + inverses |
| `ci-check.sh` | the whole KVM-free gate, including the documented CLI and vendor-assertion legs |

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
