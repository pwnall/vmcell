//! What an out-of-repo vmcell consumer stands on, exercised from the consumer position.
//!
//! This crate is the living gate for the downstream toolkit contract (design v30 §10.4, The
//! downstream toolkit contract): it owns a guest-kernel config fragment in *its* repo, builds a
//! kernel carrying it through the published toolkit (§5.6, The downstream kernel toolkit), asserts
//! the fragment actually survived `make olddefconfig`, and validates the result — with zero
//! vmcell-source edits and no fork of `pins.json`.
//!
//! **The fragment is mechanism, not consumer content** (invariant G1). `CONFIG_IKCONFIG` +
//! `CONFIG_IKCONFIG_PROC` are chosen because they are *self-proving*: a kernel built with them
//! exposes `/proc/config.gz`, a file that exists only if the fragment took, so the example can
//! assert on the data plane instead of on a proxy signal.
//!
//! **Reddening this crate is the intended failure mode of contract drift.** If a change to vmcell
//! breaks it, the fix is to reverse or version the contract change (the ledger at the top of
//! `crates/vmcell/Cargo.toml`), never to edit this crate back to green.
//!
//! The contract surface consumed here, item by item:
//!
//! | §10.4 item | used by |
//! |---|---|
//! | pins schema + overlay | [`overlay_path`], [`registry_entry`] |
//! | kernel build entry points | [`vmcell::artifact::build_labelled_kernel`] (in `main.rs`) |
//! | the resolved-config sidecar | [`read_resolved_config`] |
//! | the `VMCELL_*` env contract | [`artifacts_dir`], and the harness-getter leg in `main.rs` |
//! | the validator battery + `KconfigValues` | [`fragment_survived`], and the battery run in `main.rs` |

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use vmcell::artifact::KernelRegistryEntry;
use vmcell_artifact_validator::kconfig::KconfigValues;

/// The `kernels.<label>` this consumer adds through its overlay, and therefore the name of the
/// kernel the toolkit builds (`vmlinux-ikconfig`).
pub const KERNEL_LABEL: &str = "ikconfig";

/// The `kernel_fragments.<NAME>` this consumer owns. vmcell never ships it; the overlay does.
pub const FRAGMENT_NAME: &str = "IKCONFIG";

/// The symbols the fragment must leave **built in** (`=y`) in the resolved config.
///
/// `olddefconfig` silently drops any symbol whose dependencies are unmet (§5.6), so this list is
/// asserted against the *result* — the sidecar and, live, `/proc/config.gz` — never against the
/// fragment text that was submitted.
pub const REQUIRED_SYMBOLS: [&str; 2] = ["CONFIG_IKCONFIG", "CONFIG_IKCONFIG_PROC"];

/// The in-guest file that exists **only** when [`REQUIRED_SYMBOLS`] survived — the data-plane proof.
pub const IN_GUEST_CONFIG: &str = "/proc/config.gz";

/// This consumer's pins overlay (`$VMCELL_PINS`'s value for every leg of the example).
///
/// Baked from `CARGO_MANIFEST_DIR` at compile time, the way a cargo example addresses its own data
/// files: this crate is built and run on the same machine in every leg (its `ci-check.sh` and the
/// live CI job both run from the checkout).
#[must_use]
pub fn overlay_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("pins-overlay.json")
}

/// Where this consumer keeps its own artifacts: `$VMCELL_ARTIFACTS_DIR`, else a directory under
/// *this* workspace's `target/`.
///
/// Deliberately its own directory. `vmcell::artifact::artifacts_dir()` would resolve into the
/// vmcell checkout's `target/vmcell-artifacts` from here (its workspace-root ascent finds the
/// vmcell tree, because this example lives inside the repo), and a downstream build must never
/// write into — let alone clobber — the host project's artifact cache.
#[must_use]
pub fn artifacts_dir() -> PathBuf {
    std::env::var_os("VMCELL_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target/vmcell-artifacts"))
}

/// The [`KERNEL_LABEL`] entry of the merged (baseline + this consumer's overlay) `kernels`
/// registry.
///
/// This is the overlay half of the contract in one call: the label does not exist in vmcell's
/// committed `pins.json`, so a resolution that returns it proves the overlay was read, merged, and
/// its `fragments` key honored.
///
/// # Errors
/// Returns a message when the overlay cannot be resolved, when the label is absent (the overlay
/// was ignored — the failure this gate exists to catch), or when it declares the wrong fragments.
pub fn registry_entry() -> Result<KernelRegistryEntry, String> {
    let overlay = overlay_path();
    let registry = vmcell::artifact::resolve_kernel_registry(Some(&overlay))
        .map_err(|e| format!("resolving the kernels registry through {overlay:?} failed: {e}"))?;
    let entry = registry
        .iter()
        .find(|e| e.label == KERNEL_LABEL)
        .ok_or_else(|| {
            format!(
                "the resolved `kernels` registry has no `{KERNEL_LABEL}` label — the overlay \
                 {overlay:?} was not merged; resolved labels: [{}]",
                registry
                    .iter()
                    .map(|e| e.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    if entry.fragments != vec![FRAGMENT_NAME.to_string()] {
        return Err(format!(
            "`kernels.{KERNEL_LABEL}.fragments` resolved to {:?}, expected [{FRAGMENT_NAME:?}]",
            entry.fragments
        ));
    }
    Ok(entry.clone())
}

/// Reads and parses the resolved-config sidecar published beside `kernel` (§5.6).
///
/// The sidecar path is composed by vmcell's own [`vmcell::artifact::kernel::resolved_config_path`]
/// rather than by a local `format!`: the naming rule is contract surface, and a second copy of it
/// here is precisely the duplicate that drifts.
///
/// # Errors
/// Returns a message when the sidecar is absent (a compiling producer that published nothing —
/// the silent-drop failure the sidecar exists to make loud) or does not parse as a `.config`.
pub fn read_resolved_config(kernel: &Path) -> Result<KconfigValues, String> {
    let sidecar = vmcell::artifact::kernel::resolved_config_path(kernel);
    let text = std::fs::read_to_string(&sidecar).map_err(|e| {
        format!(
            "resolved-config sidecar missing at {}: {e} — a compiling producer must publish it \
             beside the kernel (design §5.6); without it there is no evidence of what the kernel \
             actually contains",
            sidecar.display()
        )
    })?;
    KconfigValues::parse(&text)
        .map_err(|e| format!("sidecar {} is not a .config: {e}", sidecar.display()))
}

/// The **one** fragment-survival predicate, applied to every resolved config this example gets
/// hold of — the sidecar on the host and `/proc/config.gz` read back out of the booted guest.
///
/// One law, one predicate: two copies of "did the fragment take?" would let the host leg and the
/// guest leg disagree about what surviving means.
///
/// # Errors
/// Returns a message naming the first [`REQUIRED_SYMBOLS`] entry that is not built in, and
/// distinguishing "present but disabled" (the symbol's dependencies were unmet and
/// `olddefconfig` dropped it) from "never mentioned" (the fragment never reached the build).
pub fn fragment_survived(resolved: &KconfigValues, source: &str) -> Result<(), String> {
    for symbol in REQUIRED_SYMBOLS {
        if resolved.is_builtin(symbol) {
            continue;
        }
        return Err(match resolved.get(symbol) {
            Some(value) => format!(
                "{source}: `{symbol}` resolved to {value:?}, not `=y` — the `{FRAGMENT_NAME}` \
                 fragment reached the build but olddefconfig did not keep it built in"
            ),
            None => format!(
                "{source}: `{symbol}` is absent entirely — the `{FRAGMENT_NAME}` fragment never \
                 reached the build (check that `kernels.{KERNEL_LABEL}.fragments` resolved)"
            ),
        });
    }
    Ok(())
}

/// Asserts the config the guest reports contains every symbol/value the host-side sidecar
/// recorded — the round-trip half of the data-plane proof (§5.6).
///
/// A **subset**, not an equality, and the asymmetry is deliberate: `/proc/config.gz` is written by
/// kbuild from the same `.config` the sidecar was copied from, but it is regenerated by the build
/// and may carry symbols the copied file did not. Every symbol the sidecar recorded must appear in
/// the guest with the same value — that is what "the kernel that booted is the kernel whose config
/// we published" means, and it reddens if the sidecar belongs to a different build.
///
/// # Errors
/// Returns a message naming the first symbol that is missing or differs in the guest's copy, and
/// how many symbols were compared.
pub fn guest_config_round_trips(
    guest: &KconfigValues,
    sidecar: &KconfigValues,
) -> Result<usize, String> {
    for (symbol, value) in sidecar.iter() {
        match guest.get(symbol) {
            Some(in_guest) if in_guest == value => {}
            Some(in_guest) => {
                return Err(format!(
                    "{IN_GUEST_CONFIG} disagrees with the sidecar on `{symbol}`: guest {in_guest:?} \
                     vs sidecar {value:?} — the booted kernel is not the one the sidecar describes"
                ));
            }
            None => {
                return Err(format!(
                    "{IN_GUEST_CONFIG} does not mention `{symbol}`, which the sidecar records as \
                     {value:?} — the booted kernel is not the one the sidecar describes"
                ));
            }
        }
    }
    Ok(sidecar.len())
}
