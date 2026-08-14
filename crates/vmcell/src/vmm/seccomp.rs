//! The VMM subprocess's own seccomp-BPF confinement — one predicate, four backends
//! (design §12.2, Layer 1 — the VMM's own seccomp filter / invariant §13, Cross-cutting invariants).
//!
//! Every backend ships an audited seccomp-BPF filter; the job here is to enable the
//! strictest practical one on each backend, **fail loud** when a policy cannot be
//! honored, and never leave a backend unconfined by default.
//! [`vmm_seccomp_args`](crate::vmm::seccomp::vmm_seccomp_args) is the single place a
//! [`VmmSeccomp`](crate::config::VmmSeccomp) policy becomes a backend's native CLI flag, so a new
//! backend that skips it — or wires the wrong flag — reddens the one-law golden test, the
//! same discipline as `mac_math` / `config_has_vhost_user_device`.
//!
//! The verified native semantics this encodes:
//! - **Cloud Hypervisor** `--seccomp <true|false|log>` (default `true`); passed
//!   **explicitly** so a future CH default flip cannot silently disable it (§12.2, Layer 1 — the VMM's own seccomp filter).
//! - **Firecracker** ships a built-in advanced filter that is on unless `--no-seccomp` is
//!   passed; it has **no** observe-only mode.
//! - **QEMU** `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`
//!   (default **off** — the hole this closes; a QEMU built without libseccomp errors out on
//!   `-sandbox on`, the desired fail-loud rather than running unconfined).
//! - **crosvm** always runs `--disable-sandbox` — the live-validation reversal (AGENTS.md, the
//!   jailer section): its own sandbox is a *multiprocess* minijail (per-device jailed subprocesses
//!   that `pivot_root` into `/var/empty`), incompatible with this harness's single-process
//!   supervision. Its Layer-1 flag is therefore the same on every policy, and
//!   [`Enforcing`](crate::config::VmmSeccomp::Enforcing) instead turns the **Layer-2 jailer
//!   deny-list ON** (`Crosvm::create`), which is what keeps it confined;
//!   [`Disabled`](crate::config::VmmSeccomp::Disabled) leaves that deny-list off. Like Firecracker
//!   and QEMU it has no observe-only mode, so [`Log`](crate::config::VmmSeccomp::Log) is a typed
//!   `Unsupported`.

use crate::config::VmmSeccomp;
use crate::error::{Error, Result};

/// The QEMU `-sandbox` argument enabling the strictest practical libseccomp sandbox: deny
/// obsolete syscalls, privilege elevation, process spawning, and resource control. One
/// const so the QEMU cmd builder and the golden test name the identical spec (§13, Cross-cutting invariants).
pub const QEMU_SANDBOX_SPEC: &str =
    "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny";

/// Maps `(backend, policy)` to the CLI tokens to append to that backend's spawn command.
///
/// Returns [`Error::Unsupported`] (matchable, typed) for a policy a backend cannot honor —
/// [`VmmSeccomp::Log`] on Firecracker/QEMU (neither has an observe-only mode) and any
/// unknown backend — rather than silently downgrading to a weaker or stronger policy
/// (§7.2, The fail-loud capability contract and HostCapabilities capability honesty). An empty vector means "the backend's default is already the
/// requested policy" (Firecracker's built-in filter under [`VmmSeccomp::Enforcing`];
/// QEMU's no-sandbox default under [`VmmSeccomp::Disabled`]).
///
/// # Errors
/// [`Error::Unsupported`] `{ vmm, feature: "seccomp_log" }` for [`VmmSeccomp::Log`] on a
/// backend without an audit mode, or `{ feature: "vmm_seccomp" }` for an unknown backend.
pub fn vmm_seccomp_args(backend: &str, policy: VmmSeccomp) -> Result<Vec<String>> {
    let unsupported = |feature: &str| Error::Unsupported {
        vmm: backend.to_string(),
        feature: feature.to_string(),
    };
    match backend {
        "cloud-hypervisor" => Ok(match policy {
            VmmSeccomp::Enforcing => vec!["--seccomp".to_string(), "true".to_string()],
            VmmSeccomp::Log => vec!["--seccomp".to_string(), "log".to_string()],
            VmmSeccomp::Disabled => vec!["--seccomp".to_string(), "false".to_string()],
        }),
        "firecracker" => match policy {
            // The built-in advanced filter is on unless --no-seccomp is passed.
            VmmSeccomp::Enforcing => Ok(Vec::new()),
            VmmSeccomp::Disabled => Ok(vec!["--no-seccomp".to_string()]),
            VmmSeccomp::Log => Err(unsupported("seccomp_log")),
        },
        "qemu" => match policy {
            VmmSeccomp::Enforcing => {
                Ok(vec!["-sandbox".to_string(), QEMU_SANDBOX_SPEC.to_string()])
            }
            VmmSeccomp::Disabled => Ok(Vec::new()),
            VmmSeccomp::Log => Err(unsupported("seccomp_log")),
        },
        "crosvm" => match policy {
            // crosvm's OWN sandbox is a MULTIPROCESS minijail — per-device jailed subprocesses that
            // `pivot_root` into `/var/empty` and load policy-dir seccomp. Empirically (validated live)
            // that is incompatible with the harness's single-process supervision model: it fails
            // `"/var/empty" is not a directory, cannot create jail` unless that dir is pre-created, and
            // then forks device children that fight the cgroup `add_task`/pgid-reap/`find_host_pid`
            // assumptions. So crosvm ALWAYS runs `--disable-sandbox` (a single externally-jailed
            // process). Its seccomp confinement is instead the Layer-2 jailer deny-list, which
            // `Crosvm::create` turns ON for `Enforcing` (so the backend is NOT unconfined by default)
            // and leaves OFF for `Disabled` (the loud opt-out). Both emit the same flag; the
            // Enforcing/Disabled distinction lives in the jail spec, not the argv. Log has no
            // observe-only mode → Unsupported (as on FC/QEMU).
            VmmSeccomp::Enforcing | VmmSeccomp::Disabled => {
                Ok(vec!["--disable-sandbox".to_string()])
            }
            VmmSeccomp::Log => Err(unsupported("seccomp_log")),
        },
        _ => Err(unsupported("vmm_seccomp")),
    }
}

/// The shipping-backend roster, for the doc-parity gates in this module and in
/// [`crate::vmm`]. Test-only.
///
/// [`vmm_seccomp_args`] is the one place that *must* know every shipping backend — an id it does
/// not match is a fail-loud `vmm_seccomp` `Unsupported`, so a backend cannot ship without an arm.
/// That makes its dispatch the authoritative roster, and both doc gates derive from it rather than
/// keeping a second copy (AGENTS.md "one law, one predicate"; every duplicate roster in this repo
/// has diverged, which is exactly the docs/78 §9.4 finding class).
#[cfg(test)]
pub(crate) mod roster {
    /// Each dispatched backend id paired with the prose spelling its rustdoc uses. A new dispatch
    /// arm with no entry here fails the completeness assert in
    /// [`dispatched_backend_ids`]'s callers rather than being silently skipped.
    pub(crate) const BACKEND_DISPLAY_NAMES: [(&str, &str); 4] = [
        ("cloud-hypervisor", "Cloud Hypervisor"),
        ("firecracker", "Firecracker"),
        ("qemu", "QEMU"),
        ("crosvm", "crosvm"),
    ];

    /// Spelled-out counts, so a doc's "four backends" claim is checked against the dispatch rather
    /// than against a reviewer's memory.
    pub(crate) const COUNT_WORDS: [&str; 9] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    ];

    /// The backend ids `vmm_seccomp_args` dispatches on, scanned out of this file's own source.
    ///
    /// A `match`'s arms cannot be enumerated at runtime, so this reads the dispatch's text — the
    /// same technique `flatten_dispatch_arms_are_all_advertised_in_the_roster` uses for the pins
    /// namespaces. The scan is self-checking at its call sites: they assert the arm count against
    /// [`BACKEND_DISPLAY_NAMES`], so a scan that silently matched nothing reddens instead of
    /// making every downstream assert vacuous.
    pub(crate) fn dispatched_backend_ids() -> Vec<String> {
        const SOURCE: &str = include_str!("seccomp.rs");

        let body = SOURCE
            .split_once("pub fn vmm_seccomp_args(")
            .expect("the dispatch is defined in this file")
            .1
            .split_once("match backend {")
            .expect("the dispatch matches on `backend`")
            .1;

        let mut arms = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            // The catch-all closes the dispatch; everything after it is other code.
            if line.starts_with("_ =>") {
                break;
            }
            // An arm line is `"name" => …`; policy arms, bodies and comments never start with a
            // quote.
            if !line.starts_with('"') {
                continue;
            }
            let Some((patterns, _)) = line.split_once("=>") else {
                continue;
            };
            for pat in patterns.split('|') {
                arms.push(pat.trim().trim_matches('"').to_string());
            }
        }
        arms
    }

    /// Collapses every whitespace run to a single space, so a roster name that a rustfmt-width
    /// line break split across two `///` lines ("Cloud\n/// Hypervisor") still matches. Without
    /// this the gates would silently depend on where the comment happens to wrap.
    pub(crate) fn normalize_ws(doc: &str) -> String {
        doc.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The prose spelling for `id`, panicking if the roster has no entry — the fail-loud channel
    /// that stops a newly-dispatched backend from slipping past a doc gate unchecked.
    pub(crate) fn display_name(id: &str) -> &'static str {
        BACKEND_DISPLAY_NAMES
            .iter()
            .find(|(dispatch_id, _)| *dispatch_id == id)
            .map(|(_, display)| *display)
            .unwrap_or_else(|| panic!("dispatch arm `{id}` has no doc spelling in the roster"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards §13 (Cross-cutting invariants): the one-law golden mapping. Every (backend, policy) pair that is
    // supported emits the exact native flag; wiring the wrong flag, dropping a backend, or
    // regressing the QEMU sandbox spec reddens here. The inverse (e.g. CH Enforcing not
    // passing `--seccomp true`, so a CH default flip could silently disable it) fails.
    #[test]
    fn vmm_seccomp_args_golden_per_backend() {
        assert_eq!(
            vmm_seccomp_args("cloud-hypervisor", VmmSeccomp::Enforcing).expect("ch enforcing"),
            vec!["--seccomp".to_string(), "true".to_string()]
        );
        assert_eq!(
            vmm_seccomp_args("cloud-hypervisor", VmmSeccomp::Log).expect("ch log"),
            vec!["--seccomp".to_string(), "log".to_string()]
        );
        assert_eq!(
            vmm_seccomp_args("cloud-hypervisor", VmmSeccomp::Disabled).expect("ch disabled"),
            vec!["--seccomp".to_string(), "false".to_string()]
        );

        // Firecracker: enforcing keeps the built-in filter (no flag); disabled opts out.
        assert!(
            vmm_seccomp_args("firecracker", VmmSeccomp::Enforcing)
                .expect("fc enforcing")
                .is_empty(),
            "FC Enforcing must keep the built-in filter (emit no flag)"
        );
        assert_eq!(
            vmm_seccomp_args("firecracker", VmmSeccomp::Disabled).expect("fc disabled"),
            vec!["--no-seccomp".to_string()]
        );

        // QEMU: enforcing turns on the sandbox (the hole this closes); disabled emits nothing.
        assert_eq!(
            vmm_seccomp_args("qemu", VmmSeccomp::Enforcing).expect("qemu enforcing"),
            vec!["-sandbox".to_string(), QEMU_SANDBOX_SPEC.to_string()]
        );
        assert!(
            vmm_seccomp_args("qemu", VmmSeccomp::Disabled)
                .expect("qemu disabled")
                .is_empty(),
            "QEMU Disabled must emit no -sandbox"
        );

        // crosvm: its own multiprocess minijail is incompatible with the single-process supervision
        // model (needs /var/empty, forks device children), so BOTH Enforcing and Disabled emit
        // --disable-sandbox; the Enforcing-vs-Disabled distinction is the Layer-2 jailer deny-list
        // (`Crosvm::create` enables it only for Enforcing), not the argv. A regression that stopped
        // emitting --disable-sandbox would reintroduce the `/var/empty ... cannot create jail` boot
        // failure.
        assert_eq!(
            vmm_seccomp_args("crosvm", VmmSeccomp::Enforcing).expect("crosvm enforcing"),
            vec!["--disable-sandbox".to_string()]
        );
        assert_eq!(
            vmm_seccomp_args("crosvm", VmmSeccomp::Disabled).expect("crosvm disabled"),
            vec!["--disable-sandbox".to_string()]
        );
        // The sandbox spec must actually deny the four dangerous classes (a regression to a
        // bare `-sandbox on` that dropped spawn/elevateprivileges reddens).
        assert!(QEMU_SANDBOX_SPEC.contains("spawn=deny"));
        assert!(QEMU_SANDBOX_SPEC.contains("elevateprivileges=deny"));
        assert!(QEMU_SANDBOX_SPEC.contains("resourcecontrol=deny"));
        assert!(QEMU_SANDBOX_SPEC.contains("obsolete=deny"));
    }

    // Guards §13 (Cross-cutting invariants) fail-loud: a policy a backend cannot honor is a typed Unsupported, not a
    // silent fallback. Firecracker and QEMU have no observe-only mode, so `Log` must error —
    // the inverse (silently falling back to Enforcing) would leave a caller who asked to
    // DEBUG a filter running under a killing filter, unaware.
    #[test]
    fn vmm_seccomp_args_log_unsupported_on_fc_and_qemu() {
        for backend in ["firecracker", "qemu", "crosvm"] {
            let err = vmm_seccomp_args(backend, VmmSeccomp::Log)
                .expect_err("Log must be Unsupported on a backend with no audit mode");
            assert!(
                matches!(&err, Error::Unsupported { vmm, feature }
                    if vmm == backend && feature == "seccomp_log"),
                "expected seccomp_log Unsupported for {backend}, got {err:?}"
            );
        }
    }

    // GATE (docs/78 §9.4 `seccomp-module-doc-describes-reversed-crosvm-posture`) — the module doc
    // above is a ROSTER, and a stale roster is what that finding caught: it still described the
    // pre-reversal crosvm posture and said "three backends" while four ship. The doc is the only
    // place a reader learns *why* each backend's flag is what it is, so it must name every backend
    // the dispatch below actually knows. There is no way to enumerate a `match`'s arms at runtime,
    // so this scans the dispatch's own source text (the fn is in this file), exactly as
    // `flatten_dispatch_arms_are_all_advertised_in_the_roster` does for the pins namespaces.
    // Red-on-inverse: add a `"gremlin" => …` arm without a doc bullet and this goes red naming
    // `gremlin` (the count assert reddens first); revert the "four backends" line to "three" and
    // the count assert reddens.
    #[test]
    fn module_doc_roster_names_every_dispatched_backend() {
        use super::roster;

        const SOURCE: &str = include_str!("seccomp.rs");

        // The module doc is the leading `//!` block; the markers come off before normalizing, or a
        // name the comment wrapped would read as "Cloud //! Hypervisor" and never match.
        let module_doc = roster::normalize_ws(
            &SOURCE
                .lines()
                .map_while(|l| l.strip_prefix("//!"))
                .collect::<Vec<_>>()
                .join("\n"),
        );

        let arms = roster::dispatched_backend_ids();
        // The scan itself must be able to fail: a silently-empty scan would make every assert
        // below vacuous.
        assert_eq!(
            arms.len(),
            roster::BACKEND_DISPLAY_NAMES.len(),
            "the source scan found dispatch arms {arms:?} against roster {:?}",
            roster::BACKEND_DISPLAY_NAMES
        );

        let count_word = roster::COUNT_WORDS
            .get(arms.len())
            .expect("the backend roster is small enough to spell out");
        assert!(
            module_doc.contains(&format!("{count_word} backends")),
            "the module doc must say \"{count_word} backends\" ({} dispatch arms: {arms:?})",
            arms.len()
        );

        for id in &arms {
            // Each backend's bullet is bold-headed, so the doc must carry the emphasized spelling —
            // a passing mention elsewhere in the prose does not satisfy the roster.
            let display = format!("**{}**", roster::display_name(id));
            assert!(
                module_doc.contains(&display),
                "the module doc must describe {display} — a backend whose native semantics are \
                 undocumented is the stale-roster defect this guards"
            );
        }

        // The crosvm bullet specifically: the reversal it records (always `--disable-sandbox`,
        // Enforcing = Layer-2 deny-list ON) is what the dispatch implements, so the doc must not
        // drift back to the refuted "Enforcing keeps crosvm's own sandbox (no flag)" claim.
        assert!(
            module_doc.contains("--disable-sandbox"),
            "the crosvm bullet must state the always-`--disable-sandbox` posture"
        );
        assert!(
            !module_doc.contains("sandboxes itself by default"),
            "the pre-reversal crosvm posture was refuted by live validation; the doc must not \
             re-assert it"
        );
    }

    // An unknown backend is rejected fail-loud rather than defaulting to "no flag" (which
    // would silently leave a new backend unconfined).
    #[test]
    fn vmm_seccomp_args_unknown_backend_is_unsupported() {
        let err = vmm_seccomp_args("acme-vmm", VmmSeccomp::Enforcing)
            .expect_err("an unknown backend must be Unsupported");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "acme-vmm" && feature == "vmm_seccomp"),
            "expected vmm_seccomp Unsupported, got {err:?}"
        );
    }
}
