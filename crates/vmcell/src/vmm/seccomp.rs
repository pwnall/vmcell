//! The VMM subprocess's own seccomp-BPF confinement — one predicate, three backends
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
        _ => Err(unsupported("vmm_seccomp")),
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
        for backend in ["firecracker", "qemu"] {
            let err = vmm_seccomp_args(backend, VmmSeccomp::Log)
                .expect_err("Log must be Unsupported on a backend with no audit mode");
            assert!(
                matches!(&err, Error::Unsupported { vmm, feature }
                    if vmm == backend && feature == "seccomp_log"),
                "expected seccomp_log Unsupported for {backend}, got {err:?}"
            );
        }
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
