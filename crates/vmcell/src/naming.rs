//! The one place that composes every **swept per-VM host resource name** from a single configurable
//! prefix (design; AGENTS.md "one law, one predicate").
//!
//! A VM leaks four kinds of host resource if it dies ungracefully: a network namespace, a tap
//! interface, a cgroup slice, and a scratch directory. The orphan sweep
//! ([`crate::orchestrator::sweep_orphans`]) reclaims them by matching their names — so the **naming
//! sites and the sweep filters must agree on the prefix**, or the sweep silently misses leaks. Both
//! derive from the functions here, and `prefix_matches_its_names` (a unit test) pins that agreement.
//!
//! The prefix is configurable so an operator can run isolated fleets (or avoid colliding with another
//! tool) without patching the code; it defaults to [`crate::naming::DEFAULT_RESOURCE_PREFIX`]
//! (`"vmcell"`), the value
//! that was hard-coded before it became an option.

/// The default resource-name prefix (`"vmcell"`) — the value hard-coded before this became an option.
pub const DEFAULT_RESOURCE_PREFIX: &str = "vmcell";

/// The maximum prefix length. Kept short so `<prefix>-net-<vmid>` stays well under the 15-char Linux
/// network-interface name limit for the derived tap name (`<prefix>-tap-<vmid>` → the tap is what has
/// the `IFNAMSIZ` limit; a long prefix would make the tap name invalid).
pub const MAX_RESOURCE_PREFIX_LEN: usize = 6;

/// Validates a resource prefix: non-empty, ≤ [`MAX_RESOURCE_PREFIX_LEN`], and only
/// `[A-Za-z0-9]` (so it is safe in a netns name, a network-interface name, a cgroup path, and a
/// directory name — no `/`, `-`, `.`, or whitespace, which could break any of those or confuse the
/// `<prefix>-net-<vmid>` structure the sweep parses).
///
/// # Errors
/// Returns a human-readable reason string when the prefix is empty, too long, or contains a
/// disallowed byte.
pub fn validate_resource_prefix(prefix: &str) -> Result<(), String> {
    if prefix.is_empty() {
        return Err("resource prefix must not be empty".to_string());
    }
    if prefix.len() > MAX_RESOURCE_PREFIX_LEN {
        return Err(format!(
            "resource prefix {prefix:?} is longer than {MAX_RESOURCE_PREFIX_LEN} bytes (keeps the \
             derived tap name under the 15-char interface-name limit)"
        ));
    }
    if let Some(bad) = prefix.bytes().find(|b| !b.is_ascii_alphanumeric()) {
        return Err(format!(
            "resource prefix {prefix:?} may only contain [A-Za-z0-9]; found byte {bad:#04x}"
        ));
    }
    Ok(())
}

/// The network namespace name for `vmid`: `<prefix>-net-<vmid>`.
#[must_use]
pub fn netns_name(prefix: &str, vmid: u32) -> String {
    format!("{prefix}-net-{vmid}")
}

/// The tap interface name for `vmid`: `<prefix>-tap-<vmid>`.
#[must_use]
pub fn tap_name(prefix: &str, vmid: u32) -> String {
    format!("{prefix}-tap-{vmid}")
}

/// The cgroup slice **leaf** name for `vmid`: `<prefix>-vm-<vmid>` (an ancestor path may be prepended
/// by the caller for sibling placement, §12.7).
#[must_use]
pub fn cgroup_slice_name(prefix: &str, vmid: u32) -> String {
    format!("{prefix}-vm-{vmid}")
}

/// The per-VM scratch-directory name: `<prefix>-vm-<pid>-<vmid>` (both ids so two processes' VMs never
/// collide, §12.3/§12.7).
#[must_use]
pub fn scratch_dir_name(prefix: &str, pid: u32, vmid: u32) -> String {
    format!("{prefix}-vm-{pid}-{vmid}")
}

/// The prefix the orphan sweep matches **netns** names by: `<prefix>-net-`.
#[must_use]
pub fn netns_sweep_prefix(prefix: &str) -> String {
    format!("{prefix}-net-")
}

/// The prefix the orphan sweep matches **cgroup slices and scratch dirs** by: `<prefix>-vm-` (both use
/// the `<prefix>-vm-` stem, distinct from the `<prefix>-net-` stem for namespaces).
#[must_use]
pub fn vm_resource_sweep_prefix(prefix: &str) -> String {
    format!("{prefix}-vm-")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The load-bearing invariant: every produced resource name STARTS WITH the sweep prefix the sweep
    // filters by, for ANY prefix. If a naming function and its sweep filter ever diverged (e.g. a
    // renamed stem), the sweep would silently miss that resource — this reddens instead.
    #[test]
    fn prefix_matches_its_names() {
        for prefix in ["vmcell", "acme", "z", "abc123"] {
            let vmid = 42;
            let pid = 7;
            assert!(
                netns_name(prefix, vmid).starts_with(&netns_sweep_prefix(prefix)),
                "netns name must match its sweep filter for prefix {prefix:?}"
            );
            assert!(
                cgroup_slice_name(prefix, vmid).starts_with(&vm_resource_sweep_prefix(prefix)),
                "cgroup slice name must match its sweep filter for prefix {prefix:?}"
            );
            assert!(
                scratch_dir_name(prefix, pid, vmid).starts_with(&vm_resource_sweep_prefix(prefix)),
                "scratch dir name must match its sweep filter for prefix {prefix:?}"
            );
            // The netns and vm stems are DISTINCT so a netns is never swept as a cgroup/scratch.
            assert_ne!(netns_sweep_prefix(prefix), vm_resource_sweep_prefix(prefix));
        }
    }

    #[test]
    fn default_prefix_reproduces_the_historical_names() {
        let p = DEFAULT_RESOURCE_PREFIX;
        assert_eq!(netns_name(p, 7), "vmcell-net-7");
        assert_eq!(tap_name(p, 7), "vmcell-tap-7");
        assert_eq!(cgroup_slice_name(p, 7), "vmcell-vm-7");
        assert_eq!(scratch_dir_name(p, 3, 7), "vmcell-vm-3-7");
        assert_eq!(netns_sweep_prefix(p), "vmcell-net-");
        assert_eq!(vm_resource_sweep_prefix(p), "vmcell-vm-");
    }

    #[test]
    fn validate_rejects_bad_prefixes_accepts_good() {
        assert!(validate_resource_prefix("vmcell").is_ok());
        assert!(validate_resource_prefix("acme").is_ok());
        assert!(validate_resource_prefix("").is_err(), "empty");
        assert!(
            validate_resource_prefix("has-dash").is_err(),
            "dash breaks -net- parsing"
        );
        assert!(
            validate_resource_prefix("has/slash").is_err(),
            "slash breaks paths/netns"
        );
        assert!(validate_resource_prefix("has space").is_err(), "whitespace");
        assert!(
            validate_resource_prefix("toolongprefix").is_err(),
            "over IFNAMSIZ budget"
        );
    }
}
