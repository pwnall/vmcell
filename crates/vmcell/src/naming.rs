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
//!
//! This module is one of the pure-logic modules design §15.2 names as `#![forbid(unsafe_code)]`, and
//! `every_module_the_design_forbids_unsafe_in_says_so_itself` (below) is what makes that roster true
//! by construction rather than by memory: it is law F2's sole home, and the module whose output the
//! orphan sweep uses to decide what to **delete**, so a byte-math accident here reclaims the wrong
//! resource on somebody else's host.
#![forbid(unsafe_code)]

/// The default resource-name prefix (`"vmcell"`) — the value hard-coded before this became an option.
pub const DEFAULT_RESOURCE_PREFIX: &str = "vmcell";

/// The longest **network-interface** name the Linux kernel accepts: `IFNAMSIZ - 1`, because
/// `ifreq.ifr_name` is an `IFNAMSIZ`-byte array that must still hold the NUL terminator.
///
/// This is the bound the **composers** honor; `net_sys::create_tap_in_current_netns` is the
/// boundary that enforces it, and it refuses an over-long name rather than truncating one. That
/// division is the lesson of the shape it replaced: `tun-tap`'s C shim did
/// `strncpy(ifr.ifr_name, name, IFNAMSIZ - 1)`, so an over-long name brought the tap up under a name
/// nobody composed and the failure surfaced one step later, at the `rtnetlink` index lookup, far
/// from the composer that overflowed. `libc::IFNAMSIZ` cannot be named here: `libc` is an optional dependency
/// (`host-common`) while this module compiles in every feature configuration, so the value is
/// restated and the `interface_names_fit_ifnamsiz` unit test pins the copy against the real ABI.
const MAX_INTERFACE_NAME_LEN: usize = 15;

/// The maximum prefix length. Bounded by the **longest** composed interface name,
/// `<prefix>-tap-<vmid>` ([`tap_name`]): at the highest vmid the addressing math admits (9999, four
/// digits) that is `prefix + 9` bytes, and it must fit `MAX_INTERFACE_NAME_LEN` — so 6 lands on
/// exactly 15, with **no** slack left. That is why the vmid ceiling stops at four decimal digits
/// (`net::MAX_VMID`'s roster, home 3): a fifth digit has to be bought from this budget or from a
/// new tap-name scheme. The segment bridge (`<prefix>-br-<segid>`, [`segment_bridge_name`]) carries
/// the narrower segment id and rides the same budget with room to spare; the netns, cgroup-slice
/// and scratch-dir names carry no such limit. `interface_names_fit_ifnamsiz` is the gate that
/// measures both interface classes at this prefix length and each class's own highest id.
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
             derived tap name inside the {MAX_INTERFACE_NAME_LEN}-char interface-name limit)"
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
/// by the caller for sibling placement, §13, Cross-cutting invariants).
///
/// Callers that want the path the orchestrator actually creates — leaf **plus** sibling placement —
/// want `vm_slice_name` (re-exported below on the `host-common` feature), not this leaf on its own.
#[must_use]
pub fn cgroup_slice_name(prefix: &str, vmid: u32) -> String {
    format!("{prefix}-vm-{vmid}")
}

/// The **full** cgroup slice name the orchestrator creates for a VM — the [`cgroup_slice_name`] leaf
/// plus §13 sibling placement — re-exported here beside the composers it belongs with so a consumer
/// reading a VM's cgroup files never hand-formats the path. See [`crate::metrics::vm_slice_name`].
#[cfg(feature = "host-common")]
pub use crate::metrics::vm_slice_name;

/// The per-VM scratch-directory name: `<prefix>-vm-<pid>-<vmid>` (both ids so two processes' VMs never
/// collide, §13, Cross-cutting invariants).
#[must_use]
pub fn scratch_dir_name(prefix: &str, pid: u32, vmid: u32) -> String {
    format!("{prefix}-vm-{pid}-{vmid}")
}

/// The **segment** network-namespace name for `segid`: `<prefix>-seg-<segid>` (§6.5, VM-to-VM
/// segments). One netns per segment, holding the bridge and every member's tap; a segment member
/// therefore has **no** per-VM netns.
#[must_use]
pub fn segment_netns_name(prefix: &str, segid: u32) -> String {
    format!("{prefix}-seg-{segid}")
}

/// The segment **bridge** interface name for `segid`: `<prefix>-br-<segid>` (§6.5, VM-to-VM
/// segments). The short `-br-` stem keeps it well inside `MAX_INTERFACE_NAME_LEN` — shorter than
/// the tap, which is the class that sets the [`MAX_RESOURCE_PREFIX_LEN`] budget. The figure is not
/// restated here: `interface_names_fit_ifnamsiz` measures this name at the longest legal prefix and
/// the highest segid, so the budget is checked rather than remembered.
#[must_use]
pub fn segment_bridge_name(prefix: &str, segid: u32) -> String {
    format!("{prefix}-br-{segid}")
}

/// The prefix the orphan sweep matches **netns** names by: `<prefix>-net-`.
///
/// Per-VM namespaces only — a segment namespace is matched by
/// [`segment_netns_sweep_prefix`] and liveness-checked against **segids**, not vmids (law F2,
/// §6.5). The two stems are asserted distinct by `prefix_matches_its_names`.
#[must_use]
pub fn netns_sweep_prefix(prefix: &str) -> String {
    format!("{prefix}-net-")
}

/// The prefix the orphan sweep matches **segment** namespaces by: `<prefix>-seg-` (§6.5).
///
/// Deliberately distinct from [`netns_sweep_prefix`]: the two classes live in different id
/// spaces (vmids vs segids), and sweeping a `-seg-` name against live *vmids* fails **open** —
/// a dead segid colliding with a live vmid would never be reclaimed. There is no bridge sweep
/// filter on purpose: the bridge lives inside the segment netns and dies with it.
#[must_use]
pub fn segment_netns_sweep_prefix(prefix: &str) -> String {
    format!("{prefix}-seg-")
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
            // v30 §6.5: the segment class joins the same lockstep — its netns name must match its
            // OWN sweep filter (never the per-VM `-net-` one, which is checked against vmids).
            let segid = 5;
            assert!(
                segment_netns_name(prefix, segid).starts_with(&segment_netns_sweep_prefix(prefix)),
                "segment netns name must match its sweep filter for prefix {prefix:?}"
            );
            // The three stems are PAIRWISE distinct so no class is ever swept against another
            // class's id space (the wrong-id-space bug §6.5 calls out: `trailing_id` parses
            // `<prefix>-seg-7` as 7 just as happily as `<prefix>-net-7`).
            assert_ne!(netns_sweep_prefix(prefix), vm_resource_sweep_prefix(prefix));
            assert_ne!(
                netns_sweep_prefix(prefix),
                segment_netns_sweep_prefix(prefix)
            );
            assert_ne!(
                vm_resource_sweep_prefix(prefix),
                segment_netns_sweep_prefix(prefix)
            );
            // A segment netns must NOT be caught by the per-VM netns filter, and vice versa.
            assert!(
                !segment_netns_name(prefix, segid).starts_with(&netns_sweep_prefix(prefix)),
                "a segment netns must not be swept against live vmids for prefix {prefix:?}"
            );
            assert!(
                !netns_name(prefix, vmid).starts_with(&segment_netns_sweep_prefix(prefix)),
                "a per-VM netns must not be swept against live segids for prefix {prefix:?}"
            );
            // (The bridge lives inside the segment netns and dies with it, so it has no sweep
            // filter. Its IFNAMSIZ budget — and the tap's, which is longer — is measured by
            // `interface_names_fit_ifnamsiz`, the one place that owns that law.)
        }
    }

    // The IFNAMSIZ budget, in ONE place, for EVERY composed interface-name class, at the worst
    // case the accepted-input validators admit: the longest legal prefix and the highest id.
    //
    // The defect this closes: the only length assertion this module had measured the *shorter*
    // segment bridge name (`<prefix>-br-<segid>`). `tap_name` — the longest interface name, and the
    // whole reason `MAX_RESOURCE_PREFIX_LEN` exists — was never measured, so a stem rename or a
    // prefix-budget bump stayed green through the entire KVM-free suite and surfaced as a
    // truncated-and-then-not-found tap at rtnetlink, on a privileged host, at boot.
    #[test]
    fn interface_names_fit_ifnamsiz() {
        // The ABI pin. `MAX_INTERFACE_NAME_LEN` is a deliberate second copy of a kernel constant
        // (the module compiles without `libc`, which is optional); a deliberate copy is GUARDED,
        // never trusted. `libc` is an unconditional dev-dependency, so this runs in every feature
        // configuration the unit tests are built in.
        assert_eq!(
            MAX_INTERFACE_NAME_LEN,
            libc::IFNAMSIZ - 1,
            "MAX_INTERFACE_NAME_LEN must be IFNAMSIZ minus the NUL terminator ifr_name must hold"
        );

        // The widest id each interface class can embed. The two classes carry DIFFERENT id
        // spaces — the tap embeds a vmid, the bridge a segment id — and since the H2 widening those
        // ceilings differ by a decimal digit, so one shared `max_id` would measure the tap at the
        // segment's narrower id and miss the class that actually sets this budget. Both live behind
        // `host-common`, hence the mirrors plus the equality asserts wherever both are compiled.
        let max_vmid: u32 = 9999;
        let max_segid: u32 = 254;
        #[cfg(feature = "host-common")]
        {
            assert_eq!(
                max_vmid,
                crate::net::MAX_VMID,
                "the vmid ceiling this budget assumes must be the addressing math's own ceiling                  (net::MAX_VMID's roster, home 3)"
            );
            assert_eq!(
                max_segid,
                crate::net::MAX_SEGMENT_ID,
                "the segment-id ceiling this budget assumes must be the addressing math's own"
            );
        }

        // The longest prefix `validate_resource_prefix` accepts — asserted accepted, so this is the
        // real worst case and not a hypothetical one.
        let longest = "z".repeat(MAX_RESOURCE_PREFIX_LEN);
        assert!(
            validate_resource_prefix(&longest).is_ok(),
            "a prefix of exactly MAX_RESOURCE_PREFIX_LEN bytes must be accepted"
        );

        // Every composed name that becomes a network interface. A new interface composer added to
        // this module belongs in this list — nothing else in the KVM-free suite measures it.
        for (class, name) in [
            ("tap", tap_name(&longest, max_vmid)),
            ("segment bridge", segment_bridge_name(&longest, max_segid)),
        ] {
            assert!(
                name.len() <= MAX_INTERFACE_NAME_LEN,
                "{class} name {name:?} is {} bytes, over {MAX_INTERFACE_NAME_LEN}; the composer \
                 must not emit a name the boundary will refuse — `net_sys::create_tap_in_current_netns` \
                 rejects it typed for the tap, and netlink's IFLA_IFNAME policy rejects it for the \
                 bridge, so the failure would land far from whatever composed it",
                name.len()
            );
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
        // v30 §6.5 — the segment class's golden names.
        assert_eq!(segment_netns_name(p, 7), "vmcell-seg-7");
        assert_eq!(segment_bridge_name(p, 7), "vmcell-br-7");
        assert_eq!(segment_netns_sweep_prefix(p), "vmcell-seg-");
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

/// **The §15.2 `#![forbid(unsafe_code)]` roster, gated against the design that states it.**
///
/// §15.2 claims the attribute is on "every I/O-free / logic module" and then *names them*. That
/// claim was false for `naming` — the module this gate lives in — for the whole of v33: nothing
/// checked it, so the structural guarantee held by memory. The roster is read out of the design at
/// run time (never `include_str!`) so a reissue is picked up by its heading the moment it lands,
/// which is the `docs/*.md` §12.3-roster idiom `vmm::jail`'s seccomp gate already uses.
///
/// Two directions, both loud:
///
/// * a named module missing the attribute is the D3 defect itself;
/// * a roster entry this gate cannot map to a file fails naming the entry, because a design that
///   grows a module must not silently grow an unchecked one. The parser refuses to guess — an
///   unparseable bullet is `gate misconfigured`, never a green empty roster.
#[cfg(test)]
mod design_forbid_unsafe_roster {
    /// The design section that owns the roster.
    const SECTION: &str = "15.2";
    /// The attribute the roster claims, exactly as it must appear at a module's top.
    const ATTRIBUTE: &str = "#![forbid(unsafe_code)]";

    /// The heading depth of `line` (`##` → 2), or `None` when it is not an ATX heading.
    fn heading_level(line: &str) -> Option<usize> {
        let hashes = line.trim_start().chars().take_while(|c| *c == '#').count();
        (hashes > 0).then_some(hashes)
    }

    /// Whether `line` is the heading for section `SECTION` (and not `15.20`).
    fn is_section_heading(line: &str) -> bool {
        if heading_level(line).is_none() {
            return false;
        }
        let rest = line.trim_start().trim_start_matches('#').trim_start();
        rest.strip_prefix(SECTION)
            .is_some_and(|tail| !tail.starts_with(|c: char| c.is_ascii_digit() || c == '.'))
    }

    /// The roster entries named in `markdown`'s §15.2 `#![forbid(unsafe_code)]` bullet, normalized.
    ///
    /// The bullet's shape is `- **<attribute> on every …module** — <roster> — <rationale>`, possibly
    /// wrapped over several lines. Parenthesised asides are dropped *before* splitting on commas:
    /// `net/`'s aside names `net_sys.rs`, the module that deliberately does **not** carry the
    /// attribute, so an aside read as a roster entry would invert the gate.
    ///
    /// Returns `Err` — never an empty roster — when the bullet's shape is not the one above.
    fn roster(markdown: &str) -> std::result::Result<Vec<String>, String> {
        let mut lines = markdown.lines();
        let level = lines
            .find_map(|l| is_section_heading(l).then(|| heading_level(l)).flatten())
            .ok_or_else(|| format!("no §{SECTION} heading"))?;

        // The bullet: from the `- ` that mentions the attribute, through its wrapped continuation
        // lines (indented, and not a new bullet), stopping at the next same-or-shallower heading.
        let mut bullet: Option<String> = None;
        for line in lines {
            if heading_level(line).is_some_and(|l| l <= level) {
                break;
            }
            match bullet.as_mut() {
                None => {
                    if line.trim_start().starts_with("- ") && line.contains(ATTRIBUTE) {
                        bullet = Some(line.trim().to_string());
                    }
                }
                Some(acc) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty()
                        || trimmed.starts_with("- ")
                        || !line.starts_with(char::is_whitespace)
                    {
                        break;
                    }
                    acc.push(' ');
                    acc.push_str(trimmed);
                }
            }
        }
        let bullet = bullet.ok_or_else(|| format!("§{SECTION} carries no `{ATTRIBUTE}` bullet"))?;

        // `**…module** — <roster> — <rationale>`: the roster is what sits between the bold lead's
        // em-dash and the next one.
        let after_lead = bullet
            .split_once("** — ")
            .ok_or_else(|| format!("the `{ATTRIBUTE}` bullet has no `** — ` roster lead"))?
            .1;
        let list = after_lead.split(" — ").next().unwrap_or("");

        // Drop parenthesised asides (see the doc-comment: `net_sys.rs` lives in one).
        let mut flat = String::new();
        let mut depth = 0usize;
        for c in list.chars() {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                _ if depth == 0 => flat.push(c),
                _ => {}
            }
        }

        let entries: Vec<String> = flat
            .split(',')
            .map(|e| e.replace(['`', '*'], "").trim().to_string())
            .filter(|e| !e.is_empty())
            .collect();
        if entries.is_empty() {
            return Err(format!(
                "the `{ATTRIBUTE}` bullet's roster parsed to zero entries"
            ));
        }
        Ok(entries)
    }

    /// The file each roster entry names, relative to `crates/`. An entry absent from this table is a
    /// failure, not a skip: the design grew a module and this gate must be taught where it lives.
    fn source_for(entry: &str) -> Option<&'static str> {
        match entry {
            "net/" => Some("vmcell/src/net/mod.rs"),
            "config" => Some("vmcell/src/config.rs"),
            "naming" => Some("vmcell/src/naming.rs"),
            "artifact's pure core" => Some("vmcell/src/artifact/mod.rs"),
            "the protocol codec" => Some("vmcell-protocol/src/lib.rs"),
            _ => None,
        }
    }

    /// Every non-historical `docs/*.md` that carries a §15.2 heading, as `(file name, text)`.
    /// `read_dir` does not descend, so `docs/historical/` is out of scope by construction.
    fn design_documents() -> Vec<(String, String)> {
        let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs");
        let entries =
            std::fs::read_dir(&docs).unwrap_or_else(|e| panic!("read_dir {}: {e}", docs.display()));
        let mut out = Vec::new();
        for entry in entries {
            let path = entry.unwrap_or_else(|e| panic!("docs entry: {e}")).path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            if text.lines().any(is_section_heading) {
                let name = path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().into_owned(),
                );
                out.push((name, text));
            }
        }
        assert!(
            !out.is_empty(),
            "gate misconfigured: no document under {} carries a §{SECTION} heading — the design was \
             renamed or moved and this gate is reading nothing (it must not pass vacuously)",
            docs.display()
        );
        out
    }

    #[test]
    fn every_module_the_design_forbids_unsafe_in_says_so_itself() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("crates/ is readable");

        let mut checked = 0usize;
        for (doc, text) in design_documents() {
            let entries = roster(&text)
                .unwrap_or_else(|e| panic!("gate misconfigured: {doc} §{SECTION}: {e}"));
            for entry in entries {
                let relative = source_for(&entry).unwrap_or_else(|| {
                    panic!(
                        "{doc} §{SECTION} names {entry:?} among the `{ATTRIBUTE}` modules and this \
                         gate does not know which file that is. Teach it the path (and give that \
                         module the attribute) — a roster entry nothing checks is the D3 defect \
                         with a different name."
                    )
                });
                let path = crates.join(relative);
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("gate misconfigured: read {}: {e}", path.display()));
                assert!(
                    body.lines().any(|l| l.trim() == ATTRIBUTE),
                    "{doc} §{SECTION} lists {entry:?} among the `{ATTRIBUTE}` modules, but {} does \
                     not carry the attribute. Add it — the design's structural claim must hold by \
                     construction, and dropping the entry instead weakens a stated gate for \
                     nothing.",
                    path.display()
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 5,
            "gate misconfigured: only {checked} roster entr(ies) were checked; §{SECTION} names at \
             least five modules, so the parser is reading a truncated bullet"
        );
    }
}
