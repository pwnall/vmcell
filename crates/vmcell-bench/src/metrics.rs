//! The metric-name roster: every quantity `bench-vm` can emit, and which way is *better* for it.
//!
//! WHY THIS EXISTS. The A/B comparator's first direction rule was one line —
//! `metric != "footprint_ksm_pages_sharing_delta"` — i.e. "everything is a cost except the one
//! exception I remembered". Two whole classes were wrong under it:
//!
//! * **Benefits read as costs.** `footprint_guest_mem_available` is guest memory the run got to
//!   keep; more of it is better. Under a lower-is-better default a leaner guest printed
//!   `REGRESSION`, which is the comparator praising the wrong side — the one failure a verdict
//!   word must never have.
//! * **Compositional percentages have no direction at all.** `phase_cold_connect_share` is
//!   connect's share of the cold path's total, and the four shares sum to 100%. Halve teardown and
//!   every other share *rises* — a table with a direction rule would call three phases regressions
//!   for a change that made the whole path faster. There is no verdict to give, and
//!   [`Direction::Neutral`] is how that is said out loud instead of guessed.
//!
//! So the direction is an explicit, exhaustive roster keyed by metric name, and the names
//! themselves live here as the constants `bench-vm` emits through — one fact, not two that agree
//! today. [`crate::metrics`] is therefore the only place a metric name is spelled, and
//! [`direction`] answers `None` for anything it does not know rather than defaulting to a
//! direction it guessed.
//!
//! WHY `None` IS NOT A HARD ERROR AT THE COMPARATOR. An A/B compares two *git refs*, so a metric
//! the other ref emits and this one has never heard of is an ordinary consequence of the tool
//! working — refusing the whole comparison would make `bench-ab` useless for exactly the
//! cross-version case it exists for. The comparator therefore treats an unknown metric as
//! `Neutral` **and says so loudly**. What keeps *this* tree honest is the other side: `bench-vm`
//! refuses to emit a report containing a name this roster does not carry, so a metric added here
//! without a direction cannot reach a table at all.
//!
//! Pure data and pure string composition: no clock, no filesystem, no VM.

use serde::{Deserialize, Serialize};

/// Which way is better for a metric.
///
/// Three-way and not a `bool`, because "neither" is a real answer for a compositional percentage
/// and a `bool` forces it to be a lie in one direction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// A cost: a latency, a resident-set size, a snapshot's bytes. Smaller is the win.
    LowerIsBetter,
    /// A benefit: memory handed back to the guest, pages deduplicated away. Larger is the win.
    HigherIsBetter,
    /// **No verdict is possible.** A share of a whole moves when any *other* part of the whole
    /// moves, so its direction says nothing about the change. A row carrying this prints its
    /// delta and no verdict word.
    Neutral,
}

// ----------------------------------------------------------------------------
// The names, as the constants `bench-vm` emits through.
// ----------------------------------------------------------------------------

/// Cold boot to steward-connected, per iteration.
pub const COLD_BOOT: &str = "cold_boot";
/// Snapshot restore to steward-connected, per iteration.
pub const WARM_RESTORE: &str = "warm_restore";
/// Boot with the smoltcp NAT attached (`net-egress`).
pub const NET_START: &str = "net_start";
/// Boot with the privileged tap/nft egress path and the MITM proxy.
pub const NET_START_PRIVILEGED: &str = "net_start_privileged";
/// Boot with the unprivileged smoltcp egress path and the MITM proxy.
pub const NET_START_TLS: &str = "net_start_tls";
/// In-guest vsock round-trip.
pub const VSOCK_RTT: &str = "vsock_rtt";
/// In-guest egress round-trip over the plain NAT.
pub const NET_EGRESS_RTT: &str = "net_egress_rtt";
/// In-guest HTTPS-through-MITM round-trip on the privileged egress path.
pub const NET_EGRESS_PRIVILEGED_RTT: &str = "net_egress_privileged_rtt";
/// In-guest HTTPS-through-MITM round-trip on the unprivileged egress path.
pub const NET_EGRESS_TLS_RTT: &str = "net_egress_tls_rtt";
/// Wall time to fan a zygote master out into its clones.
pub const ZYGOTE_FANOUT: &str = "zygote_fanout";
/// Wall time from a clone's start to its steward answering.
pub const ZYGOTE_STEWARD_READY: &str = "zygote_steward_ready";
/// The second vsock handshake that opens a session mux.
pub const SESSION_CONNECT: &str = "session_connect";
/// Open → spawn → exit for one session stream.
pub const SESSION_OPEN: &str = "session_open";
/// Host RssAnon across every resident guest's VMM.
pub const FOOTPRINT_RSS_ANON_TOTAL: &str = "footprint_rss_anon_total";
/// Host RssAnon per resident guest (the total's integer mean).
pub const FOOTPRINT_RSS_ANON_PER_GUEST: &str = "footprint_rss_anon_per_guest";
/// Host RssFile across every resident guest's VMM (shared erofs page cache).
pub const FOOTPRINT_RSS_FILE_TOTAL: &str = "footprint_rss_file_total";
/// Host RssFile per resident guest.
pub const FOOTPRINT_RSS_FILE_PER_GUEST: &str = "footprint_rss_file_per_guest";
/// Host RssShmem across every resident guest's VMM (guest RAM touched).
pub const FOOTPRINT_RSS_SHMEM_TOTAL: &str = "footprint_rss_shmem_total";
/// Host RssShmem per resident guest.
pub const FOOTPRINT_RSS_SHMEM_PER_GUEST: &str = "footprint_rss_shmem_per_guest";
/// Marginal host RssAnon added by one more guest (VMM overhead only).
pub const FOOTPRINT_MARGINAL_RSS_ANON: &str = "footprint_marginal_rss_anon";
/// Marginal host RssShmem added by one more guest.
pub const FOOTPRINT_MARGINAL_RSS_SHMEM: &str = "footprint_marginal_rss_shmem";
/// KSM `pages_sharing` gained over the run — pages deduplicated away.
pub const FOOTPRINT_KSM_PAGES_SHARING_DELTA: &str = "footprint_ksm_pages_sharing_delta";
/// Guest `MemTotal`.
pub const FOOTPRINT_GUEST_MEM_TOTAL: &str = "footprint_guest_mem_total";
/// Guest `MemAvailable`, mean across the resident guests.
pub const FOOTPRINT_GUEST_MEM_AVAILABLE: &str = "footprint_guest_mem_available";
/// Guest PID 1 (the steward) RSS, mean across the resident guests.
pub const FOOTPRINT_GUEST_PID1_RSS: &str = "footprint_guest_pid1_rss";
/// Total bytes one snapshot occupies on disk.
pub const SUSPEND_TOTAL_BYTES: &str = "suspend_total_bytes";
/// Bytes of that snapshot held by the guest-memory file.
pub const SUSPEND_MEMORY_FILE_BYTES: &str = "suspend_memory_file_bytes";
/// The memory file's share of the snapshot total.
pub const SUSPEND_MEMORY_FILE_SHARE: &str = "suspend_memory_file_share";

/// The suffix [`share_metric`] appends.
const SHARE_SUFFIX: &str = "_share";

/// The two paths the phase budget measures, as they appear in a phase metric's name.
///
/// COLD and RESTORE print the same four row names, so an unqualified phase metric silently pools
/// them — the defect `crate::report`'s module docs record. These two tokens are what qualifies
/// them, and the roster below is their cross product with [`PHASE_STEPS`].
pub const PHASE_PATHS: [&str; 2] = ["cold", "restore"];

/// The four phases of one measured path.
pub const PHASE_STEPS: [&str; 4] = ["create", "connect", "exec", "teardown"];

/// The daemon-API operations `daemon-api` mode times.
pub const DAEMON_OPS: [&str; 5] = ["create", "restore", "exec", "list", "destroy"];

/// The metric name for one phase of one path, e.g. `phase_cold_connect`.
///
/// The ONE composer, shared by the roster's own test and by `bench-vm`'s emission site, so a
/// rename cannot leave the table keyed on a name nothing emits.
#[must_use]
pub fn phase_metric(path: &str, step: &str) -> String {
    format!("phase_{path}_{step}")
}

/// The metric name for a path's summed phase means, e.g. `phase_restore_total`.
#[must_use]
pub fn phase_total_metric(path: &str) -> String {
    format!("phase_{path}_total")
}

/// The share-of-total companion of `base`, e.g. `phase_cold_connect_share`.
#[must_use]
pub fn share_metric(base: &str) -> String {
    format!("{base}{SHARE_SUFFIX}")
}

/// The metric name for one daemon-API operation, e.g. `daemon_restore`.
#[must_use]
pub fn daemon_metric(op: &str) -> String {
    format!("daemon_{op}")
}

/// **The roster.** Every metric name `bench-vm` can emit, with the direction that makes its
/// verdict word a claim rather than a guess.
///
/// The fixed names are the constants above — the entry and the emitted string are one fact, not
/// two that happen to agree. The composed names (the phase cross product, the shares, the daemon
/// ops) are spelled out because a `const` array cannot call [`phase_metric`]; the test
/// `the_composers_and_the_roster_agree_in_both_directions` is what keeps the two from drifting,
/// and it fails in **both** directions — a composed name missing from the roster, and a roster
/// entry no composer can produce.
pub const METRIC_DIRECTIONS: &[(&str, Direction)] = &[
    // --- Latencies. Every one of these is a cost.
    (COLD_BOOT, Direction::LowerIsBetter),
    (WARM_RESTORE, Direction::LowerIsBetter),
    (NET_START, Direction::LowerIsBetter),
    (NET_START_PRIVILEGED, Direction::LowerIsBetter),
    (NET_START_TLS, Direction::LowerIsBetter),
    (VSOCK_RTT, Direction::LowerIsBetter),
    (NET_EGRESS_RTT, Direction::LowerIsBetter),
    (NET_EGRESS_PRIVILEGED_RTT, Direction::LowerIsBetter),
    (NET_EGRESS_TLS_RTT, Direction::LowerIsBetter),
    (ZYGOTE_FANOUT, Direction::LowerIsBetter),
    (ZYGOTE_STEWARD_READY, Direction::LowerIsBetter),
    (SESSION_CONNECT, Direction::LowerIsBetter),
    (SESSION_OPEN, Direction::LowerIsBetter),
    // --- Daemon-API operations: `daemon_metric` over `DAEMON_OPS`. Latencies, so costs.
    ("daemon_create", Direction::LowerIsBetter),
    ("daemon_restore", Direction::LowerIsBetter),
    ("daemon_exec", Direction::LowerIsBetter),
    ("daemon_list", Direction::LowerIsBetter),
    ("daemon_destroy", Direction::LowerIsBetter),
    // --- Phase distributions: `phase_metric` over PHASE_PATHS x PHASE_STEPS. Costs.
    ("phase_cold_create", Direction::LowerIsBetter),
    ("phase_cold_connect", Direction::LowerIsBetter),
    ("phase_cold_exec", Direction::LowerIsBetter),
    ("phase_cold_teardown", Direction::LowerIsBetter),
    ("phase_restore_create", Direction::LowerIsBetter),
    ("phase_restore_connect", Direction::LowerIsBetter),
    ("phase_restore_exec", Direction::LowerIsBetter),
    ("phase_restore_teardown", Direction::LowerIsBetter),
    // --- Phase totals: `phase_total_metric` over PHASE_PATHS. Costs.
    ("phase_cold_total", Direction::LowerIsBetter),
    ("phase_restore_total", Direction::LowerIsBetter),
    // --- Phase SHARES: `share_metric` over the eight names above. NO DIRECTION — these are parts
    // --- of one whole and sum to 100%, so making teardown twice as fast RAISES every other share.
    // --- A direction rule here calls three phases regressions for a change that improved the path.
    ("phase_cold_create_share", Direction::Neutral),
    ("phase_cold_connect_share", Direction::Neutral),
    ("phase_cold_exec_share", Direction::Neutral),
    ("phase_cold_teardown_share", Direction::Neutral),
    ("phase_restore_create_share", Direction::Neutral),
    ("phase_restore_connect_share", Direction::Neutral),
    ("phase_restore_exec_share", Direction::Neutral),
    ("phase_restore_teardown_share", Direction::Neutral),
    // --- Host memory footprint. Resident bytes are a cost…
    (FOOTPRINT_RSS_ANON_TOTAL, Direction::LowerIsBetter),
    (FOOTPRINT_RSS_ANON_PER_GUEST, Direction::LowerIsBetter),
    (FOOTPRINT_RSS_FILE_TOTAL, Direction::LowerIsBetter),
    (FOOTPRINT_RSS_FILE_PER_GUEST, Direction::LowerIsBetter),
    (FOOTPRINT_RSS_SHMEM_TOTAL, Direction::LowerIsBetter),
    (FOOTPRINT_RSS_SHMEM_PER_GUEST, Direction::LowerIsBetter),
    (FOOTPRINT_MARGINAL_RSS_ANON, Direction::LowerIsBetter),
    (FOOTPRINT_MARGINAL_RSS_SHMEM, Direction::LowerIsBetter),
    (FOOTPRINT_GUEST_PID1_RSS, Direction::LowerIsBetter),
    // …and these three are BENEFITS, which is the half a lower-is-better default gets backwards:
    // KSM's delta counts pages deduplicated away, and the two guest figures are memory the guest
    // got to keep out of the same `--mem-mib`. More is the win in all three.
    (FOOTPRINT_KSM_PAGES_SHARING_DELTA, Direction::HigherIsBetter),
    (FOOTPRINT_GUEST_MEM_TOTAL, Direction::HigherIsBetter),
    (FOOTPRINT_GUEST_MEM_AVAILABLE, Direction::HigherIsBetter),
    // --- Snapshot size: bytes are a cost, and the share is compositional like the phase shares.
    (SUSPEND_TOTAL_BYTES, Direction::LowerIsBetter),
    (SUSPEND_MEMORY_FILE_BYTES, Direction::LowerIsBetter),
    (SUSPEND_MEMORY_FILE_SHARE, Direction::Neutral),
];

/// The direction recorded for `metric`, or `None` when this build's roster does not carry it.
///
/// `None` is a real answer and never a default: see the module docs for why the comparator turns
/// it into a loud `Neutral` while `bench-vm` turns it into a refusal.
#[must_use]
pub fn direction(metric: &str) -> Option<Direction> {
    METRIC_DIRECTIONS
        .iter()
        .find(|(name, _)| *name == metric)
        .map(|(_, dir)| *dir)
}

/// Every metric name this build knows, in roster order.
pub fn names() -> impl Iterator<Item = &'static str> {
    METRIC_DIRECTIONS.iter().map(|(name, _)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // Every composed name the emitting side can build must be in the roster, AND every composed
    // entry in the roster must be one a composer can build. Both directions, because each catches
    // a different drift: a new phase step whose share silently defaults to a direction, and a
    // roster entry left behind by a rename that nothing emits any more. RED on the inverse (drop
    // one entry, or add a step to PHASE_STEPS without extending the roster): the set difference
    // names the offender.
    #[test]
    fn the_composers_and_the_roster_agree_in_both_directions() {
        let mut composed: BTreeSet<String> = BTreeSet::new();
        for path in PHASE_PATHS {
            composed.insert(phase_total_metric(path));
            for step in PHASE_STEPS {
                let name = phase_metric(path, step);
                composed.insert(share_metric(&name));
                composed.insert(name);
            }
        }
        for op in DAEMON_OPS {
            composed.insert(daemon_metric(op));
        }
        assert_eq!(
            composed.len(),
            2 + 8 + 8 + 5,
            "the composed domains changed shape: {composed:?}"
        );

        let roster: BTreeSet<&str> = names().collect();
        for name in &composed {
            assert!(
                roster.contains(name.as_str()),
                "`{name}` is a name the composers can build, but the roster has no direction for \
                 it — a metric with no entry reaches the comparator as a guess"
            );
        }
        // …and the other way: a roster entry that LOOKS composed but no composer produces is a
        // rename that only half landed.
        for name in roster {
            let looks_composed = name.starts_with("phase_")
                || name.starts_with("daemon_")
                || name.ends_with(SHARE_SUFFIX);
            if looks_composed && name != SUSPEND_MEMORY_FILE_SHARE {
                assert!(
                    composed.contains(name),
                    "roster entry `{name}` is shaped like a composed name but no composer builds \
                     it — either the composer's domain lost a token or the entry is dead"
                );
            }
        }
    }

    // A roster with a duplicate key is a roster where the second entry is unreachable, and
    // `direction` would answer with whichever one sorts first in the source. RED on the inverse
    // (paste an entry twice): the length assert fails.
    #[test]
    fn the_roster_has_no_duplicate_names() {
        let unique: BTreeSet<&str> = names().collect();
        assert_eq!(
            unique.len(),
            METRIC_DIRECTIONS.len(),
            "duplicate metric names in the roster"
        );
    }

    // The whole point of the three-way roster: an unknown name is `None`, never a direction the
    // lookup invented. RED on the inverse (a `_ => LowerIsBetter` fallback): the `is_none` fails.
    #[test]
    fn an_unknown_metric_has_no_direction_at_all() {
        assert!(direction("a_metric_no_ref_ever_emitted").is_none());
        assert!(direction("").is_none());
        // A prefix of a real name is not that name: a substring matcher would answer for it.
        assert!(direction("cold").is_none());
        assert!(direction("phase_cold_connect_sha").is_none());
        for name in names() {
            assert!(direction(name).is_some(), "{name} must resolve");
        }
    }

    // The two classes the one-line predicate got wrong, pinned by name so a future "simplification"
    // back to `metric != ksm` goes red here rather than in a table nobody re-reads.
    #[test]
    fn benefits_and_compositional_shares_are_not_costs() {
        assert_eq!(
            direction(FOOTPRINT_GUEST_MEM_AVAILABLE),
            Some(Direction::HigherIsBetter),
            "guest memory the run kept is a benefit; lower-is-better prints IMPROVEMENT for a \
             guest that lost memory"
        );
        assert_eq!(
            direction(FOOTPRINT_KSM_PAGES_SHARING_DELTA),
            Some(Direction::HigherIsBetter)
        );
        assert_eq!(
            direction(&share_metric(&phase_metric("cold", "connect"))),
            Some(Direction::Neutral),
            "a share of a whole moves when any OTHER part moves; there is no verdict to give"
        );
        assert_eq!(
            direction(SUSPEND_MEMORY_FILE_SHARE),
            Some(Direction::Neutral)
        );
        assert_eq!(direction(COLD_BOOT), Some(Direction::LowerIsBetter));
        // Every share in the roster is Neutral — the class, not just the two spot checks above.
        for name in names() {
            if name.ends_with(SHARE_SUFFIX) {
                assert_eq!(
                    direction(name),
                    Some(Direction::Neutral),
                    "{name} is a share and must carry no direction"
                );
            }
        }
    }
}
