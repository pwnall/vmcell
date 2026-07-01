//! Guest PID-1 agent support library: the zombie-reaper / exec-waiter coordination.
//!
//! Extracted into the guest-agent member crate (v15 §10.1) so this PID-1 logic —
//! and its unit tests — compile without any host async stack. The thin binary in
//! `main.rs` drives a [`ReaperCoordinator`]; the host never links this code (it
//! shares only the [`vmcell_protocol`] wire enum).
#![deny(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex};

/// Default upper bound on retained child exit statuses in a [`ReaperCoordinator`].
///
/// As PID 1, the guest agent reaps re-parented grandchildren that no exec
/// waiter will ever claim. Their statuses are pruned once this many newer
/// statuses have been recorded, so the status map cannot grow without bound.
pub const DEFAULT_MAX_REAPED_STATUSES: usize = 1024;

/// Maps a reaped child's termination into the exit code reported to the host.
///
/// A signal-terminated child reports `128 + signal` (shell convention, e.g.
/// `SIGKILL` (9) → 137), a normally-exited child reports its status, and an
/// indeterminate termination reports 1. This is the inverse of the
/// false-127 reaper bug: a process that ran to completion (or was killed)
/// must never be reported with the spawn-failure code 127.
#[must_use]
pub fn exit_code_from_termination(
    terminating_signal: Option<i32>,
    exit_status: Option<i32>,
) -> i32 {
    if let Some(signal) = terminating_signal {
        128 + signal
    } else {
        exit_status.unwrap_or(1)
    }
}

/// Coordinates the PID-1 zombie reaper with per-exec waiter threads.
///
/// The reaper thread records each reaped child's exit code keyed by pid via
/// [`ReaperCoordinator::record_exit`]; an exec waiter blocks in
/// [`ReaperCoordinator::wait_for`] until the status for its pid is recorded and
/// then claims it. A single WNOHANG reaper feeds every waiter, so no waiter can
/// steal another child's status (the false-127 race). Statuses for pids that no
/// waiter ever claims are bounded by a generation-based prune (see
/// [`DEFAULT_MAX_REAPED_STATUSES`]).
#[derive(Debug)]
pub struct ReaperCoordinator {
    inner: Mutex<ReaperInner>,
    available: Condvar,
    max_statuses: usize,
}

#[derive(Debug, Default)]
struct ReaperInner {
    /// `pid -> (exit code, generation at which it was recorded)`.
    statuses: HashMap<u32, (i32, u64)>,
    /// pids an exec waiter is currently blocked on; never pruned out from under
    /// the waiter.
    waiting: HashSet<u32>,
    /// `pid -> generation epoch captured when an exec reserved the pid`. A
    /// status reaped at or before this epoch belonged to a *previous* occupant
    /// of the (reused) pid and must never be delivered to the reserving waiter.
    reservations: HashMap<u32, u64>,
    /// Monotonic record counter used to age out unclaimed statuses and to order
    /// a reaped status relative to a pid reservation.
    generation: u64,
}

impl ReaperCoordinator {
    /// Creates a coordinator with the default status bound.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_statuses(DEFAULT_MAX_REAPED_STATUSES)
    }

    /// Creates a coordinator retaining at most `max_statuses` unclaimed exit
    /// statuses (clamped to at least 1).
    #[must_use]
    pub fn with_max_statuses(max_statuses: usize) -> Self {
        Self {
            inner: Mutex::new(ReaperInner::default()),
            available: Condvar::new(),
            max_statuses: max_statuses.max(1),
        }
    }

    /// Reserves `pid` for an exec waiter that just spawned a child with it.
    ///
    /// PID 1 reaps re-parented grandchildren no waiter will ever claim, so a
    /// status for `pid` can linger in the map until a generation prune ages it
    /// out. If the kernel later reuses `pid` for a fresh exec child, that stale
    /// status would otherwise be mis-delivered to the new waiter (a false exit
    /// code for a process that never produced it). Calling `reserve` from the
    /// exec path immediately after spawn closes that window: it drops any
    /// pre-existing status for `pid` and records the current generation as the
    /// reservation epoch, so a subsequent [`ReaperCoordinator::wait_for`] only
    /// accepts a status reaped strictly *after* this point. The matching
    /// reservation is consumed when `wait_for` returns the child's own status.
    pub fn reserve(&self, pid: u32) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Drop a status left by a previous occupant of this (now reused) pid; it
        // is not this child's and must not be claimed.
        inner.statuses.remove(&pid);
        let epoch = inner.generation;
        inner.reservations.insert(pid, epoch);
    }

    /// Records a reaped child's `code` for `pid` and wakes any waiter.
    ///
    /// Unclaimed statuses are pruned once `max_statuses` newer statuses have
    /// been recorded, so a flood of re-parented grandchildren cannot grow the
    /// map without bound. A status a waiter is currently blocked on is never
    /// pruned.
    pub fn record_exit(&self, pid: u32, code: i32) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.generation = inner.generation.wrapping_add(1);
        let generation = inner.generation;
        inner.statuses.insert(pid, (code, generation));

        if inner.statuses.len() > self.max_statuses {
            let max = self.max_statuses as u64;
            let ReaperInner {
                statuses, waiting, ..
            } = &mut *inner;
            statuses.retain(|reaped_pid, (_, recorded)| {
                waiting.contains(reaped_pid) || generation.wrapping_sub(*recorded) < max
            });
        }
        drop(inner);
        self.available.notify_all();
    }

    /// Blocks until the exit status for `pid` is recorded, then claims and
    /// returns it.
    ///
    /// If `pid` was [`ReaperCoordinator::reserve`]d, only a status reaped
    /// strictly after the reservation epoch is accepted: a stale status from a
    /// previous occupant of the reused pid is discarded and the wait continues,
    /// so the false-127-class mis-delivery under pid reuse cannot occur. Without
    /// a reservation the first recorded status for `pid` is returned (the
    /// legacy single-occupant behavior).
    pub fn wait_for(&self, pid: u32) -> i32 {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.waiting.insert(pid);
        let reserved_at = inner.reservations.get(&pid).copied();
        loop {
            if let Some(&(code, recorded)) = inner.statuses.get(&pid) {
                // A status counts for this waiter unless the pid was reserved and
                // the status was reaped at or before the reservation epoch (i.e.
                // it belongs to a prior occupant of the reused pid). Serial-number
                // (RFC 1982 style) comparison keeps this correct even if the
                // generation counter ever wraps.
                let accept = match reserved_at {
                    None => true,
                    Some(epoch) => {
                        let age = recorded.wrapping_sub(epoch);
                        age != 0 && age < u64::MAX / 2
                    }
                };
                inner.statuses.remove(&pid);
                if accept {
                    inner.waiting.remove(&pid);
                    inner.reservations.remove(&pid);
                    return code;
                }
                // Stale pre-reservation status discarded; keep waiting for this
                // child's own exit rather than spinning on it.
            }
            inner = self
                .available
                .wait(inner)
                .unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Number of recorded-but-unclaimed exit statuses (for diagnostics/tests).
    #[must_use]
    pub fn pending_statuses(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .statuses
            .len()
    }
}

impl Default for ReaperCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod reaper_tests {
    //! Default-suite (KVM-free) tests for the false-127 reaper coordination.
    //! Each guards a specific documented inverse so the contract cannot silently
    //! regress; see §4.3 / AGENTS.md "PID-1 reaper vs. waiter".
    use super::{ReaperCoordinator, exit_code_from_termination};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn signal_termination_maps_to_128_plus_signal_not_127() {
        // SIGKILL (9) → 137 by shell convention; SIGTERM (15) → 143. The
        // false-127 bug reported a killed/completed process as the
        // spawn-failure code 127. Inverse `128 + signal` → `127` goes red here.
        assert_eq!(exit_code_from_termination(Some(9), None), 137);
        assert_eq!(exit_code_from_termination(Some(15), None), 143);
        assert_ne!(
            exit_code_from_termination(Some(9), None),
            127,
            "a signal-killed child must never be reported as the spawn-failure 127"
        );
    }

    #[test]
    fn normal_exit_passes_through_status() {
        assert_eq!(exit_code_from_termination(None, Some(0)), 0);
        assert_eq!(exit_code_from_termination(None, Some(42)), 42);
    }

    #[test]
    fn indeterminate_termination_is_one_not_127() {
        // Neither signal nor exit status known: report 1, never 127. Inverse
        // `unwrap_or(1)` → `unwrap_or(127)` goes red here.
        assert_eq!(exit_code_from_termination(None, None), 1);
        assert_ne!(exit_code_from_termination(None, None), 127);
    }

    #[test]
    fn out_of_order_claims_return_each_pids_own_status() {
        let coord = ReaperCoordinator::new();
        coord.record_exit(100, 10);
        coord.record_exit(200, 20);
        coord.record_exit(300, 30);
        // Claim in a different order than recorded; each call gets ITS pid's
        // code, never another's. Inverse (return any recorded status) goes red.
        assert_eq!(coord.wait_for(200), 20);
        assert_eq!(coord.wait_for(100), 10);
        assert_eq!(coord.wait_for(300), 30);
        assert_eq!(coord.pending_statuses(), 0);
    }

    #[test]
    fn blocked_waiter_does_not_steal_another_pids_status() {
        let coord = Arc::new(ReaperCoordinator::new());
        let waiter = {
            let coord = Arc::clone(&coord);
            std::thread::spawn(move || coord.wait_for(42))
        };
        // Let the waiter register and park on pid 42.
        std::thread::sleep(Duration::from_millis(50));

        // Record an UNRELATED pid. A correct waiter must not wake-and-claim it
        // (the false-127 steal). Inverse (wait_for returns the first available
        // status) makes the waiter finish early with 99.
        coord.record_exit(7, 99);
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "waiter for pid 42 must not steal pid 7's status"
        );

        // Record the real pid; the waiter claims exactly its own code.
        coord.record_exit(42, 5);
        assert_eq!(waiter.join().unwrap(), 5);
        // pid 7's status was never consumed by the wrong waiter.
        assert_eq!(coord.pending_statuses(), 1);
    }

    #[test]
    fn unclaimed_statuses_are_bounded_by_prune() {
        let coord = ReaperCoordinator::with_max_statuses(4);
        for pid in 0..100u32 {
            coord.record_exit(pid, pid as i32);
        }
        // Inverse (prune removed) leaves all 100 statuses; this asserts the bound.
        assert!(
            coord.pending_statuses() <= 4,
            "unclaimed reaped statuses must be bounded; got {}",
            coord.pending_statuses()
        );
    }

    #[test]
    fn reserved_pid_discards_stale_grandchild_status_under_reuse() {
        // PID-reuse mis-delivery guard (§4.3 reaper-vs-waiter). A re-parented
        // grandchild exits and is reaped under pid X but never claimed, leaving a
        // lingering status. The kernel later reuses pid X for an exec child. The
        // exec path reserves pid X immediately after spawn; the new waiter must
        // claim only ITS OWN exit, never the stale grandchild status.
        //
        // Inverse / buggy "no-generation" version (wait_for returns the first
        // recorded status for the pid, no reservation): the waiter wakes and
        // returns STALE_CODE immediately, so `waiter.is_finished()` is true after
        // the reservation and the assertion below goes red.
        const PID: u32 = 4321;
        const STALE_CODE: i32 = 111; // a grandchild's exit, must never be delivered
        const REAL_CODE: i32 = 7; // the exec child's own exit

        let coord = Arc::new(ReaperCoordinator::new());
        // Lingering unclaimed status from the previous occupant of pid X.
        coord.record_exit(PID, STALE_CODE);
        assert_eq!(coord.pending_statuses(), 1);

        // Exec spawns a child that reuses pid X and reserves it after spawn.
        coord.reserve(PID);

        let waiter = {
            let coord = Arc::clone(&coord);
            std::thread::spawn(move || coord.wait_for(PID))
        };
        // Give the waiter time to register and (in the buggy version) wrongly
        // claim the stale status.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "reserved waiter must not deliver the pre-reservation grandchild status"
        );

        // The exec child's own exit is reaped after the reservation; only this
        // status may be returned.
        coord.record_exit(PID, REAL_CODE);
        let got = waiter.join().unwrap();
        assert_eq!(
            got, REAL_CODE,
            "reserved waiter must claim its own post-reservation exit"
        );
        assert_ne!(
            got, STALE_CODE,
            "a reused pid must never deliver the prior occupant's status"
        );
        assert_eq!(coord.pending_statuses(), 0);
    }

    #[test]
    fn reservation_only_constrains_its_own_pid() {
        // A reservation for one pid must not change delivery for an unreserved
        // pid (the legacy single-occupant path stays intact).
        let coord = ReaperCoordinator::new();
        coord.reserve(1);
        coord.record_exit(2, 55); // unreserved pid: first status delivered as before
        assert_eq!(coord.wait_for(2), 55);
        // The reserved pid still works once its own post-reservation status lands.
        coord.record_exit(1, 9);
        assert_eq!(coord.wait_for(1), 9);
    }

    #[test]
    fn blocked_waiter_survives_unrelated_reap_flood() {
        let coord = Arc::new(ReaperCoordinator::with_max_statuses(2));
        let waiter = {
            let coord = Arc::clone(&coord);
            std::thread::spawn(move || coord.wait_for(999))
        };
        std::thread::sleep(Duration::from_millis(50));

        // Drive many prunes with unrelated reaps while the waiter is parked, then
        // record its own status; it must still be delivered (not lost to prune).
        for pid in 0..50u32 {
            coord.record_exit(pid, 1);
        }
        coord.record_exit(999, 7);
        assert_eq!(waiter.join().unwrap(), 7);
    }
}
