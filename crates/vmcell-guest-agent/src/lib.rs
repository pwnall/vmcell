//! Guest PID-1 agent support library: the zombie-reaper / exec-waiter coordination.
//!
//! Extracted into the guest-agent member crate (v15 §10.1) so this PID-1 logic —
//! and its unit tests — compile without any host async stack. The thin binary in
//! `main.rs` drives a [`ReaperCoordinator`]; the host never links this code (it
//! shares only the [`vmcell_protocol`] wire enum).
//!
//! No crate-level `forbid(unsafe_code)`: `netif` issues raw `ioctl`/socket syscalls for the
//! post-restore MAC/loopback bring-up, so the unsafe surface is audited via
//! `undocumented_unsafe_blocks` + `unsafe_op_in_unsafe_fn` instead.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro
    )
)]

/// Minimal interface-configuration helpers (native MAC rotation) for the
/// post-restore resync — libc-only, so the lean-agent graph stays host-stack-free.
pub mod netif;

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

impl ReaperInner {
    /// Bumps the generation, records `code` for `pid`, and prunes unclaimed
    /// statuses beyond `max_statuses`. The caller must hold the coordinator
    /// lock; callers wake waiters after releasing it.
    fn record(&mut self, pid: u32, code: i32, max_statuses: usize) {
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.statuses.insert(pid, (code, generation));

        if self.statuses.len() > max_statuses {
            let max = max_statuses as u64;
            let ReaperInner {
                statuses, waiting, ..
            } = self;
            statuses.retain(|reaped_pid, (_, recorded)| {
                waiting.contains(reaped_pid) || generation.wrapping_sub(*recorded) < max
            });
        }
    }
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

    /// Returns the current record generation, to be captured by the exec path
    /// **before** spawning a child and passed to [`ReaperCoordinator::reserve`]
    /// as the reservation epoch.
    ///
    /// The epoch must pre-date the fork so `reserve` can classify a status it
    /// finds already recorded for the child's pid: a status recorded **at or
    /// before** the epoch belongs to a previous occupant of the (reused) pid —
    /// that occupant's zombie was necessarily reaped (and, via the atomic
    /// [`ReaperCoordinator::drain_reaped`], recorded) before the kernel could
    /// hand the pid to the new child — while a status recorded **after** the
    /// epoch is the new child's own exit, drained by PID 1 before the exec
    /// thread reached `reserve` (the fast-exit race, AGENT-2).
    #[must_use]
    pub fn pre_spawn_epoch(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .generation
    }

    /// Reserves `pid` for an exec waiter that just spawned a child with it,
    /// using the [`ReaperCoordinator::pre_spawn_epoch`] captured **before** the
    /// spawn.
    ///
    /// PID 1 reaps re-parented grandchildren no waiter will ever claim, so a
    /// status for `pid` can linger in the map until a generation prune ages it
    /// out. If the kernel later reuses `pid` for a fresh exec child, that stale
    /// status would otherwise be mis-delivered to the new waiter (a false exit
    /// code for a process that never produced it). `reserve` drops such a
    /// pre-epoch status and records the epoch, so a subsequent
    /// [`ReaperCoordinator::wait_for`] only accepts a status reaped strictly
    /// after it. The matching reservation is consumed when `wait_for` returns
    /// the child's own status.
    ///
    /// The epoch **must** be captured before the spawn, not here (AGENT-2): an
    /// instant child can exit and be drained by the PID-1 reaper in the window
    /// between `spawn` and `reserve` (on one vcpu the child often runs to
    /// completion before the exec thread is rescheduled). Its own status is then
    /// already in the map — recorded *after* the pre-spawn epoch — and must
    /// survive the reservation; the pre-fix unconditional wipe stranded the
    /// waiter forever and surfaced on the host as a sporadic 10 s
    /// "Agent exec timed out" on an instant command. Residual window, honestly:
    /// a grandchild status recorded *between* the epoch capture and the fork
    /// whose pid the kernel immediately hands to the new child would still be
    /// misattributed — that needs the whole pid space to recycle within the
    /// microseconds-wide spawn window, which is unreachable in practice.
    ///
    /// A symmetric residual window exists on the *other* side (L-GUEST-5): if
    /// exec A's child (pid X) exits and is drained but A's waiter has not yet
    /// claimed its status, and exec B's [`pre_spawn_epoch`] happens to be captured
    /// after A's status generation, then `reserve(X, B's_epoch)` classifies A's
    /// still-unclaimed status as a pre-epoch previous occupant's and removes it.
    /// This requires a full pid wrap inside A's claim window with concurrent
    /// execs, making it as unreachable as the grandchild window above.
    ///
    /// [`pre_spawn_epoch`]: ReaperCoordinator::pre_spawn_epoch
    pub fn reserve(&self, pid: u32, pre_spawn_epoch: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Drop only a status recorded at or before the pre-spawn epoch (a
        // previous occupant's); one recorded after it is this child's own exit
        // and must be left for the waiter. Serial-number comparison mirrors
        // `wait_for` so the two stay consistent under generation wrap.
        if let Some(&(_, recorded)) = inner.statuses.get(&pid) {
            let age = recorded.wrapping_sub(pre_spawn_epoch);
            let recorded_after_epoch = age != 0 && age < u64::MAX / 2;
            if !recorded_after_epoch {
                inner.statuses.remove(&pid);
            }
        }
        inner.reservations.insert(pid, pre_spawn_epoch);
    }

    /// Records a reaped child's `code` for `pid` and wakes any waiter.
    ///
    /// Unclaimed statuses are pruned once `max_statuses` newer statuses have
    /// been recorded, so a flood of re-parented grandchildren cannot grow the
    /// map without bound. A status a waiter is currently blocked on is never
    /// pruned.
    ///
    /// This records a status the caller reaped *outside* the coordinator lock.
    /// The PID-1 reaper must instead use [`ReaperCoordinator::drain_reaped`],
    /// which performs the reap and the record under one lock so a reused pid
    /// cannot be reserved between them (the residual PID-reuse race, §4.3).
    pub fn record_exit(&self, pid: u32, code: i32) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.record(pid, code, self.max_statuses);
        drop(inner);
        self.available.notify_all();
    }

    /// Reaps and records exit statuses **atomically** with respect to
    /// [`ReaperCoordinator::reserve`].
    ///
    /// `reap` is invoked repeatedly *while the coordinator lock is held* and
    /// must perform a single non-blocking `waitpid(WNOHANG)`-style reap,
    /// returning `Some((pid, code))` for each reaped child or `None` once none
    /// remain. Because the reap and its record happen under the *same* lock, an
    /// exec thread cannot `reserve` a pid in the window *between* a `waitpid`
    /// that freed it and the record of its status: a fork can only reuse a pid
    /// after the `waitpid` that reaped its zombie, and that `waitpid` runs
    /// inside this critical section together with the record, so the stale
    /// grandchild status is always recorded *before* the reservation that then
    /// clears it. Recording the reaped status outside the lock (via a bare
    /// [`ReaperCoordinator::record_exit`]) reopens that race: the stale status
    /// lands *after* the reservation epoch and is mis-delivered as the reused
    /// child's exit.
    ///
    /// `reap` must not call back into this coordinator (it would deadlock).
    pub fn drain_reaped<F>(&self, mut reap: F)
    where
        F: FnMut() -> Option<(u32, i32)>,
    {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut recorded_any = false;
        while let Some((pid, code)) = reap() {
            inner.record(pid, code, self.max_statuses);
            recorded_any = true;
        }
        drop(inner);
        if recorded_any {
            self.available.notify_all();
        }
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

        // Exec spawns a child that reuses pid X and reserves it after spawn. The
        // epoch is captured just before that spawn — i.e. after the previous
        // occupant's status was recorded (the pid can only be reused once its
        // zombie was reaped, and the atomic drain records under the same lock).
        let epoch = coord.pre_spawn_epoch();
        coord.reserve(PID, epoch);

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
    fn reap_and_record_are_atomic_wrt_reservation_under_pid_reuse() {
        // AGENT-1: residual PID-reuse race. A zombie holds a pid until reaped, so
        // a fork can only reuse pid X *after* the `waitpid` that reaped its
        // grandchild. In the buggy NON-atomic reaper the grandchild's status is
        // recorded *after* that `waitpid` releases the lock; in that window a fork
        // reuses X, the exec path `reserve()`s it, and the child's own exit is
        // recorded — then the late stale record lands *past* the reservation epoch
        // and is mis-delivered. `drain_reaped` closes this by recording the reaped
        // status inside the SAME critical section the reap runs in.
        //
        // Here the reap closure runs under the coordinator lock; it releases the
        // "reusing" thread and gives it time to try to `reserve` while it (the
        // reap) still holds the lock, then yields the stale status. Under the
        // atomic impl the reserve blocks on the held lock until STALE is recorded,
        // so the reservation clears STALE and the reused child claims its own
        // REAL exit. Under the non-atomic inverse (record outside the lock) the
        // reserve+REAL land first and STALE overwrites them past the epoch, so the
        // waiter wrongly returns STALE and the assertion below reddens.
        const PID: u32 = 9001;
        const STALE_CODE: i32 = 111; // grandchild exit; must never reach the waiter
        const REAL_CODE: i32 = 3; // the reused exec child's own exit

        let coord = Arc::new(ReaperCoordinator::new());
        let (reaped_tx, reaped_rx) = std::sync::mpsc::channel::<()>();

        // Models the exec path that reuses freed pid X: once the reaper signals it
        // has reaped (freed) X, reserve X and record the reused child's own exit.
        let reusing = {
            let coord = Arc::clone(&coord);
            std::thread::spawn(move || {
                reaped_rx.recv().unwrap();
                // The pre-spawn epoch capture takes the coordinator lock, so
                // under the atomic drain it blocks until STALE is recorded —
                // the epoch then post-dates STALE and the reservation clears it.
                let epoch = coord.pre_spawn_epoch();
                coord.reserve(PID, epoch);
                coord.record_exit(PID, REAL_CODE);
            })
        };

        let mut yielded = false;
        coord.drain_reaped(|| {
            if yielded {
                return None;
            }
            yielded = true;
            // Release the reusing thread, then hold the lock long enough for it to
            // reach (and, under the atomic impl, block on) `reserve` before STALE
            // is recorded.
            reaped_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            Some((PID, STALE_CODE))
        });

        reusing.join().unwrap();

        let got = coord.wait_for(PID);
        assert_eq!(
            got, REAL_CODE,
            "a pid reused after reaping must deliver its own exit, not the stale \
             grandchild status recorded in the same drain"
        );
        assert_ne!(
            got, STALE_CODE,
            "the non-atomic reap+record race must not resurface"
        );
        assert_eq!(coord.pending_statuses(), 0);
    }

    #[test]
    fn reserve_after_fast_child_already_drained_delivers_status() {
        // AGENT-2: an instant child (`head -c 32 /dev/urandom` takes ~1 ms) can
        // exit and be drained by the PID-1 reaper in the window between `spawn`
        // and `reserve` — on a 1-vcpu guest the child often runs to completion
        // before the exec thread is rescheduled. The pre-fix `reserve` wiped any
        // pre-existing status for the pid — including the child's OWN — so
        // `wait_for` blocked forever and the host saw a sporadic 10 s
        // "Agent exec timed out" on a command that had already succeeded (the
        // dominant snapshot_restore::firecracker flake). With the pre-SPAWN
        // epoch, the child's status (recorded strictly after the epoch) survives
        // the reservation and is delivered immediately. The buggy inverse
        // (unconditional wipe / epoch captured at reserve time) reddens the
        // recv_timeout below instead of hanging the suite.
        const PID: u32 = 777;
        let coord = Arc::new(ReaperCoordinator::new());
        let epoch = coord.pre_spawn_epoch(); // captured before the "spawn"
        // The child exits instantly; the PID-1 drain records it BEFORE the exec
        // thread reaches `reserve`.
        coord.record_exit(PID, 0);
        coord.reserve(PID, epoch);
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter_coord = Arc::clone(&coord);
        std::thread::spawn(move || {
            let _ = tx.send(waiter_coord.wait_for(PID));
        });
        let got = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("waiter must deliver the fast child's own status, not hang (AGENT-2)");
        assert_eq!(got, 0, "the fast child's own exit code must be delivered");
        assert_eq!(coord.pending_statuses(), 0);
    }

    #[test]
    fn reservation_only_constrains_its_own_pid() {
        // A reservation for one pid must not change delivery for an unreserved
        // pid (the legacy single-occupant path stays intact).
        let coord = ReaperCoordinator::new();
        let epoch = coord.pre_spawn_epoch();
        coord.reserve(1, epoch);
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
