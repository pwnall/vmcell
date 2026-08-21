//! The host→guest **tuning channel**, observed end to end: a cell that declares a non-default
//! `Timeouts` profile and a guest that is caught honoring it (finding G7) — and the two **shipped
//! presets** booted as presets (docs/90 T2, "a knob nobody boots is a claim nobody makes").
//!
//! Why this file has to exist. The two cadence tokens travel to the guest on the kernel command
//! line, and until v33 nothing could tell a guest that read them from a guest that ignored them:
//! `vmcell-steward`'s compiled fallbacks were byte-identical to `vmcell`'s emitted defaults
//! (20 ms / 250 ms on both sides, four literals in two crates), and no suite ever booted a cell with
//! anything else. Rename either token, or delete the guest's parse block outright, and every test in
//! the tree stayed green — the steward fell back to exactly the numbers the host meant to send. The
//! spelling half is closed at compile time now (`vmcell_protocol::STEWARD_ACCEPT_POLL` /
//! `STEWARD_REBIND_IDLE` are the one definition each side reads), but a shared const cannot prove
//! the guest *acts* on what arrives. Only a boot can.
//!
//! **What is observed, and why it is behavior rather than a log line.** The steward logs its
//! resolved cadence at `info`, and the guest carries no `RUST_LOG`, so `tracing_subscriber`'s
//! default filter keeps everything below `error` off the serial console — the same trap the declared
//! port's leg fell into (`service_steward.rs`). So these legs measure the *mechanism* instead: the
//! re-bind loop drops its listener and `bind`s a fresh one after `rebind_idle` of idleness (§8.2),
//! and a fresh `socket(2)` gets a fresh inode number that never repeats. Counting the DISTINCT
//! `socket:[…]` targets under `/proc/1/fd` over a fixed sampling window therefore counts how many
//! listeners PID 1 created during it — a measured cadence, read out of the kernel's own bookkeeping,
//! with no guest-side code added for the test (law C6's spirit: no new guest code, and nothing in
//! `vmcell-steward` knows these legs exist).
//!
//! The sampling runs inside ONE `exec`, deliberately: only a real `accept` restarts the idle
//! deadline, so a host that polled from outside would reset the very window it is measuring.
//!
//! Paired, in one test, because the number alone means nothing: the same script, on the same
//! rootfs, against two cells differing in exactly one variable — the declared window. The
//! longer-window cell must show fewer listeners than the shorter-window one, in proportion. A
//! guest that ignores the token produces the *same* count for both, which is the pre-fix behavior
//! said out loud.
//!
//! **The three legs, and what each one is worth.**
//!
//! * [`the_declared_rebind_window_is_the_one_the_guest_honors`] — a hand-tuned window (16× the
//!   default) against a default-window twin. The falsifiability half of G7, with the widest margin
//!   available, which is why it stays the primary leg.
//! * [`the_low_latency_preset_is_the_window_the_guest_actually_runs_on`] — the same measurement with
//!   [`Timeouts::low_latency`] *itself* on the subject cell: the preset, not a hand-mutated field.
//!   Before it, the preset's numbers were only unit-asserted (`config.rs`), so a preset that shipped
//!   a window the guest never ran was invisible. Its control is the **same preset** with
//!   `guest_rebind_idle` put back to the shipped default: differing by one variable is a rule here
//!   (AGENTS, "a differential leg must differ in exactly ONE variable"), and a literal
//!   `Timeouts::default()` twin would differ in seven fields at once.
//! * [`both_shipped_presets_arrive_on_the_guests_own_kernel_command_line`] — both presets booted,
//!   each cell's `/proc/cmdline` read back in-guest and required to carry that preset's own rendered
//!   tokens. This is the **arrival** claim, not the honoring one, and it is the whole of what
//!   [`Timeouts::throughput`] gets: its window is 200 ms against the default's 250 ms, a 1.25×
//!   separation that sits inside this measurement's noise, so a churn leg for it would be a
//!   coin-flip dressed as a gate. The honoring claim is a property of the *channel*, which the two
//!   churn legs establish; what a second profile adds is that its own numbers reach the guest.
//!   `throughput`'s distinctive knob, `shutdown_grace`, is host-side and never crosses the boundary
//!   — no in-guest observation can see it, and it is not covered here.
//!
//! **The live legs' own arithmetic is falsifiable without KVM.** Their verdicts are a handful of
//! integer inequalities over measured counts, and the defect that matters — a bound loose enough
//! that a guest ignoring the token also clears it — is invisible to a green live run by
//! construction. So the discriminators are predicates ([`churn_beats_midpoint`],
//! [`churn_rate_beats_midpoint`], [`churn_ceiling`], [`window_elapsed`]) and
//! [`the_preset_legs_arithmetic_separates_an_honored_window_from_an_ignored_one`] drives each one
//! with the counts both outcomes actually produce, derived from the presets and the sampler rather
//! than typed in.
//!
//! **Exactly one variable is on the measured path**, even though a preset moves seven fields at
//! once. Five of them are host-side and never cross the boundary. Of the two that do,
//! `guest_accept_poll` paces *failure recovery only*: `recovery_backoff(IdleWindowElapsed, _)` is
//! `Duration::ZERO` (`vmcell-steward/src/serve.rs`, law L-GUEST-4), so an idle re-bind — the only
//! event these legs count — is not paced by it. What is left is `guest_rebind_idle`.
//!
//! CH-only, like `service_steward.rs` and `custom_init.rs`: this is a guest-side property reached
//! through a host-side cmdline feature, so one primary-backend proof suffices, and it needs no
//! capability beyond KVM (`network_disabled`, no tap, no snapshot).
//!
//! **Which recipe selects it.** `just test-privileged` (`-p vmcell … --run-ignored all -E 'kind(test)
//! & !(test(unprivileged) | test(smoltcp))'`) — the live legs are `#[ignore]`d and no other filter
//! picks them up. The KVM-free premise checks below run everywhere, including `just ci`.
//!
//! **"Runs everywhere" is a claim about the HOST, not about an attribute list** — and it shipped
//! false. The premise check reached `common::get_vmlinux()`/`get_rootfs()` through the shared config
//! builder, and those getters do not hand back a path: they **require a built artifact**, failing
//! loud with `guest kernel missing at …/vmlinux`. Every box that has run `vmcell build` satisfies
//! that and no fresh checkout does, so `just test-unit` was green on a developer box and red in CI's
//! artifact-free `test-unit` job. The artifact pair is therefore a **parameter** of
//! [`tuned_cell_cfg`]: the live legs hand it the real artifacts, and the premise checks hand it a
//! scratch pair, because a `Duration` reaching a `VmConfig` has nothing to do with which kernel image
//! the cell would boot.
//!
//! Mirror that CI condition locally with `VMCELL_KERNEL=/nonexistent/vmlinux just test-unit`: the
//! getters require the kernel and never build it, so hiding it alone reproduces the job. (Pointing
//! `VMCELL_ARTIFACTS_DIR` at an empty dir reproduces it too, but it also reddens
//! `repack_outside_checkout`'s consumer-position leg, whose subject *is* that variable's precedence.)
//!
//! **These legs mean nothing against a stale rootfs.** The parser under test is baked into
//! `rootfs.erofs`. A central runner must therefore, in order: `vmcell build --kernel-source
//! host-make` (the bare default is `prebuilt`, which swaps in a `vmlinux` lacking
//! `CONFIG_KVM_INTEL`), then `just bless` (a sudo here, since a rebuilt runner strips its blessing;
//! an mtime-only bump re-dates without one), then
//! `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just
//! test-privileged`.

#![cfg(feature = "cloud-hypervisor")]

use std::path::PathBuf;
use std::time::Duration;

use vmcell::config::{RootfsSource, Timeouts, VmConfig};
use vmcell::steward::ExecRequest;

mod common;

/// The re-bind window the hand-tuned subject cell declares: 16× the shipped default, so the
/// difference in observed listener churn is an order of magnitude rather than a ratio inside the
/// noise. Well inside `STEWARD_REBIND_IDLE`'s ceiling, so the guest honors it verbatim rather than
/// clamping it (pinned by [`the_measured_window_is_non_default_and_honored_verbatim`]).
const SUBJECT_REBIND_IDLE: Duration = Duration::from_millis(4_000);

/// How the in-guest sampler paces itself: `samples` reads of `/proc/1/fd`, `sample_ms` apart.
///
/// A parameter rather than two constants because the two churn legs measure windows an order of
/// magnitude apart, and the sample period is not free to be the same: a listener that lives
/// `rebind_idle` is seen **only** if some sample falls inside its lifetime, which is guaranteed
/// exactly when the sample period is at or below that lifetime. Sampling the 150 ms preset window at
/// the hand-tuned leg's 100 ms cadence would leave no margin for a loaded host's per-iteration
/// `fork`+`exec` cost, and every listener it dropped would push the count toward the *default*
/// cadence — i.e. toward a false green.
#[derive(Clone, Copy)]
struct Sampler {
    /// How many times `/proc/1/fd` is read.
    samples: u32,
    /// Milliseconds of `sleep` between reads. Rendered into the script as decimal seconds, so this
    /// number has exactly one spelling.
    sample_ms: u64,
}

/// The pacing the hand-tuned leg uses: ~9 s of wall time, two full [`SUBJECT_REBIND_IDLE`] windows
/// and ~36 default ones.
const HAND_TUNED_SAMPLER: Sampler = Sampler {
    samples: 90,
    sample_ms: 100,
};

/// The pacing the preset leg uses: ~10 s nominal (~12 s measured, the per-iteration cost), at a
/// sample period a third of [`Timeouts::low_latency`]'s 150 ms window — the capture margin the
/// [`Sampler`] doc explains, pinned by
/// [`the_preset_churn_leg_can_tell_low_latency_from_the_default_window`].
const PRESET_SAMPLER: Sampler = Sampler {
    samples: 200,
    sample_ms: 50,
};

impl Sampler {
    /// Samples PID 1's socket-inode set and prints `<distinct sockets> <elapsed seconds>`.
    ///
    /// `readlink` rather than `ls -l`: the link target is the datum, and `ls`'s columns are locale-
    /// and timestamp-shaped. The elapsed seconds are printed — and asserted on — because a `sleep`
    /// that did not sleep would make the whole measurement finish in milliseconds and the low-churn
    /// assertion pass vacuously. Both numbers are spliced from `self` rather than typed into the
    /// script, so the window the assertions reason about and the window the guest runs cannot drift
    /// apart.
    fn script(self) -> String {
        let Self { samples, sample_ms } = self;
        // Whole seconds and the millisecond remainder, so `sleep`'s argument is derived from
        // `sample_ms` instead of being a second spelling of it.
        let (secs, millis) = (sample_ms / 1000, sample_ms % 1000);
        format!(
            "start=$(date +%s); \
             n=$(for i in $(seq 1 {samples}); do readlink /proc/1/fd/* 2>/dev/null; \
                 sleep {secs}.{millis:03}; done \
                 | sed -n 's/^socket:\\[\\([0-9]*\\)\\]$/\\1/p' | sort -u | wc -l); \
             echo \"$n $(( $(date +%s) - start ))\""
        )
    }

    /// The nominal sampling window in milliseconds — sleep time only, so the guest's own measured
    /// elapsed is always at least this (never less), which is the direction the non-vacuity
    /// assertion needs.
    fn window_ms(self) -> u64 {
        u64::from(self.samples) * self.sample_ms
    }
}

/// A re-bind window in whole milliseconds, for the count arithmetic. Saturating, and never zero:
/// this is a divisor, and the shared floor keeps the real value well clear of it.
fn rebind_ms(window: Duration) -> u64 {
    u64::try_from(window.as_millis()).unwrap_or(u64::MAX).max(1)
}

/// The shipped balanced profile with one field moved — the shape a real caller uses, and the shape
/// the hand-tuned leg's two cells differ by.
///
/// `Timeouts` is `#[non_exhaustive]`, so an out-of-crate caller cannot use struct-update syntax
/// (`Timeouts { .., ..Default::default() }` does not compile here) and mutates the `pub` field
/// instead — which is also the one the orchestrator re-clamps at `start()` (M-ORCH-3).
fn default_with_rebind_idle(rebind_idle: Duration) -> Timeouts {
    let mut timeouts = Timeouts::default();
    timeouts.guest_rebind_idle = rebind_idle;
    timeouts
}

/// A `Pid1` cell (the steward IS pid 1, so the sampler reads `/proc/1/fd`) whose only non-default
/// property is the timing profile it is handed, over the artifact pair it is handed.
///
/// The pair is a parameter rather than a `common::get_*()` call inside: those getters **build or
/// require** the artifacts, so calling them here made the KVM-free premise checks below fail on
/// every host that has not run `vmcell build` (see the module header). The live legs pass the real
/// pair.
fn tuned_cell_cfg(kernel: PathBuf, rootfs_image: PathBuf, timeouts: Timeouts) -> VmConfig {
    VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .timeouts(timeouts)
    .network_disabled()
    .build()
    .expect("a Pid1 cell with a tuned timing profile is an ordinary cell")
}

/// A real, absolute, non-kernel artifact pair in a scratch dir that cleans itself up on the panic
/// path as well as the success path (a test's fixtures are residue too).
///
/// The files are real and absolute because that is what the builder validates at this boundary — it
/// checks absoluteness and deliberately not existence, so this stays honest if it ever checks both.
/// The `TempDir` is returned, not dropped here: dropping it would delete the paths before the caller
/// has used them.
fn scratch_artifact_pair() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let pair = tempfile::tempdir().expect("a scratch dir for the artifact pair");
    let (kernel, rootfs) = (
        pair.path().join("vmlinux"),
        pair.path().join("rootfs.erofs"),
    );
    std::fs::write(&kernel, b"not a kernel").expect("write the kernel stand-in");
    std::fs::write(&rootfs, b"not an image").expect("write the rootfs stand-in");
    (pair, kernel, rootfs)
}

/// Boots a cell under `timeouts`, measures PID 1's listener churn with `sampler`, and tears it down.
///
/// The one place the real artifact pair enters: `common::get_vmlinux`/`get_rootfs` require a built
/// `vmlinux` + `rootfs.erofs`, which is a live-suite precondition and not a premise-check one.
///
/// Returns `(distinct socket inodes, elapsed seconds the guest measured)`.
async fn measure_listener_churn(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    timeouts: Timeouts,
    sampler: Sampler,
) -> (u64, u64) {
    let cfg = tuned_cell_cfg(common::get_vmlinux(), common::get_rootfs(), timeouts);
    let mut vm = common::start_vm(vmm, cfg).await;

    let out = vm
        .steward(Some(Duration::from_secs(30)))
        .await
        .expect("a Pid1 cell must answer on the control plane")
        .exec(
            ExecRequest::new(vec!["/bin/sh".into(), "-c".into(), sampler.script()])
                // Well past the sample: `handle_exec` arms a kill thread on the child's process
                // group at the deadline, and the default 10 s would SIGKILL the sampler mid-window.
                .with_timeout(Duration::from_secs(120)),
        )
        .await
        .expect("the sampling exec must complete");
    assert_eq!(
        out.code,
        0,
        "the in-guest sampler failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // `split_whitespace`, not `split_once(' ')`: some `wc` implementations pad their count, and a
    // parse failure here would read as "the guest is broken" rather than "the field was padded".
    let mut fields = stdout.split_whitespace();
    let parsed = match (fields.next(), fields.next(), fields.next()) {
        (Some(count), Some(elapsed), None) => (
            count
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("bad count in {stdout:?}: {e}")),
            elapsed
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("bad elapsed in {stdout:?}: {e}")),
        ),
        _ => panic!("sampler must print exactly `<count> <elapsed>`, got {stdout:?}"),
    };

    vm.kill().await.expect("teardown");
    parsed
}

/// Did the sampler really cover its window? A `sleep` that silently did nothing (or a sampler killed
/// early) would collapse the window to milliseconds, and a cadence assertion on a window that never
/// elapsed proves nothing at all.
///
/// The bound is 80% of the nominal sleep total, not a constant: the two legs sample for different
/// lengths, and a per-leg literal is a number that can drift away from the schedule it describes.
fn window_elapsed(secs: u64, sampler: Sampler) -> bool {
    secs * 1000 >= sampler.window_ms() * 4 / 5
}

/// [`window_elapsed`] as an assertion, so the two live legs share one message.
fn assert_window_elapsed(name: &str, secs: u64, sampler: Sampler) {
    assert!(
        window_elapsed(secs, sampler),
        "{name}: the in-guest sampler must cover its window; it reported {secs} s for \
         {} × {} ms",
        sampler.samples,
        sampler.sample_ms
    );
}

/// Did a cell that measured `count` distinct listeners over `secs` seconds churn faster than the
/// cadence exactly **between** `subject_ms` and `control_ms`?
///
/// The preset leg's discriminator, as a predicate rather than an inline expression, so the
/// arithmetic the live leg's verdict rests on has a red-on-inverse that runs without KVM
/// ([`the_preset_legs_arithmetic_separates_an_honored_window_from_an_ignored_one`]). The midpoint is
/// where both directions keep the most margin: a cell honoring the shorter window sits well above
/// it, and one that fell back to the longer one sits well below.
///
/// Cross-multiplied (`count * (a + b) > 2 * elapsed_ms`) rather than divided, so integer truncation
/// cannot move the line.
fn churn_beats_midpoint(count: u64, secs: u64, subject_ms: u64, control_ms: u64) -> bool {
    count * (subject_ms + control_ms) > 2 * secs * 1000
}

/// The same discriminator applied to the two cells' churn **rates**: does the subject's rate beat
/// the control's by at least the midpoint factor?
///
/// Rates, not raw counts, because each cell measures its own elapsed time and a stretched sample on
/// one of them would otherwise distort the comparison. `(count, secs)` per cell.
fn churn_rate_beats_midpoint(
    subject: (u64, u64),
    control: (u64, u64),
    subject_ms: u64,
    control_ms: u64,
) -> bool {
    subject.0 * control.1 * 2 * subject_ms >= control.0 * subject.1 * (subject_ms + control_ms)
}

/// The count a cell running `window` for `secs` seconds may not exceed: one listener per window,
/// plus the sockets that are not listeners at all (the accepted control-plane connection, and
/// whatever else PID 1 holds open across the sample) — then doubled, so scheduling noise on a loaded
/// host cannot turn a cadence assertion into a flake.
///
/// Derived from the window the GUEST measured rather than from a constant, because the number of
/// re-binds is a function of wall time: a slow box stretches the sample and legitimately raises the
/// count, and a fixed ceiling would call that a defect.
fn churn_ceiling(secs: u64, window: Duration) -> u64 {
    4 + 2 * (1 + secs * 1000 / rebind_ms(window))
}

/// **A declared re-bind window is the window the guest actually runs on.**
///
/// The falsifiability half of finding G7. `rebind_idle` is the number that bounds how long a
/// restored guest stays unreachable after the VMM re-creates its vhost-vsock device (§8.2), and
/// before this leg a caller could ask for any window at all and silently get the compiled 250 ms —
/// including a caller asking for a *tighter* one, which is the direction that matters.
///
/// RED ON INVERSE, **measured live on this host**: plant `push_guest_timeout_args` to render
/// `STEWARD_REBIND_IDLE.default` instead of `timeouts.guest_rebind_idle` — the "emitter ignores the
/// profile" shape — and the subject cell reports **40** distinct sockets over its 10 s window
/// against a bound of 10, failing with `the guest ignored vmcell_rebind_idle_ms=`. Green on the same
/// host, twice: 6 sockets over 9 s.
///
/// The three plants this leg is here for all end in that same guest-observable state — the steward
/// re-binding on the compiled 250 ms cadence because the value it needed never arrived: re-spell the
/// token on either side, delete a `parse_tuning` line from `StewardOptions::apply_cmdline`, or send
/// the default regardless of the profile. The host-side ones are demonstrable without a rootfs
/// rebuild (above); the guest-side one needs `vmcell build --kernel-source host-make` first, and is
/// caught without a boot by `token_channel_tests` in `vmcell-steward/src/options.rs`.
///
/// The two cells differ in exactly one variable, so a red here has one cause.
#[tokio::test]
#[ignore = "needs KVM"]
async fn the_declared_rebind_window_is_the_one_the_guest_honors() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());

    let (subject, subject_secs) = measure_listener_churn(
        &vmm,
        default_with_rebind_idle(SUBJECT_REBIND_IDLE),
        HAND_TUNED_SAMPLER,
    )
    .await;
    let (control, control_secs) = measure_listener_churn(
        &vmm,
        default_with_rebind_idle(vmcell_protocol::STEWARD_REBIND_IDLE.default),
        HAND_TUNED_SAMPLER,
    )
    .await;

    // Non-vacuity first: both samples really covered their window.
    assert_window_elapsed("subject", subject_secs, HAND_TUNED_SAMPLER);
    assert_window_elapsed("control", control_secs, HAND_TUNED_SAMPLER);

    // The control is the positive control for the OBSERVATION: at the shipped 250 ms the steward
    // re-binds ~36 times in this window, so a count near 1 would mean the measurement cannot see a
    // re-bind at all and the subject's low count is meaningless.
    assert!(
        control >= 12,
        "the default 250 ms window must produce visible listener churn — {control} distinct sockets \
         in {control_secs} s means /proc/1/fd is not showing re-binds, so this leg cannot see the \
         property it exists to measure"
    );

    // MEASURED on this host: 6 distinct sockets over a 9 s window against a bound of 10, and 40 over
    // a 10 s window when the emitter was planted to send the default — so the green margin is ~1.7×
    // and the red one ~4×.
    let subject_ceiling = churn_ceiling(subject_secs, SUBJECT_REBIND_IDLE);
    assert!(
        subject <= subject_ceiling,
        "the declared {SUBJECT_REBIND_IDLE:?} window must produce at most {subject_ceiling} \
         distinct sockets over the {subject_secs} s the guest measured — {subject} is the COMPILED \
         {:?} cadence, i.e. the guest ignored `{}`",
        vmcell_protocol::STEWARD_REBIND_IDLE.default,
        vmcell_protocol::STEWARD_REBIND_IDLE.token
    );

    // And the relation, which is the actual claim: the churn RATE scales with the declared window.
    // Compared as rates (cross-multiplied, so it stays integer arithmetic) rather than as raw counts,
    // because the two boots measure their own windows and a stretched sample on one of them would
    // otherwise distort the comparison. The declared windows differ by 16×; 3× is asserted, so this
    // is a property with a wide margin rather than a benchmark. Measured: 40/10 s against 6/9 s.
    assert!(
        control * subject_secs >= 3 * subject * control_secs,
        "listener churn must scale with the declared window: {control} distinct sockets in \
         {control_secs} s at {:?} against {subject} in {subject_secs} s at {SUBJECT_REBIND_IDLE:?} \
         is not a cadence difference — a guest that ignored the token would show the SAME rate for \
         both cells, which is exactly the pre-fix behavior",
        vmcell_protocol::STEWARD_REBIND_IDLE.default
    );
}

/// **The `low_latency` PRESET, booted as a preset, is the window the guest runs on.**
///
/// docs/90's T2 finding, one entry: `Timeouts::low_latency()` shipped as a documented profile whose
/// values no boot had ever produced. The leg above proves the *channel* carries a window, but it
/// builds that window by hand — so a preset that named a number the guest could never run (below the
/// shared floor, past the guest's ceiling, or simply not what the emitter sends) was a claim with no
/// gate. The preset is the subject here, unmutated.
///
/// **One variable.** The control is `Timeouts::low_latency()` with `guest_rebind_idle` restored to
/// the shipped default, built by mutating that one field — so the two cells differ by construction
/// rather than by assertion. A literal `Timeouts::default()` twin would have differed in seven
/// fields at once; the measured path only sees this one (module header), but "only sees" is an
/// argument and one-variable-by-construction is not.
///
/// **The channel is falsifiable on this field**, which is the first thing to check here: the
/// preset's 150 ms is neither the guest's compiled fallback (250 ms) nor equal to the control's
/// value, so a guest that ignored the token would run the *same* cadence for both cells. That is
/// pinned KVM-free by [`the_preset_churn_leg_can_tell_low_latency_from_the_default_window`], which
/// also pins the 3/2 separation the arithmetic below needs.
///
/// **The bound is the midpoint cadence**, derived rather than tuned: a cell honoring 150 ms churns
/// ~1.67× as fast as one honoring 250 ms, so the discriminator sits halfway between "honored" and
/// "ignored" and both directions keep ~25–33% of margin. Two independent forms are asserted — an
/// absolute one against the subject's own elapsed time (true even if the control boot misbehaves)
/// and the twin ratio.
///
/// RED ON INVERSE (the same three plants as the leg above; **not** measured live from this seat —
/// the blessed runner was stale, see the report accompanying this change): plant
/// `push_guest_timeout_args` to render `STEWARD_REBIND_IDLE.default` and both cells run 250 ms, so
/// the subject's count collapses from ~80 to ~48 over a ~12 s window and the midpoint assertion
/// (>~60) fires; a preset whose `guest_rebind_idle` were moved to the default reddens the KVM-free
/// premise check instead, before a VM is ever booted.
#[tokio::test]
#[ignore = "needs KVM"]
async fn the_low_latency_preset_is_the_window_the_guest_actually_runs_on() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());

    // The preset itself, exactly as a caller writes it.
    let preset = Timeouts::low_latency();
    // …and the same preset with the ONE measured field put back to the shipped default.
    let mut control_profile = Timeouts::low_latency();
    control_profile.guest_rebind_idle = Timeouts::default().guest_rebind_idle;

    let (subject, subject_secs) = measure_listener_churn(&vmm, preset, PRESET_SAMPLER).await;
    let (control, control_secs) =
        measure_listener_churn(&vmm, control_profile, PRESET_SAMPLER).await;

    assert_window_elapsed("low_latency", subject_secs, PRESET_SAMPLER);
    assert_window_elapsed("default-window twin", control_secs, PRESET_SAMPLER);

    let subject_ms = rebind_ms(preset.guest_rebind_idle);
    let control_ms = rebind_ms(control_profile.guest_rebind_idle);
    // What the midpoint cadence would have produced, for the messages only: the verdicts go through
    // `churn_beats_midpoint` / `churn_rate_beats_midpoint`, which are cross-multiplied so integer
    // truncation cannot move the line this division rounds.
    let midpoint_of = |secs: u64| 2 * secs * 1000 / (subject_ms + control_ms);

    // Positive control for the OBSERVATION, derived rather than a literal: the default-window twin
    // must show at least half the churn its own cadence predicts. A count near 1 would mean
    // /proc/1/fd is not showing re-binds at all, and every number below would be noise.
    let control_expected = control_secs * 1000 / control_ms;
    assert!(
        control * 2 >= control_expected,
        "the {control_ms} ms twin must produce visible listener churn — {control} distinct sockets \
         in {control_secs} s against the ~{control_expected} its cadence predicts means \
         /proc/1/fd is not showing re-binds, so this leg cannot see the property it measures"
    );

    // (1) Absolute: the preset cell churned FASTER than the midpoint cadence. True on the subject's
    // own numbers, so it holds even if the control boot is disturbed — a guest that fell back to the
    // compiled 250 ms lands below this line.
    assert!(
        churn_beats_midpoint(subject, subject_secs, subject_ms, control_ms),
        "the {subject_ms} ms preset window must produce more than ~{} distinct sockets over the \
         {subject_secs} s the guest measured (the midpoint of {subject_ms} ms and {control_ms} ms) \
         — {subject} is the {control_ms} ms cadence, i.e. the guest ignored `{}` and ran its \
         compiled fallback",
        midpoint_of(subject_secs),
        vmcell_protocol::STEWARD_REBIND_IDLE.token
    );

    // (2) …and not faster than the preset's own window allows, so this asserts the declared cadence
    // verbatim in BOTH directions: a guest that clamped the value to the shared 20 ms floor would
    // show ~600 here, which is as wrong as showing ~48.
    let subject_ceiling = churn_ceiling(subject_secs, preset.guest_rebind_idle);
    assert!(
        subject <= subject_ceiling,
        "the {subject_ms} ms preset window must produce at most {subject_ceiling} distinct sockets \
         over {subject_secs} s — {subject} is a cadence the preset never asked for"
    );

    // (3) The twin ratio, cross-multiplied so it stays integer arithmetic and each cell is measured
    // against its own elapsed time: the preset's churn rate must beat the default-window twin's by
    // at least the midpoint factor. A guest that ignored the token shows the SAME rate for both.
    assert!(
        churn_rate_beats_midpoint(
            (subject, subject_secs),
            (control, control_secs),
            subject_ms,
            control_ms
        ),
        "listener churn must scale with the PRESET's window: {subject} distinct sockets in \
         {subject_secs} s at {subject_ms} ms against {control} in {control_secs} s at \
         {control_ms} ms is not a cadence difference — the two cells differ in exactly that one \
         field, so the same rate means the preset's window never reached the guest"
    );
}

/// Every whitespace-delimited token on `cmdline` starting with `token`'s key, as one value.
///
/// Exactly one must be present: the guest's parser takes the FIRST match, so an emitter that
/// appended both a preset's number and the default's would hand the guest the wrong one while a
/// `contains` assertion stayed green (the same shape `config.rs`'s emitter test guards host-side).
/// Whole-token equality, not `contains`, for the same reason a substring match is banned on refusal
/// strings: `…_ms=250` is a substring of `…_ms=2500`.
fn sole_cmdline_token(cmdline: &str, token: vmcell_protocol::TuningToken) -> String {
    let hits: Vec<&str> = cmdline
        .split_whitespace()
        .filter(|arg| arg.starts_with(token.token))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "the guest's own command line must carry exactly one `{}` token, found {hits:?} in \
         {cmdline:?}",
        token.token
    );
    hits.first()
        .copied()
        .unwrap_or_default() // unreachable past the assertion above; no indexing, no unwrap
        .to_string()
}

/// Boots a cell under `timeouts` and reads the kernel command line back out of the guest.
///
/// `/proc/cmdline` is the guest kernel's own copy of what the VMM handed it — the transported
/// artifact, not a host-side rendering of it.
async fn guest_cmdline(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    timeouts: Timeouts,
) -> String {
    let cfg = tuned_cell_cfg(common::get_vmlinux(), common::get_rootfs(), timeouts);
    let mut vm = common::start_vm(vmm, cfg).await;

    let out = vm
        .steward(Some(Duration::from_secs(30)))
        .await
        .expect("a Pid1 cell must answer on the control plane")
        .exec(ExecRequest::new(vec![
            "/bin/cat".into(),
            "/proc/cmdline".into(),
        ]))
        .await
        .expect("reading /proc/cmdline must complete");
    assert_eq!(
        out.code,
        0,
        "cat /proc/cmdline failed in-guest: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cmdline = String::from_utf8_lossy(&out.stdout).trim().to_string();

    vm.kill().await.expect("teardown");
    cmdline
}

/// **Both shipped presets, booted, with their own numbers on the guest's own command line.**
///
/// The arrival half of the T2 gap, and the only live coverage [`Timeouts::throughput`] gets — see
/// the module header for why its 200 ms window is deliberately not measured as churn. `config.rs`
/// already pins what the emitter *composes*; what no host-side test can see is whether the token
/// survives the trip: the boot protocol, the VMM's own cmdline handling, and the kernel's argument
/// splitting all sit between `build_kernel_cmdline` and `/proc/cmdline`, and a token dropped there
/// is exactly the silent fallback G7 is about.
///
/// The values are compared against the PRESET's own fields — a positive identity, rendered through
/// the shared token so no `format!` here can drift from the wire spelling. The negative ("the
/// default's number is not there") is not a separate assertion: [`sole_cmdline_token`] requires
/// exactly one token per key and this pins its value, which is strictly stronger. The positive
/// control for that negative is the same parse on the same file finding the preset's number.
///
/// RED ON INVERSE (**not** measured live from this seat, see the report accompanying this change):
/// plant `push_guest_timeout_args` to render `STEWARD_REBIND_IDLE.default` and the equality fires
/// with `vmcell_rebind_idle_ms=250` against `…=150`; make it emit both and the `hits.len() == 1`
/// assertion fires instead. A rootfs rebuild is not needed for either — nothing guest-side
/// participates in this leg beyond `cat`.
#[tokio::test]
#[ignore = "needs KVM"]
async fn both_shipped_presets_arrive_on_the_guests_own_kernel_command_line() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());

    for (name, profile) in [
        ("low_latency", Timeouts::low_latency()),
        ("throughput", Timeouts::throughput()),
    ] {
        let cmdline = guest_cmdline(&vmm, profile).await;
        for (knob, value, token) in [
            (
                "guest_accept_poll",
                profile.guest_accept_poll,
                vmcell_protocol::STEWARD_ACCEPT_POLL,
            ),
            (
                "guest_rebind_idle",
                profile.guest_rebind_idle,
                vmcell_protocol::STEWARD_REBIND_IDLE,
            ),
        ] {
            assert_eq!(
                sole_cmdline_token(&cmdline, token),
                token.render(value),
                "{name}.{knob}: the guest's command line must carry the PRESET's {value:?}, not \
                 the default the steward would fall back to; the whole line was {cmdline:?}"
            );
        }
    }
}

/// The hand-tuned leg's premise, checked without KVM **and without a built artifact**: the window it
/// declares must be non-default **and** honored verbatim.
///
/// A live leg whose "non-default" value quietly became the default (or drifted outside the window the
/// guest clamps into) would pass while measuring nothing — the vacuity shape AGENTS rule 2 forbids,
/// and the one a reviewer on a KVM-free box cannot otherwise check. So it must run on a box that has
/// never built an artifact, which is what CI's `test-unit` job and a fresh checkout are; the scratch
/// pair below is what makes "without KVM" true of the host rather than only of the attribute list.
///
/// RED on the inverse: set `SUBJECT_REBIND_IDLE` to `STEWARD_REBIND_IDLE.default` and the
/// inequality fires; set it to 90 s (past the shared ceiling) and the ceiling assertion fires.
#[test]
fn the_measured_window_is_non_default_and_honored_verbatim() {
    let token = vmcell_protocol::STEWARD_REBIND_IDLE;
    assert_ne!(
        SUBJECT_REBIND_IDLE, token.default,
        "the subject cell must declare a NON-default window or the live leg measures nothing"
    );
    assert!(
        SUBJECT_REBIND_IDLE >= token.floor && SUBJECT_REBIND_IDLE <= token.ceiling,
        "{SUBJECT_REBIND_IDLE:?} is outside the guest's clamp window [{:?}, {:?}], so the guest \
         would honor a different number than the one this leg asserts about",
        token.floor,
        token.ceiling
    );
    // The cell really carries it: `.timeouts()` clamps, and a clamp that moved the value would make
    // the emitted token differ from the constant this file reasons about.
    //
    // Over a SCRATCH artifact pair, not the built one: this assertion is about a `Duration` surviving
    // the builder, and `common::get_vmlinux()` would turn it into an assertion about whether this host
    // has run `vmcell build` (the module header records the CI red that taught us).
    let (_pair, kernel, rootfs) = scratch_artifact_pair();
    assert_eq!(
        tuned_cell_cfg(
            kernel,
            rootfs,
            default_with_rebind_idle(SUBJECT_REBIND_IDLE)
        )
        .timeouts
        .guest_rebind_idle,
        SUBJECT_REBIND_IDLE,
        "the builder must carry the declared window through unclamped"
    );
    // The sample window must span several subject windows, or "a handful of re-binds" is a bound on
    // a window that never elapsed.
    assert!(
        HAND_TUNED_SAMPLER.window_ms() >= 2 * rebind_ms(SUBJECT_REBIND_IDLE),
        "the sampling window ({} × {} ms) must cover at least two declared {SUBJECT_REBIND_IDLE:?} \
         re-bind windows",
        HAND_TUNED_SAMPLER.samples,
        HAND_TUNED_SAMPLER.sample_ms
    );
}

/// The preset leg's premise, checked without KVM and without a built artifact: **the preset's window
/// is one this measurement can tell apart from the default's**.
///
/// This is the unfalsifiable-channel check, done first and by hand, because this repo has already
/// shipped the shape once: a channel whose two ends default to the same value is unfalsifiable by
/// construction, and the pre-v33 steward's compiled fallbacks equalled the host's emitted defaults.
/// If `low_latency`'s window ever became the guest's fallback — or merely came close enough to it
/// that the sampler cannot separate them — the live leg would keep passing while measuring nothing.
///
/// RED on the inverse, each assertion having a different plant (**measured KVM-free on this host**):
/// set `low_latency`'s `guest_rebind_idle` to `STEWARD_REBIND_IDLE.default` and the trap check
/// fires; set it to 200 ms and the 3/2 separation fires (the same reason `throughput` is not the
/// subject of a churn leg); set it to 60 ms and the capture-margin assertion fires, because the
/// 50 ms sampler would start missing listeners in the direction of a false green.
#[test]
fn the_preset_churn_leg_can_tell_low_latency_from_the_default_window() {
    let token = vmcell_protocol::STEWARD_REBIND_IDLE;
    let preset = Timeouts::low_latency();
    let control_window = Timeouts::default().guest_rebind_idle;

    // The control twin's window IS the guest's compiled fallback, which is what makes "the guest
    // ignored the token" and "the guest ran the control's window" the same observation.
    assert_eq!(
        control_window, token.default,
        "the default profile's window must be the guest's compiled fallback, or the live leg's \
         control cell is not the shape its red-on-inverse assumes"
    );
    // The trap: subject and control must not agree.
    assert_ne!(
        preset.guest_rebind_idle, control_window,
        "`low_latency` must declare a NON-default re-bind window or the preset leg measures nothing"
    );
    // …and must be the TIGHTER of the two, which is the direction `low_latency` exists to move and
    // the one the live leg's inequalities are written for.
    assert!(
        preset.guest_rebind_idle < control_window,
        "`low_latency` must SHORTEN the re-bind window ({:?} against {control_window:?}); the live \
         leg asserts more churn, not less",
        preset.guest_rebind_idle
    );
    // Separation, not merely difference: the live leg discriminates at the midpoint of the two
    // cadences, so a ratio much under 3/2 puts both sides of that line inside the measurement's
    // noise. `throughput`'s 200 ms is exactly the case this rejects.
    let (preset_ms, control_ms) = (
        rebind_ms(preset.guest_rebind_idle),
        rebind_ms(control_window),
    );
    assert!(
        2 * control_ms >= 3 * preset_ms,
        "`low_latency`'s {preset_ms} ms window is not far enough from the default's {control_ms} ms \
         for listener churn to separate them (needs at least 3/2); the live leg would be a \
         coin-flip"
    );
    // Honored verbatim: outside the shared window the guest clamps, and would run a cadence neither
    // the preset nor this leg asked for.
    assert!(
        preset.guest_rebind_idle >= token.floor && preset.guest_rebind_idle <= token.ceiling,
        "{:?} is outside the guest's clamp window [{:?}, {:?}]",
        preset.guest_rebind_idle,
        token.floor,
        token.ceiling
    );
    // Capture margin: a listener is seen only if a sample falls inside its lifetime, which is
    // guaranteed exactly when the sample period is at or below the window. Half of it is required,
    // so the guest's per-iteration `fork`+`exec` cost has room — and every listener the sampler
    // missed would push the count toward the DEFAULT cadence, i.e. toward a false green.
    assert!(
        2 * PRESET_SAMPLER.sample_ms <= preset_ms,
        "the {} ms sample period must be at most half the {preset_ms} ms window it measures, or \
         the sampler undercounts in the direction that hides a regression",
        PRESET_SAMPLER.sample_ms
    );
    // And the sample must span enough of the SLOWER cadence for the control's own positive control
    // to mean something.
    assert!(
        PRESET_SAMPLER.window_ms() >= 8 * control_ms,
        "the sampling window ({} × {} ms) must cover at least eight {control_ms} ms windows",
        PRESET_SAMPLER.samples,
        PRESET_SAMPLER.sample_ms
    );
}

/// Both shipped presets survive the builder **unchanged**, and neither one's guest-side cadence is
/// the value the steward would compile in anyway.
///
/// The premise of [`both_shipped_presets_arrive_on_the_guests_own_kernel_command_line`], and the
/// half of it a KVM-free box can check. Whole-struct equality rather than field-by-field: the
/// builder re-clamps (`Timeouts::clamped`), so a preset that named a value below a correctness floor
/// would silently boot as something else, and a `#[non_exhaustive]` struct grows fields that a
/// hand-written field list would not notice.
///
/// RED on the inverse (**measured KVM-free on this host**): give `throughput` a `guest_accept_poll`
/// of 0 ms and the equality fires — the builder clamps it to the shared 1 ms floor, which is exactly
/// the "the cell boots a number the preset never named" case. Set either preset's guest cadence to
/// its token default and the fallback assertion fires.
#[test]
fn the_shipped_presets_survive_the_builder_and_differ_from_the_guests_fallbacks() {
    let (_pair, kernel, rootfs) = scratch_artifact_pair();
    for (name, profile) in [
        ("low_latency", Timeouts::low_latency()),
        ("throughput", Timeouts::throughput()),
    ] {
        assert_eq!(
            tuned_cell_cfg(kernel.clone(), rootfs.clone(), profile).timeouts,
            profile,
            "{name}: the builder must boot the preset the caller named, unchanged"
        );
        for (knob, value, token) in [
            (
                "guest_accept_poll",
                profile.guest_accept_poll,
                vmcell_protocol::STEWARD_ACCEPT_POLL,
            ),
            (
                "guest_rebind_idle",
                profile.guest_rebind_idle,
                vmcell_protocol::STEWARD_REBIND_IDLE,
            ),
        ] {
            assert_ne!(
                value, token.default,
                "{name}.{knob} equals the steward's compiled fallback, so a guest that ignored \
                 `{}` entirely would be indistinguishable from one honoring this preset — the live \
                 leg would prove nothing",
                token.token
            );
        }
    }
}

/// Sockets PID 1 holds across a sample that are **not** re-bound listeners — the accepted
/// control-plane connection, and whatever else it keeps open. Counted here only to prove the
/// discrimination below survives them: they inflate BOTH cells' counts, which pushes an ignored
/// window *toward* the honored side, so a discriminator that only worked on the ideal numbers would
/// be a false green waiting to happen.
const NON_LISTENER_SOCKETS: u64 = 4;

/// **The preset leg's arithmetic tells an honored window from an ignored one** — checked without
/// KVM, on the counts the two outcomes actually produce.
///
/// The live legs cannot run on a KVM-free box, so their verdict logic would otherwise be reviewed by
/// reading it. It is a handful of integer inequalities over measured counts, and the class of defect
/// that matters — a bound loose enough to pass for a guest that ignored the token — is invisible to
/// a green live run by construction. So the discriminators are predicates
/// ([`churn_beats_midpoint`], [`churn_rate_beats_midpoint`], [`churn_ceiling`],
/// [`window_elapsed`]) and this is the red-on-inverse for each: the counts a cell honoring
/// `low_latency`'s window produces, and the counts the SAME cell produces if the token never
/// arrives and the steward runs its compiled fallback.
///
/// Both count sets are derived from the presets and the sampler, never typed in, so a retuned preset
/// re-derives the numbers instead of silently invalidating them.
///
/// RED on the inverse (**measured on this host**, KVM-free): weaken `churn_beats_midpoint` to `>=
/// elapsed_ms / control_ms` — the "bound the ignored cell also clears" shape — and the
/// `!churn_beats_midpoint(ignored, …)` legs fire.
#[test]
fn the_preset_legs_arithmetic_separates_an_honored_window_from_an_ignored_one() {
    let preset = Timeouts::low_latency();
    let (subject_ms, control_ms) = (
        rebind_ms(preset.guest_rebind_idle),
        rebind_ms(Timeouts::default().guest_rebind_idle),
    );
    // The nominal sample, in whole seconds — the floor of what a live run measures (the guest's own
    // per-iteration cost only ever stretches it).
    let secs = PRESET_SAMPLER.window_ms() / 1000;
    // One listener per window over the sample, which is what each outcome looks like:
    let honored = secs * 1000 / subject_ms;
    let ignored = secs * 1000 / control_ms;
    assert!(
        honored > ignored,
        "the two outcomes must produce different counts ({honored} against {ignored}) or there is \
         nothing here to discriminate"
    );

    // (1) The absolute discriminator, both verdicts, with and without the sockets that are not
    // listeners at all.
    for offset in [0, NON_LISTENER_SOCKETS] {
        assert!(
            churn_beats_midpoint(honored + offset, secs, subject_ms, control_ms),
            "a cell honoring {subject_ms} ms ({} sockets in {secs} s) must clear the midpoint bound",
            honored + offset
        );
        assert!(
            !churn_beats_midpoint(ignored + offset, secs, subject_ms, control_ms),
            "a cell that fell back to {control_ms} ms ({} sockets in {secs} s) must NOT clear the \
             midpoint bound — this is the bound's whole job",
            ignored + offset
        );
    }

    // (2) The rate discriminator, against the default-window twin: honored passes, ignored (the two
    // cells running the SAME cadence, which is what an unread token looks like) fails.
    let twin = (ignored + NON_LISTENER_SOCKETS, secs);
    assert!(churn_rate_beats_midpoint(
        (honored + NON_LISTENER_SOCKETS, secs),
        twin,
        subject_ms,
        control_ms
    ));
    assert!(
        !churn_rate_beats_midpoint(twin, twin, subject_ms, control_ms),
        "two cells showing the same rate must fail the ratio test — that IS the pre-fix behavior"
    );
    // Non-vacuity of the ratio leg: a stretched sample on one cell must not flip either verdict,
    // which is why it compares rates instead of counts. Same outcomes with the control's sample 20%
    // longer.
    assert!(churn_rate_beats_midpoint(
        (honored, secs),
        (ignored * 6 / 5, secs * 6 / 5),
        subject_ms,
        control_ms
    ));

    // (3) The ceiling, which catches the other direction: a guest that clamped the window to the
    // shared floor instead of honoring it.
    let ceiling = churn_ceiling(secs, preset.guest_rebind_idle);
    assert!(
        honored + NON_LISTENER_SOCKETS <= ceiling,
        "the honored count {honored} must sit under the ceiling {ceiling}"
    );
    let floor_clamped = secs * 1000 / rebind_ms(vmcell_protocol::STEWARD_REBIND_IDLE.floor);
    assert!(
        floor_clamped > ceiling,
        "a guest clamping to the {:?} floor ({floor_clamped} sockets) must break the ceiling \
         {ceiling}",
        vmcell_protocol::STEWARD_REBIND_IDLE.floor
    );

    // (4) Non-vacuity of the sample itself, for both legs' samplers: the threshold accepts a real
    // run and rejects a sampler whose `sleep` did nothing.
    for sampler in [HAND_TUNED_SAMPLER, PRESET_SAMPLER] {
        assert!(window_elapsed(sampler.window_ms() / 1000, sampler));
        assert!(
            !window_elapsed(1, sampler),
            "a 1 s report for a {} ms sample must be rejected",
            sampler.window_ms()
        );
    }
}
