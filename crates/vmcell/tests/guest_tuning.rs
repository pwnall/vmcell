//! The host→guest **tuning channel**, observed end to end: a cell that declares a non-default
//! `Timeouts` profile and a guest that is caught honoring it (finding G7).
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
//! port's leg fell into (`service_steward.rs`). So this leg measures the *mechanism* instead: the
//! re-bind loop drops its listener and `bind`s a fresh one after `rebind_idle` of idleness (§8.2),
//! and a fresh `socket(2)` gets a fresh inode number that never repeats. Counting the DISTINCT
//! `socket:[…]` targets under `/proc/1/fd` over a fixed sampling window therefore counts how many
//! listeners PID 1 created during it — a measured cadence, read out of the kernel's own bookkeeping,
//! with no guest-side code added for the test (law C6's spirit: no new guest code, and nothing in
//! `vmcell-steward` knows this leg exists).
//!
//! The sampling runs inside ONE `exec`, deliberately: only a real `accept` restarts the idle
//! deadline, so a host that polled from outside would reset the very window it is measuring.
//!
//! Paired, in one test, because the number alone means nothing: the same script, on the same
//! rootfs, against two cells differing in exactly one variable — the declared window. The long-window
//! cell must show a handful of listeners and the default-window cell an order of magnitude more. A
//! guest that ignores the token produces the *same* count for both, which is the pre-fix behavior
//! said out loud.
//!
//! CH-only, like `service_steward.rs` and `custom_init.rs`: this is a guest-side property reached
//! through a host-side cmdline feature, so one primary-backend proof suffices, and it needs no
//! capability beyond KVM (`network_disabled`, no tap, no snapshot).
//!
//! **Which recipe selects it.** `just test-privileged` (`-p vmcell … --run-ignored all -E 'kind(test)
//! & !(test(unprivileged) | test(smoltcp))'`) — the live leg is `#[ignore]`d and no other filter
//! picks it up. The KVM-free premise check below runs everywhere, including `just ci`.
//!
//! **"Runs everywhere" is a claim about the HOST, not about an attribute list** — and it shipped
//! false. The premise check reached `common::get_vmlinux()`/`get_rootfs()` through the shared config
//! builder, and those getters do not hand back a path: they **require a built artifact**, failing
//! loud with `guest kernel missing at …/vmlinux`. Every box that has run `vmcell build` satisfies
//! that and no fresh checkout does, so `just test-unit` was green on a developer box and red in CI's
//! artifact-free `test-unit` job. The artifact pair is therefore a **parameter** of
//! [`tuned_cell_cfg`]: the live leg hands it the real artifacts, and the premise check hands it a
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
//! `CONFIG_KVM_INTEL`), then `just bless` (one sudo; blessing is stripped on rewrite), then
//! `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just
//! test-privileged`.

#![cfg(feature = "cloud-hypervisor")]

use std::path::PathBuf;
use std::time::Duration;

use vmcell::config::{RootfsSource, Timeouts, VmConfig};
use vmcell::steward::ExecRequest;

mod common;

/// The re-bind window the subject cell declares: 16× the shipped default, so the difference in
/// observed listener churn is an order of magnitude rather than a ratio inside the noise. Well
/// inside `STEWARD_REBIND_IDLE`'s ceiling, so the guest honors it verbatim rather than clamping it
/// (pinned by [`the_measured_window_is_non_default_and_honored_verbatim`]).
const SUBJECT_REBIND_IDLE: Duration = Duration::from_millis(4_000);

/// How many 100 ms samples the in-guest script takes: ~9 s of wall time, which is two full
/// [`SUBJECT_REBIND_IDLE`] windows and ~36 default ones.
const SAMPLES: u32 = 90;

/// Samples PID 1's socket-inode set for [`SAMPLES`] × 100 ms and prints
/// `<distinct sockets> <elapsed seconds>`.
///
/// `readlink` rather than `ls -l`: the link target is the datum, and `ls`'s columns are locale- and
/// timestamp-shaped. The elapsed seconds are printed — and asserted on — because a `sleep` that did
/// not sleep would make the whole measurement finish in milliseconds and the low-churn assertion
/// pass vacuously. The sample count is spliced from [`SAMPLES`] rather than typed into the script,
/// so the window the assertions reason about and the window the guest runs cannot drift apart.
fn sample_listener_churn_sh() -> String {
    format!(
        "start=$(date +%s); \
         n=$(for i in $(seq 1 {SAMPLES}); do readlink /proc/1/fd/* 2>/dev/null; sleep 0.1; done \
             | sed -n 's/^socket:\\[\\([0-9]*\\)\\]$/\\1/p' | sort -u | wc -l); \
         echo \"$n $(( $(date +%s) - start ))\""
    )
}

/// A re-bind window in whole milliseconds, for the count arithmetic. Saturating, and never zero:
/// this is a divisor, and the shared floor keeps the real value well clear of it.
fn rebind_ms(window: Duration) -> u64 {
    u64::try_from(window.as_millis()).unwrap_or(u64::MAX).max(1)
}

/// A `Pid1` cell (the steward IS pid 1, so the sampler reads `/proc/1/fd`) whose only non-default
/// property is the declared re-bind window, over the artifact pair it is handed.
///
/// The pair is a parameter rather than a `common::get_*()` call inside: those getters **build or
/// require** the artifacts, so calling them here made the KVM-free premise check below fail on every
/// host that has not run `vmcell build` (see the module header). The live leg passes the real pair.
fn tuned_cell_cfg(kernel: PathBuf, rootfs_image: PathBuf, rebind_idle: Duration) -> VmConfig {
    // `Timeouts` is `#[non_exhaustive]`, so an out-of-crate caller cannot use struct-update syntax
    // (`Timeouts { .., ..Default::default() }` does not compile here) and mutates the `pub` field
    // instead — which is also the shape a real caller uses, and the one the orchestrator re-clamps
    // at `start()` (M-ORCH-3).
    let mut timeouts = Timeouts::default();
    timeouts.guest_rebind_idle = rebind_idle;

    VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .timeouts(timeouts)
    .network_disabled()
    .build()
    .expect("a Pid1 cell with a tuned re-bind window is an ordinary cell")
}

/// Boots a cell with `rebind_idle`, measures PID 1's listener churn, and tears it down.
///
/// The one place the real artifact pair enters: `common::get_vmlinux`/`get_rootfs` require a built
/// `vmlinux` + `rootfs.erofs`, which is a live-suite precondition and not a premise-check one.
///
/// Returns `(distinct socket inodes, elapsed seconds the guest measured)`.
async fn measure_listener_churn(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    rebind_idle: Duration,
) -> (usize, u64) {
    let cfg = tuned_cell_cfg(common::get_vmlinux(), common::get_rootfs(), rebind_idle);
    let mut vm = common::start_vm(vmm, cfg).await;

    let out = vm
        .steward(Some(Duration::from_secs(30)))
        .await
        .expect("a Pid1 cell must answer on the control plane")
        .exec(
            ExecRequest::new(vec![
                "/bin/sh".into(),
                "-c".into(),
                sample_listener_churn_sh(),
            ])
            // Well past the ~9 s sample: `handle_exec` arms a kill thread on the child's process
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
                .parse::<usize>()
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

    let (subject, subject_secs) = measure_listener_churn(&vmm, SUBJECT_REBIND_IDLE).await;
    let (control, control_secs) =
        measure_listener_churn(&vmm, vmcell_protocol::STEWARD_REBIND_IDLE.default).await;
    // `u64` from here on: the counts feed the rate arithmetic below, and one conversion site beats a
    // cast per assertion.
    let (subject, control) = (
        u64::try_from(subject).unwrap_or(u64::MAX),
        u64::try_from(control).unwrap_or(u64::MAX),
    );

    // Non-vacuity first: both samples really covered their window. A `sleep` that silently did
    // nothing (or a sampler killed early) would collapse the window to milliseconds, and a
    // "hardly any re-binds" assertion on a window that never elapsed proves nothing at all.
    for (name, secs) in [("subject", subject_secs), ("control", control_secs)] {
        assert!(
            secs >= 8,
            "{name}: the in-guest sampler must cover its window; it reported {secs} s for \
             {SAMPLES} × 100 ms"
        );
    }

    // The control is the positive control for the OBSERVATION: at the shipped 250 ms the steward
    // re-binds ~36 times in this window, so a count near 1 would mean the measurement cannot see a
    // re-bind at all and the subject's low count is meaningless.
    assert!(
        control >= 12,
        "the default 250 ms window must produce visible listener churn — {control} distinct sockets \
         in {control_secs} s means /proc/1/fd is not showing re-binds, so this leg cannot see the \
         property it exists to measure"
    );

    // The subject: one listener per declared window, plus the sockets that are not listeners at all
    // (the accepted control-plane connection, and whatever else PID 1 holds open across the sample)
    // — then doubled, so scheduling noise on a loaded host cannot turn a cadence assertion into a
    // flake. The bound is derived from the window the GUEST measured rather than from a constant,
    // because the number of re-binds is a function of wall time: a slow box stretches the sample and
    // legitimately raises the count, and a fixed ceiling would call that a defect.
    //
    // MEASURED on this host: 6 distinct sockets over a 9 s window against a bound of 10, and 40 over
    // a 10 s window when the emitter was planted to send the default — so the green margin is ~1.7×
    // and the red one ~4×.
    let subject_ceiling = 4 + 2 * (1 + subject_secs * 1000 / rebind_ms(SUBJECT_REBIND_IDLE));
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

/// The live leg's premise, checked without KVM **and without a built artifact**: the window it
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
    // has run `vmcell build` (the module header records the CI red that taught us). The files are real
    // and absolute because that is what the builder validates at this boundary — it checks
    // absoluteness and deliberately not existence, so this stays honest if it ever checks both.
    let pair = tempfile::tempdir().expect("a scratch dir for the artifact pair");
    let (kernel, rootfs) = (
        pair.path().join("vmlinux"),
        pair.path().join("rootfs.erofs"),
    );
    std::fs::write(&kernel, b"not a kernel").expect("write the kernel stand-in");
    std::fs::write(&rootfs, b"not an image").expect("write the rootfs stand-in");
    assert_eq!(
        tuned_cell_cfg(kernel, rootfs, SUBJECT_REBIND_IDLE)
            .timeouts
            .guest_rebind_idle,
        SUBJECT_REBIND_IDLE,
        "the builder must carry the declared window through unclamped"
    );
    // The sample window must span several subject windows, or "a handful of re-binds" is a bound on
    // a window that never elapsed.
    assert!(
        u64::from(SAMPLES) * 100 >= 2 * rebind_ms(SUBJECT_REBIND_IDLE),
        "the sampling window ({SAMPLES} × 100 ms) must cover at least two declared \
         {SUBJECT_REBIND_IDLE:?} re-bind windows"
    );
}
