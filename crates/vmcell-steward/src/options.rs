//! What the steward is told, and where it learns it (design §3.5, v33 delta 5).
//!
//! Everything that used to be a compiled-in constant or a hardcoded path in `main.rs` is a field
//! of [`StewardOptions`], so a caller — the shipped binary, a `Service`-mode unit, or a host-side
//! unit test — states it rather than inheriting it. Placement is the load-bearing one: the PID-1
//! contract is *parameterized* by it (filesystem assembly, the subreaper bit, SIGTERM policy),
//! never forked into a second copy of the code.
//!
//! **Recorded shift from the §3.5 sketch.** The sketch says "the BINARY parses `/proc/cmdline`".
//! It cannot: under [`GuestPlacement::Pid1`] nothing has mounted `/proc` when the binary starts —
//! the assembly mounts it — so a binary-side read returns `unwrap_or_default()`'s empty string and
//! would silently disable share mounts, the tuning tokens, and the declared port. [`crate::run`]
//! therefore reads `/proc/cmdline` at the placement-correct moment and applies it through
//! [`StewardOptions::apply_cmdline`], which is pure and public — which is what the sketch's
//! testability intent was actually after.

use std::path::PathBuf;
use std::time::Duration;

/// Where this steward runs — the guest-side half of the host's `StewardPlacement` (design §3.5).
///
/// Not a flag and not a config field: the binary derives it from [`Self::from_getpid`], which is
/// unforgeable. A kernel-started steward is pid 1; a systemd- or `mini-init`-started one is not.
///
/// The host's `vmcell::config::StewardPlacement` is a *different* type on purpose — it carries the
/// port and the two C8 questions the host asks, and the steward crate cannot depend on `vmcell`
/// without dragging tokio into a graph `scripts/check-lean-tree.sh` bans.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GuestPlacement {
    /// The kernel started the steward as PID 1 (`init=/usr/sbin/vmcell-steward`).
    ///
    /// The steward owns the filesystem assembly, every orphan reparents to it by definition, and
    /// SIGTERM means "power the guest off" — a returning PID 1 kernel-panics the guest.
    Pid1,
    /// Somebody else's init started the steward as a service.
    ///
    /// The filesystem is already assembled (re-running `pivot_root` would be destructive), the
    /// subreaper bit becomes load-bearing, and SIGTERM means "shut down gracefully and exit" — an
    /// exit that is legal *precisely* because this steward is not pid 1.
    Service,
}

impl GuestPlacement {
    /// Selects the placement from the running process's own pid — unforgeable and flagless.
    #[must_use]
    pub fn from_getpid() -> Self {
        if rustix::process::getpid().is_init() {
            GuestPlacement::Pid1
        } else {
            GuestPlacement::Service
        }
    }

    /// Whether this placement owns the tmpfs/overlay/`pivot_root` assembly (§3.4).
    ///
    /// The fatal-mount policy is scoped with it: under `Service` those mounts are somebody else's,
    /// and re-running the sequence would be destructive rather than merely redundant.
    #[must_use]
    pub const fn assembles_the_filesystem(self) -> bool {
        matches!(self, GuestPlacement::Pid1)
    }

    /// Whether this placement needs `PR_SET_CHILD_SUBREAPER`.
    ///
    /// **This is the regression that would otherwise be silent.** As pid 1 the steward needs no
    /// bit — every orphan reparents to it. As a service it does: without the bit a double-forking
    /// payload reparents to the real init, which reaps it, and
    /// [`crate::ReaperCoordinator::wait_for`] blocks on a status that will never be recorded. The
    /// host sees a hung `exec`, not an error.
    #[must_use]
    pub const fn needs_child_subreaper(self) -> bool {
        matches!(self, GuestPlacement::Service)
    }

    /// The SIGTERM policy this placement implies when the caller names none.
    #[must_use]
    pub const fn default_sigterm_policy(self) -> SigtermPolicy {
        match self {
            GuestPlacement::Pid1 => SigtermPolicy::PowerOff,
            GuestPlacement::Service => SigtermPolicy::Shutdown,
        }
    }
}

/// What SIGTERM means for this steward (design §3.5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SigtermPolicy {
    /// Flush and `reboot(RB_POWER_OFF)`, never returning — the `Pid1` contract.
    PowerOff,
    /// Stop accepting, tear down live sessions per law C3, exit cleanly.
    ///
    /// Under `Pid1` this would kernel-panic the guest. Under `Service` the opposite is true:
    /// `PowerOff` would mean `systemctl stop vmcell-steward` powers off the machine and `restart`
    /// never returns.
    Shutdown,
}

/// Whether [`crate::run`] installs the global `tracing` subscriber.
///
/// A service under a journal — or a host-side unit test that already installed one — must be able
/// to decline; `tracing_subscriber::fmt::init()` is process-global and installing it twice is an
/// error the steward has no business raising.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TracingSetup {
    /// `run` calls `tracing_subscriber::fmt::init()` itself.
    Install,
    /// The caller already installed a subscriber; `run` installs none.
    AlreadyInstalled,
}

/// The vsock accept loop's two cadences (§8.2, §5.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// Failure-recovery cadence: the `bind` retry and every reason `recovery_backoff` rate-limits.
    pub accept_poll: Duration,
    /// Re-bind idle window — the post-restore "deaf listener" bound.
    pub rebind_idle: Duration,
}

/// Compiled **default** recovery cadence for the vsock control plane, used when
/// the host emits no [`vmcell_protocol::STEWARD_ACCEPT_POLL`] token on the cmdline
/// (§5.3, The kernel command line).
///
/// **Derived, not re-typed** (finding G7): the host's own default and this fallback are one fact,
/// and they used to be two literals that happened to be equal — which is what made the whole
/// channel unfalsifiable, since a guest that ignored the token behaved exactly like one that
/// honored it. The shared const carries the token spelling, this default and the clamp window
/// together; see its doc for why the two sides deliberately agree on the *value*.
///
/// **Semantic change (OPP-2):** the accept path itself is event-driven — a
/// blocking `poll(2)` on the listener fd wakes sub-millisecond on connection
/// arrival — so this cadence no longer bounds connect latency. It paces
/// `serve_vsock`'s *failure* recovery: the `bind` retry, and every reason
/// `recovery_backoff` rate-limits. The `parse_ms` floor clamp (1 ms) stays
/// load-bearing on those paths: a hostile `vmcell_accept_poll_ms=0` must not turn
/// a bind→poll→fail loop into a busy-spin.
pub const ACCEPT_POLL: Duration = vmcell_protocol::STEWARD_ACCEPT_POLL.default;

/// Compiled **default** re-bind idle window, used when the host emits no
/// [`vmcell_protocol::STEWARD_REBIND_IDLE`] token on the cmdline (§5.3, The kernel command line):
/// re-bind the listener after this
/// much idle time with no new connection. Bounds the post-restore "deaf listener"
/// window (§8.2, Restore correctness: a restored VM is not a fresh VM): on CH `--restore` the pre-snapshot listener stops yielding
/// accepts, and the guest only re-attaches to the re-created vhost-vsock device by
/// re-binding. Re-binding is harmless during normal operation (accepted
/// connections keep their own fds), so a shorter idle only tightens the worst-case
/// reconnect without new risk.
///
/// Derived from the shared token for the reason [`ACCEPT_POLL`] states.
pub const REBIND_IDLE: Duration = vmcell_protocol::STEWARD_REBIND_IDLE.default;

/// The guest-helper directory the steward prepends to every child's `PATH`, and the mount point a
/// registered handler artifact lands at (§10.5).
pub const DEFAULT_TOOLS_DIR: &str = "/vmcell-tools";

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            accept_poll: ACCEPT_POLL,
            rebind_idle: REBIND_IDLE,
        }
    }
}

/// Everything [`crate::run`] is told, rather than compiles in (design §3.5).
#[derive(Clone, Debug)]
pub struct StewardOptions {
    /// Where this steward runs. Parameterizes the PID-1 contract; never forks the code.
    pub placement: GuestPlacement,
    /// The vsock port to bind. Defaults to [`vmcell_protocol::STEWARD_VSOCK_PORT`]; a cell that
    /// declares `StewardPlacement::Service { port }` moves it through `vmcell_steward_port=`.
    pub vsock_port: u32,
    /// The handler mount point prepended to every child's exec `PATH` (§10.5).
    pub tools_dir: PathBuf,
    /// The accept loop's cadences; the cmdline tuning tokens override these.
    pub tuning: Tuning,
    /// What SIGTERM means. Defaults to [`GuestPlacement::default_sigterm_policy`].
    pub on_sigterm: SigtermPolicy,
    /// The retained-exit-status bound handed to [`crate::ReaperCoordinator::with_max_statuses`].
    pub max_reaped_statuses: usize,
    /// Whether `run` installs the global tracing subscriber.
    pub tracing: TracingSetup,
}

impl StewardOptions {
    /// The defaults for `placement`, with the SIGTERM policy that placement implies.
    #[must_use]
    pub fn new(placement: GuestPlacement) -> Self {
        StewardOptions {
            placement,
            vsock_port: vmcell_protocol::STEWARD_VSOCK_PORT,
            tools_dir: PathBuf::from(DEFAULT_TOOLS_DIR),
            tuning: Tuning::default(),
            on_sigterm: placement.default_sigterm_policy(),
            max_reaped_statuses: crate::DEFAULT_MAX_REAPED_STATUSES,
            tracing: TracingSetup::Install,
        }
    }

    /// Applies the `vmcell_`-prefixed kernel-cmdline tokens over these options.
    ///
    /// The cmdline is **untrusted** (§5.3) — F3's `vmcell_` prefix rule reserves the tokens
    /// against caller spoofing, but their *values* are whatever arrived. The tuning tokens are
    /// deliberately forgiving (absent/garbage → the compiled default, clamped to a correctness
    /// floor so a hostile `0` cannot busy-spin). The port token is deliberately **not**: see
    /// [`parse_steward_port`].
    ///
    /// The two cadence tokens are read through their shared [`vmcell_protocol::TuningToken`]s, so
    /// their spelling, fallback and clamp window are the host's — there is no second copy here to
    /// drift from the emitter (finding G7). That the guest really *acts* on what arrives is a live
    /// property, gated by `vmcell/tests/guest_tuning.rs`.
    pub fn apply_cmdline(&mut self, cmdline: &str) {
        self.tuning.accept_poll = parse_tuning(cmdline, vmcell_protocol::STEWARD_ACCEPT_POLL);
        self.tuning.rebind_idle = parse_tuning(cmdline, vmcell_protocol::STEWARD_REBIND_IDLE);
        match parse_steward_port(cmdline) {
            StewardPortToken::Absent => {}
            StewardPortToken::Valid(port) => self.vsock_port = port,
            StewardPortToken::Invalid(raw) => {
                // Loud, and then the default — the host is dialing *something*, and a silent
                // fallback would leave the two sides on different ports with nothing but an opaque
                // connect timeout to show for it. This warning plus the host's control-plane health
                // gate is what turns that class into a diagnosis (§3.5).
                tracing::warn!(
                    "vmcell-steward: ignoring malformed vmcell_steward_port={:?}; binding the \
                     default port {}. If the host declared a non-default port, the control plane \
                     will not come up.",
                    raw,
                    vmcell_protocol::STEWARD_VSOCK_PORT
                );
            }
        }
    }
}

/// What a `vmcell_steward_port=` token on the kernel command line turned out to be.
///
/// Three outcomes, not two: "absent" and "garbage" mean different things to an operator, and
/// collapsing them is what would make a typo look like a default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StewardPortToken {
    /// No token — the cell declared the default port, which is emitted as no token at all.
    Absent,
    /// A usable port.
    Valid(u32),
    /// Present and unusable, carrying the raw text for the warning.
    Invalid(String),
}

/// Parses `vmcell_steward_port=` from the kernel command line — **strictly**, unlike its
/// forgiving `parse_ms` siblings.
///
/// §3.5's rule, and the reason for the asymmetry: a garbage tuning token costs a cadence, while a
/// garbage port token would leave the host dialing one port and the steward bound to another — a
/// mismatch that surfaces only as an opaque connect timeout. So the parse rejects rather than
/// silently clamps, `run` logs the rejection, and the value falls back to the default the host
/// omits the token for.
///
/// `0` and `u32::MAX` are the AF_VSOCK reserved values `VmConfigBuilder::build` already refuses
/// host-side; rejecting them here too keeps the two sides' validity domains equal.
#[must_use]
pub fn parse_steward_port(cmdline: &str) -> StewardPortToken {
    let Some(raw) = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("vmcell_steward_port="))
    else {
        return StewardPortToken::Absent;
    };
    match raw.parse::<u32>() {
        Ok(port) if port != 0 && port != u32::MAX => StewardPortToken::Valid(port),
        _ => StewardPortToken::Invalid(raw.to_string()),
    }
}

/// A virtio-fs share the guest must mount, decoded from one `vmcell_share=` token.
pub(crate) struct ShareMount {
    /// virtio-fs mount tag.
    pub(crate) tag: String,
    /// Absolute in-guest mount point (the host's `Share::guest_path`, default `/<tag>`).
    pub(crate) mount_point: String,
    /// Whether to mount read-only (the host declared `ro`).
    pub(crate) read_only: bool,
}

/// Parses `vmcell_share=<tag>:<guest_path>:<ro|rw>` tokens out of the kernel
/// command line.
///
/// The host emits one token per configured share (`config::push_share_args`), and
/// the guest mounts each `tag` at its `guest_path`. A token is skipped — never
/// trusted — when it is malformed (fewer than three `:`-separated fields, an empty
/// tag or mount point, or an access mode other than `ro`/`rw`), so a corrupt boot
/// line cannot silently mount read-write a share the host declared read-only.
pub(crate) fn parse_share_mounts(cmdline: &str) -> Vec<ShareMount> {
    cmdline
        .split_ascii_whitespace()
        .filter_map(|tok| tok.strip_prefix("vmcell_share="))
        .filter_map(|spec| {
            let mut fields = spec.splitn(3, ':');
            let tag = fields.next()?;
            let mount_point = fields.next()?;
            let access = fields.next()?;
            if tag.is_empty() || mount_point.is_empty() {
                return None;
            }
            let read_only = match access {
                "ro" => true,
                "rw" => false,
                _ => return None,
            };
            Some(ShareMount {
                tag: tag.to_string(),
                mount_point: mount_point.to_string(),
                read_only,
            })
        })
        .collect()
}

/// Reads one shared host↔guest cadence token off the (UNTRUSTED) kernel command line.
///
/// The **one** place a [`vmcell_protocol::TuningToken`] is unpacked into [`parse_ms`]'s bounds, and
/// the reason it is a function rather than four arguments at each call site: `floor_ms` and
/// `ceil_ms` are adjacent same-typed parameters, so a transposed pair would clamp every arriving
/// value to the ceiling and read as a plausible cadence. One unpacking site, two call sites, no way
/// to transpose them differently.
///
/// The token, the fallback and the window all come from the shared const, so there is no spelling or
/// default left on this side of the boundary for the host's copy to drift from (finding G7).
fn parse_tuning(cmdline: &str, token: vmcell_protocol::TuningToken) -> Duration {
    parse_ms(
        cmdline,
        token.token,
        token.default_ms(),
        token.floor_ms(),
        token.ceiling_ms(),
    )
}

/// Parses a whole-millisecond timeout token out of the (UNTRUSTED) kernel command
/// line, clamped into the inclusive `[floor_ms, ceil_ms]` window.
///
/// Scans the whitespace-split tokens for the first that `strip_prefix(key)` and
/// then parses as a `u64`, and clamps the result into `[floor_ms, ceil_ms]` — so a
/// hostile or fat-fingered boot line cannot drive a guest timeout to a busy-spin
/// (`0`) or an unbounded stall. An absent, non-numeric, or overflowing token falls
/// back to `default_ms` (assumed already in range). `/proc/cmdline` is
/// host-controlled but treated as untrusted here, exactly like
/// [`parse_share_mounts`].
pub(crate) fn parse_ms(
    cmdline: &str,
    key: &str,
    default_ms: u64,
    floor_ms: u64,
    ceil_ms: u64,
) -> std::time::Duration {
    let ms = cmdline
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix(key)?.parse::<u64>().ok())
        .map_or(default_ms, |v| v.clamp(floor_ms, ceil_ms));
    std::time::Duration::from_millis(ms)
}

/// The **host's own renderer feeding the guest's own parser** — the two ends of the tuning channel
/// meeting in one KVM-free test.
///
/// It lives beside the parser (rather than in `tests.rs` with the rest of the battery) because it is
/// the only test in the tree that can hold both halves: `vmcell` — which emits these tokens — cannot
/// see this crate, and this crate cannot see `vmcell`, which is precisely the asymmetry that let the
/// two spellings drift with nothing red (finding G7). `vmcell_protocol::TuningToken::render` is the
/// production emitter `vmcell::config::push_guest_timeout_args` calls, so what is parsed here is
/// byte-for-byte what a real cell boots with.
#[cfg(test)]
mod token_channel_tests {
    use super::{GuestPlacement, StewardOptions};
    use std::time::Duration;
    use vmcell_protocol::{STEWARD_ACCEPT_POLL, STEWARD_REBIND_IDLE};

    /// A cmdline shaped like the real one: owned tokens on both sides of the rendered pair, so a
    /// parser that took the whole line (or the wrong neighbour) cannot pass.
    fn rendered_cmdline(accept: Duration, rebind: Duration) -> String {
        format!(
            "console=ttyS0 loglevel=6 root=/dev/vda ro {} {} panic=1 \
             init=/usr/sbin/vmcell-steward vmcell_vmid=7",
            STEWARD_ACCEPT_POLL.render(accept),
            STEWARD_REBIND_IDLE.render(rebind),
        )
    }

    // A NON-DEFAULT profile, rendered by the host's emitter, must arrive as itself. This is the
    // assertion the pre-fix tree could not make: the guest's fallbacks were byte-identical to the
    // host's defaults, so every test that booted a default cell passed whether or not the parse
    // existed at all.
    //
    // RED on the inverse, three ways, all measured: (1) hand-spell either token in
    // `apply_cmdline` (`vmcell_accept_poll=`) — the equality fires with 20 ms against 5 ms;
    // (2) delete a `parse_tuning` line — the same, with the compiled default; (3) transpose
    // `floor_ms`/`ceiling_ms` in `parse_tuning` — `u64::clamp` panics on `min > max`, so both this
    // test and the window one fail inside [`parse_ms`] rather than returning a plausible cadence.
    // Renaming the shared const itself does not need this test: it is a compile error on both sides
    // at once, which is the whole point of moving the spelling into the shared crate.
    #[test]
    fn a_non_default_profile_rendered_by_the_host_is_the_one_the_guest_resolves() {
        // `Timeouts::low_latency()`'s guest half, the profile finding G7 names as the silent
        // casualty: a caller asking for 5 ms / 150 ms and getting 20 / 250.
        let (accept, rebind) = (Duration::from_millis(5), Duration::from_millis(150));
        let mut opts = StewardOptions::new(GuestPlacement::Pid1);
        opts.apply_cmdline(&rendered_cmdline(accept, rebind));
        assert_eq!(
            opts.tuning.accept_poll, accept,
            "the guest must honor the accept cadence the host rendered, not its own fallback"
        );
        assert_eq!(
            opts.tuning.rebind_idle, rebind,
            "the guest must honor the re-bind window the host rendered — this is the number that \
             bounds how long a restored guest stays unreachable (§8.2)"
        );
        // Non-vacuity: the values asserted above are NOT the fallbacks, so the assertions cannot be
        // satisfied by a steward that ignored the command line entirely.
        assert_ne!(accept, STEWARD_ACCEPT_POLL.default);
        assert_ne!(rebind, STEWARD_REBIND_IDLE.default);
    }

    // The window is shared too, so an out-of-range render resolves to the SHARED bound rather than
    // to a second copy of it. Both directions, because the host clamps only the floor: a value under
    // the floor is a config error the host also refuses, while one over the ceiling is a divergence
    // only this side can bound.
    //
    // RED on the inverse: replace either bound in `parse_tuning` with a literal that differs from
    // the shared const (say `ceil_ms = 5_000`) and the ceiling assertion fires.
    #[test]
    fn an_out_of_window_render_resolves_to_the_shared_bound() {
        let mut opts = StewardOptions::new(GuestPlacement::Pid1);
        opts.apply_cmdline(&rendered_cmdline(
            Duration::ZERO,
            STEWARD_REBIND_IDLE.ceiling + Duration::from_secs(60),
        ));
        assert_eq!(
            opts.tuning.accept_poll, STEWARD_ACCEPT_POLL.floor,
            "a rendered 0 must clamp to the shared floor: PID 1's bind-retry loop must not busy-spin"
        );
        assert_eq!(
            opts.tuning.rebind_idle, STEWARD_REBIND_IDLE.ceiling,
            "an absurd re-bind window must clamp to the shared ceiling"
        );
    }

    // An absent token means "the host said nothing", and the fallback must be the SHARED default —
    // the same fact the host emits for a default profile, not a second literal that happens to
    // match it today.
    //
    // RED on the inverse: re-type either fallback in `options.rs` as a literal (say 30 ms) and the
    // equality fires; the pre-fix tree had exactly that shape and no test could see it.
    #[test]
    fn an_absent_token_falls_back_to_the_shared_default() {
        let mut opts = StewardOptions::new(GuestPlacement::Pid1);
        opts.apply_cmdline("console=ttyS0 ro init=/usr/sbin/vmcell-steward vmcell_vmid=7");
        assert_eq!(opts.tuning.accept_poll, STEWARD_ACCEPT_POLL.default);
        assert_eq!(opts.tuning.rebind_idle, STEWARD_REBIND_IDLE.default);
        assert_eq!(super::ACCEPT_POLL, STEWARD_ACCEPT_POLL.default);
        assert_eq!(super::REBIND_IDLE, STEWARD_REBIND_IDLE.default);
    }
}
