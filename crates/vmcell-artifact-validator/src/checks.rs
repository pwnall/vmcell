//! The contract checks, **extracted** from vmcell's integration suite so the validator and the
//! tests share one implementation. Each check is `async fn(...) -> Result<(), String>`
//! (`Ok` = the contract property held, `Err(msg)` = it was violated). The validator maps those
//! onto [`CheckStatus`](crate::CheckStatus); a refactored integration test calls the same
//! function and asserts `Ok`.
//!
//! Checks operate on the primitives they need — a `&mut StewardClient` for guest probes, a
//! `&MicroVm` for host-side reads (serial log, cgroup usage), or a backend `&V` for
//! multi-VM checks (concurrency). The [`run_core`]/[`run_extended`]/[`run_full`] orchestrators
//! boot capability-appropriate VMs and collect outcomes.

use std::path::Path;
use std::time::Duration;

use vmcell::ExecRequest;
use vmcell::config::{
    Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig, VmConfigBuilder,
};
use vmcell::orchestrator::MicroVm;
use vmcell::steward::StewardClient;
use vmcell::vmm::{VmInstance, Vmm};

use crate::classify::{
    BANNER_SIGNATURE, BootKind, explain_boot_failure_of, explain_without_serial,
};
use crate::conformance::ProbeOutcome;
use crate::harness::{cgroup_memory_delegated, try_start_vm};
use crate::{ArtifactSet, CheckOutcome, Level};

/// Tears a probe VM down once its check's verdict has already been decided, reporting a failure
/// rather than discarding it.
///
/// WHY NOT PROPAGATING IS CORRECT HERE, and why this is a function rather than eleven bare
/// `let _ =` statements (AGENTS.md "Fail loud", plus its Suppressions rule — *route repeated
/// legitimate sites through one helper*):
///
///   * The verdict is **already recorded**. Every call site sits after a `record(…)`, a `return
///     Err(…)`, or the last observation the check makes. Turning a teardown error into the check's
///     answer would report a *host* problem as an *artifact* contract violation, which is the one
///     thing this crate must never do.
///   * Teardown is not skipped, only its graceful half: [`MicroVm`]'s `Drop` is the guaranteed,
///     ordered path (AGENTS.md "Teardown is ownership"), so a failed `shutdown()` leaks nothing.
///   * It is still **said out loud**, at `warn!`, because a run where every VM failed to shut down
///     gracefully is a run whose host is in trouble — and that used to be invisible.
async fn shutdown_after_check<V: Vmm>(vm: MicroVm<V>) {
    if let Err(e) = vm.shutdown().await {
        tracing::warn!(
            "artifact-validator: graceful VM shutdown failed after a check ({e}); \
             MicroVm::Drop is the guaranteed teardown"
        );
    }
}

/// The steward-handshake budget every check allows before it calls the boot failed (§9.4: deadlines
/// are outer-bounds-inner — this is the outer bound `StewardClient` turns into its `Instant`).
/// **One** statement of the number: an inline per-call 60-second literal anywhere in this module is
/// a second copy of the same law, and `every_steward_budget_is_a_named_const` reddens on it.
const STEWARD_READY_BUDGET: Duration = Duration::from_secs(60);

/// The steward-handshake budget for a VM booted **concurrently with others**
/// (`concurrency_distinct_ids`): three guests contending for the same host take longer than one.
const CONCURRENT_STEWARD_READY_BUDGET: Duration = Duration::from_secs(180);

/// How long [`kernel_banner`] waits for the kernel's banner before calling the boot failed.
const KERNEL_BANNER_BUDGET: Duration = Duration::from_secs(15);

/// How long `metrics.usage_readable` lets the booted guest run before reading its cgroup counters
/// back — `memory.peak` is only non-zero once the guest has actually touched memory.
const USAGE_SETTLE: Duration = Duration::from_secs(2);

/// How often [`await_kernel_banner`] re-reads the console while waiting.
const BANNER_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Reads `serial_log` and renders the classified boot failure — the one composition every arm with
/// a **live VM** uses (`fs` + [`explain_boot_failure_of`]).
///
/// The unreadable case is not silently rendered as an empty console: an empty captured log means
/// "the VM ran and printed nothing" (a real §5.4 signature *for a fresh boot*), while an unreadable
/// log is *absence of evidence*, so it routes through [`explain_without_serial`] instead. Either
/// way the message names the console it consulted, so the reader can go look at it.
///
/// `kind` is explicit at every call site (no default): the only VM in this module whose console is
/// empty **by construction** is the restored one in [`snapshot_restore_attempt`], and rendering
/// it as a fresh boot accused a kernel that had provably just booted of not being a kernel.
async fn explain_boot_failure_at(kind: BootKind, serial_log: &Path, base: &str) -> String {
    let base = format!("{base} (serial log {})", serial_log.display());
    match tokio::fs::read_to_string(serial_log).await {
        Ok(text) => explain_boot_failure_of(kind, &text, &base),
        Err(e) => {
            tracing::warn!(
                path = %serial_log.display(),
                error = %e,
                "serial log unreadable; reporting the boot failure without console evidence"
            );
            explain_without_serial(&base, &format!("it could not be read: {e}"))
        }
    }
}

/// [`explain_boot_failure_at`] against a **freshly booted** VM's own console — the single place a
/// serial-log path is derived from a [`MicroVm`]. A restored VM's console goes through
/// [`explain_boot_failure_at`] with [`BootKind::Restored`]; there is no `MicroVm` predicate for
/// "was this restored?" (the orchestrator's `restored` flag is private and one-shot), so the
/// distinction is made where the restore happens.
async fn explain_boot_failure_for<V: Vmm>(vm: &MicroVm<V>, base: &str) -> String {
    explain_boot_failure_at(BootKind::Fresh, vm.instance().serial_log(), base).await
}

/// The message every `MicroVm::start` failure records — one shape for all of them, since they all
/// lose the console the same way (the per-VM scratch dir dies with the failed start).
fn failed_start(e: &impl std::fmt::Display) -> String {
    explain_without_serial(
        &format!("VM failed to start: {e}"),
        "MicroVm::start failed and took its per-VM scratch dir (with the console) with it",
    )
}

/// The base sentence every steward-handshake failure records, naming the budget that expired.
///
/// `budget` is passed rather than read off [`STEWARD_READY_BUDGET`] so the sentence names the budget
/// the call **actually** used: the arms that inject a different one (a unit test's millisecond
/// budget, a concurrent boot's longer one) must not report the default's number.
fn steward_handshake_base(e: &impl std::fmt::Display, budget: Duration) -> String {
    format!(
        "steward handshake failed within the {}s budget: {e}",
        budget.as_secs()
    )
}

/// A base builder for `artifacts` (the caller-supplied kernel + erofs rootfs pair).
fn base_cfg(a: &ArtifactSet) -> VmConfigBuilder {
    VmConfig::builder(
        a.kernel.clone(),
        RootfsSource::Erofs {
            image: a.rootfs.clone(),
        },
    )
}

/// Runs `argv` in the guest, mapping a steward transport error into a check-failure string.
async fn exec(steward: &mut StewardClient, argv: &[&str]) -> Result<vmcell::ExecOutcome, String> {
    let req = ExecRequest::new(argv.iter().map(|s| (*s).to_string()).collect());
    steward
        .exec(req)
        .await
        .map_err(|e| format!("steward exec {argv:?} failed at the transport level: {e}"))
}

// ---------------------------------------------------------------------------
// Core checks (need only KVM; run on one net-disabled VM)
// ---------------------------------------------------------------------------

/// The kernel reaches userspace: the serial console shows the [`BANNER_SIGNATURE`] banner within a
/// bounded window (← `boot.rs`). A kernel that never boots (bad config, wrong format) reddens.
///
/// On failure the message names the §5.4 contract clause the serial log proves was broken
/// ([`explain_boot_failure_of`]) — never a bare timeout (§5.6).
///
/// # Errors
/// Returns `Err` if the kernel never reaches userspace within the boot window (bad config / wrong format) or the console cannot be read.
pub async fn kernel_banner<V: Vmm>(vm: &MicroVm<V>) -> Result<(), String> {
    await_kernel_banner(vm.instance().serial_log(), KERNEL_BANNER_BUDGET).await
}

/// The bounded banner poll, with the budget injected so it is drivable in a unit test (§9.4: the
/// deadline is an [`tokio::time::Instant`], computed once and bounding the whole loop).
///
/// Both failure shapes are distinguished, because they have different causes: a console that was
/// *read* and lacks the banner is evidence for [`explain_boot_failure_of`] to classify, while a
/// console file the VMM never created is *no* evidence and routes through
/// [`explain_without_serial`].
async fn await_kernel_banner(serial_log: &Path, budget: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + budget;
    // `None` until the file is first read: an unwritten console is the normal early-boot case, so
    // it is retried rather than reported. The newest text that *was* read is what the classifier
    // sees when the budget expires.
    let mut last: Option<String> = None;
    loop {
        if let Ok(content) = tokio::fs::read_to_string(serial_log).await {
            if content.contains(BANNER_SIGNATURE) {
                return Ok(());
            }
            last = Some(content);
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(BANNER_POLL_INTERVAL).await;
    }
    let base = format!(
        "kernel did not print the '{BANNER_SIGNATURE}' banner within {}s (serial log {})",
        budget.as_secs(),
        serial_log.display()
    );
    Err(match last {
        // Fresh: `await_kernel_banner` only ever polls a VM booted from its kernel entry point,
        // so an absent banner IS the §5.4 no-direct-boot-kernel signature here.
        Some(text) => explain_boot_failure_of(BootKind::Fresh, &text, &base),
        None => explain_without_serial(
            &base,
            "the VMM never created the serial log, so no console was captured",
        ),
    })
}

/// An exec round-trips: `echo` returns exit 0 with the expected stdout (← `boot.rs`). Proves the
/// vsock control plane + PID-1 steward exec path end to end.
///
/// # Errors
/// Returns `Err` if the exec fails, exits non-zero, or returns unexpected stdout.
pub async fn steward_exec_roundtrip(steward: &mut StewardClient) -> Result<(), String> {
    let out = exec(steward, &["echo", "vmcell-validate-marker"]).await?;
    if out.code != 0 {
        return Err(format!("echo exited {} (expected 0)", out.code));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("vmcell-validate-marker") {
        return Err(format!("echo stdout missing marker; got {stdout:?}"));
    }
    Ok(())
}

/// `put_file` then read the bytes back **in the guest** — a real round-trip, not a mock UDS
/// assertion (← `exec_vsock.rs`; AGENTS.md "mock where round-trip is required"). Proves the
/// PutFile protocol writes real guest files.
///
/// # Errors
/// Returns `Err` if `put_file` fails or the bytes read back in-guest differ.
pub async fn steward_put_file_roundtrip(steward: &mut StewardClient) -> Result<(), String> {
    let dst = "/run/vmcell-validate-putfile";
    let payload = b"vmcell-validate-putfile-payload-42";
    steward
        .put_file(dst, payload, Some(Duration::from_secs(10)))
        .await
        .map_err(|e| format!("put_file failed: {e}"))?;
    let out = exec(steward, &["cat", dst]).await?;
    if out.code != 0 {
        return Err(format!("reading back {dst} exited {}", out.code));
    }
    if out.stdout != payload {
        return Err(format!(
            "put_file round-trip mismatch: wrote {} bytes, read {} back",
            payload.len(),
            out.stdout.len()
        ));
    }
    Ok(())
}

/// The rootfs ships glibc `libc.so.6` (← §4.2, Rootfs sources and the one packer libc6 scan; the dynamically-linked steward already
/// proves it, but a custom rootfs is checked explicitly across the common multiarch paths).
///
/// # Errors
/// Returns `Err` if `libc.so.6` is absent from every probed multiarch path (or the probe exec fails).
pub async fn rootfs_libc6(steward: &mut StewardClient) -> Result<(), String> {
    let out = exec(
        steward,
        &[
            "sh",
            "-c",
            "test -e /lib/x86_64-linux-gnu/libc.so.6 || test -e /lib64/libc.so.6 \
             || test -e /usr/lib/x86_64-linux-gnu/libc.so.6",
        ],
    )
    .await?;
    if out.code != 0 {
        return Err("glibc libc.so.6 not found at any standard path (§5.4)".into());
    }
    Ok(())
}

/// The injected deployment proxy CA is baked into the trust store (← §4.2, Rootfs sources and the one packer / §10, The artifact build pipeline CA injection).
///
/// # Errors
/// Returns `Err` if the injected proxy CA is not present in the guest trust store.
pub async fn rootfs_ca_cert(steward: &mut StewardClient) -> Result<(), String> {
    let out = exec(
        steward,
        &[
            "test",
            "-f",
            "/usr/local/share/ca-certificates/vmcell-ca.crt",
        ],
    )
    .await?;
    if out.code != 0 {
        return Err(
            "injected deployment CA (/usr/local/share/ca-certificates/vmcell-ca.crt) missing"
                .into(),
        );
    }
    Ok(())
}

/// The shell command that proves **every** guest-tools applet resolves on the exec PATH:
/// `command -v <applet> >/dev/null` per [`vmcell_protocol::GUEST_TOOLS_APPLETS`] entry, `&&`-ed.
///
/// Composed from the roster, never re-typed. The roster is the one list the helper's dispatch
/// table, the rootfs symlink manifest, and this check all derive from (design §4.4), and this
/// module held the last re-typed copy — three of the four names in a shell string, which is how a
/// roster grows an applet that nothing on the contract surface ever checks for.
///
/// # Errors
/// Returns `Err` as [`probe_command_for`] does.
fn guest_tools_probe_command() -> Result<String, String> {
    probe_command_for(vmcell_protocol::GUEST_TOOLS_APPLETS)
}

/// [`guest_tools_probe_command`]'s composition, taking the roster as an argument so its accept /
/// reject matrix is unit-testable against rosters the shipped const cannot express.
///
/// # Errors
/// Returns `Err` if a roster entry is not a bare word (it would need quoting to survive `sh -c`,
/// and a probe that silently mis-parses is a check that passes for the wrong reason) or if the
/// roster is empty (a probe of nothing passes vacuously).
fn probe_command_for(roster: &[&str]) -> Result<String, String> {
    if roster.is_empty() {
        return Err("GUEST_TOOLS_APPLETS is empty: the PATH probe would pass vacuously".into());
    }
    let mut probes = Vec::with_capacity(roster.len());
    for applet in roster {
        if applet.is_empty()
            || !applet
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(format!(
                "guest-tools applet {applet:?} is not a bare word; the `sh -c` PATH probe cannot \
                 carry it unquoted"
            ));
        }
        probes.push(format!("command -v {applet} >/dev/null"));
    }
    Ok(probes.join(" && "))
}

/// The in-rootfs guest-tools multicall is present and **every**
/// [`vmcell_protocol::GUEST_TOOLS_APPLETS`] name resolves on the steward's exec PATH
/// (← §4.4, The in-rootfs guest-tools helper).
///
/// # Errors
/// Returns `Err` if the roster cannot be composed into a probe, or if any roster name does not
/// resolve on the exec PATH.
pub async fn rootfs_guest_tools(steward: &mut StewardClient) -> Result<(), String> {
    let probe = guest_tools_probe_command()?;
    let out = exec(steward, &["sh", "-c", probe.as_str()]).await?;
    if out.code != 0 {
        return Err(format!(
            "not every guest-tools applet resolves on PATH (§5.3); the roster is {} and the probe \
             was `{probe}`",
            vmcell_protocol::GUEST_TOOLS_APPLETS.join(", ")
        ));
    }
    Ok(())
}

/// The tmpfs overlay upper is writable over the read-only erofs base: write then read a file on
/// the root fs (← §4.1, The erofs read-only base + tmpfs overlay). A read-only-only root (missing overlay/tmpfs) reddens.
///
/// # Errors
/// Returns `Err` if the root fs is not writable (missing tmpfs overlay) or the write/read-back mismatches.
pub async fn rootfs_overlay_writable(steward: &mut StewardClient) -> Result<(), String> {
    let out = exec(
        steward,
        &[
            "sh",
            "-c",
            "echo overlay-probe > /vmcell-validate-overlay && cat /vmcell-validate-overlay \
             && rm -f /vmcell-validate-overlay",
        ],
    )
    .await?;
    if out.code != 0 {
        return Err(format!(
            "writing to the overlay root failed (exit {}): {}",
            out.code,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    if !String::from_utf8_lossy(&out.stdout).contains("overlay-probe") {
        return Err("overlay write did not read back (tmpfs overlay upper not writable)".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Extended checks
// ---------------------------------------------------------------------------

/// The kernel's IP-PNP configured `eth0` at boot from the `ip=` cmdline — **no guest netlink**
/// (← `host_endpoint.rs`, §5.3, The kernel command line/§13, Cross-cutting invariants). Asserts, via guest-tools `ip`, that `eth0` is `state up`
/// carrying the **exact** `(vmid%254)+1` /30 address the orchestrator's `ip_math` expects (a
/// kernel that configured a wrong/default address, or a cmdline/`ip_math` desync, reddens), and
/// that a non-empty routing table exists (IP-PNP installs the default route).
///
/// # Errors
/// Returns `Err` if `eth0` is not `state up`, carries the wrong address vs `ip_math`, or has no route.
pub async fn net_ip_pnp<V: Vmm>(vm: &mut MicroVm<V>) -> Result<(), String> {
    let (_, guest_ip, _) = vmcell::net::ip_math(vm.vmid())
        .map_err(|e| format!("ip_math({}) failed: {e}", vm.vmid()))?;
    // Captured before the `&mut` steward borrow (see `guest_core_checks`).
    let serial_log = vm.instance().serial_log().to_path_buf();
    let steward = match vm.steward(Some(STEWARD_READY_BUDGET)).await {
        Ok(a) => a,
        Err(e) => {
            return Err(explain_boot_failure_at(
                BootKind::Fresh,
                &serial_log,
                &steward_handshake_base(&e, STEWARD_READY_BUDGET),
            )
            .await);
        }
    };
    let addr = exec(steward, &["ip", "a"]).await?;
    if addr.code != 0 {
        return Err(format!(
            "`ip a` exited {} (guest-tools ip unavailable?)",
            addr.code
        ));
    }
    let stdout = String::from_utf8_lossy(&addr.stdout);
    if !stdout.contains("eth0") || !stdout.contains("state up") {
        return Err(format!(
            "guest eth0 is not up — IP-PNP did not configure the interface at boot; `ip a` was:\n{stdout}"
        ));
    }
    // guest-tools `ip a` prints the `inet <addr>/<prefix>` line (SIOCGIFADDR), so verify the
    // exact IP-PNP address rather than merely that the link is up.
    if !stdout.contains(&format!("inet {guest_ip}/")) {
        return Err(format!(
            "guest eth0 does not carry its IP-PNP address {guest_ip}; `ip a` was:\n{stdout}"
        ));
    }
    let route = exec(steward, &["ip", "route"]).await?;
    if route.code != 0 {
        return Err(format!("`ip route` exited {}", route.code));
    }
    if route.stdout.is_empty() {
        return Err(
            "guest has no routes — IP-PNP did not install the default route from ip=".into(),
        );
    }
    Ok(())
}

/// A read-only virtio-fs share rejects writes with EROFS and serves reads; a read-write share's
/// writes are visible on the host (← `shares_ro_rw.rs`, §4.5, Shared directories (virtio-fs)). `in_marker` was written to the RO
/// share host-side; `host_out_dir` is the RW share's host directory.
///
/// # Errors
/// Returns `Err` if the RO share accepts a write (or fails reads) or the RW share's write is not visible host-side.
pub async fn virtiofs_shares(
    steward: &mut StewardClient,
    host_out_dir: &std::path::Path,
) -> Result<(), String> {
    // RO read works.
    let read = exec(steward, &["cat", "/vmcell-in/input.txt"]).await?;
    if read.code != 0 || read.stdout != b"hello world" {
        return Err(format!(
            "RO share read failed (exit {}, stdout {:?})",
            read.code,
            String::from_utf8_lossy(&read.stdout)
        ));
    }
    // RO write is rejected with the SPECIFIC EROFS signal (not any nonzero — §4.5, Shared directories (virtio-fs)/L-TEST-1).
    let ro_write = exec(steward, &["sh", "-c", "echo x > /vmcell-in/nope.txt"]).await?;
    if ro_write.code == 0 {
        return Err("write to a read-only virtio-fs share unexpectedly succeeded".into());
    }
    if !String::from_utf8_lossy(&ro_write.stderr).contains("Read-only file system") {
        return Err(format!(
            "RO share write must fail with EROFS 'Read-only file system'; got: {}",
            String::from_utf8_lossy(&ro_write.stderr)
        ));
    }
    // RW write is visible on the host.
    let rw_write = exec(steward, &["sh", "-c", "echo rw-ok > /vmcell-out/out.txt"]).await?;
    if rw_write.code != 0 {
        return Err(format!("RW share write exited {}", rw_write.code));
    }
    let host_seen = tokio::fs::read_to_string(host_out_dir.join("out.txt"))
        .await
        .map_err(|e| format!("RW share output not visible on host: {e}"))?;
    if host_seen.trim() != "rw-ok" {
        return Err(format!("RW share host content mismatch: {host_seen:?}"));
    }
    Ok(())
}

/// With nested virt enabled, the guest sees `/dev/kvm` — `kvm-ok` exits 0 (← `nested_virt.rs`,
/// §5.3, The kernel command line). The VM must have been booted with `nested_virt = true`.
///
/// # Errors
/// Returns `Err` if `/dev/kvm` is absent in the guest (`kvm-ok` non-zero) — e.g. the VM was not booted with `nested_virt`.
pub async fn nested_kvm_ok(steward: &mut StewardClient) -> Result<(), String> {
    let out = exec(steward, &["kvm-ok"]).await?;
    if out.code != 0 {
        return Err(format!(
            "kvm-ok exited {} — nested /dev/kvm not exposed to the guest",
            out.code
        ));
    }
    Ok(())
}

/// How long the whole-image extended-attribute scan is allowed inside the guest.
///
/// Generous because the scan is one `xattr list` fork per path and an image is thousands of paths;
/// finite because the conformance battery's per-check deadlines are what keep
/// "fails loudly per check" from becoming "hangs per battery" (§10.6). Exceeding it surfaces as
/// [`crate::conformance::ProbeOutcome::NotRun`] — undecided, never a verified absence.
const XATTR_SCAN_BUDGET: Duration = Duration::from_secs(300);

/// How many in-guest paths the scan will visit before it gives up and reports the observation
/// **incomplete**.
///
/// A cap rather than an unbounded walk, and the cap is *reported* rather than silently truncating:
/// a partial walk that found nothing is not evidence of an absence, and the whole point of
/// [`crate::conformance::ProbeOutcome::NotRun`] is that saying so is cheaper than being wrong. The
/// number is sized for a Debian-derived userland (order 10^4 paths) with headroom.
const XATTR_SCAN_PATH_CAP: u64 = 60_000;

/// The three markers the in-guest scan prints — one line, first token, never translated.
///
/// Parsed by [`classify_xattr_scan`], which is the pure half of this probe: the shell says only
/// what it saw, and the mapping onto a [`crate::conformance::ProbeOutcome`] is unit-gated.
const XATTR_MARK_PRESENT: &str = "VMCELL-XATTR-PRESENT";
/// See [`XATTR_MARK_PRESENT`] — the scan completed and found no extended attribute anywhere.
const XATTR_MARK_ABSENT: &str = "VMCELL-XATTR-ABSENT";
/// See [`XATTR_MARK_PRESENT`] — the scan could not complete, so it decides nothing.
const XATTR_MARK_INCOMPLETE: &str = "VMCELL-XATTR-INCOMPLETE";

/// The `sh -c` program the scan runs: walk the image, ask the `xattr` applet about each path, stop
/// at the first path that carries one.
///
/// Composed from `cap` so the cap is one fact, and kept a pure function so the program text is
/// assertable without a guest.
///
/// * `-xdev` keeps the walk on the rootfs the artifact IS: `/proc`, `/sys`, `/dev` and any tmpfs
///   the steward mounted are separate filesystems, and their attributes are the *kernel's*, not the
///   artifact's. The overlay upper counts as the same filesystem as the erofs base beneath it,
///   which is exactly right — the merged tree is what a cell actually sees.
/// * The loop short-circuits on the first hit, so a preserving artifact costs only as much walking
///   as it takes to reach one attribute; the full cost is paid only by an artifact that has none,
///   which is the case that needs completeness to mean anything.
/// * `xattr list` is vmcell's own applet ([`vmcell_protocol::GUEST_TOOLS_APPLETS`]), not a distro
///   `getfattr`: the rootfs is not required to ship the `attr` package, and a probe that silently
///   degrades to "command not found" would report a verified absence for every image on earth.
fn xattr_scan_program(cap: u64) -> String {
    format!(
        r#"find / -xdev \( -type f -o -type d -o -type l \) -print 2>/dev/null | {{
  n=0
  while IFS= read -r p; do
    n=$((n+1))
    if [ "$n" -gt {cap} ]; then printf '{XATTR_MARK_INCOMPLETE} path-cap %s\n' "{cap}"; exit 0; fi
    names=$(xattr list "$p" 2>/dev/null)
    if [ -n "$names" ]; then printf '{XATTR_MARK_PRESENT} %s %s\n' "$p" "$names"; exit 0; fi
  done
  if [ "$n" -eq 0 ]; then printf '{XATTR_MARK_INCOMPLETE} no-paths-walked\n'; exit 0; fi
  printf '{XATTR_MARK_ABSENT} %s\n' "$n"
}}"#
    )
}

/// What [`xattr_scan_program`]'s output means — the pure half of the probe (§10.6's judgement is
/// pure for the same reason: a three-valued verdict decided inside an I/O function is a verdict no
/// machine without KVM can check).
///
/// The three answers, and why each is the honest one:
///
/// * a path carries an attribute → [`ProbeOutcome::Works`]. This is the only *positive* observation
///   available: the attribute is in the packed image and the guest kernel hands it back.
/// * the walk completed and no path carries one → [`ProbeOutcome::DoesNotWork`]. Complete, so it is
///   an observation rather than a shrug — and note what it does NOT distinguish: an artifact whose
///   policy stripped the attributes from an artifact whose source layers had none to keep. Both are
///   the same fact about the artifact, which is the fact the declaration makes a claim about:
///   `xattr_preserved` says this image *carries* preserved attributes. The message says both
///   remedies out loud so the reader is not left to guess which one they are in.
/// * anything else — the cap, an empty walk, a non-zero exit, unparseable output →
///   [`ProbeOutcome::NotRun`]. An incomplete walk that found nothing is not evidence of an absence,
///   and §10.6's whole `Unverified` state exists so that saying so beats guessing.
fn classify_xattr_scan(code: i32, stdout: &str, stderr: &str) -> ProbeOutcome {
    if code != 0 {
        return ProbeOutcome::NotRun(format!(
            "the in-guest extended-attribute scan exited {code}: {}. An unrun scan decides \
             nothing — a `sh`/`find`-less image cannot be walked, and reporting that is not the \
             same as reporting an absence",
            stderr.trim()
        ));
    }
    let line = stdout.lines().find(|l| {
        l.starts_with(XATTR_MARK_PRESENT)
            || l.starts_with(XATTR_MARK_ABSENT)
            || l.starts_with(XATTR_MARK_INCOMPLETE)
    });
    match line {
        Some(l) if l.starts_with(XATTR_MARK_PRESENT) => ProbeOutcome::Works,
        Some(l) if l.starts_with(XATTR_MARK_ABSENT) => {
            let walked = l
                .split_whitespace()
                .nth(1)
                .unwrap_or("an unreported number of");
            ProbeOutcome::DoesNotWork(format!(
                "the in-guest scan walked {walked} paths and not one of them carries an extended \
                 attribute, so this artifact preserves none. Either its base layers carried no \
                 `SCHILY.xattr` records to keep (declare nothing, or `\"xattrs\": \"strip\"`), or \
                 the pack ran under `strip` (§4.7) — a declaration of `xattr_preserved` is a claim \
                 a consumer builds a fixture on either way"
            ))
        }
        Some(l) => ProbeOutcome::NotRun(format!(
            "the in-guest extended-attribute scan did not complete ({}), so it observed neither a \
             presence nor an absence",
            l.trim()
        )),
        None => ProbeOutcome::NotRun(format!(
            "the in-guest extended-attribute scan printed no verdict marker; it emitted {:?}. \
             Without a marker the walk cannot be told from a shell that never ran it",
            stdout.trim()
        )),
    }
}

/// The §10.6 data-plane probe for [`vmcell::feature::Feature::XattrPreserved`]: boot the artifact
/// and ask, in-guest, whether **any** of its paths carries an extended attribute (← §4.7, the
/// `xattr` applet).
///
/// Boots its own VM (the [`snapshot_restore_roundtrip`] shape) rather than taking a
/// `&mut StewardClient`, because the conformance battery runs it against an arbitrary subject's
/// artifact pair rather than inside one of the level runs.
///
/// Networking is disabled: the question is about bytes in the image, and a probe that needed egress
/// would fail for the network's reasons on an artifact whose attributes are perfectly intact.
pub async fn xattr_preserved_probe<V: Vmm>(vmm: &V, a: &ArtifactSet) -> ProbeOutcome {
    let cfg = match base_cfg(a).network_disabled().build() {
        Ok(cfg) => cfg,
        Err(e) => {
            return ProbeOutcome::NotRun(format!("xattr-probe config build failed: {e}"));
        }
    };
    let mut vm = match MicroVm::start(vmm, cfg, &vmcell::HostEnv::hermetic()).await {
        Ok(vm) => vm,
        Err(e) => return ProbeOutcome::NotRun(format!("xattr-probe: {}", failed_start(&e))),
    };
    // Captured before the `&mut` steward borrow (see `guest_core_checks`).
    let serial_log = vm.instance().serial_log().to_path_buf();
    let steward = match vm.steward(Some(STEWARD_READY_BUDGET)).await {
        Ok(s) => s,
        Err(e) => {
            let base = format!(
                "xattr-probe: {}",
                steward_handshake_base(&e, STEWARD_READY_BUDGET)
            );
            let why = explain_boot_failure_at(BootKind::Fresh, &serial_log, &base).await;
            return ProbeOutcome::NotRun(why);
        }
    };
    let program = xattr_scan_program(XATTR_SCAN_PATH_CAP);
    let req =
        ExecRequest::new(vec!["sh".into(), "-c".into(), program]).with_timeout(XATTR_SCAN_BUDGET);
    let outcome = steward.exec(req).await;
    shutdown_after_check(vm).await;
    match outcome {
        Ok(out) => classify_xattr_scan(
            out.code,
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(e) => ProbeOutcome::NotRun(format!(
            "the in-guest extended-attribute scan failed at the transport level within its {}s \
             budget: {e}",
            XATTR_SCAN_BUDGET.as_secs()
        )),
    }
}

/// Per-VM cgroup usage is observable and honestly reports enforcement (← `metrics_limits.rs`,
/// §7.1, What is read and enforced). Requires the memory controller delegated (the caller gates on that).
///
/// # Errors
/// Returns `Err` if per-VM cgroup usage cannot be read or misreports enforcement.
pub async fn metrics_usage_readable<V: Vmm>(vm: &MicroVm<V>) -> Result<(), String> {
    let usage = vm
        .usage()
        .await
        .map_err(|e| format!("usage() failed: {e}"))?;
    if !usage.mem_limit_enforced {
        return Err(
            "memory controller delegated but ResourceUsage::mem_limit_enforced is false".into(),
        );
    }
    if usage.mem_peak_mib == 0 {
        return Err("memory controller delegated but memory.peak reads 0".into());
    }
    Ok(())
}

/// The whole `metrics.usage_readable` arm: the steward handshake that proves the guest actually
/// booted, the settle window that lets it touch memory, then [`metrics_usage_readable`].
///
/// Extracted with both durations injected so the **handshake decision** is drivable KVM-free
/// (`usage-readable-swallows-steward-handshake`): the handshake used to be a bare `let _`, so a guest
/// that never came up still reached the cgroup readout and the check could report anything but the
/// boot failure that caused it. Every sibling arm renders a failed handshake through
/// [`explain_boot_failure_at`]; this one now does too.
async fn usage_readable_after_steward_ready<V: Vmm>(
    vm: &mut MicroVm<V>,
    ready_budget: Duration,
    settle: Duration,
) -> Result<(), String> {
    // Captured before the `&mut` steward borrow (see `guest_core_checks`).
    let serial_log = vm.instance().serial_log().to_path_buf();
    if let Err(e) = vm.steward(Some(ready_budget)).await {
        return Err(explain_boot_failure_at(
            BootKind::Fresh,
            &serial_log,
            &steward_handshake_base(&e, ready_budget),
        )
        .await);
    }
    // Steward-ready: let the guest consume some memory before the counters are read back.
    tokio::time::sleep(settle).await;
    metrics_usage_readable(vm).await
}

// ---------------------------------------------------------------------------
// Full checks
// ---------------------------------------------------------------------------

/// Boots N VMs **concurrently** on shared allocators and asserts each gets a distinct
/// vmid / guest-CID / vsock path and execs successfully (← `concurrency.rs`, §13, Cross-cutting invariants). Catches an
/// allocator that hands out duplicates under contention.
///
/// # Errors
/// Returns `Err` if any concurrent VM fails to boot/exec or two VMs collide on vmid / guest-CID / vsock path.
pub async fn concurrency_distinct_ids<V: Vmm>(vmm: &V, a: &ArtifactSet) -> Result<(), String> {
    let cfg = base_cfg(a)
        .network_disabled()
        .build()
        .map_err(|e| format!("config build failed: {e}"))?;
    let env = vmcell::HostEnv::hermetic();

    // Drive N starts CONCURRENTLY on the shared allocators (join_all polls in place, so the
    // futures may borrow `vmm` — no `'static`/`spawn` needed).
    let starts = (0..3).map(|_| MicroVm::start(vmm, cfg.clone(), &env));
    let mut vms = Vec::new();
    for res in futures::future::join_all(starts).await {
        vms.push(res.map_err(|e| failed_start(&e))?);
    }

    let mut vmids = std::collections::HashSet::new();
    let mut vsocks = std::collections::HashSet::new();
    let mut cids = std::collections::HashSet::new();
    for vm in &vms {
        if !vmids.insert(vm.vmid()) {
            return Err(format!(
                "duplicate vmid {} under concurrent start",
                vm.vmid()
            ));
        }
        if !vsocks.insert(vm.instance().vsock_path().to_path_buf()) {
            return Err("duplicate vsock path under concurrent start".into());
        }
        if !cids.insert(vm.instance().guest_cid()) {
            return Err("duplicate guest CID under concurrent start".into());
        }
    }
    for mut vm in vms {
        // Captured before the `&mut` steward borrow (see `guest_core_checks`). The budget is
        // deliberately not `STEWARD_READY_BUDGET`: three guests boot concurrently here.
        let serial_log = vm.instance().serial_log().to_path_buf();
        let steward = match vm.steward(Some(CONCURRENT_STEWARD_READY_BUDGET)).await {
            Ok(a) => a,
            Err(e) => {
                // The sentence is composed by the one `steward_handshake_base` (now that it takes the
                // budget it must name), not a second copy of the phrasing that only differed in
                // which const it read.
                return Err(explain_boot_failure_at(
                    BootKind::Fresh,
                    &serial_log,
                    &format!(
                        "a concurrently-started VM: {}",
                        steward_handshake_base(&e, CONCURRENT_STEWARD_READY_BUDGET)
                    ),
                )
                .await);
            }
        };
        let out = exec(steward, &["true"]).await?;
        if out.code != 0 {
            return Err(format!("concurrent VM exec `true` exited {}", out.code));
        }
        shutdown_after_check(vm).await;
    }
    Ok(())
}

/// Where a probe stopped — which is **not** the same question as what it observed.
///
/// A candidate that never reached the point where the feature could be exercised has said nothing
/// about the feature. Reporting that as [`ProbeOutcome::DoesNotWork`] let an artifact that cannot
/// boot at all earn a *verified absence* (docs/90 M8): [`crate::conformance::judge`] reads a
/// measured "does not work" against an absence declaration as the one `Pass` an absence can earn.
/// The positive-control pairing cannot catch it — the control is a **different** artifact, so it
/// boots fine and the pair looks healthy. Only the candidate's own stop tells the two apart, which
/// is why the line is drawn here, at the arm that failed, rather than in the judgement.
///
/// [`xattr_preserved_probe`] has always drawn this line (its config/boot/handshake arms are all
/// `NotRun`); this is the same law, applied to the probe that did not.
enum ProbeStop {
    /// The probe never got to exercise the feature — the config did not build, the VM did not
    /// start, the guest never handed shakes, the host had no scratch space. →
    /// [`ProbeOutcome::NotRun`], which §10.6 renders as `Unverified`, never a pass.
    Setup(String),
    /// The feature **was** exercised and it did not work. → [`ProbeOutcome::DoesNotWork`], the
    /// measurement an absence declaration can be verified against.
    Exercised(String),
}

impl ProbeStop {
    /// The failure text, whichever side of the line it fell on.
    ///
    /// A *level* check (`snapshot.restore_roundtrip`) judges a declared-**present** property, where
    /// both sides are the same verdict — the artifact pair did not survive the round trip — so the
    /// split changes nothing there and the recorded message is byte-identical.
    fn into_why(self) -> String {
        match self {
            ProbeStop::Setup(why) | ProbeStop::Exercised(why) => why,
        }
    }
}

/// The one mapping from a stopped probe onto a §10.6 outcome.
///
/// Pure, so both directions are unit-gated
/// (`a_setup_stop_is_notrun_and_an_exercised_stop_is_doesnotwork`) on a machine with no KVM. Which
/// *probe arm* produces which stop is a second question: a fake reaches the setup arms, and only a
/// KVM host reaches the measuring ones, so those are pinned by a source scan.
fn stopped_probe_outcome(stop: ProbeStop) -> ProbeOutcome {
    match stop {
        ProbeStop::Setup(why) => ProbeOutcome::NotRun(why),
        ProbeStop::Exercised(why) => ProbeOutcome::DoesNotWork(why),
    }
}

/// Snapshot a running VM and restore it, confirming the **restored** VM boots back to
/// steward-ready and execs (← `snapshot_restore.rs`, §8, Snapshot, restore, and cloning/§8.2, Restore correctness: a restored VM is not a fresh VM). Proves the artifact survives the
/// PVH snapshot/restore path. The VM must be a snapshot-eligible config (no vhost-user device).
///
/// The level-check form of the crate-private `snapshot_restore_probe` (deliberately unlinked: a
/// public doc must not link a private item): one body, two callers, because a level check asks "does
/// this declared-present property hold" — both stop kinds are the same `Err` — while the §10.6
/// battery asks "what did we observe", where they are not the same answer.
///
/// # Errors
/// Returns `Err` if snapshot or restore fails, or the restored VM does not return to steward-ready and exec.
pub async fn snapshot_restore_roundtrip<V: Vmm>(vmm: &V, a: &ArtifactSet) -> Result<(), String> {
    snapshot_restore_attempt(vmm, a)
        .await
        .map_err(ProbeStop::into_why)
}

/// The §10.6 data-plane probe for [`vmcell::feature::Feature::SnapshotRestore`]: the same round trip
/// [`snapshot_restore_roundtrip`] runs, reported as a [`ProbeOutcome`] so a candidate that never
/// booted is `NotRun` (undecided) rather than a measured absence — see [`ProbeStop`].
pub(crate) async fn snapshot_restore_probe<V: Vmm>(vmm: &V, a: &ArtifactSet) -> ProbeOutcome {
    match snapshot_restore_attempt(vmm, a).await {
        Ok(()) => ProbeOutcome::Works,
        Err(stop) => stopped_probe_outcome(stop),
    }
}

/// The round trip proper. Every arm states which side of the [`ProbeStop`] line it is on, and the
/// boundary is [`MicroVm::snapshot`] — the first call that actually exercises the feature.
async fn snapshot_restore_attempt<V: Vmm>(vmm: &V, a: &ArtifactSet) -> Result<(), ProbeStop> {
    let mut cfg = base_cfg(a)
        .network_disabled()
        .build()
        .map_err(|e| ProbeStop::Setup(format!("snapshot-eligible config build failed: {e}")))?;
    // Snapshot-eligible: net=None → no vhost-user device (§13, Cross-cutting invariants); set the flag on the built
    // config (the pair is already vhost-user-free, so this stays valid).
    cfg.snapshotting = true;
    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg.clone(), &env)
        .await
        .map_err(|e| ProbeStop::Setup(format!("snapshot-source: {}", failed_start(&e))))?;
    // Boot to steward-ready before snapshotting.
    if let Err(e) = vm.steward(Some(STEWARD_READY_BUDGET)).await {
        let base = format!(
            "snapshot-source: {}",
            steward_handshake_base(&e, STEWARD_READY_BUDGET)
        );
        // THE M8 arm: a guest that never handed shakes was never asked to snapshot, so this says
        // nothing about the artifact's snapshot support.
        return Err(ProbeStop::Setup(explain_boot_failure_for(&vm, &base).await));
    }

    let snap_dir = tempfile::tempdir().map_err(|e| ProbeStop::Setup(format!("tempdir: {e}")))?;
    vm.snapshot(snap_dir.path())
        .await
        .map_err(|e| ProbeStop::Exercised(format!("snapshot() failed: {e}")))?;
    shutdown_after_check(vm).await;

    let mut restored = MicroVm::restore(vmm, snap_dir.path(), cfg, &env)
        .await
        .map_err(|e| ProbeStop::Exercised(format!("restore() failed: {e}")))?;
    // Captured before the `&mut` steward borrow (see `guest_core_checks`).
    let restored_serial = restored.instance().serial_log().to_path_buf();
    let steward = match restored.steward(Some(STEWARD_READY_BUDGET)).await {
        Ok(a) => a,
        Err(e) => {
            let base = format!(
                "restored VM: {}",
                steward_handshake_base(&e, STEWARD_READY_BUDGET)
            );
            // THE restored console (m9): empty by construction — the guest kernel printed its
            // banner in the snapshot SOURCE, on that VM's console file. Reading it as a fresh boot
            // told this check that a kernel which had just booted, snapshotted and resumed "is not
            // a direct-boot PVH-ELF vmlinux". `checks_render_a_restored_console_as_restored` pins
            // this argument.
            //
            // `Exercised`, not `Setup`: the snapshot and the restore both succeeded and the guest
            // did not come back — that IS the feature failing, and calling it undecidable would
            // hide a broken restore behind an `Unverified` (M8's inverse).
            return Err(ProbeStop::Exercised(
                explain_boot_failure_at(BootKind::Restored, &restored_serial, &base).await,
            ));
        }
    };
    let out = exec(steward, &["true"])
        .await
        .map_err(ProbeStop::Exercised)?;
    if out.code != 0 {
        return Err(ProbeStop::Exercised(format!(
            "restored VM exec `true` exited {}",
            out.code
        )));
    }
    shutdown_after_check(restored).await;
    Ok(())
}

/// A host cgroup memory cap below guest RAM is the binding limit: a runaway allocation trips the
/// host OOM killer, observable via `memory.events` `oom_kill` (← `metrics_limits.rs`, §7, Resource monitoring and limits). The VM
/// must be booted with `mem_mib=512, limits.mem_max_mib=Some(256)`.
///
/// `resource_prefix` must be the [`VmConfig::resource_prefix`] the VM was **started** with: it is
/// what names the cgroup slice this check reads. It is a required parameter and not a default,
/// because assuming the default silently pointed the read at a path that exists for no VM
/// configured with any other prefix (docs/81 d3) — a check that then fails for the wrong reason.
///
/// # Errors
/// Returns `Err` if the capped allocation does not trip the host OOM killer (no `oom_kill` observed) or the metric cannot be read.
pub async fn metrics_mem_limit_ooms<V: Vmm>(
    vm: &mut MicroVm<V>,
    resource_prefix: &str,
) -> Result<(), String> {
    let events_path = cgroup_events_path(resource_prefix, vm.vmid());
    // Fire a runaway allocation; the VMM may itself be OOM-killed, so ignore the exec result —
    // the binding signal is the host counter.
    {
        // Captured before the `&mut` steward borrow (see `guest_core_checks`).
        let serial_log = vm.instance().serial_log().to_path_buf();
        let steward = match vm.steward(Some(STEWARD_READY_BUDGET)).await {
            Ok(a) => a,
            Err(e) => {
                return Err(explain_boot_failure_at(
                    BootKind::Fresh,
                    &serial_log,
                    &steward_handshake_base(&e, STEWARD_READY_BUDGET),
                )
                .await);
            }
        };
        // The exec is EXPECTED to fail: `tail /dev/zero` is a runaway allocation whose whole job
        // is to trip the host OOM killer, which usually takes the guest — and sometimes the VMM —
        // with it. The binding signal is the host `memory.events` counter read below, never this
        // call's outcome, so an error here is the check working.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the OOM probe is expected to die with its guest; the host memory.events counter below is the binding signal"
        )]
        let _ = exec(steward, &["tail", "/dev/zero"]).await;
    }
    for _ in 0..50 {
        if let Ok(events) = std::fs::read_to_string(&events_path)
            && let Some(n) = parse_oom_kill(&events)
            && n > 0
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "cgroup memory cap did not trip the host OOM killer (no oom_kill at {})",
        events_path.display()
    ))
}

/// The `/sys/fs/cgroup/<slice>/memory.events` path for the VM `vmid` started with
/// `resource_prefix`.
///
/// The slice name comes from [`vmcell::metrics::vm_slice_name`] — the one law that spells both the
/// `<prefix>-vm-<vmid>` leaf and its §13 sibling placement under the base parsed out of
/// `/proc/self/cgroup`. This function used to compose that itself, as
/// `format!("{base}/vmcell-vm-{vmid}")`, under a rustdoc claiming it "matches the orchestrator's
/// slice placement": it matched only for a VM left on the default
/// [`vmcell::naming::DEFAULT_RESOURCE_PREFIX`], and read a path that exists for **no** VM
/// configured with any other prefix (docs/81 d3). The prefix is now a parameter with no default,
/// so the wrong path is not reachable without a caller naming it.
///
/// Gated by `cgroup_events_path_composes_from_the_configured_prefix` (the composition) and
/// `the_oom_check_reads_the_slice_of_the_vm_it_booted` (the call site that supplies the prefix).
fn cgroup_events_path(resource_prefix: &str, vmid: u32) -> std::path::PathBuf {
    let name = vmcell::metrics::vm_slice_name(resource_prefix, vmid);
    std::path::PathBuf::from(format!("/sys/fs/cgroup/{name}/memory.events"))
}

/// Parses `oom_kill` from a cgroup-v2 `memory.events` file (← `metrics_limits.rs`).
fn parse_oom_kill(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("oom_kill") {
            return it.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Orchestration: boot capability-appropriate VMs and collect outcomes
// ---------------------------------------------------------------------------

fn record(outcomes: &mut Vec<CheckOutcome>, id: &'static str, level: Level, r: Result<(), String>) {
    outcomes.push(CheckOutcome::from_result(id, level, r));
}

fn skip(
    outcomes: &mut Vec<CheckOutcome>,
    id: &'static str,
    level: Level,
    reason: impl Into<String>,
) {
    outcomes.push(CheckOutcome::skip(id, level, reason));
}

/// The [`Level::Core`] roster, in run order — **the one list**, and the mechanism behind
/// "every check records or skips its id on every path" (design §10.6, §18 delta 3).
///
/// [`run_core`] records what it reached; the `fill_unrecorded` tail skips the rest, naming the
/// check whose failure stopped the run. Two consequences, both load-bearing: a failed boot never *shrinks* the
/// report (a consumer diffing against a stored baseline sees a Skip with a reason, not a check that
/// vanished), and the roster is enumerable against a `fail_create` fake — which is what let the
/// rustdoc roster gate extend from Full to all three levels instead of staying waived.
pub const CORE_CHECK_IDS: &[&str] = &[
    "boot.config",
    "boot.kernel_banner",
    "boot.steward_ready",
    "steward.exec_roundtrip",
    "steward.put_file_roundtrip",
    "rootfs.libc6",
    "rootfs.ca_cert",
    "rootfs.guest_tools",
    "rootfs.overlay_writable",
    "lifecycle.clean_shutdown",
];

/// The [`Level::Extended`] roster, in run order (see [`CORE_CHECK_IDS`] for the mechanism).
pub const EXTENDED_CHECK_IDS: &[&str] = &[
    "net.ip_pnp",
    "virtiofs.shares",
    "nested.kvm_ok",
    "metrics.usage_readable",
];

/// The [`Level::Full`] roster, in run order (see [`CORE_CHECK_IDS`] for the mechanism).
pub const FULL_CHECK_IDS: &[&str] = &[
    "concurrency.distinct_ids",
    "snapshot.restore_roundtrip",
    "metrics.mem_limit_ooms",
];

/// Records a [`CheckStatus::Skip`](crate::CheckStatus::Skip) for every `roster` id the run did not
/// already record, with `reason` — the tail every level runner ends with.
///
/// It is deliberately *idempotent per id* and driven off the accumulated outcomes rather than a
/// per-arm bookkeeping flag: an arm that returns early on a path nobody thought about still leaves
/// its id in the report, which is the whole point (the pre-v33 `run_core` dropped seven ids when a
/// VM failed to start, and the missing enumeration was the recorded reason two of the three roster
/// gates did not exist).
pub(crate) fn fill_unrecorded(
    outcomes: &mut Vec<CheckOutcome>,
    roster: &[&'static str],
    level: Level,
    reason: &str,
) {
    for id in roster {
        if !outcomes.iter().any(|o| o.id == *id) {
            skip(outcomes, id, level, reason);
        }
    }
}

/// Core: one net-disabled VM → banner, steward-ready, exec/put-file round-trips, rootfs presence,
/// overlay, clean shutdown. Never skips for want of a host capability (KVM is a precondition) —
/// but every id in [`CORE_CHECK_IDS`] is **recorded or skipped on every path**, including the
/// paths that die before the guest hands shakes (design §10.6).
pub async fn run_core<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let stopped = run_core_inner(vmm, a, outcomes).await;
    // `None` = the run reached the end, so the fill is a no-op. If it ever is not, the reason names
    // the bug rather than leaving an id silently missing from the report.
    let reason = stopped.unwrap_or_else(|| {
        "not attempted: the Core run ended without reporting why (a check that ran records its own \
         outcome, so this reason means the roster and the run disagree)"
            .to_string()
    });
    fill_unrecorded(outcomes, CORE_CHECK_IDS, Level::Core, &reason);
}

/// [`run_core`]'s body. Returns `Some(reason)` when it stopped early — the reason every id it did
/// not reach is skipped with, naming the check whose failure stopped the run so the report points
/// at the cause instead of repeating it nine times.
async fn run_core_inner<V: Vmm>(
    vmm: &V,
    a: &ArtifactSet,
    outcomes: &mut Vec<CheckOutcome>,
) -> Option<String> {
    let cfg = match base_cfg(a).network_disabled().build() {
        Ok(c) => {
            // Recorded on the success path too (v33 delta 3): an error-only id is invisible to a
            // roster enumeration, and "the id is missing" and "the check passed" must not be the
            // same observation for a consumer diffing reports.
            record(outcomes, "boot.config", Level::Core, Ok(()));
            c
        }
        Err(e) => {
            record(
                outcomes,
                "boot.config",
                Level::Core,
                Err(format!("config build failed: {e}")),
            );
            return Some("not attempted: the VM config did not build (see boot.config)".into());
        }
    };
    let mut vm = match try_start_vm(vmm, cfg).await {
        Ok(vm) => vm,
        Err(e) => {
            // `MicroVm::start` owns the per-VM temp dir, so on this arm the serial log is already
            // deleted — there is no console evidence at all, and `start` also fails for reasons
            // that are not the artifact pair (missing VMM binary, denied host resource), so this
            // must NOT assert the "not a direct-boot vmlinux" clause. Both Core boot checks are
            // recorded so a failed start never *shrinks* the report's roster.
            let msg = failed_start(&e);
            record(
                outcomes,
                "boot.kernel_banner",
                Level::Core,
                Err(msg.clone()),
            );
            record(outcomes, "boot.steward_ready", Level::Core, Err(msg));
            return Some("not attempted: the VM never started (see boot.kernel_banner)".into());
        }
    };
    record(
        outcomes,
        "boot.kernel_banner",
        Level::Core,
        kernel_banner(&vm).await,
    );

    // steward-ready gates every guest probe; if it fails, record it and stop the guest checks.
    match vm.steward(Some(STEWARD_READY_BUDGET)).await {
        Ok(_) => record(outcomes, "boot.steward_ready", Level::Core, Ok(())),
        Err(e) => {
            // The VM is still alive here, so its serial log is readable — this is the arm that
            // catches both the erofs root-mount panic (which surfaces only as "Panic detected in
            // serial log") and the missing-`CONFIG_VSOCKETS` guest.
            let msg =
                explain_boot_failure_for(&vm, &steward_handshake_base(&e, STEWARD_READY_BUDGET))
                    .await;
            record(outcomes, "boot.steward_ready", Level::Core, Err(msg));
            shutdown_after_check(vm).await;
            return Some(
                "not attempted: the guest never reached steward-ready (see boot.steward_ready)"
                    .into(),
            );
        }
    }
    // Re-borrow the steward for each check (the connection is cached on the VM).
    match guest_core_checks(&mut vm).await {
        Ok(results) => {
            for (id, res) in results {
                record(outcomes, id, Level::Core, res);
            }
        }
        Err(msg) => {
            record(outcomes, "steward.exec_roundtrip", Level::Core, Err(msg));
            shutdown_after_check(vm).await;
            return Some(
                "not attempted: the steward connection was lost after the handshake (see \
                 steward.exec_roundtrip)"
                    .into(),
            );
        }
    }
    record(
        outcomes,
        "lifecycle.clean_shutdown",
        Level::Core,
        vm.shutdown().await.map_err(|e| e.to_string()),
    );
    None
}

/// Runs the guest-facing Core checks against `vm`'s cached steward, returning (id, result) pairs.
///
/// `Err(msg)` is the distinct "the steward went away between the handshake and the probes" case:
/// the caller records it against `steward.exec_roundtrip` and skips the remaining guest ids with a
/// reason pointing there, rather than repeating one transport failure as five contract violations.
async fn guest_core_checks<V: Vmm>(
    vm: &mut MicroVm<V>,
) -> Result<Vec<(&'static str, Result<(), String>)>, String> {
    // Captured before the `&mut` steward borrow so the failure arm can still read the console (the
    // borrow checker keeps the mutable borrow alive across the whole `match` here).
    let serial_log = vm.instance().serial_log().to_path_buf();
    let steward = match vm.steward(Some(STEWARD_READY_BUDGET)).await {
        Ok(a) => a,
        Err(e) => {
            return Err(explain_boot_failure_at(
                BootKind::Fresh,
                &serial_log,
                &format!("steward unavailable: {e}"),
            )
            .await);
        }
    };
    Ok(vec![
        (
            "steward.exec_roundtrip",
            steward_exec_roundtrip(steward).await,
        ),
        (
            "steward.put_file_roundtrip",
            steward_put_file_roundtrip(steward).await,
        ),
        ("rootfs.libc6", rootfs_libc6(steward).await),
        ("rootfs.ca_cert", rootfs_ca_cert(steward).await),
        ("rootfs.guest_tools", rootfs_guest_tools(steward).await),
        (
            "rootfs.overlay_writable",
            rootfs_overlay_writable(steward).await,
        ),
    ])
}

/// Extended: capability-gated probes, each on its own appropriately-configured VM.
///
/// Every [`EXTENDED_CHECK_IDS`] entry is recorded or skipped on every path (see [`run_core`]).
pub async fn run_extended<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    run_extended_inner(vmm, a, outcomes).await;
    // Every arm below records on each of its own paths, so this tail is a no-op today. It is here
    // because that property must survive the next arm somebody adds: a forgotten path leaves a
    // skipped id with a reason, never a check that silently vanished from the roster.
    fill_unrecorded(
        outcomes,
        EXTENDED_CHECK_IDS,
        Level::Extended,
        "not attempted: the Extended run did not reach this check",
    );
}

async fn run_extended_inner<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let caps = vmm.capabilities();

    // net / IP-PNP (unprivileged NAT).
    if caps.unprivileged_vhost_user_net {
        match base_cfg(a)
            .net(NetConfig::Unprivileged {
                egress: Egress::Open,
                host_services_port: None,
            })
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "net.ip_pnp",
                Level::Extended,
                Err(format!("config: {e}")),
            ),
            Ok(cfg) => match try_start_vm(vmm, cfg).await {
                Err(e) => record(
                    outcomes,
                    "net.ip_pnp",
                    Level::Extended,
                    Err(failed_start(&e)),
                ),
                Ok(mut vm) => {
                    record(
                        outcomes,
                        "net.ip_pnp",
                        Level::Extended,
                        net_ip_pnp(&mut vm).await,
                    );
                    shutdown_after_check(vm).await;
                }
            },
        }
    } else {
        skip(
            outcomes,
            "net.ip_pnp",
            Level::Extended,
            format!("backend {} lacks unprivileged_vhost_user_net", vmm.id()),
        );
    }

    // virtio-fs shares. Needs both the backend capability AND CAP_SYS_ADMIN (for virtiofsd's
    // `--sandbox namespace`); without the cap virtiofsd cannot mount — an environment limitation,
    // not an artifact defect — so skip-with-reason rather than fail.
    if !caps.virtio_fs_shares {
        skip(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            format!("backend {} lacks virtio_fs_shares", vmm.id()),
        );
    } else if !crate::harness::has_cap_sys_admin() {
        skip(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            "virtio-fs shares need CAP_SYS_ADMIN for the virtiofsd sandbox",
        );
    } else {
        run_shares_check(vmm, a, outcomes).await;
    }

    // nested virt.
    if caps.nested_virt {
        match base_cfg(a)
            .network_disabled()
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "nested.kvm_ok",
                Level::Extended,
                Err(format!("config: {e}")),
            ),
            Ok(mut cfg) => {
                cfg.nested_virt = true;
                match try_start_vm(vmm, cfg).await {
                    Err(e) => record(
                        outcomes,
                        "nested.kvm_ok",
                        Level::Extended,
                        Err(failed_start(&e)),
                    ),
                    Ok(mut vm) => {
                        // Captured before the `&mut` steward borrow (see `guest_core_checks`).
                        let serial_log = vm.instance().serial_log().to_path_buf();
                        let res = match vm.steward(Some(STEWARD_READY_BUDGET)).await {
                            Ok(steward) => nested_kvm_ok(steward).await,
                            Err(e) => Err(explain_boot_failure_at(
                                BootKind::Fresh,
                                &serial_log,
                                &steward_handshake_base(&e, STEWARD_READY_BUDGET),
                            )
                            .await),
                        };
                        record(outcomes, "nested.kvm_ok", Level::Extended, res);
                        shutdown_after_check(vm).await;
                    }
                }
            }
        }
    } else {
        skip(
            outcomes,
            "nested.kvm_ok",
            Level::Extended,
            format!("backend {} lacks nested_virt", vmm.id()),
        );
    }

    // cgroup usage readout.
    if cgroup_memory_delegated() {
        match base_cfg(a)
            .network_disabled()
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "metrics.usage_readable",
                Level::Extended,
                Err(format!("config: {e}")),
            ),
            Ok(mut cfg) => {
                cfg.limits.mem_max_mib = Some(256);
                match try_start_vm(vmm, cfg).await {
                    Err(e) => record(
                        outcomes,
                        "metrics.usage_readable",
                        Level::Extended,
                        Err(failed_start(&e)),
                    ),
                    Ok(mut vm) => {
                        record(
                            outcomes,
                            "metrics.usage_readable",
                            Level::Extended,
                            usage_readable_after_steward_ready(
                                &mut vm,
                                STEWARD_READY_BUDGET,
                                USAGE_SETTLE,
                            )
                            .await,
                        );
                        shutdown_after_check(vm).await;
                    }
                }
            }
        }
    } else {
        skip(
            outcomes,
            "metrics.usage_readable",
            Level::Extended,
            "memory cgroup controller not delegated to this process",
        );
    }
}

/// Boots a VM with a RO + RW virtio-fs share and runs the shares check.
async fn run_shares_check<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            record(
                outcomes,
                "virtiofs.shares",
                Level::Extended,
                Err(format!("tempdir: {e}")),
            );
            return;
        }
    };
    let in_dir = tmp.path().join("in");
    let out_dir = tmp.path().join("out");
    if let Err(e) =
        std::fs::create_dir_all(&in_dir).and_then(|()| std::fs::create_dir_all(&out_dir))
    {
        record(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            Err(format!("mkdir: {e}")),
        );
        return;
    }
    if let Err(e) = std::fs::write(in_dir.join("input.txt"), "hello world") {
        record(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            Err(format!("seed RO share: {e}")),
        );
        return;
    }
    let cfg = match base_cfg(a)
        .with_share(Share::new(
            "vmcell-in",
            &in_dir,
            Access::ReadOnly,
            CachePolicy::Never,
        ))
        .with_share(Share::new(
            "vmcell-out",
            &out_dir,
            Access::ReadWrite,
            CachePolicy::Never,
        ))
        .network_disabled()
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            record(
                outcomes,
                "virtiofs.shares",
                Level::Extended,
                Err(format!("config: {e}")),
            );
            return;
        }
    };
    match try_start_vm(vmm, cfg).await {
        Err(e) => record(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            Err(failed_start(&e)),
        ),
        Ok(mut vm) => {
            // Captured before the `&mut` steward borrow (see `guest_core_checks`).
            let serial_log = vm.instance().serial_log().to_path_buf();
            let res = match vm.steward(Some(STEWARD_READY_BUDGET)).await {
                Ok(steward) => virtiofs_shares(steward, &out_dir).await,
                Err(e) => Err(explain_boot_failure_at(
                    BootKind::Fresh,
                    &serial_log,
                    &steward_handshake_base(&e, STEWARD_READY_BUDGET),
                )
                .await),
            };
            record(outcomes, "virtiofs.shares", Level::Extended, res);
            shutdown_after_check(vm).await;
        }
    }
}

/// Full: the expensive/privileged contract — snapshot/restore, concurrency, memory-limit OOM.
///
/// Every [`FULL_CHECK_IDS`] entry is recorded or skipped on every path (see [`run_core`]).
pub async fn run_full<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    run_full_inner(vmm, a, outcomes).await;
    // See `run_extended`: a no-op today, load-bearing for the arm added tomorrow.
    fill_unrecorded(
        outcomes,
        FULL_CHECK_IDS,
        Level::Full,
        "not attempted: the Full run did not reach this check",
    );
}

async fn run_full_inner<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let caps = vmm.capabilities();

    // concurrency (no special capability).
    record(
        outcomes,
        "concurrency.distinct_ids",
        Level::Full,
        concurrency_distinct_ids(vmm, a).await,
    );

    // snapshot / restore.
    if caps.snapshot_restore {
        record(
            outcomes,
            "snapshot.restore_roundtrip",
            Level::Full,
            snapshot_restore_roundtrip(vmm, a).await,
        );
    } else {
        skip(
            outcomes,
            "snapshot.restore_roundtrip",
            Level::Full,
            format!("backend {} lacks snapshot_restore", vmm.id()),
        );
    }

    // memory-limit OOM.
    if cgroup_memory_delegated() {
        match base_cfg(a)
            .mem_mib(512)
            .network_disabled()
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "metrics.mem_limit_ooms",
                Level::Full,
                Err(format!("config: {e}")),
            ),
            Ok(mut cfg) => {
                cfg.limits.mem_max_mib = Some(256);
                // The slice this check reads is named after the prefix the VM is really started
                // with (docs/81 d3), captured here because `cfg` moves into `try_start_vm`. A
                // literal here would put back the default-prefix assumption the fix removed, and
                // `the_oom_check_reads_the_slice_of_the_vm_it_booted` reddens on one.
                let resource_prefix = cfg.resource_prefix.clone();
                match try_start_vm(vmm, cfg).await {
                    Err(e) => record(
                        outcomes,
                        "metrics.mem_limit_ooms",
                        Level::Full,
                        Err(failed_start(&e)),
                    ),
                    Ok(mut vm) => {
                        record(
                            outcomes,
                            "metrics.mem_limit_ooms",
                            Level::Full,
                            metrics_mem_limit_ooms(&mut vm, &resource_prefix).await,
                        );
                        shutdown_after_check(vm).await;
                    }
                }
            }
        }
    } else {
        skip(
            outcomes,
            "metrics.mem_limit_ooms",
            Level::Full,
            "memory cgroup controller not delegated to this process",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmcell::vmm::{FakeVmm, FaultMenu};

    /// `try_start_vm`'s env with the cgroup seam swapped for the shared
    /// [`vmcell::metrics::FakeCgroupFs`], for the KVM-free tests below that drive a `FakeVmm`
    /// through `MicroVm::start` only to obtain a handle and never look at a cgroup.
    ///
    /// They cannot use [`try_start_vm`]: it builds `vmcell::HostEnv::hermetic()` internally and
    /// exposes no cgroup seam, and `hermetic()` wires the REAL sysfs backend — which `mkdir`s
    /// `/sys/fs/cgroup/<base>/<prefix>-vm-<vmid>` and therefore needs the host cgroup tree
    /// delegated to the test process. That holds on a systemd user session and does NOT hold on a
    /// GitHub hosted runner (`system.slice/hosted-compute-agent.service`), where both tests failed
    /// with `Cgroup("create cgroup …: Permission denied (os error 13)")`. `try_start_vm` itself is
    /// deliberately left alone: it is the contract-surface harness the LIVE battery uses, and the
    /// `metrics.usage_readable` check needs the real seam to read real counters.
    ///
    /// The fake is `vmcell`'s own, reached through its non-default `test-support` feature taken as
    /// a **dev**-dependency (docs/81 §9). This crate used to hand-roll a fourth `TestCgroupFs`
    /// copy of it beside the three backend crates' — every one of them an always-`Ok` no-op that
    /// recorded nothing, so nothing about the seam was assertable from any of them.
    ///
    /// Assignment, not `..HostEnv::hermetic()`: `HostEnv` is `#[non_exhaustive]`, so
    /// functional-update syntax is rejected outside `vmcell`.
    ///
    /// FAKE-BLIND AXIS: `FakeCgroupFs` models slices in a `HashMap` and touches no filesystem, so
    /// the real slice create/limit/readback path is covered only by the live
    /// `metrics.usage_readable` arm of a `Level::Extended` run on a KVM host, never here.
    fn unit_test_env() -> vmcell::HostEnv {
        let mut env = vmcell::HostEnv::hermetic();
        env.cgroups = std::sync::Arc::new(vmcell::metrics::FakeCgroupFs::new());
        env
    }

    // The three-valued xattr verdict, decided purely. This is the half of the probe a machine with
    // no KVM can check, and it is the half that decides what §10.6's `judge` reports: an
    // "incomplete" walk mis-read as an absence turns every unwalkable image into a *verified*
    // absence, which is precisely the constant-that-certifies-everything §10.6 exists to forbid.
    //
    // RED four ways, each observed: (a) `DoesNotWork` for the cap marker — the cap leg's
    // `NotRun` assertion fails; (b) `Works` for the absent marker — the absent leg fails;
    // (c) treating a non-zero exit as an absence — the exit leg fails; (d) defaulting an
    // unrecognized stdout to `DoesNotWork` — the no-marker leg fails.
    #[test]
    fn the_xattr_scan_verdict_separates_absence_from_an_unfinished_walk() {
        assert_eq!(
            classify_xattr_scan(
                0,
                &format!("{XATTR_MARK_PRESENT} /bin/ping security.capability\n"),
                ""
            ),
            ProbeOutcome::Works,
            "a path that carries an attribute is the one positive observation available"
        );

        let ProbeOutcome::DoesNotWork(why) =
            classify_xattr_scan(0, &format!("{XATTR_MARK_ABSENT} 8123\n"), "")
        else {
            panic!("a COMPLETED walk that found nothing is an observation, not a shrug");
        };
        assert!(
            why.contains("8123"),
            "the evidence must carry how much was walked, or a reader cannot tell a real scan \
             from a scan of nothing: {why}"
        );
        assert!(
            why.contains("strip") && why.contains("SCHILY.xattr"),
            "…and it must name BOTH readings — a base with no records to keep, and a pack that \
             stripped them — because the scan genuinely does not distinguish them: {why}"
        );

        // The cap, the empty walk, a non-zero exit and unparseable output are all `NotRun`. Each
        // one mis-read as `DoesNotWork` is a *verified absence* awarded to an image nobody managed
        // to look inside.
        for (label, code, stdout) in [
            (
                "the path cap",
                0,
                format!("{XATTR_MARK_INCOMPLETE} path-cap 60000\n"),
            ),
            (
                "an empty walk",
                0,
                format!("{XATTR_MARK_INCOMPLETE} no-paths-walked\n"),
            ),
            ("a shell that failed", 127, String::new()),
            ("output with no marker", 0, "find: not found\n".to_string()),
        ] {
            assert!(
                matches!(
                    classify_xattr_scan(code, &stdout, "sh: find: not found"),
                    ProbeOutcome::NotRun(_)
                ),
                "{label} decides nothing and must be reported as undecided, never as an absence"
            );
        }
    }

    // The scan program itself: the three properties that make its output trustworthy, asserted on
    // the text because there is no guest here. `-xdev` is the load-bearing one — without it the
    // walk descends into `/proc` and `/sys`, whose attributes belong to the kernel rather than to
    // the artifact, and a `security.selinux` on a procfs node would report "preserved" for an image
    // that preserved nothing.
    //
    // RED on the inverse: drop `-xdev`, drop the cap comparison, or swap the applet for `getfattr`.
    #[test]
    fn the_xattr_scan_program_walks_the_artifact_and_bounds_itself() {
        let program = xattr_scan_program(1234);
        assert!(
            program.contains("-xdev"),
            "the walk must stay on the artifact's own filesystem: {program}"
        );
        assert!(
            program.contains("xattr list") && !program.contains("getfattr"),
            "the reader is vmcell's own applet — the rootfs is not required to ship `attr`, and a \
             probe that degrades to `command not found` reports a verified absence for every image \
             on earth: {program}"
        );
        assert!(
            program.contains("1234") && program.contains(XATTR_MARK_INCOMPLETE),
            "the cap must be both applied and REPORTED; a silent truncation is an absence claim \
             about the part nobody looked at: {program}"
        );
        assert!(
            program.contains(XATTR_MARK_PRESENT) && program.contains(XATTR_MARK_ABSENT),
            "all three verdicts must be reachable from the program the classifier parses"
        );
    }

    #[test]
    fn test_parse_oom_kill() {
        assert_eq!(parse_oom_kill("low 0\noom_kill 3\n"), Some(3));
        assert_eq!(parse_oom_kill("low 0\nhigh 1\n"), None);
    }

    // CONTRACT GATE (design §4.4, docs/81 m22 follow-up): the guest-tools PATH probe is COMPOSED
    // from `vmcell_protocol::GUEST_TOOLS_APPLETS`, so adding an applet to the roster extends what
    // the validator battery checks with no edit in this file. This module held the last re-typed
    // copy of the roster — three of four names in a shell string.
    // RED on the inverse (restore
    // `"command -v ip >/dev/null && command -v curl >/dev/null && command -v kvm-ok >/dev/null"`):
    // the per-entry assertion fires on `echo-server`, which that string never probed, and the
    // count assertion fires at 3 != 4.
    #[test]
    fn guest_tools_probe_is_composed_from_the_roster() {
        let roster = vmcell_protocol::GUEST_TOOLS_APPLETS;
        let probe = guest_tools_probe_command().expect("the shipped roster must compose");
        for applet in roster {
            assert!(
                probe.contains(&format!("command -v {applet} >/dev/null")),
                "the probe must test every roster entry; {applet} is missing from `{probe}`"
            );
        }
        // No name beyond the roster, and none dropped: a probe that tests MORE than the roster is
        // the same drift in the other direction (it would redden on a legitimately removed applet).
        assert_eq!(
            probe.matches("command -v ").count(),
            roster.len(),
            "the probe must name the roster exactly, got `{probe}`"
        );
        // Every probe is `&&`-chained, so a missing applet fails the command rather than being
        // masked by a later success.
        assert_eq!(
            probe.matches(" && ").count(),
            roster.len() - 1,
            "the probes must be &&-chained, got `{probe}`"
        );
    }

    // The composition's reject legs, driven against rosters the shipped const cannot express: a
    // probe of nothing passes vacuously, and a name needing shell quoting would be mis-parsed by
    // `sh -c` (a check that passes for the wrong reason). The positive control is the shipped
    // roster in the test above.
    #[test]
    fn guest_tools_probe_rejects_a_roster_it_cannot_carry() {
        assert!(
            probe_command_for(&[]).is_err(),
            "an empty roster must be rejected, not composed into a vacuous probe"
        );
        for bad in ["ip curl", "$(id)", "curl;rm", "", "kvm ok"] {
            let err = probe_command_for(&[bad])
                .expect_err(&format!("{bad:?} must be rejected, not composed"));
            assert!(
                err.contains("bare word") || err.contains("empty"),
                "the rejection must name the cause, got {err:?}"
            );
        }
        // Positive control for the accept side of the same matrix: the shapes a real applet name
        // takes (including the hyphenated and dotted ones) compose.
        let ok = probe_command_for(&["ip", "kvm-ok", "echo-server", "foo.sh"])
            .expect("bare-word applet names must compose");
        assert_eq!(ok.matches("command -v ").count(), 4, "got `{ok}`");
    }

    /// A guest that panicked mounting the erofs root, as the console really records it. Written to
    /// a real file by the tests below, because the bug class these tests exist to catch lives in
    /// the *reading* — `classify.rs`'s canned-log tests never touch the filesystem.
    const PANICKED_CONSOLE: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) #1 SMP PREEMPT_DYNAMIC
[    0.402244] No filesystem could mount root, tried:
[    0.402901] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(254,0)
";

    /// The same guest, before it ever printed the banner (the console the banner poll would see).
    const PANICKED_CONSOLE_NO_BANNER: &str = "\
[    0.402244] No filesystem could mount root, tried:
[    0.402901] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(254,0)
";

    // THE wiring gate. `classify.rs`'s tests all call the classifier directly, so a `serial_text`
    // that read the log and threw it away (`Ok(_) => String::new()`) left 21/21 green while every
    // classified boot failure reported the wrong clause. This drives the real fs read: the bytes on
    // disk must reach the classifier and the tail.
    #[tokio::test]
    async fn explain_boot_failure_at_classifies_the_console_it_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("serial.log");
        std::fs::write(&log, PANICKED_CONSOLE).expect("write console");

        let msg = explain_boot_failure_at(BootKind::Fresh, &log, "steward handshake failed").await;
        assert!(msg.starts_with("steward handshake failed"), "{msg}");
        assert!(
            msg.contains("contract violation:") && msg.contains("CONFIG_EROFS_FS"),
            "the message must name the clause the console proves: {msg}"
        );
        assert!(
            msg.contains("VFS: Unable to mount root fs on unknown-block(254,0)"),
            "the tail must quote the console that was read: {msg}"
        );
        assert!(msg.contains(&log.display().to_string()), "{msg}");
    }

    // An unreadable console is absence of evidence, not proof of a silent console: it must not be
    // rendered as the "not a direct-boot PVH vmlinux" contract violation.
    #[tokio::test]
    async fn explain_boot_failure_at_reports_absence_when_the_console_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("never-created.log");

        let msg =
            explain_boot_failure_at(BootKind::Fresh, &missing, "steward handshake failed").await;
        assert!(msg.contains("no serial evidence:"), "{msg}");
        assert!(msg.contains("it could not be read"), "{msg}");
        assert!(
            !msg.contains("contract violation:"),
            "an unreadable log proves no clause: {msg}"
        );
    }

    // The banner poll feeds the classifier the newest text it actually read. Guards dropping
    // `last` (the poll's only evidence) and a poll wired to a second copy of the banner literal.
    #[tokio::test]
    async fn await_kernel_banner_classifies_the_console_it_polled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("serial.log");
        std::fs::write(&log, PANICKED_CONSOLE_NO_BANNER).expect("write console");

        let err = await_kernel_banner(&log, Duration::from_millis(50))
            .await
            .expect_err("a console without the banner must fail the check");
        assert!(
            err.contains("contract violation:") && err.contains("CONFIG_EROFS_FS"),
            "the banner arm must classify the console it polled: {err}"
        );
    }

    // The positive control for the shared banner literal: a real banner line satisfies the poll.
    // Guards the poll and `classify_serial` drifting onto two different literals.
    #[tokio::test]
    async fn await_kernel_banner_accepts_the_shared_banner_literal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("serial.log");
        std::fs::write(&log, PANICKED_CONSOLE).expect("write console");
        assert!(
            PANICKED_CONSOLE.contains(BANNER_SIGNATURE),
            "the fixture must carry the banner the kernel really prints"
        );

        await_kernel_banner(&log, Duration::from_millis(50))
            .await
            .expect("a console carrying the banner passes the check");
    }

    // A console file the VMM never created is no evidence at all — not "the VM ran and printed
    // nothing". Guards the arm that used to classify an empty string as NoDirectBootKernel.
    #[tokio::test]
    async fn await_kernel_banner_without_a_console_reports_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("never-created.log");

        let err = await_kernel_banner(&missing, Duration::from_millis(50))
            .await
            .expect_err("no console means the check fails");
        assert!(err.contains("no serial evidence:"), "{err}");
        assert!(
            !err.contains("contract violation:"),
            "a console that never existed proves no clause: {err}"
        );
        assert!(
            err.contains("CONFIG_PVH"),
            "the candidate cause survives: {err}"
        );
    }

    // `run_core`'s start-failure arm, driven end to end without KVM: the WHOLE Core roster stays in
    // the report (v33 delta 3 — a failed start must not shrink it), the two boot ids fail carrying
    // the no-evidence rendering rather than an asserted contract violation (`MicroVm::start` also
    // fails for reasons that are not the artifact pair, which is exactly what a missing
    // `cloud-hypervisor` binary looks like), and every id the run could not reach is a Skip naming
    // the check that stopped it — never a silent absence and never a spurious pass.
    #[tokio::test]
    async fn run_core_records_the_whole_roster_when_the_vm_never_starts() {
        let vmm = FakeVmm::with_faults(FaultMenu {
            fail_create: true,
            ..FaultMenu::default()
        });
        let artifacts = ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs");
        let mut outcomes = Vec::new();
        run_core(&vmm, &artifacts, &mut outcomes).await;

        let ids: Vec<&str> = outcomes.iter().map(|o| o.id).collect();
        assert_eq!(ids, CORE_CHECK_IDS.to_vec(), "{ids:?}");
        // The config built (the pair's paths are never opened by the builder), so `boot.config` is
        // a recorded Pass — the error-only id v33 made unconditional.
        assert_eq!(
            outcomes
                .iter()
                .find(|o| o.id == "boot.config")
                .map(|o| &o.status),
            Some(&crate::CheckStatus::Pass)
        );
        for o in &outcomes {
            if o.id == "boot.config" {
                continue;
            }
            if !matches!(o.id, "boot.kernel_banner" | "boot.steward_ready") {
                let crate::CheckStatus::Skip(reason) = &o.status else {
                    panic!(
                        "{} was never attempted, so it must be a Skip with a reason, got {:?}",
                        o.id, o.status
                    );
                };
                assert!(
                    reason.contains("boot.kernel_banner"),
                    "the skip must point at the check that stopped the run: {reason}"
                );
                continue;
            }
            let crate::CheckStatus::Fail(msg) = &o.status else {
                panic!(
                    "{} must fail when the VM never starts: {:?}",
                    o.id, o.status
                );
            };
            assert!(msg.contains("VM failed to start:"), "{msg}");
            assert!(msg.contains("no serial evidence:"), "{msg}");
            assert!(
                !msg.contains("contract violation:"),
                "a VMM that never started proves no §5.4 clause: {msg}"
            );
            assert!(
                msg.contains("CONFIG_PVH"),
                "the candidate cause survives: {msg}"
            );
        }
    }

    // Every Extended/Full arm reports its boot failures through the same renderer as Core — the
    // crate doc's "every arm that reports a VM which failed to start" claim, driven. Guards the
    // bare `Err(format!("boot: {e}"))` these arms used to record, which named no clause, no
    // console, and no candidate cause.
    #[tokio::test]
    async fn every_extended_and_full_boot_failure_names_the_missing_evidence() {
        let vmm = FakeVmm::with_faults(FaultMenu {
            fail_create: true,
            ..FaultMenu::default()
        });
        let artifacts = ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs");
        let mut outcomes = Vec::new();
        run_extended(&vmm, &artifacts, &mut outcomes).await;
        run_full(&vmm, &artifacts, &mut outcomes).await;

        let failures: Vec<(&str, &String)> = outcomes
            .iter()
            .filter_map(|o| match &o.status {
                crate::CheckStatus::Fail(m) => Some((o.id, m)),
                _ => None,
            })
            .collect();
        assert!(
            failures.len() >= 3,
            "a backend that cannot create a VM must fail several Extended/Full checks; got \
             {failures:?} (skips: {:?})",
            outcomes
                .iter()
                .map(|o| (o.id, &o.status))
                .collect::<Vec<_>>()
        );
        for (id, msg) in failures {
            assert!(
                msg.contains("no serial evidence:"),
                "{id} reports a boot failure without routing through the renderers: {msg}"
            );
        }
    }

    // The steward budget is one law in one place. Guards re-inlining a per-call literal — the state
    // the module was in with the const declared and seven copies of the number still in the calls.
    #[test]
    fn every_steward_budget_is_a_named_const() {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/checks.rs"));
        // Built at runtime so this test's own needles are not the thing it counts.
        let literal = format!("Duration::from_secs({})", STEWARD_READY_BUDGET.as_secs());
        assert_eq!(
            SRC.matches(&literal).count(),
            1,
            "{literal} must appear exactly once (the STEWARD_READY_BUDGET const)"
        );
        let inline_call = format!("steward(Some(Duration::{}", "from_secs");
        assert_eq!(
            SRC.matches(&inline_call).count(),
            0,
            "every `steward(Some(..))` budget must be a named const, not an inline literal"
        );
    }

    /// docs/81 d3, end to end and KVM-free: the slice the **orchestrator really creates** for a VM
    /// with a non-default `resource_prefix`, and the slice `metrics_mem_limit_ooms` reads, are the
    /// same name. This is the loop the finding left open — the two halves below each pin one side
    /// of it, and this pins that they meet.
    ///
    /// It is only assertable because the cgroup seam is now `vmcell`'s **recording**
    /// [`vmcell::metrics::FakeCgroupFs`] (docs/81 §9): the hand-rolled `TestCgroupFs` this crate
    /// used to carry — one of four byte-alike copies — was an always-`Ok` no-op that remembered
    /// nothing, so no test driven by it could say which slice was created.
    ///
    /// FAKE-BLIND AXIS: the fake models slices in a `HashMap`, so this is evidence about the
    /// *name*, never about a real cgroup existing on disk. The live `metrics.mem_limit_ooms` arm
    /// of a `Level::Full` run on a KVM host is what proves the path is readable.
    #[tokio::test]
    async fn the_oom_path_names_the_slice_the_orchestrator_actually_created() {
        let vmm = FakeVmm::default();
        let prefix = "acme";
        let cfg = base_cfg(&ArtifactSet::new(
            "/nonexistent/vmlinux",
            "/nonexistent/rootfs.erofs",
        ))
        .resource_prefix(prefix)
        .network_disabled()
        .build()
        .expect("config builds");

        let cgroups = std::sync::Arc::new(vmcell::metrics::FakeCgroupFs::new());
        let mut env = vmcell::HostEnv::hermetic();
        env.cgroups = cgroups.clone();
        let mut vm = MicroVm::start(&vmm, cfg, &env)
            .await
            .expect("the fake backend starts");
        let vmid = vm.vmid();

        let slice = vmcell::metrics::vm_slice_name(prefix, vmid);
        let default_slice =
            vmcell::metrics::vm_slice_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, vmid);
        assert!(
            cgroups.has_slice(&slice),
            "the orchestrator created no slice named {slice} (is the default-prefix \
             {default_slice} there instead? {})",
            cgroups.has_slice(&default_slice)
        );
        assert_eq!(
            cgroup_events_path(prefix, vmid),
            std::path::PathBuf::from(format!("/sys/fs/cgroup/{slice}/memory.events")),
            "the check reads a slice the orchestrator never created"
        );

        vm.kill().await.expect("the fake backend stops");
    }

    /// docs/81 d3, the composition half: the `memory.events` path `metrics.mem_limit_ooms` reads
    /// is named by the ONE law, [`vmcell::metrics::vm_slice_name`], from the prefix it is handed —
    /// not by a hardcoded `vmcell-vm-` literal, which named a slice that exists for **no** VM
    /// configured with a non-default `resource_prefix`.
    ///
    /// Behavioural, not a scan: it calls the shipped composer with a non-default prefix. Restoring
    /// the old `format!("{base}/vmcell-vm-{vmid}")` reddens the first assertion, because the
    /// composed path then names `vmcell-vm-7` for a VM whose slice is `acme-vm-7`. Hermetic on any
    /// host: whether `/proc/self/cgroup` yields a sibling base or not only changes the prefix of
    /// the path, never its final two components.
    #[test]
    fn cgroup_events_path_composes_from_the_configured_prefix() {
        let non_default = "acme";
        assert_ne!(
            non_default,
            vmcell::naming::DEFAULT_RESOURCE_PREFIX,
            "the whole point of this test is a prefix the old hardcoded literal could not spell"
        );

        let path = cgroup_events_path(non_default, 7);
        let rendered = path.display().to_string();
        assert!(
            rendered.ends_with("/acme-vm-7/memory.events"),
            "the OOM counter must be read from the slice of a VM started with \
             `resource_prefix = {non_default:?}`, got {rendered}"
        );
        assert!(
            !rendered.contains("vmcell-vm-"),
            "the default prefix is hardcoded into the path of a non-default VM: {rendered}"
        );
        assert_eq!(
            path,
            std::path::PathBuf::from(format!(
                "/sys/fs/cgroup/{}/memory.events",
                vmcell::metrics::vm_slice_name(non_default, 7)
            )),
            "the slice name must come from `vmcell::metrics::vm_slice_name`, not a second copy \
             of the composition"
        );

        // Positive control: the default prefix still resolves to the slice it always named, so
        // the assertions above are about the prefix flowing through — not about `acme` in
        // particular — and the two paths really do differ.
        let default = cgroup_events_path(vmcell::naming::DEFAULT_RESOURCE_PREFIX, 7);
        assert!(
            default
                .display()
                .to_string()
                .ends_with("/vmcell-vm-7/memory.events"),
            "the default-prefix path must be unchanged: {}",
            default.display()
        );
        assert_ne!(
            default, path,
            "a composer that ignored its prefix argument would make both assertions vacuous"
        );
    }

    /// docs/81 d3, the call-site half. The gate above proves `cgroup_events_path` honours the
    /// prefix it is *given*; this proves the shipped caller gives it the prefix of the VM it
    /// actually booted, and that no hand-formatted slice name survives in this module.
    ///
    /// A source scan, in the shape of `vmcell-qemu`'s `virtiofs_pacing_gate`, because the property
    /// lives on one line inside an orchestrator that needs a real KVM host to run: nothing
    /// KVM-free can observe which string that call passed. Its own predicate and scanner controls
    /// are `the_oom_call_site_scanner_rejects_the_regression_shapes` below, so this is not a test
    /// that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_oom_check_reads_the_slice_of_the_vm_it_booted() {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/checks.rs"));
        /// The shipped calls to the check in this module: one, in `run_full`.
        ///
        /// Asserted exactly, so a scan that silently matched nothing — the way every
        /// source-scanning gate fails vacuously — reddens instead of passing over an empty set.
        const EXPECTED_OOM_CALL_SITES: usize = 1;

        let code = production_code(SRC);
        let calls = calls_to(&code, "metrics_mem_limit_ooms");
        assert_eq!(
            calls.len(),
            EXPECTED_OOM_CALL_SITES,
            "expected {EXPECTED_OOM_CALL_SITES} `metrics_mem_limit_ooms` call in `run_full`; \
             found {}: {calls:?}. If a site was legitimately added or removed, update \
             EXPECTED_OOM_CALL_SITES — do not delete the scan.",
            calls.len()
        );
        for call in &calls {
            assert!(
                call_names_the_configured_prefix(call),
                "docs/81 d3: this check must be handed the `resource_prefix` of the `VmConfig` \
                 the VM was started with, never a literal or the default — `{call}`"
            );
        }

        // …and no second copy of the composition survives anywhere in this module's production
        // text: the `-vm-` infix is `vmcell::naming`'s to spell, not this crate's.
        assert!(
            !code.contains("-vm-"),
            "a slice/resource name is hand-formatted in this module; compose it through \
             `vmcell::naming` (docs/81 d3): {}",
            code.match_indices("-vm-")
                .map(|(at, _)| &code[at.saturating_sub(60)..(at + 20).min(code.len())])
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }

    /// This module's production text: everything before the first `#[cfg(test)]`, whole-line
    /// comments (`//`, and therefore `///` too) dropped and the rest joined, per the in-repo
    /// source-scan convention. Joining is what lets the scan see a rustfmt-wrapped call whole.
    fn production_code(source: &str) -> String {
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Every call expression naming `callee` in `code`, each truncated at its statement's `;`.
    /// A **definition** (`fn callee(`) is not a call and is skipped, so a signature change that
    /// drops the generics cannot inflate the count into a confusing red.
    fn calls_to<'a>(code: &'a str, callee: &str) -> Vec<&'a str> {
        let needle = format!("{callee}(");
        code.match_indices(&needle)
            .filter(|(at, _)| !code[..*at].ends_with("fn "))
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    /// The law: the shipped call hands the check the prefix the VM was **configured** with — the
    /// binding taken off the `VmConfig` before it moved into `try_start_vm` — never a string
    /// literal and never the default const.
    fn call_names_the_configured_prefix(call: &str) -> bool {
        call.contains("&resource_prefix")
            && !call.contains('"')
            && !call.contains("DEFAULT_RESOURCE_PREFIX")
    }

    /// The scanner's own red-on-inverse: the predicate must reject every way of putting the
    /// default prefix back, and the scanner must see a wrapped call whole while ignoring prose,
    /// definitions and `#[cfg(test)]` text.
    #[test]
    fn the_oom_call_site_scanner_rejects_the_regression_shapes() {
        assert!(!call_names_the_configured_prefix(
            "metrics_mem_limit_ooms(&mut vm, \"vmcell\").await"
        ));
        assert!(!call_names_the_configured_prefix(
            "metrics_mem_limit_ooms(&mut vm, vmcell::naming::DEFAULT_RESOURCE_PREFIX).await"
        ));
        assert!(call_names_the_configured_prefix(
            "metrics_mem_limit_ooms(&mut vm, &resource_prefix).await"
        ));

        let synthetic = "// metrics_mem_limit_ooms(&mut vm, \"vmcell\") in a comment is not a call\n\
             pub async fn metrics_mem_limit_ooms(vm: &mut MicroVm<V>, p: &str) {}\n\
             record(o, metrics_mem_limit_ooms(\n    &mut vm, &resource_prefix).await);\n\
             #[cfg(test)]\nmod tests { metrics_mem_limit_ooms(&mut vm, \"vmcell\"); }";
        let code = production_code(synthetic);
        let calls = calls_to(&code, "metrics_mem_limit_ooms");
        assert_eq!(
            calls.len(),
            1,
            "the comment, the definition and the `#[cfg(test)]` call must all be invisible: {code}"
        );
        assert!(
            call_names_the_configured_prefix(calls[0]),
            "a rustfmt-wrapped call must be seen whole: {calls:?}"
        );
        // The banned infix really is detectable in production text (so its assertion is not
        // vacuous), and really is invisible in a comment.
        assert!(production_code("let n = format!(\"{p}-vm-{vmid}\");").contains("-vm-"));
        assert!(!production_code("// <prefix>-vm-<vmid> in prose").contains("-vm-"));
    }

    // `metrics.usage_readable` must FAIL, naming the boot failure, when the guest never hands
    // shakes. The handshake was a bare `let _` (`usage-readable-swallows-steward-handshake`), so the
    // arm walked into the cgroup readout on a guest that never booted and reported anything but the
    // reason — on a host where the counters happen to read back, a green PASS.
    //
    // KVM-free: the fake backend's vsock path has no listener, so the handshake genuinely fails;
    // the budget is injected (1s, not `STEWARD_READY_BUDGET`) so it fails in a second rather than a
    // minute, and the message must name *that* budget. What this fake cannot see is the pass side —
    // a real delegated cgroup readout — which is the live `metrics.usage_readable` leg of a
    // `Level::Extended` validation run on a KVM host.
    #[tokio::test]
    async fn usage_readable_fails_naming_the_boot_failure_when_the_steward_never_handshakes() {
        let vmm = FakeVmm::default();
        let cfg = base_cfg(&ArtifactSet::new(
            "/nonexistent/vmlinux",
            "/nonexistent/rootfs.erofs",
        ))
        .network_disabled()
        .build()
        .expect("config builds");
        // `MicroVm::start` over `unit_test_env()` rather than `try_start_vm`, which has no cgroup
        // seam — see `unit_test_env` above.
        let mut vm = MicroVm::start(&vmm, cfg, &unit_test_env())
            .await
            .expect("the fake backend starts");
        let serial = vm.instance().serial_log().display().to_string();

        let err =
            usage_readable_after_steward_ready(&mut vm, Duration::from_secs(1), Duration::ZERO)
                .await
                .expect_err("a guest that never hands shakes has no readable usage to report");
        assert!(
            err.starts_with("steward handshake failed within the 1s budget"),
            "the arm must report the handshake failure, with the budget it really used: {err}"
        );
        assert!(
            err.contains(&serial),
            "the message must name the VM's own console ({serial}): {err}"
        );
        assert!(
            !err.contains("memory controller delegated"),
            "a guest that never booted must not be reported as a cgroup readout problem: {err}"
        );
        vm.kill().await.expect("the fake backend stops");
    }

    // The one line that turns a VM into a console path. Guards `explain_boot_failure_for` reading
    // some other file than the VM's own serial log.
    #[tokio::test]
    async fn explain_boot_failure_for_reads_the_vms_own_console() {
        let vmm = FakeVmm::default();
        let cfg = base_cfg(&ArtifactSet::new(
            "/nonexistent/vmlinux",
            "/nonexistent/rootfs.erofs",
        ))
        .network_disabled()
        .build()
        .expect("config builds");
        // `MicroVm::start` over `unit_test_env()` rather than `try_start_vm`, which has no cgroup
        // seam — see `unit_test_env` above.
        let mut vm = MicroVm::start(&vmm, cfg, &unit_test_env())
            .await
            .expect("the fake backend starts");
        let expected = vm.instance().serial_log().display().to_string();

        let msg = explain_boot_failure_for(&vm, "steward handshake failed").await;
        assert!(
            msg.contains(&expected),
            "the message must name the VM's own serial log ({expected}): {msg}"
        );
        vm.kill().await.expect("the fake backend stops");
    }

    // m9, the fs-reading half: a RESTORED VM's console file exists and is empty (the VMM created
    // it; the guest kernel printed its banner in the snapshot source, on another console). Read as
    // a fresh boot, that file said "not a direct-boot PVH-ELF vmlinux" about a kernel that had just
    // booted, snapshotted and resumed. `classify.rs` gates the pure classifier; this drives the
    // real read, which is the composition `snapshot_restore_roundtrip` actually calls.
    #[tokio::test]
    async fn explain_boot_failure_at_reads_a_restored_console_as_restored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("restored-serial.log");
        std::fs::write(&log, "").expect("write the empty restored console");

        let msg = explain_boot_failure_at(
            BootKind::Restored,
            &log,
            "restored VM: steward handshake failed within the 60s budget",
        )
        .await;
        assert!(
            !msg.contains("contract violation:") && !msg.contains("CONFIG_PVH"),
            "a restored VM's empty console proves no §5.4 clause: {msg}"
        );
        assert!(
            msg.contains("RESTORED from a snapshot"),
            "the message must explain why the console is empty: {msg}"
        );
        assert!(msg.contains(&log.display().to_string()), "{msg}");

        // The positive control: the SAME empty file, read as the fresh boot it is not, still
        // renders the verdict fresh boots earn — so the difference is the kind, not the file.
        let fresh =
            explain_boot_failure_at(BootKind::Fresh, &log, "the banner never appeared").await;
        assert!(fresh.contains("CONFIG_PVH"), "{fresh}");
    }

    /// `snapshot_restore_attempt`'s body, read out of this file with its comments stripped — the two
    /// source scans below both need it, and both would otherwise trip on a comment that merely
    /// *names* the token they are looking for.
    ///
    /// The first column-0 `}` closes the function, so this is its body alone — not the needles in
    /// the scans further down the file.
    fn snapshot_attempt_code() -> String {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/checks.rs"));
        let after = SRC
            .split("async fn snapshot_restore_attempt")
            .nth(1)
            .expect("the function must exist");
        let end = after
            .find("\n}\n")
            .expect("the function has a closing brace");
        after
            .get(..end)
            .expect("a char boundary at a newline")
            .lines()
            .filter_map(|l| l.split("//").next())
            .collect::<Vec<&str>>()
            .join("\n")
    }

    // The mapping M8 turned on, purely: a probe that stopped in SETUP decides nothing (`NotRun` →
    // `Unverified`), and only a probe that got to exercise the feature can report a measured absence
    // (`DoesNotWork` → the one `Pass` an absence declaration can earn). RED on the inverse: collapse
    // either arm onto the other — which is exactly the shape the defect had, every `Err` mapped to
    // `DoesNotWork` — and the corresponding leg fails.
    #[test]
    fn a_setup_stop_is_notrun_and_an_exercised_stop_is_doesnotwork() {
        assert_eq!(
            stopped_probe_outcome(ProbeStop::Setup("the VM never started".into())),
            ProbeOutcome::NotRun("the VM never started".into())
        );
        assert_eq!(
            stopped_probe_outcome(ProbeStop::Exercised("restore() failed".into())),
            ProbeOutcome::DoesNotWork("restore() failed".into())
        );
        // The level check keeps both as one `Err` with the same text: it judges a declared-present
        // property, where "never got there" and "got there and it broke" are the same verdict.
        assert_eq!(
            ProbeStop::Setup("the VM never started".into()).into_why(),
            "the VM never started"
        );
        assert_eq!(
            ProbeStop::Exercised("restore() failed".into()).into_why(),
            "restore() failed"
        );
    }

    /// The sentences [`snapshot_restore_attempt`] **prefixes** a setup stop with, in the order it
    /// can reach them: the config, the snapshot SOURCE VM (its start and its handshake share one
    /// stage), and the host scratch dir. "Why the candidate was undecidable" is one of these plus
    /// the cause it carries.
    ///
    /// Prefixes, not substrings, and that is the whole point. Every arm composes
    /// `format!("<stage>: {cause}")`, so the stage is the head and the cause is the tail — and the
    /// tail is the only part that varies with the host: `MicroVm::start`'s error text embeds the
    /// **vmid this run allocated** (`…/vmcell-vm-26` on one call, `…/vmcell-vm-123` on the next).
    /// Matching the head is what makes the assertion deterministic; matching anywhere would let a
    /// cause that happens to quote another stage's words re-classify the stop.
    ///
    /// [`the_stage_prefixes_are_the_ones_the_probe_composes`] pins every entry against the probe's
    /// own source, so a renamed arm reddens this roster instead of quietly emptying it.
    const SETUP_STAGE_PREFIXES: [&str; 3] = [
        "snapshot-eligible config build failed: ",
        "snapshot-source: ",
        "tempdir: ",
    ];

    /// The same for the **measuring** arms — the stops a setup failure must never be reported as,
    /// which is the direction M8 shipped.
    const EXERCISED_STAGE_PREFIXES: [&str; 3] =
        ["snapshot() failed: ", "restore() failed: ", "restored VM: "];

    /// Which stage a probe reason names, panicking if it names none or more than one.
    ///
    /// The deterministic half of a reason whose tail (an errno, a path, an allocated vmid) is the
    /// host's business. Also asserts the reason carries a cause *after* the stage: a bare stage
    /// label says where the probe stopped and not why, and "why" is the payload `Unverified` exists
    /// to deliver.
    fn stage_named_by(why: &str) -> &'static str {
        let matched: Vec<&'static str> = SETUP_STAGE_PREFIXES
            .into_iter()
            .chain(EXERCISED_STAGE_PREFIXES)
            .filter(|p| why.starts_with(p))
            .collect();
        assert_eq!(
            matched.len(),
            1,
            "a probe reason must name exactly one stage the probe can stop at (setup \
             {SETUP_STAGE_PREFIXES:?}, measuring {EXERCISED_STAGE_PREFIXES:?}); {why:?} named \
             {matched:?}"
        );
        let stage = matched[0];
        assert!(
            why.len() > stage.len(),
            "the stage names WHERE the probe stopped; what follows it is why, and an undecidable \
             verdict without a why is a shrug: {why:?}"
        );
        stage
    }

    // Non-vacuity for the two rosters above: every stage they name must still be composed by the
    // probe. A renamed arm would otherwise leave `stage_named_by` unable to match anything, and its
    // panic would read as a product defect rather than as a stale test constant. Read off the same
    // comment-stripped source slice the two scans below use, so a needle that survives only in a
    // COMMENT does not count.
    //
    // RED on the inverse: rename any arm's sentence in `snapshot_restore_attempt` (or mistype an
    // entry above) and the stage it no longer composes is named here.
    #[test]
    fn the_stage_prefixes_are_the_ones_the_probe_composes() {
        let code = snapshot_attempt_code();
        for stage in SETUP_STAGE_PREFIXES
            .into_iter()
            .chain(EXERCISED_STAGE_PREFIXES)
        {
            // The `: ` a stage ends with is followed by `{e}`/`{}` in the source, so the needle is
            // the stage sentence itself.
            let needle = stage.trim_end().trim_end_matches(':');
            assert!(
                code.contains(needle),
                "the probe no longer composes `{needle}`, so this roster is stale and \
                 `stage_named_by` would classify nothing:\n{code}"
            );
        }
    }

    // M8, at the arm that shipped it: an artifact that cannot boot at all must come back `NotRun`,
    // never `DoesNotWork` — the latter is what let it earn a *verified absence* from `judge`, with
    // the healthy control keeping the run green. `fail_create` is a candidate that never reaches the
    // point where a snapshot could be attempted, which is the whole class.
    //
    // WHICH setup failure occurs is deliberately not part of the premise. On a delegated developer
    // box the fake's `create` fault is what stops the start; on an undelegated hosted runner the
    // real cgroup seam is refused (`Permission denied`) one step earlier — `snapshot_restore_attempt`
    // builds `HostEnv::hermetic()` itself, so no test can hand it `unit_test_env`'s fake. Both are
    // the same stop at the same stage, and the stage is the claim.
    //
    // RED on the inverse: map the attempt's `Err` back to `DoesNotWork` (or move any arm before
    // `vm.snapshot(` to `ProbeStop::Exercised`) and this fails. The end-to-end verdict is gated one
    // module over (`an_unbootable_candidate_is_unverified_never_a_verified_absence`).
    #[tokio::test]
    async fn the_snapshot_probe_reports_an_unbootable_candidate_as_notrun() {
        let vmm = FakeVmm::with_faults(FaultMenu {
            fail_create: true,
            ..FaultMenu::default()
        });
        let artifacts = ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs");
        let outcome = snapshot_restore_probe(&vmm, &artifacts).await;
        let ProbeOutcome::NotRun(why) = &outcome else {
            panic!(
                "a candidate that never booted decides nothing about snapshot support: {outcome:?}"
            );
        };
        // THE CLASSIFICATION, plus the reason it can be trusted. `NotRun` alone is also what a probe
        // that shrugged without saying anything returns; `stage_named_by` requires the verdict to
        // name one of the stages the probe can stop at AND to carry the cause after it.
        let stage = stage_named_by(why);
        assert!(
            SETUP_STAGE_PREFIXES.contains(&stage),
            "a candidate whose VM never started stopped in SETUP; reporting the stage `{stage}` \
             claims the probe exercised the feature on a VM that does not exist: {why:?}"
        );

        // The level check's verdict on the same artifact is the same stop — a declared-present
        // property the candidate never reached is still a failure, and it fails at the same stage.
        //
        // Compared by STAGE, not as whole strings, which is what this assertion used to be: the two
        // calls each allocate their own vmid, and `MicroVm::start`'s error text names it, so on a
        // host where the cgroup seam is the thing that refuses (a GitHub hosted runner) the two
        // reasons differ in exactly that number and byte-equality was red for a reason that has
        // nothing to do with the property. That the two callers render a stop's text identically is
        // `into_why`'s own law, gated purely in
        // `a_setup_stop_is_notrun_and_an_exercised_stop_is_doesnotwork`; what is left for this leg
        // is that both callers reach the same arm on the same input.
        let level_why = snapshot_restore_roundtrip(&vmm, &artifacts)
            .await
            .expect_err("a declared-present property the candidate never reached is a failure");
        assert_eq!(
            stage_named_by(&level_why),
            stage,
            "probe {why:?} vs level check {level_why:?}"
        );
    }

    // M8's BOUNDARY, in the shape of the m9 scan below: which side of the setup/measurement line
    // each arm falls on is only observable on a KVM host with a snapshot-capable backend, so it is
    // pinned on the source. Everything before `vm.snapshot(` is setup (the feature was never
    // exercised → undecided); everything from there on is the measurement. An arm on the wrong side
    // is either M8 itself (an unbootable candidate certified as a verified absence) or its inverse
    // (a broken restore excused as undecidable).
    #[test]
    fn the_snapshot_probe_classifies_setup_before_the_attempt_and_measurement_after() {
        let code = snapshot_attempt_code();
        let attempt = code
            .find("vm.snapshot(")
            .expect("the probe must attempt a snapshot");
        let (before, after) = code.split_at(attempt);
        assert!(
            before.contains("ProbeStop::Setup"),
            "non-vacuity: the arms before the attempt are the setup ones"
        );
        assert!(
            !before.contains("ProbeStop::Exercised"),
            "an arm that runs BEFORE the snapshot attempt cannot have measured the feature — \
             reporting it as a measured absence is docs/90 M8: {before}"
        );
        assert!(
            after.contains("ProbeStop::Exercised"),
            "non-vacuity: the arms from the attempt on are the measuring ones"
        );
        assert!(
            !after.contains("ProbeStop::Setup"),
            "an arm that runs AFTER the snapshot attempt has exercised the feature; calling it a \
             setup failure would excuse a broken snapshot/restore as undecidable: {after}"
        );
    }

    // m9, the WIRING half. The classifier and the fs read are both gated above, but which kind
    // `snapshot_restore_attempt` passes is only observable on a KVM host with a snapshot-capable
    // backend — the one thing the KVM-free suite structurally cannot reach (AGENTS.md rule 4). This
    // reads the source instead: inside that function, the console rendered AFTER `MicroVm::restore`
    // must be the restored one, and the snapshot-source arm before it must not be. Guards the
    // argument being swapped back (either direction) by a later edit.
    #[test]
    fn snapshot_restore_roundtrip_renders_the_restored_console_as_restored() {
        let code = snapshot_attempt_code();
        let body = code.as_str();

        let restore_call = body
            .find("MicroVm::restore(")
            .expect("the check must restore a VM");
        let restored_kind = body
            .find("BootKind::Restored")
            .expect("the restored VM's console must be rendered with BootKind::Restored");
        assert!(
            restored_kind > restore_call,
            "the restored rendering must belong to the restored VM, not the snapshot source"
        );
        let source_arm = body.get(..restore_call).expect("a char boundary");
        assert!(
            !source_arm.contains("BootKind::Restored"),
            "the snapshot SOURCE boots fresh; its console must not be read as a restored one"
        );
    }

    /// How many times `id` is spelled as a string literal in this module's production text — its
    /// roster entry plus every site that records or skips it.
    fn id_literal_sites(code: &str, id: &str) -> usize {
        code.matches(&format!("\"{id}\"")).count()
    }

    /// THE DELETE-A-CHECK GATE, and the reason the roster is not self-certifying.
    ///
    /// `fill_unrecorded` is what makes a report never shrink — but it is also what would hide a
    /// deleted check: rip the call out of `guest_core_checks` and the id still appears, as a Skip
    /// with a plausible reason, and the rustdoc roster gates stay green because they compare
    /// documented ids against *recorded* ones. So the roster is pinned from the other side too:
    /// every id must have a recording site in the code, not merely a line in the const.
    ///
    /// A source scan, in the shape of `the_oom_check_reads_the_slice_of_the_vm_it_booted` above,
    /// because the property lives at call sites inside orchestrators that need a real guest to run.
    /// Its own scanner controls are `the_roster_scanner_distinguishes_a_declaration_from_a_call`.
    #[test]
    fn every_roster_id_has_a_recording_site() {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/checks.rs"));
        let code = production_code(SRC);
        for (level, roster) in [
            ("Core", CORE_CHECK_IDS),
            ("Extended", EXTENDED_CHECK_IDS),
            ("Full", FULL_CHECK_IDS),
        ] {
            assert!(!roster.is_empty(), "the {level} roster is empty");
            for id in roster {
                let sites = id_literal_sites(&code, id);
                assert!(
                    sites >= 2,
                    "{level} check `{id}` appears {sites} time(s) in production code: it is in the \
                     roster const but nothing records it, so a run would report it as a Skip \
                     forever. Either restore the check or remove the id from the roster AND its \
                     Level rustdoc — a check that quietly became a permanent skip is the roster \
                     gate's blind spot, which is why this scan exists."
                );
            }
        }
    }

    /// The scanner's own red-on-inverse: it must see a roster line and a recording site as two
    /// occurrences, and a roster line alone as one (the state a deleted check leaves behind).
    #[test]
    fn the_roster_scanner_distinguishes_a_declaration_from_a_call() {
        let declared_only = "const CORE_CHECK_IDS: &[&str] = &[ \"boot.config\", ];";
        assert_eq!(id_literal_sites(declared_only, "boot.config"), 1);
        let declared_and_recorded = "const CORE_CHECK_IDS: &[&str] = &[ \"boot.config\", ]; \
             record(outcomes, \"boot.config\", Level::Core, Ok(()));";
        assert_eq!(id_literal_sites(declared_and_recorded, "boot.config"), 2);
        // Substring safety: a longer id containing a shorter one must not inflate the shorter
        // one's count, because the needle is quoted on both sides.
        assert_eq!(id_literal_sites("\"boot.config_extra\"", "boot.config"), 0);
    }
}
