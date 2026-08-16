//! The `Pid1` filesystem assembly (design §3.4) — tmpfs, overlay, `pivot_root`, the core mounts,
//! the host's virtio-fs shares, and loopback.
//!
//! **Scoped to [`crate::GuestPlacement::Pid1`] by v33 delta 5.** Under `Service` somebody else
//! assembled the filesystem and re-running `pivot_root` would be destructive, so none of this
//! runs — and the fatal-mount policy is scoped with it, which is the whole reason the policy is a
//! parameter rather than a second copy of the code.
//!
//! The fatal set is EXACTLY the four mounts {tmpfs `/mnt`, overlay, `/proc`, `/dev`} plus the
//! `pivot_root` sequence itself; everything else here is warn-and-continue, because returning
//! `Err` from PID 1 kernel-panics the guest ("Attempted to kill init").

use rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_change, unmount,
};
use rustix::process::pivot_root;

use crate::netif;
use crate::options::{ShareMount, parse_share_mounts};

/// The **one** PID-1 root assembly: core mounts, the host's declared virtio-fs shares, and
/// loopback — everything a guest's PID 1 owes the processes that run in it.
///
/// Public because `mini-init` (the `vmcell-guest-tools` applet that stands in for a real init in
/// the service-placement gates, §3.5) must assemble the *same* root. A second copy of the mount
/// sequence over in guest-tools is exactly the shape AGENTS.md bans — the tree already carries one
/// deliberate guest-side duplication (the `ifreq` layout) and it needed a divergence guard to stay
/// honest. Reusing this function instead means a service-placement cell's filesystem is
/// byte-for-byte the one a `Pid1` cell gets, which is what makes the two placements' live legs
/// comparable rather than merely similar.
///
/// # Errors
///
/// Returns `Err` for any member of the fatal set — the four core mounts {tmpfs `/mnt`, overlay,
/// `/proc`, `/dev`} and the `pivot_root` sequence. Shares and loopback are best-effort and never
/// surface here. A caller that is PID 1 must treat the error as terminal-loud: returning from PID 1
/// kernel-panics the guest, which is the intended, visible failure for a root that would not build.
pub fn assemble_guest_root() -> Result<(), Box<dyn std::error::Error>> {
    assemble_core_mounts()?;
    // Read AFTER the core mounts: `/proc` is one of them, so an earlier read sees no procfs at all
    // and silently yields an empty cmdline — the ordering trap recorded on [`crate::options`].
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    mount_shares(&cmdline);
    bring_up_loopback();
    Ok(())
}

/// Assembles the guest root: tmpfs, overlay, `pivot_root`, and the core mounts.
///
/// # Errors
///
/// Returns `Err` for any member of the fatal set — the four core mounts and the `pivot_root`
/// sequence. Under `Pid1` that error reaches `main`, PID 1 returns, and the kernel panics; that is
/// the intended, loud failure for a root that could not be assembled.
pub(crate) fn assemble_core_mounts() -> Result<(), Box<dyn std::error::Error>> {
    // Mount setup. `/sys` is NOT in the fatal core-mount set ({tmpfs /mnt, overlay,
    // /proc, /dev} — FOUR mounts, §3.4, The guest: vmcell-steward as PID 1;
    // earlier revisions of this comment listed three and understated their own code):
    // its *mount* failure is tolerated below (:127-138), so its
    // mount-point creation must be tolerated too — a fatal `?` here would
    // kernel-panic PID 1 ("Attempted to kill init") on a policy the steward
    // otherwise treats as best-effort (AGENT-6).
    if let Err(e) = std::fs::create_dir_all("/sys") {
        tracing::warn!(
            "vmcell-steward: could not create /sys mount point: {}; continuing (sysfs is not a fatal core mount)",
            e
        );
    }
    std::fs::create_dir_all("/proc")?;
    std::fs::create_dir_all("/mnt")?;

    if let Err(e) = mount(
        "tmpfs",
        "/mnt",
        "tmpfs",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-steward as PID 1): failure returns Err and kernel-panics PID 1, so
        // log it at error — louder than the tolerated best-effort failures (sysfs,
        // shares, loopback) that log at warn (N-GUEST-1: the levels were inverted).
        tracing::error!("vmcell-steward: mount tmpfs failed: {}", e);
        return Err(e.into());
    }
    std::fs::create_dir_all("/mnt/upper")?;
    std::fs::create_dir_all("/mnt/work")?;
    std::fs::create_dir_all("/mnt/rootfs")?;

    if let Err(e) = mount(
        "overlay",
        "/mnt/rootfs",
        "overlay",
        MountFlags::empty(),
        Some(c"lowerdir=/,upperdir=/mnt/upper,workdir=/mnt/work"),
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-steward as PID 1): error level (N-GUEST-1).
        tracing::error!("vmcell-steward: overlay failed: {}", e);
        return Err(e.into());
    }

    if let Err(e) = std::env::set_current_dir("/mnt/rootfs") {
        tracing::error!("vmcell-steward: failed to chdir to /mnt/rootfs: {}", e);
        return Err(e.into());
    }
    std::fs::create_dir_all("oldroot")?;

    if let Err(e) = pivot_root(".", "oldroot") {
        // Fatal core mount (§3.4, The guest: vmcell-steward as PID 1): error level (N-GUEST-1).
        tracing::error!("vmcell-steward: pivot_root failed: {}", e);
        return Err(e.into());
    }
    // The `else` is unnecessary after the early `return Err` above (N-GUEST-1):
    // the success path continues here.
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )?;
    unmount("oldroot", UnmountFlags::DETACH)?;
    std::fs::remove_dir_all("oldroot")?;

    // /sys is NOT part of the fatal core-mount set — that set is EXACTLY the FOUR
    // mounts {tmpfs /mnt, overlay, /proc, /dev} (§3.4, The guest: vmcell-steward
    // as PID 1); the tmpfs at :186-198 returns Err like the other three. The vsock control plane, the
    // overlay/pivot_root sequence, and restore-path MAC rotation (ioctls) do not
    // require sysfs, so a failed sysfs mount is logged and tolerated like the
    // share-mount / loopback paths below. Returning Err from PID 1's main would
    // kernel-panic the guest ("Attempted to kill init").
    if let Err(e) = mount(
        "sysfs",
        "/sys",
        "sysfs",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        tracing::warn!(
            "vmcell-steward: sysfs mount failed: {}; continuing without /sys",
            e
        );
    }
    if let Err(e) = mount(
        "proc",
        "/proc",
        "proc",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-steward as PID 1): error level (N-GUEST-1).
        tracing::error!("vmcell-steward: proc failed: {}", e);
        return Err(e.into());
    }
    if let Err(e) = mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        MountFlags::empty(),
        None::<&core::ffi::CStr>,
    ) {
        // Fatal core mount (§3.4, The guest: vmcell-steward as PID 1): error level (N-GUEST-1).
        tracing::error!("vmcell-steward: devtmpfs failed: {}", e);
        return Err(e.into());
    }

    // devpts at /dev/pts powers interactive PTY sessions (§3, The control plane: vsock, the host clients, and the steward):
    // `/dev/ptmx` allocates a master and `ptsname` resolves the slave under
    // /dev/pts. Best-effort and NOT in the fatal core-mount set {tmpfs /mnt, overlay,
    // /proc, /dev} (§3.4, The guest: vmcell-steward as PID 1) — only PTY *sessions* need it (they fail loud with
    // `SessionExit(127)` if it is absent); one-shot exec, pipe sessions, and the
    // vsock control plane do not. So a failure is logged and tolerated like the
    // sysfs/share/loopback mounts (returning Err from PID 1 kernel-panics the
    // guest). `newinstance` is legacy/ignored on modern kernels; the standard
    // `gid=5,mode=620,ptmxmode=666` gives the usual /dev/pts semantics.
    if let Err(e) = std::fs::create_dir_all("/dev/pts") {
        tracing::warn!(
            "vmcell-steward: could not create /dev/pts mount point: {}; PTY sessions unavailable",
            e
        );
    } else if let Err(e) = mount(
        "devpts",
        "/dev/pts",
        "devpts",
        MountFlags::empty(),
        Some(c"gid=5,mode=620,ptmxmode=666"),
    ) {
        tracing::warn!(
            "vmcell-steward: devpts mount failed: {}; PTY sessions unavailable (pipe sessions and exec unaffected)",
            e
        );
    }
    Ok(())
}

/// Mount the virtio-fs shares the host configured, decoded from the kernel
/// command line (`vmcell_share=<tag>:<guest_path>:<ro|rw>` tokens emitted by
/// `config::push_share_args`). Tags are caller-defined, not built into the
/// steward (§4.5, Shared directories (virtio-fs)): the steward honours whatever `VmConfig.shares` specified rather
/// than a hardcoded `imp-*` list. A share is optional — a config may attach
/// none (the benchmark / exec-only paths do), and virtiofsd may not be attached
/// for a declared tag, so a failed mount is logged and skipped, never
/// propagated: returning Err from PID 1's main kernel-panics the guest
/// ("Attempted to kill init").
pub(crate) fn mount_shares(cmdline: &str) {
    for ShareMount {
        tag,
        mount_point,
        read_only,
    } in parse_share_mounts(cmdline)
    {
        if let Err(e) = std::fs::create_dir_all(&mount_point) {
            tracing::warn!(
                "vmcell-steward: could not create mount point {}: {}; skipping share",
                mount_point,
                e
            );
            continue;
        }

        let flags = if read_only {
            MountFlags::RDONLY
        } else {
            MountFlags::empty()
        };
        if let Err(e) = mount(
            tag.as_str(),
            &mount_point as &str,
            "virtiofs",
            flags,
            None::<&core::ffi::CStr>,
        ) {
            tracing::warn!(
                "vmcell-steward: optional virtiofs share {} not attached: {}; continuing",
                tag,
                e
            );
        } else {
            tracing::info!(
                "vmcell-steward: mounted virtiofs {} at {} ({})",
                tag,
                mount_point,
                if read_only { "ro" } else { "rw" }
            );
        }
    }
}

/// Brings loopback up, best-effort.
///
/// `Pid1`-scoped: under `Service` the guest's own init owns `lo`, and a second bring-up is at best
/// redundant. Never fatal — the vsock control plane does not need loopback.
pub(crate) fn bring_up_loopback() {
    // Bring up loopback without shelling out to `ip`, via the audited 40-byte
    // `IfReq` helper (C-GUEST-1/M-GUEST-5). The prior inline path here declared an
    // 18-byte `ifreq` and passed it to `SIOCG/SIOCSIFFLAGS`, which `copy_to_user`
    // the kernel's 40-byte `struct ifreq` — a 22-byte OOB write on PID 1's stack.
    // Best-effort: loopback is not required for the vsock control plane, so a
    // failure is logged and tolerated (returning `Err` from PID 1 would panic).
    if let Err(e) = netif::set_loopback_up() {
        tracing::warn!(
            "vmcell-steward: loopback bring-up failed: {}; continuing without lo",
            e
        );
    }
}
