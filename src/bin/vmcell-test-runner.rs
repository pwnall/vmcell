use capctl::{Cap, CapState};
use std::env;
use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, exit};

/// Builds the operator-facing remediation message shown when the runner lacks
/// its capabilities.
///
/// The precondition (`ensure_blessed_or_explain`) checks the **effective** set,
/// so the printed `setcap` must grant `+ep` (effective + permitted). A bare `+p`
/// would set only the permitted set and the runner would still fail the check.
fn blessing_remediation(uid: u32, exe: &Path) -> String {
    format!(
        "error: vmcell-test-runner is missing CAP_NET_ADMIN/CAP_SYS_ADMIN (uid={uid}, no file caps).\n\
         It was almost certainly rebuilt. Restore its privileges (one-time, until next rebuild):\n\n\
         sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {}\n\n\
         Then re-run the privileged suite. See §12.8.",
        exe.display()
    )
}

fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String> {
    let caps = CapState::get_current().map_err(|e| e.to_string())?;

    // Check if euid is 0 (setuid root fallback).
    let euid = rustix::process::geteuid();
    if euid.as_raw() == 0 {
        return Ok(());
    }

    // The privileged window needs these caps in the EFFECTIVE set (file-caps +ep form).
    let mut missing = Vec::new();
    for &c in need {
        if !caps.effective.has(c) {
            missing.push(c);
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        Err(blessing_remediation(
            rustix::process::getuid().as_raw(),
            &exe,
        ))
    }
}

/// Returns the real cargo `target` directory this runner was built into.
///
/// Anchored on the runner's own canonicalized executable path — NOT an
/// attacker-controllable env var — because the binary lives at
/// `<target>/<profile>/vmcell-test-runner`, so the nearest ancestor directory named
/// `target` is the cargo target dir. Used as the confinement root for the test
/// binary about to be exec'd.
fn real_cargo_target_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot resolve current exe: {e}"))?
        .canonicalize()
        .map_err(|e| format!("cannot canonicalize current exe: {e}"))?;
    for ancestor in exe.ancestors() {
        if ancestor.file_name() == Some(OsStr::new("target")) {
            return Ok(ancestor.to_path_buf());
        }
    }
    Err(format!(
        "could not locate a cargo `target` directory above the runner at {}",
        exe.display()
    ))
}

/// Verifies that `candidate` is safely confined under `target_root`.
///
/// Rejects any `..` (parent-dir) component and requires `candidate` to be a
/// real path-component descendant of `target_root`. A bare "has a component
/// named `target`" check is not confinement: it accepts unrelated paths like
/// `/home/target/evil` and — because `..` resolves away — escapes such as
/// `…/target/../../usr/bin/sh`. Component-wise `starts_with` also rejects a
/// sibling-prefix like `…/target-evil/…`.
fn confine_under(candidate: &Path, target_root: &Path) -> Result<(), String> {
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!(
            "refusing target {}: contains a `..` component",
            candidate.display()
        ));
    }
    if candidate.starts_with(target_root) {
        Ok(())
    } else {
        Err(format!(
            "refusing target {}: not a descendant of the cargo target dir {}",
            candidate.display(),
            target_root.display()
        ))
    }
}

/// Confirms the exec target resolves to a binary inside this runner's cargo
/// `target` directory.
///
/// Defense-in-depth for the privileged window: `..` is rejected on the raw input
/// first (canonicalization strips `..`, so a later check could not distinguish
/// an escape attempt), then the path is canonicalized (resolving symlinks; a
/// non-existent path fails closed) and checked to be a descendant of the real
/// cargo target dir.
fn ensure_under_cargo_target_dir(target: &str) -> Result<(), String> {
    let raw = Path::new(target);
    if raw.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "refusing target {target}: contains a `..` component"
        ));
    }
    let resolved = raw
        .canonicalize()
        .map_err(|e| format!("cannot resolve target {target}: {e}"))?;
    let target_root = real_cargo_target_dir()?;
    confine_under(&resolved, &target_root)
}

/// Looks up the numeric gid for a group name, or `None` if it does not exist.
fn lookup_group_gid(name: &str) -> Option<libc::gid_t> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `getgrnam` receives a valid NUL-terminated C string and returns
    // either NULL or a pointer to a `group`. We read `gr_gid` once and copy it
    // out; the pointer is not retained. Single-threaded pre-exec context.
    unsafe {
        let grp = libc::getgrnam(cname.as_ptr());
        if grp.is_null() {
            None
        } else {
            Some((*grp).gr_gid)
        }
    }
}

/// Returns the process's current supplementary group ids.
fn current_supplementary_groups() -> Vec<libc::gid_t> {
    // SAFETY: the first `getgroups` (size 0, null ptr) only queries the count;
    // the second fills an exactly-sized buffer. Standard `getgroups(2)` usage.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut());
        if n <= 0 {
            return Vec::new();
        }
        let mut buf: Vec<libc::gid_t> = vec![0; n as usize];
        let got = libc::getgroups(n, buf.as_mut_ptr());
        if got < 0 {
            return Vec::new();
        }
        buf.truncate(got as usize);
        buf
    }
}

/// Builds the supplementary-group list to install before dropping uid.
///
/// Always includes the primary `gid`; additionally preserves `kvm_gid` when the
/// process currently holds it, so the exec'd test keeps `/dev/kvm` access by
/// group membership (it is `root:kvm 0660`) instead of relying solely on the
/// incidental `CAP_DAC_OVERRIDE` we carry. Never duplicates the primary gid and
/// never invents a membership the invoker did not have.
fn merge_preserved_groups(
    gid: libc::gid_t,
    kvm_gid: Option<libc::gid_t>,
    held: &[libc::gid_t],
) -> Vec<libc::gid_t> {
    let mut groups = vec![gid];
    if let Some(kvm) = kvm_gid {
        if kvm != gid && held.contains(&kvm) {
            groups.push(kvm);
        }
    }
    groups
}

fn main() {
    // No tracing-subscriber here. This binary runs in the privileged window and
    // must stay dependency-thin (no host async/log stack), and it has to report
    // failures that occur BEFORE the privilege drop — a subscriber initialized
    // after the drop could not show them. Fatal errors go straight to stderr.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("vmcell-test-runner: usage: vmcell-test-runner <test-binary> [args...]");
        exit(1);
    }

    // DAC_OVERRIDE is required by the privileged tap path: `netns_rs::NetNs::new`
    // creates the bind-mount target under `/var/run/netns`, which is `root:root`,
    // and SYS_ADMIN alone does not bypass the file-permission check.
    let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
    if let Err(e) = ensure_blessed_or_explain(&need) {
        eprintln!("{e}");
        exit(1);
    }

    let target = &args[1];
    if let Err(e) = ensure_under_cargo_target_dir(target) {
        eprintln!("vmcell-test-runner: {e}");
        exit(1);
    }

    // Setuid-root form: drop to the invoking user's gid/uid HERE — before we
    // raise ambient capabilities further down. This is the privileged-window
    // ordering rule: for the setuid form, change uid *before* raising ambient,
    // so the exec'd test runs as the user yet inherits the two caps via the
    // ambient set. PR_SET_KEEPCAPS preserves the permitted set across the uid
    // change. There is deliberately no second uid drop later: by the time we
    // raise ambient, euid is already non-zero.
    let euid = rustix::process::geteuid();
    let uid = rustix::process::getuid();
    if euid.as_raw() == 0 && uid.as_raw() != 0 {
        // prctl(PR_SET_KEEPCAPS, 1)
        if let Err(e) = capctl::prctl::set_keepcaps(true) {
            eprintln!("vmcell-test-runner: failed to set keepcaps: {e}");
            exit(1);
        }

        let gid = rustix::process::getgid();
        // Preserve the `kvm` supplementary group across the setgroups() drop when
        // the invoking user holds it: /dev/kvm is `root:kvm 0660`, so dropping to
        // a bare [primary gid] would leave it reachable only via the incidental
        // CAP_DAC_OVERRIDE we carry. Group membership is the intended, narrower
        // path. Computed while still euid 0 so getgroups/getgrnam are unrestricted.
        let kvm_gid = lookup_group_gid("kvm");
        let groups = merge_preserved_groups(gid.as_raw(), kvm_gid, &current_supplementary_groups());
        // SAFETY: We are dropping privileges from root to the original user's UID/GID.
        // This is safe because we immediately exit on failure, and no threads are spawned yet.
        // `groups` is a non-empty, correctly-sized slice and `setgroups` reads
        // exactly `groups.len()` gids from its pointer.
        unsafe {
            if libc::setresgid(gid.as_raw(), gid.as_raw(), gid.as_raw()) != 0 {
                eprintln!("vmcell-test-runner: setresgid failed");
                exit(1);
            }
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
                eprintln!("vmcell-test-runner: setgroups failed");
                exit(1);
            }
            if libc::setresuid(uid.as_raw(), uid.as_raw(), uid.as_raw()) != 0 {
                eprintln!("vmcell-test-runner: setresuid failed");
                exit(1);
            }
        }
    }

    let mut caps = match CapState::get_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vmcell-test-runner: failed to get current capabilities: {e}");
            exit(1);
        }
    };

    for &c in &need {
        caps.inheritable.add(c);
    }

    if let Err(e) = caps.set_current() {
        eprintln!("vmcell-test-runner: failed to set inheritable capabilities: {e}");
        exit(1);
    }

    // Shrink the bounding set down to the two caps we need, so the exec'd test
    // can never regain anything else. PR_CAPBSET_DROP needs CAP_SETPCAP in the
    // EFFECTIVE set; the setuid-root form clears effective on the uid change and
    // the file-caps (+ep) form never carries SETPCAP at all, so this is
    // best-effort — and we must surface, never swallow, a failure.
    //
    // Best-effort: if we hold SETPCAP in the permitted set (the setuid-root
    // form), raise it into effective first so the drops below can succeed.
    if let Ok(mut st) = CapState::get_current() {
        let can_raise_setpcap = st.permitted.has(Cap::SETPCAP) && !st.effective.has(Cap::SETPCAP);
        if can_raise_setpcap {
            st.effective.add(Cap::SETPCAP);
            // Best-effort: a failure surfaces as a drop failure reported below.
            let _ = st.set_current();
        }
    }

    let mut bounding_drop_failures = 0usize;
    for c in Cap::probe_supported() {
        if need.contains(&c) {
            continue;
        }
        // Surface — never swallow — a failed drop: silently no-oping turns a
        // stated security step (shrinking the bounding set) into a lie.
        if capctl::bounding::drop(c).is_err() {
            bounding_drop_failures += 1;
        }
    }
    if bounding_drop_failures > 0 {
        eprintln!(
            "vmcell-test-runner: warning: could not drop {bounding_drop_failures} bounding-set \
             capabilities (PR_CAPBSET_DROP needs CAP_SETPCAP in the effective set); the bounding \
             set is wider than intended"
        );
    }

    // Raise ambient last, after the bounding set is shrunk and uid is dropped.
    for &c in &need {
        if let Err(e) = capctl::ambient::raise(c) {
            eprintln!("vmcell-test-runner: failed to raise ambient capability {c:?}: {e}");
            exit(1);
        }
    }

    // Trim permitted/effective down to exactly the two caps we need.
    let mut final_caps = match CapState::get_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vmcell-test-runner: failed to read capabilities before trim: {e}");
            exit(1);
        }
    };
    final_caps.permitted.clear();
    final_caps.effective.clear();
    for &c in &need {
        final_caps.permitted.add(c);
        final_caps.effective.add(c);
    }
    if let Err(e) = final_caps.set_current() {
        eprintln!("vmcell-test-runner: failed to trim capabilities: {e}");
        exit(1);
    }

    let err = Command::new(target).args(&args[2..]).exec();
    eprintln!("vmcell-test-runner: failed to exec {target}: {err}");
    exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Buggy impl this guards: the remediation printed `cap_..+p`, but the
    // precondition checks the EFFECTIVE set, so a user who ran the printed `+p`
    // command would set permitted-only and STILL fail the check. It must grant
    // `+ep` (effective + permitted).
    #[test]
    fn remediation_message_grants_effective_and_permitted() {
        let msg = blessing_remediation(1000, Path::new("/x/target/debug/vmcell-test-runner"));
        assert!(
            msg.contains("cap_net_admin,cap_sys_admin,cap_dac_override+ep"),
            "remediation must grant the three caps with +ep: {msg}"
        );
        // The permitted-only spellings must not appear.
        assert!(!msg.contains("+p "), "must not print a bare +p flag: {msg}");
        assert!(
            !msg.contains("+p\n"),
            "must not print a bare +p flag: {msg}"
        );
    }

    // Guards M-RUN-2: confinement must be a real path-descendant check, not a
    // bare "has a component named target". The buggy impl accepted any path with
    // a `target` component (so `/home/target/evil`), giving essentially no
    // confinement before the three-ambient-cap exec.
    #[test]
    fn confine_under_requires_real_descendant() {
        let root = Path::new("/home/u/proj/target");
        assert!(confine_under(Path::new("/home/u/proj/target/debug/it"), root).is_ok());
        // Unrelated path that merely contains a `target` component → rejected.
        assert!(confine_under(Path::new("/home/target/evil"), root).is_err());
        // Sibling-prefix: a string `starts_with` would accept it; path-component
        // confinement must not.
        assert!(confine_under(Path::new("/home/u/proj/target-evil/x"), root).is_err());
    }

    #[test]
    fn confine_under_rejects_parent_dir_components() {
        let root = Path::new("/tmp/x/target");
        assert!(confine_under(Path::new("/tmp/x/target/../../usr/bin/sh"), root).is_err());
    }

    // `..` is rejected before any filesystem resolution, so even a non-existent
    // escape path fails closed (the old impl had no `..` rejection at all).
    #[test]
    fn ensure_under_cargo_target_dir_rejects_dotdot() {
        assert!(ensure_under_cargo_target_dir("/tmp/x/target/../../usr/bin/sh").is_err());
        assert!(ensure_under_cargo_target_dir("relative/../escape").is_err());
    }

    // Guards the kvm-gid preservation: the primary gid is always present, the kvm
    // group is preserved iff currently held, never duplicated, never invented.
    // The buggy `setgroups(1, [gid])` drops kvm unconditionally → first case red.
    #[test]
    fn merge_preserved_groups_keeps_kvm_only_when_held() {
        // kvm (108) held → preserved alongside the primary gid.
        let g = merge_preserved_groups(1000, Some(108), &[108, 4, 27]);
        assert!(g.contains(&1000));
        assert!(
            g.contains(&108),
            "kvm gid must survive the setgroups drop: {g:?}"
        );

        // kvm not held → not added (don't invent membership).
        assert_eq!(
            merge_preserved_groups(1000, Some(108), &[4, 27]),
            vec![1000]
        );

        // kvm == primary → no duplicate.
        assert_eq!(merge_preserved_groups(108, Some(108), &[108]), vec![108]);

        // no kvm group on the host → just the primary gid.
        assert_eq!(merge_preserved_groups(1000, None, &[4]), vec![1000]);
    }
}
