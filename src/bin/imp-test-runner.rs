use capctl::{Cap, CapState};
use std::env;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, exit};

/// Builds the operator-facing remediation message shown when the runner lacks
/// its capabilities.
///
/// The precondition (`ensure_blessed_or_explain`) checks the **effective** set,
/// so the printed `setcap` must grant `+ep` (effective + permitted). A bare `+p`
/// would set only the permitted set and the runner would still fail the check.
fn blessing_remediation(uid: u32, exe: &Path) -> String {
    format!(
        "error: imp-test-runner is missing CAP_NET_ADMIN/CAP_SYS_ADMIN (uid={uid}, no file caps).\n\
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

fn ensure_under_cargo_target_dir(target: &str) -> Result<(), String> {
    let path = Path::new(target);
    if path.components().any(|c| c.as_os_str() == "target") {
        Ok(())
    } else {
        Err(format!(
            "Target {} does not appear to be inside a cargo target directory.",
            target
        ))
    }
}

fn main() {
    // No tracing-subscriber here. This binary runs in the privileged window and
    // must stay dependency-thin (no host async/log stack), and it has to report
    // failures that occur BEFORE the privilege drop — a subscriber initialized
    // after the drop could not show them. Fatal errors go straight to stderr.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("imp-test-runner: usage: imp-test-runner <test-binary> [args...]");
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
        eprintln!("imp-test-runner: {e}");
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
            eprintln!("imp-test-runner: failed to set keepcaps: {e}");
            exit(1);
        }

        let gid = rustix::process::getgid();
        // SAFETY: We are dropping privileges from root to the original user's UID/GID.
        // This is safe because we immediately exit on failure, and no threads are spawned yet.
        unsafe {
            if libc::setresgid(gid.as_raw(), gid.as_raw(), gid.as_raw()) != 0 {
                eprintln!("imp-test-runner: setresgid failed");
                exit(1);
            }
            if libc::setgroups(1, &gid.as_raw() as *const u32) != 0 {
                eprintln!("imp-test-runner: setgroups failed");
                exit(1);
            }
            if libc::setresuid(uid.as_raw(), uid.as_raw(), uid.as_raw()) != 0 {
                eprintln!("imp-test-runner: setresuid failed");
                exit(1);
            }
        }
    }

    let mut caps = match CapState::get_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("imp-test-runner: failed to get current capabilities: {e}");
            exit(1);
        }
    };

    for &c in &need {
        caps.inheritable.add(c);
    }

    if let Err(e) = caps.set_current() {
        eprintln!("imp-test-runner: failed to set inheritable capabilities: {e}");
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
            "imp-test-runner: warning: could not drop {bounding_drop_failures} bounding-set \
             capabilities (PR_CAPBSET_DROP needs CAP_SETPCAP in the effective set); the bounding \
             set is wider than intended"
        );
    }

    // Raise ambient last, after the bounding set is shrunk and uid is dropped.
    for &c in &need {
        if let Err(e) = capctl::ambient::raise(c) {
            eprintln!("imp-test-runner: failed to raise ambient capability {c:?}: {e}");
            exit(1);
        }
    }

    // Trim permitted/effective down to exactly the two caps we need.
    let mut final_caps = match CapState::get_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("imp-test-runner: failed to read capabilities before trim: {e}");
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
        eprintln!("imp-test-runner: failed to trim capabilities: {e}");
        exit(1);
    }

    let err = Command::new(target).args(&args[2..]).exec();
    eprintln!("imp-test-runner: failed to exec {target}: {err}");
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
        let msg = blessing_remediation(1000, Path::new("/x/target/debug/imp-test-runner"));
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

    // Guards the cargo-target-dir confinement: a path outside any `target`
    // directory must be rejected so the runner cannot exec an arbitrary binary.
    #[test]
    fn target_must_be_under_cargo_target_dir() {
        assert!(ensure_under_cargo_target_dir("/home/u/proj/target/debug/it").is_ok());
        assert!(ensure_under_cargo_target_dir("/usr/bin/evil").is_err());
    }
}
