use capctl::{Cap, CapState};
use std::env;
use std::os::unix::process::CommandExt;
use std::process::{Command, exit};

fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String> {
    let caps = CapState::get_current().map_err(|e| e.to_string())?;

    // Check if euid is 0 (setuid root fallback)
    let euid = rustix::process::geteuid();
    if euid.as_raw() == 0 {
        return Ok(());
    }

    // Check if we have the needed caps in the permitted set (file caps method)
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
        Err(format!(
            "error: imp-test-runner is missing CAP_NET_ADMIN/CAP_SYS_ADMIN (uid={}, no file caps).\n\
             It was almost certainly rebuilt. Restore its privileges (one-time, until next rebuild):\n\n\
             sudo setcap cap_net_admin,cap_sys_admin+p {}\n\n\
             Then re-run the privileged suite. See §12.8.",
            rustix::process::getuid().as_raw(),
            exe.display()
        ))
    }
}

fn ensure_under_cargo_target_dir(target: &str) -> Result<(), String> {
    let path = std::path::Path::new(target);
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
    tracing_subscriber::fmt::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        tracing::error!("Usage: imp-test-runner <test-binary> [args...]");
        exit(1);
    }

    let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN];
    if let Err(e) = ensure_blessed_or_explain(&need) {
        tracing::error!("{}", e);
        exit(1);
    }

    let target = &args[1];
    if let Err(e) = ensure_under_cargo_target_dir(target) {
        tracing::error!("{}", e);
        exit(1);
    }

    // Setuid fallback handling: if euid is 0 but we want to run as the dev uid
    let euid = rustix::process::geteuid();
    let uid = rustix::process::getuid();
    if euid.as_raw() == 0 && uid.as_raw() != 0 {
        // prctl(PR_SET_KEEPCAPS, 1)
        if let Err(e) = capctl::prctl::set_keepcaps(true) {
            tracing::error!("Failed to set keepcaps: {}", e);
            exit(1);
        }

        let gid = rustix::process::getgid();
        // SAFETY: We are dropping privileges from root to the original user's UID/GID.
        // This is safe because we immediately exit on failure, and no threads are spawned yet.
        unsafe {
            if libc::setresgid(gid.as_raw(), gid.as_raw(), gid.as_raw()) != 0 {
                tracing::error!("setresgid failed");
                exit(1);
            }
            if libc::setgroups(1, &gid.as_raw() as *const u32) != 0 {
                tracing::error!("setgroups failed");
                exit(1);
            }
            if libc::setresuid(uid.as_raw(), uid.as_raw(), uid.as_raw()) != 0 {
                tracing::error!("setresuid failed");
                exit(1);
            }
        }
    }

    let mut caps = match CapState::get_current() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to get current capabilities: {}", e);
            exit(1);
        }
    };

    for &c in &need {
        caps.inheritable.add(c);
    }

    if let Err(e) = caps.set_current() {
        tracing::error!("Failed to set inheritable capabilities: {}", e);
        exit(1);
    }

    // Drop bounding set
    let mut to_drop = Vec::new();
    for c in Cap::probe_supported() {
        if !need.contains(&c) {
            to_drop.push(c);
        }
    }
    for c in to_drop {
        let _ = capctl::bounding::drop(c);
    }

    // For setuid form, change uid before raising ambient
    let ruid = rustix::process::getuid();
    let euid = rustix::process::geteuid();
    if euid.as_raw() == 0 && ruid.as_raw() != 0 {
        // Keep caps across setuid
        unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
        if unsafe { libc::setuid(ruid.as_raw()) } != 0 {
            tracing::error!("Failed to drop setuid privileges");
            exit(1);
        }
    }

    for &c in &need {
        if let Err(e) = capctl::ambient::raise(c) {
            tracing::error!("Failed to raise ambient capability {:?}: {}", c, e);
            exit(1);
        }
    }

    // Trim P/E after
    let mut final_caps = CapState::get_current().expect("get current caps");
    final_caps.permitted.clear();
    final_caps.effective.clear();
    for &c in &need {
        final_caps.permitted.add(c);
        final_caps.effective.add(c);
    }
    final_caps.set_current().expect("set current caps");

    let err = Command::new(target).args(&args[2..]).exec();
    tracing::error!("Failed to exec {}: {}", target, err);
    exit(1);
}
