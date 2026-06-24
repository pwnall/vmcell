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
        if !caps.permitted.has(c) {
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
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: imp-test-runner <test-binary> [args...]");
        exit(1);
    }

    let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN];
    if let Err(e) = ensure_blessed_or_explain(&need) {
        eprintln!("{}", e);
        exit(1);
    }

    let target = &args[1];
    if let Err(e) = ensure_under_cargo_target_dir(target) {
        eprintln!("{}", e);
        exit(1);
    }

    // Setuid fallback handling: if euid is 0 but we want to run as the dev uid
    let euid = rustix::process::geteuid();
    let uid = rustix::process::getuid();
    if euid.as_raw() == 0 && uid.as_raw() != 0 {
        // prctl(PR_SET_KEEPCAPS, 1)
        if let Err(e) = capctl::prctl::set_keepcaps(true) {
            eprintln!("Failed to set keepcaps: {}", e);
            exit(1);
        }

        let gid = rustix::process::getgid();
        unsafe {
            if libc::setresgid(gid.as_raw(), gid.as_raw(), gid.as_raw()) != 0 {
                eprintln!("setresgid failed");
                exit(1);
            }
            if libc::setgroups(1, &gid.as_raw() as *const u32) != 0 {
                eprintln!("setgroups failed");
                exit(1);
            }
            if libc::setresuid(uid.as_raw(), uid.as_raw(), uid.as_raw()) != 0 {
                eprintln!("setresuid failed");
                exit(1);
            }
        }
    }

    let mut caps = match CapState::get_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to get current capabilities: {}", e);
            exit(1);
        }
    };

    for &c in &need {
        caps.inheritable.add(c);
    }

    if let Err(e) = caps.set_current() {
        eprintln!("Failed to set inheritable capabilities: {}", e);
        exit(1);
    }

    for &c in &need {
        if let Err(e) = capctl::ambient::raise(c) {
            eprintln!("Failed to raise ambient capability {:?}: {}", c, e);
            exit(1);
        }
    }

    let mut to_drop = Vec::new();
    for c in Cap::probe_supported() {
        if !need.contains(&c) {
            to_drop.push(c);
        }
    }
    for c in to_drop {
        let _ = capctl::bounding::drop(c);
    }

    let err = Command::new(target).args(&args[2..]).exec();
    eprintln!("Failed to exec {}: {}", target, err);
    exit(1);
}
