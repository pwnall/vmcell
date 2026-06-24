//! Guest agent running as PID 1 inside the microvm.
#![deny(missing_docs)]
#![deny(clippy::missing_errors_doc)]
use imp_testing::agent::protocol::{ExecRequest, Message};
use rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_change, unmount,
};
use rustix::process::{WaitOptions, pivot_root, waitpid};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use vsock::{VsockAddr, VsockListener, VsockStream};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("imp-guest-agent: starting");

    // Mount setup
    let _ = std::fs::create_dir_all("/sys");
    let _ = std::fs::create_dir_all("/proc");
    let _ = std::fs::create_dir_all("/mnt");

    // Setup tmpfs overlay over the read-only erofs root via pivot_root
    let _ = mount("tmpfs", "/mnt", "tmpfs", MountFlags::empty(), "");
    let _ = std::fs::create_dir_all("/mnt/upper");
    let _ = std::fs::create_dir_all("/mnt/work");
    let _ = std::fs::create_dir_all("/mnt/rootfs");

    let _ = mount(
        "overlay",
        "/mnt/rootfs",
        "overlay",
        MountFlags::empty(),
        "lowerdir=/,upperdir=/mnt/upper,workdir=/mnt/work",
    );

    std::env::set_current_dir("/mnt/rootfs").expect("failed to chdir to /mnt/rootfs");
    let _ = std::fs::create_dir_all("oldroot");

    if pivot_root(".", "oldroot").is_ok() {
        let _ = mount_change(
            "/",
            MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        );
        let _ = unmount("oldroot", UnmountFlags::DETACH);
        let _ = std::fs::remove_dir_all("oldroot");
    } else {
        println!("imp-guest-agent: pivot_root failed");
    }

    // Mount essential filesystems
    let _ = mount("sysfs", "/sys", "sysfs", MountFlags::empty(), "");
    let _ = mount("proc", "/proc", "proc", MountFlags::empty(), "");
    let _ = mount("devtmpfs", "/dev", "devtmpfs", MountFlags::empty(), "");

    for tag_str in ["imp-in", "imp-out", "imp-bin"] {
        let mount_point = format!("/{}", tag_str);
        let _ = std::fs::create_dir_all(&mount_point);

        let flags = if tag_str == "imp-in" || tag_str == "imp-bin" {
            MountFlags::RDONLY
        } else {
            MountFlags::empty()
        };
        if mount(tag_str, &mount_point as &str, "virtiofs", flags, "").is_ok() {
            println!(
                "imp-guest-agent: mounted virtiofs {} at {}",
                tag_str, mount_point
            );
        } else {
            println!("imp-guest-agent: failed to mount virtiofs {}", tag_str);
        }
    }

    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();

    // Spawn vsock listener thread
    std::thread::spawn(move || {
        let addr = VsockAddr::new(0xFFFFFFFF, 5000); // VMADDR_CID_ANY
        let listener = match VsockListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                println!("imp-guest-agent: failed to bind vsock: {}", e);
                return;
            }
        };
        println!("imp-guest-agent: listening on vsock port 5000");

        for stream in listener.incoming() {
            match stream {
                Ok(mut s) => {
                    println!("imp-guest-agent: accepted connection");
                    let _ = handle_connection(&mut s);
                }
                Err(e) => {
                    println!("imp-guest-agent: accept error: {}", e);
                }
            }
        }
    });

    // Main thread acts as PID 1 zombie reaper
    let term = Arc::new(AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term));

    loop {
        if term.load(std::sync::atomic::Ordering::Relaxed) {
            println!("imp-guest-agent: received SIGTERM, exiting");
            break Ok(());
        }
        // Wait for any child with WNOHANG
        match waitpid(None, WaitOptions::NOHANG) {
            Ok(Some(_)) => {
                // Reaped a child
            }
            Ok(None) | Err(rustix::io::Errno::CHILD) => {
                // No more children to reap right now
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => {
                // Should not happen, but avoid hot loop
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

fn handle_connection(stream: &mut VsockStream) -> Result<(), Box<dyn std::error::Error>> {
    let ready_msg = postcard::to_stdvec(&Message::Ready)?;
    send_framed(stream, &ready_msg)?;

    loop {
        let req_bytes = read_framed(stream)?;
        let msg: Message = postcard::from_bytes(&req_bytes)?;

        if let Message::Exec(req) = msg {
            handle_exec(req, stream)?;
        } else if let Message::PutFile { dst, bytes } = msg {
            handle_put_file(&dst, &bytes, stream)?;
        }
    }
}

fn send_framed(stream: &mut VsockStream, data: &[u8]) -> std::io::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}

fn read_framed(stream: &mut VsockStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}

fn handle_put_file(
    dst: &str,
    bytes: &[u8],
    stream: &mut VsockStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = std::path::Path::new(dst).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dst, bytes)?;
        Ok(())
    })();

    let code = if result.is_ok() { 0 } else { 1 };
    let exit_msg = postcard::to_stdvec(&Message::Exit(code))?;
    send_framed(stream, &exit_msg)?;
    Ok(())
}

fn handle_exec(
    req: ExecRequest,
    stream: &mut VsockStream,
) -> Result<(), Box<dyn std::error::Error>> {
    if req.argv.is_empty() {
        let exit_msg = postcard::to_stdvec(&Message::Exit(1))?;
        send_framed(stream, &exit_msg)?;
        return Ok(());
    }

    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..]);

    if let Some(cwd) = req.cwd {
        cmd.current_dir(cwd);
    }

    for (k, v) in req.env {
        cmd.env(k, v);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            let mut stdout = child.stdout.take().expect("failed to get stdout");
            let mut stderr = child.stderr.take().expect("failed to get stderr");

            let (tx, rx) = std::sync::mpsc::channel();
            let tx_out = tx.clone();
            let tx_err = tx.clone();
            let out_handle = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let _ = tx_out.send(Message::Stdout(buf[..n].to_vec()));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            });

            let err_handle = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stderr.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let _ = tx_err.send(Message::Stderr(buf[..n].to_vec()));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            });

            std::thread::spawn(move || {
                let code = match child.wait() {
                    Ok(status) => status.code().unwrap_or(1),
                    Err(_) => 127,
                };
                let _ = out_handle.join();
                let _ = err_handle.join();
                let _ = tx.send(Message::Exit(code));
            });

            for msg in rx {
                let bytes = postcard::to_stdvec(&msg)?;
                send_framed(stream, &bytes)?;
                if let Message::Exit(_) = msg {
                    break;
                }
            }
        }
        Err(e) => {
            let err_msg = format!("Failed to spawn command: {}", e);
            let msg = postcard::to_stdvec(&Message::Stderr(err_msg.into_bytes()))?;
            send_framed(stream, &msg)?;

            let exit_msg = postcard::to_stdvec(&Message::Exit(127))?;
            send_framed(stream, &exit_msg)?;
        }
    }

    Ok(())
}
