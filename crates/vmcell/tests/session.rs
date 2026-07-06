//! Live (KVM) integration tests for interactive sessions (design 62 §22): PTY +
//! controlling terminal + winsize (§12.29), streaming stdin (§22.2), multiplexed
//! concurrent exec over one connection (§12.28), and connection-owns-its-sessions
//! teardown (§12.27). Sessions ride the vsock agent only (no snapshot), so every
//! case runs on **all three** backends via `vmm_matrix_test!` — no `require_cap!`
//! skips. Every assertion is on the **data plane** (guest output / process
//! residue), not a proxy signal (rubric A10).

use std::time::Duration;
use vmcell::ExecRequest;
use vmcell::agent::session::{SessionEvent, SessionSpecBuilder};
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::RealClock;

mod common;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

fn base_cfg() -> VmConfig {
    VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .network_disabled()
    .build()
    .expect("VmConfig")
}

/// Boots a VM, waits for the agent (the standard boot gate), and opens a session
/// multiplexer connection.
async fn boot_and_connect<V: vmcell::vmm::Vmm>(
    vmm: &V,
) -> (vmcell::MicroVm<V>, vmcell::agent::session::SessionMux) {
    let mut vm = common::start_vm(vmm, base_cfg()).await;
    // Confirm the guest agent is up before dialing a second (session) connection.
    vm.agent(Some(Duration::from_secs(60)), &RealClock)
        .await
        .expect("agent must reach ready");
    let mux = vm
        .connect_sessions(Some(Duration::from_secs(30)))
        .await
        .expect("session mux must connect");
    (vm, mux)
}

// §12.29: a PTY session is a controlling-terminal session leader — `isatty()` true
// in-guest, the initial window installed, and a mid-session resize delivered
// (SIGWINCH). A pipe session is the negative control (`not a tty`). Data-plane:
// `test -t` / `stty size` output. RED if the PTY setup drops setsid/TIOCSCTTY (no
// tty) or the winsize install/resize is lost.
vmm_matrix_test!(session_pty_isatty_and_winsize, |vmm| {
    session_pty_impl(&vmm).await;
});

async fn session_pty_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let (vm, mux) = boot_and_connect(vmm).await;

    // (1) PTY session: both ends are a tty, and the initial window is 24x80.
    let mut pty = mux
        .open(
            SessionSpecBuilder::new(argv(&[
                "/bin/sh",
                "-c",
                "test -t 0 && test -t 1 && echo ISATTY; stty size",
            ]))
            .pty(24, 80)
            .build(),
        )
        .await
        .expect("open pty session");
    let out = pty.wait().await;
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.code, 0, "pty session exit code; output={text:?}");
    assert!(
        text.contains("ISATTY"),
        "a PTY session's stdin AND stdout must be a tty; output={text:?}"
    );
    assert!(
        text.contains("24 80"),
        "the initial PTY window must be 24 rows x 80 cols; output={text:?}"
    );

    // (2) Resize: the shell blocks on `read`, we resize BEFORE unblocking it, so
    // `stty size` reports the NEW window (SIGWINCH took effect), not the initial.
    let mut resz = mux
        .open(
            SessionSpecBuilder::new(argv(&["/bin/sh", "-c", "read _; stty size"]))
                .pty(24, 80)
                .build(),
        )
        .await
        .expect("open resize session");
    resz.resize(50, 120).await.expect("resize");
    resz.write_stdin(b"\n").await.expect("unblock read");
    let out = resz.wait().await;
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("50 120"),
        "a mid-session resize must take effect; output={text:?}"
    );
    assert!(
        !text.contains("24 80"),
        "the resized window must replace the initial one; output={text:?}"
    );

    // (3) Negative control: a pipe session's stdin is NOT a tty.
    let mut pipe = mux
        .open(
            SessionSpecBuilder::new(argv(&[
                "/bin/sh",
                "-c",
                "test -t 0 && echo IS_TTY || echo NOT_TTY",
            ]))
            .build(),
        )
        .await
        .expect("open pipe session");
    let out = pipe.wait().await;
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("NOT_TTY"),
        "a pipe session must NOT be a tty (positive/negative control); output={text:?}"
    );

    drop(mux);
    vm.shutdown().await.expect("shutdown");
}

// §22.2 / rubric A10: streaming stdin round-trips through a running command. `cat`
// echoes each streamed chunk; `close_stdin` (EOF) drives it to exit 0. RED if
// stdin is not delivered (the one-shot path nails it to /dev/null) or EOF is lost.
vmm_matrix_test!(session_streaming_stdin, |vmm| {
    session_stdin_impl(&vmm).await;
});

async fn session_stdin_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let (vm, mux) = boot_and_connect(vmm).await;

    let mut cat = mux
        .open(SessionSpecBuilder::new(argv(&["/bin/cat"])).build())
        .await
        .expect("open cat session");
    cat.write_stdin(b"hello\n").await.expect("write 1");
    cat.write_stdin(b"more data\n").await.expect("write 2");
    cat.close_stdin().await.expect("close stdin (EOF)");
    let out = cat.wait().await;
    assert_eq!(
        out.code, 0,
        "cat exits 0 on stdin EOF; stderr={:?}",
        out.stderr
    );
    assert_eq!(
        out.stdout, b"hello\nmore data\n",
        "cat must echo the streamed stdin verbatim"
    );

    drop(mux);
    vm.shutdown().await.expect("shutdown");
}

// §12.28: two sessions multiplexed over ONE connection. Each emits a large,
// self-identifying, window-filling stream; both must arrive intact with ZERO
// cross-attribution and no torn frames. RED if the guest's single-writer discipline
// is broken (interleaved frames corrupt) or the host demux ignores the id.
vmm_matrix_test!(session_multiplexed_exec, |vmm| {
    session_mux_impl(&vmm).await;
});

async fn session_mux_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let (vm, mux) = boot_and_connect(vmm).await;

    // ~1000 lines of a 16-char marker each ≈ 27 KiB per session — many 4096-byte
    // guest pump chunks, interleaved on the wire with the other session's.
    const N: usize = 1000;
    let cmd_a = format!("i=0; while [ $i -lt {N} ]; do echo AAAAAAAAAAAAAAAA-$i; i=$((i+1)); done");
    let cmd_b = format!("i=0; while [ $i -lt {N} ]; do echo BBBBBBBBBBBBBBBB-$i; i=$((i+1)); done");
    let mut a = mux
        .open(SessionSpecBuilder::new(argv(&["/bin/sh", "-c", &cmd_a])).build())
        .await
        .expect("open A");
    let mut b = mux
        .open(SessionSpecBuilder::new(argv(&["/bin/sh", "-c", &cmd_b])).build())
        .await
        .expect("open B");

    // Drain both concurrently over the one connection.
    let (a_out, b_out) = tokio::join!(a.wait(), b.wait());
    assert_eq!(a_out.code, 0, "A exit; stderr={:?}", a_out.stderr);
    assert_eq!(b_out.code, 0, "B exit; stderr={:?}", b_out.stderr);
    let a_text = String::from_utf8_lossy(&a_out.stdout);
    let b_text = String::from_utf8_lossy(&b_out.stdout);
    assert_eq!(
        a_text.matches("AAAAAAAAAAAAAAAA-").count(),
        N,
        "session A must receive ALL its lines intact"
    );
    assert_eq!(b_text.matches("BBBBBBBBBBBBBBBB-").count(), N);
    assert!(
        !a_text.contains('B'),
        "session A must NOT receive any of session B's bytes (no cross-attribution / interleave corruption)"
    );
    assert!(
        !b_text.contains('A'),
        "session B must NOT receive session A's bytes"
    );

    drop(mux);
    vm.shutdown().await.expect("shutdown");
}

// §12.27: a connection owns its sessions. A persistent `sleep` session's process
// group is killed when the mux (connection) drops — the process is gone. Data-plane
// residue: the pid existed (it echoed itself and was sleeping), then is gone
// (its /proc cmdline no longer names `sleep`). RED if teardown does not kill.
vmm_matrix_test!(session_connection_owns_sessions, |vmm| {
    session_teardown_impl(&vmm).await;
});

async fn session_teardown_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let (mut vm, mux) = boot_and_connect(vmm).await;

    let mut persistent = mux
        .open(SessionSpecBuilder::new(argv(&["/bin/sh", "-c", "echo $$; exec sleep 600"])).build())
        .await
        .expect("open persistent session");

    // Read the session process group leader's pid (existed-before proof).
    let mut acc: Vec<u8> = Vec::new();
    loop {
        match persistent.recv().await {
            Some(SessionEvent::Stdout(d)) => {
                acc.extend(d);
                if acc.contains(&b'\n') {
                    break;
                }
            }
            Some(SessionEvent::Exit(c)) => panic!("persistent session exited early with {c}"),
            Some(_) => {}
            None => panic!("connection closed before the session reported its pid"),
        }
    }
    let text = String::from_utf8_lossy(&acc);
    let pid: u32 = text
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("could not parse pid from {text:?}"));

    // Drop the session AND the mux → the connection closes → the guest kills every
    // still-open session's process group (§12.27).
    drop(persistent);
    drop(mux);
    // Let the guest observe EOF, kill the group, and reap.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // From a FRESH one-shot exec, the pid's process must be gone: its /proc cmdline
    // no longer names `sleep` (robust against pid reuse — a reused pid would run our
    // own check command, never `sleep`).
    let agent = vm
        .agent(Some(Duration::from_secs(30)), &RealClock)
        .await
        .expect("agent for residue check");
    let outcome = agent
        .exec(ExecRequest::new(argv(&[
            "/bin/sh",
            "-c",
            &format!("tr '\\0' ' ' < /proc/{pid}/cmdline 2>/dev/null; echo END"),
        ])))
        .await
        .expect("residue check exec");
    let text = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        !text.contains("sleep"),
        "the persistent session's process group must be killed when its connection drops (§12.27); \
         pid {pid} still runs `sleep`: {text:?}"
    );

    vm.shutdown().await.expect("shutdown");
}
