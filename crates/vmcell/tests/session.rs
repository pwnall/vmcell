//! Live (KVM) integration tests for interactive sessions (§3, The control plane: vsock, the host clients, and the guest agent): PTY +
//! controlling terminal + winsize (§13, Cross-cutting invariants), streaming stdin (§3.3, Interactive-session wire semantics), multiplexed
//! concurrent exec over one connection (§13, Cross-cutting invariants), connection-owns-its-sessions
//! teardown (§13, Cross-cutting invariants), and stdin-pressure liveness (M6). Sessions ride the
//! vsock agent only (no snapshot), so every
//! case runs on **all four** backends via `vmm_matrix_test!` — no `require_cap!`
//! skips. Every assertion is on the **data plane** (guest output / process
//! residue), not a proxy signal (rubric A10).

use std::time::Duration;
use vmcell::ExecRequest;
use vmcell::agent::session::{SessionEvent, SessionSpecBuilder};
use vmcell::config::{RootfsSource, VmConfig};

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
    vm.agent(Some(Duration::from_secs(60)))
        .await
        .expect("agent must reach ready");
    let mux = vm
        .connect_sessions(Some(Duration::from_secs(30)))
        .await
        .expect("session mux must connect");
    (vm, mux)
}

// §13 (Cross-cutting invariants): a PTY session is a controlling-terminal session leader — `isatty()` true
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

// §3.3 (Interactive-session wire semantics) / rubric A10: streaming stdin round-trips through a running command. `cat`
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

// §13 (Cross-cutting invariants): two sessions multiplexed over ONE connection. Each emits a large,
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

// §13 (Cross-cutting invariants): a connection owns its sessions. A persistent `sleep` session's process
// group is killed when the mux (connection) drops — the process is gone. Data-plane
// residue: the pid existed (it echoed itself and was sleeping), then is gone
// (its /proc cmdline no longer names `sleep`). RED if teardown does not kill.
vmm_matrix_test!(session_connection_owns_sessions, |vmm| {
    session_teardown_impl(&vmm).await;
});

async fn session_teardown_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let (mut vm, mux) = boot_and_connect(vmm).await;

    let mut persistent = mux
        .open(SessionSpecBuilder::new(argv(&["/bin/sh", "-c", PERSISTENT_SH])).build())
        .await
        .expect("open persistent session");

    // Read the session process group leader's pid (existed-before proof).
    let pid = session_leader_pid(&mut persistent).await;

    // Drop the session AND the mux → the connection closes → the guest kills every
    // still-open session's process group (§13, Cross-cutting invariants).
    drop(persistent);
    drop(mux);
    // Let the guest observe EOF, kill the group, and reap.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_sleep_pgroup_gone(
        &mut vm,
        pid,
        "the persistent session's process group must be killed when its connection drops (§13, Cross-cutting invariants)",
    )
    .await;

    vm.shutdown().await.expect("shutdown");
}

/// A child that never reads its stdin: `sh` consumes its script from `-c`, and
/// `exec sleep` replaces it with a process that reads nothing at all — so the
/// guest-side stdin pipe fills and stays full. `echo $$` first, so the leg can
/// name the session's process-group leader for a residue proof.
const PERSISTENT_SH: &str = "echo $$; exec sleep 600";

/// Bytes streamed at a non-reading child by [`flood_stdin`]: 512 KiB is eight
/// times a full 64 KiB guest pipe, so the guest's stdin writer is genuinely
/// parked (not merely slow) for the rest of the leg.
const FLOOD_BYTES: usize = 512 * 1024;

/// Reads the pid a persistent session's shell echoes as its first line — the
/// existed-before half of a process-residue proof. Bounded, so a session that
/// never reports its pid fails the leg instead of hanging the suite.
async fn session_leader_pid(session: &mut vmcell::agent::session::Session) -> u32 {
    let mut acc: Vec<u8> = Vec::new();
    let read = async {
        loop {
            match session.recv().await {
                Some(SessionEvent::Stdout(d)) => {
                    acc.extend(d);
                    if acc.contains(&b'\n') {
                        return;
                    }
                }
                Some(SessionEvent::Exit(c)) => panic!("persistent session exited early with {c}"),
                Some(_) => {}
                None => panic!("connection closed before the session reported its pid"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .expect("the session must report its pid well inside 30s");
    let text = String::from_utf8_lossy(&acc);
    text.split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("could not parse pid from {text:?}"))
}

/// The process-residue proof: from a FRESH one-shot exec, `pid`'s /proc cmdline no
/// longer names `sleep` (robust against pid reuse — a reused pid would run our own
/// check command, never `sleep`). `why` states the law the residue would break.
async fn assert_sleep_pgroup_gone<V: vmcell::vmm::Vmm>(
    vm: &mut vmcell::MicroVm<V>,
    pid: u32,
    why: &str,
) {
    let agent = vm
        .agent(Some(Duration::from_secs(30)))
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
        "{why}; pid {pid} still runs `sleep`: {text:?}"
    );
}

/// Streams [`FLOOD_BYTES`] at a session whose child never reads, then lets the
/// bytes land: the host writer task is aborted by `SessionMux`'s `Drop`, so the
/// settle is what makes the guest-side pressure real rather than racy. 64 KiB per
/// frame — one full pipe each, far under `MAX_FRAME_BYTES`.
async fn flood_stdin(session: &vmcell::agent::session::Session) {
    let chunk = vec![b'X'; 64 * 1024];
    for _ in 0..(FLOOD_BYTES / chunk.len()) {
        session
            .write_stdin(&chunk)
            .await
            .expect("streaming stdin at a non-reading child must not fail host-side");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
}

// M6 (`guest-dispatch-blocking-stdin-wedge`), the live half of the gate the review
// named (its KVM-free half is `route_stdin_does_not_block_on_a_full_pipe_and_eof_follows_every_byte`
// + `stdin_writer_gives_up_on_closing_so_teardown_join_is_bounded` in
// vmcell-guest-agent). A child that stops reading its stdin must not wedge the
// connection that owns it: 512 KiB is streamed at a `sleep` that reads nothing, so
// the guest's 64 KiB stdin pipe is full and its writer parked, and BOTH consequences
// the pre-fix inline `write_all` produced are asserted on the data plane:
//   (1) `CloseSession` is still dispatched — `close()` yields the session's terminal
//       `SessionExit`, and the killed process group is gone from /proc.
//   (2) The C3 teardown still runs — a second flooded session's process group is
//       killed when the connection drops (`session_connection_owns_sessions`'s
//       property, now under stdin pressure).
// RED pre-fix, by construction: the dispatch thread parks inside the first `Stdin`
// frame's write, so (1) never sees an Exit (the 30 s bound fails the leg fast rather
// than hanging the suite) and `serve_loop` never returns, so (2) finds `sleep` alive.
vmm_matrix_test!(session_stdin_flood_does_not_wedge_the_connection, |vmm| {
    session_stdin_flood_impl(&vmm).await;
});

async fn session_stdin_flood_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let (mut vm, mux) = boot_and_connect(vmm).await;

    // (1) Dispatch liveness under a full guest pipe.
    let mut closed = mux
        .open(SessionSpecBuilder::new(argv(&["/bin/sh", "-c", PERSISTENT_SH])).build())
        .await
        .expect("open the close-under-pressure session");
    let closed_pid = session_leader_pid(&mut closed).await;
    flood_stdin(&closed).await;
    closed
        .close()
        .await
        .expect("CloseSession must still reach the guest");
    let exit = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match closed.recv().await {
                Some(SessionEvent::Exit(code)) => return Some(code),
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .expect(
        "`close()` must yield SessionExit well inside 30s, not park behind a full stdin pipe (M6)",
    );
    assert!(
        exit.is_some(),
        "close() under stdin pressure must deliver the session's terminal SessionExit, \
         not end the stream with the connection"
    );
    assert_sleep_pgroup_gone(
        &mut vm,
        closed_pid,
        "an explicit close() must kill the session's process group even with its stdin pipe full (M6)",
    )
    .await;

    // (2) The C3 (§13, Cross-cutting invariants) teardown under the same pressure.
    let mut persistent = mux
        .open(SessionSpecBuilder::new(argv(&["/bin/sh", "-c", PERSISTENT_SH])).build())
        .await
        .expect("open the residue session");
    let pid = session_leader_pid(&mut persistent).await;
    flood_stdin(&persistent).await;
    drop(persistent);
    drop(mux);
    // Let the guest observe EOF, give up on the parked stdin write (one
    // `STDIN_POLL_SLICE`), kill the group, and reap.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    assert_sleep_pgroup_gone(
        &mut vm,
        pid,
        "a flooded session's process group must still be killed when its connection drops (§13, Cross-cutting invariants; M6)",
    )
    .await;

    vm.shutdown().await.expect("shutdown");
}
