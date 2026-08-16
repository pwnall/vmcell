//! Multicall guest **test-helper** binary: a small Rust stand-in for the distro
//! `ip`, `curl`, and `kvm-ok` tools the integration tests invoke inside the
//! guest, plus the `echo-server` listener the host's raw vsock dial and the
//! VM-to-VM segment gates connect to (§3.2, §6.5).
//!
//! It is baked into the rootfs erofs at `/vmcell-tools/vmcell-guest-tools` (with
//! `ip`/`curl`/`kvm-ok`/`echo-server` symlinks), which the steward places on
//! the exec `PATH`. Baking — rather than a virtio-fs share — is what lets the
//! *unprivileged* egress test use the tools: virtiofsd cannot enter its sandbox
//! unprivileged, so a share fails there, whereas the erofs rootfs is served over
//! virtio-blk in both modes. This keeps the base image otherwise minimal (no
//! `iproute2`/`curl`/`cpu-checker` packages) while still exercising the real
//! operations the tests assert on: genuine HTTP(S) requests (honoring the proxy
//! env + the `-k` flag), real `/dev/kvm` access, real interface/route state, and a
//! real AF_VSOCK/TCP listener.
//!
//! Dispatch is busy-box style: when invoked through an
//! `ip`/`curl`/`kvm-ok`/`echo-server` symlink the command is taken from `argv[0]`;
//! otherwise the first argument selects it (`vmcell-guest-tools <cmd> …`). The
//! `echo-server` applet is additionally usable as a custom `init=` target (its
//! symlink is an absolute path and it needs no writable root), which is how the
//! raw dial's guard-bypass claim is validated live with no steward in the guest.
//!
//! `print_stdout`/`print_stderr` are intentionally NOT denied here — reproducing
//! `ip`/`curl`/`kvm-ok` output on stdout/stderr, and announcing/diagnosing the
//! `echo-server` listener on the serial console (a custom-`init=` guest's only
//! observable), is the whole point of the tool. Because that stdout **is** a
//! persisted host artifact, the accept loops pace their failures through
//! `accept_error_pacing` rather than logging per iteration.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::dbg_macro,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use std::io::Write;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|p| basename(p)).unwrap_or_default();

    // `argv[0]` selects the command when invoked via a symlink; otherwise fall
    // back to `vmcell-guest-tools <cmd> …`.
    let (cmd, rest): (String, &[String]) = if is_known(&prog) {
        (prog, args.get(1..).unwrap_or(&[]))
    } else {
        match args.get(1) {
            Some(c) => (c.clone(), args.get(2..).unwrap_or(&[])),
            None => {
                // Rendered from the roster, never re-typed: a usage line that lists a name
                // the binary cannot dispatch (or omits one it can) is the same drift in
                // its most user-visible form.
                eprintln!(
                    "usage: vmcell-guest-tools <{}> [args…]",
                    vmcell_protocol::GUEST_TOOLS_APPLETS.join("|")
                );
                // expect(disallowed_methods): a busy-box multicall helper relays its status as the
                // process exit code; nothing is owned to unwind here (usage error before any work).
                #[expect(
                    clippy::disallowed_methods,
                    reason = "multicall helper relays status as its exit code; nothing owned to unwind (usage error)"
                )]
                std::process::exit(2);
            }
        }
    };

    let code = match applet(&cmd) {
        Some(run) => run(rest),
        None => {
            eprintln!("vmcell-guest-tools: unknown command {cmd}");
            2
        }
    };
    // expect(disallowed_methods): the multicall helper's whole contract is to relay the selected
    // sub-tool's exit code as its own process status; there is no owned host state to unwind.
    #[expect(
        clippy::disallowed_methods,
        reason = "multicall helper relays the sub-tool's exit code as its status; no owned host state to unwind"
    )]
    std::process::exit(code);
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// One applet: takes the sub-command's own arguments, returns its exit code (never
/// exits itself, so `main`'s single `std::process::exit` suppression covers the
/// whole class).
type Applet = fn(&[String]) -> i32;

/// The applet dispatch table: one implementation per
/// [`vmcell_protocol::GUEST_TOOLS_APPLETS`] entry, in the roster's order.
///
/// The roster is NOT restated here. Its length is this array's length (a mismatch is a
/// type error) and the `const` assertion below compares the names element-wise — so
/// growing, dropping, renaming, or reordering the roster without the matching
/// edit here fails to **compile**. That is the point: `vmcell`'s
/// `rootfs_injection_manifest` derives its `/vmcell-tools/<name>` symlinks from the same
/// const, so a symlink can no longer exist without a dispatch arm. Before docs/81 m22 the
/// two sides were independent literals and the one-sided edit shipped twice — a symlinked
/// name with no arm exits 2, which as a custom `init=` panics the guest kernel.
const APPLETS: [(&str, Applet); vmcell_protocol::GUEST_TOOLS_APPLETS.len()] = [
    ("ip", run_ip),
    ("curl", run_curl),
    ("kvm-ok", run_kvm_ok_applet),
    ("echo-server", run_echo_server),
    ("mini-init", run_mini_init),
];

// Compile-time proof that `APPLETS` names exactly the roster, element-wise and in order.
// The array type above already pins the COUNT; this pins the NAMES, which is what catches a
// rename and an insert-in-the-middle (both of which keep the counts equal while silently
// re-pairing a name with another applet's implementation).
const _: () = assert!(
    applet_names_match_roster(),
    "APPLETS must name vmcell_protocol::GUEST_TOOLS_APPLETS element-wise, in order"
);

/// Element-wise name equality between [`APPLETS`] and the roster, evaluable in a `const`.
const fn applet_names_match_roster() -> bool {
    let roster = vmcell_protocol::GUEST_TOOLS_APPLETS;
    let mut i = 0;
    while i < roster.len() {
        // expect(indexing_slicing): a `const fn` has no iterator, and `<[T]>::get` is not
        // const here; `i < roster.len()` bounds both slices (APPLETS' length IS
        // `roster.len()`, by its type). Any slip is a compile error, never a guest panic.
        #[expect(
            clippy::indexing_slicing,
            reason = "const-context element walk; `i < roster.len()` bounds both slices, and APPLETS' length is roster.len() by type"
        )]
        let paired = str_eq(APPLETS[i].0, roster[i]);
        if !paired {
            return false;
        }
        i += 1;
    }
    true
}

/// `&str` equality usable in a `const` (`PartialEq` is not const).
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        // expect(indexing_slicing): same const-context reason as above; `i < a.len()` and
        // the lengths are equal, so both index expressions are in bounds.
        #[expect(
            clippy::indexing_slicing,
            reason = "const-context byte walk; `i < a.len()` and the two lengths are equal"
        )]
        let same = a[i] == b[i];
        if !same {
            return false;
        }
        i += 1;
    }
    true
}

fn applet(name: &str) -> Option<Applet> {
    APPLETS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, run)| *run)
}

fn is_known(name: &str) -> bool {
    applet(name).is_some()
}

// ---------------------------------------------------------------------------
// `kvm-ok` — nested-virt probe (cpu-checker stand-in).
// ---------------------------------------------------------------------------

/// The exit code `curl`, `echo-server` and `kvm-ok` use for an invocation they cannot honor.
///
/// It is deliberately NOT one of `kvm-ok`'s own answers (0 = KVM usable, 1 = not usable), so a
/// rejected argv can never be read as "nested virt is unavailable" — the assertion
/// `nested_virt.rs` makes. The `ip` applet is the one exception, answering 1: that is the code
/// its `ip link set` rejection has always used and what its callers already distinguish.
const EXIT_USAGE: i32 = 2;

/// Validates `kvm-ok`'s argv. Pure, so the accept/reject law is unit-testable without `/dev/kvm`.
///
/// `kvm-ok` probes one fixed thing — whether `/dev/kvm` can be opened read-write — so there is no
/// argument it can honor, and every argument is therefore rejected naming it. The applet used to
/// be registered as `|_args| run_kvm_ok()`, silently discarding whatever it was handed: a caller
/// asking `kvm-ok --verbose` (or a typo'd `kvm-ok -q`) got the plain probe's exit code and could
/// not tell the flag had been dropped. That is the same accept-then-ignore hazard the `curl` and
/// `ip` shims were made fail-loud over — an accepted-but-ignored flag silently voids whatever
/// property the caller passed it for.
fn parse_kvm_ok_args(args: &[String]) -> Result<(), String> {
    if let Some(first) = args.first() {
        return Err(format!(
            "unexpected argument {first:?} — this is vmcell's kvm-ok shim \
             (/vmcell-tools/kvm-ok), not cpu-checker; it probes /dev/kvm and takes no arguments"
        ));
    }
    Ok(())
}

/// The `kvm-ok` applet: rejects any argv it cannot honor, then runs the probe.
fn run_kvm_ok_applet(args: &[String]) -> i32 {
    if let Err(msg) = parse_kvm_ok_args(args) {
        eprintln!("kvm-ok: {msg}");
        eprintln!("usage: kvm-ok");
        return EXIT_USAGE;
    }
    run_kvm_ok()
}

fn run_kvm_ok() -> i32 {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => {
            println!("INFO: /dev/kvm exists");
            println!("KVM acceleration can be used");
            0
        }
        Err(e) => {
            println!("INFO: /dev/kvm does not exist: {e}");
            println!("KVM acceleration can NOT be used");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// `mini-init` — the smallest generic init that runs the steward as a service
// (v33 §3.5, §18 delta 5).
// ---------------------------------------------------------------------------

/// How many steward starts inside [`MINI_INIT_FAILURE_WINDOW`] count as a crash-loop.
///
/// The cap is what makes the restart policy honest. A real init's `Restart=always` is exactly what
/// makes the service SIGTERM leg satisfiable — the steward tears down, exits, and comes back — but
/// an init that restarts a steward that *cannot* start would spin forever, and a guest that spins
/// silently is indistinguishable from a guest that is working. So the cap powers off fail-loud,
/// which the host reads as a dead cell with a named reason on the serial console.
const MINI_INIT_MAX_RAPID_FAILURES: u32 = 5;

/// The window [`MINI_INIT_MAX_RAPID_FAILURES`] is counted over. A steward that stays up longer
/// than this resets the counter — a long-lived steward that eventually exits is a restart, not a
/// crash-loop.
const MINI_INIT_FAILURE_WINDOW: Duration = Duration::from_secs(30);

/// Where the rootfs injection manifest always places the steward binary.
const MINI_INIT_STEWARD_PATH: &str = "/usr/sbin/vmcell-steward";

/// Validates `mini-init`'s argv. Pure, so the accept/reject law is unit-testable with no guest.
///
/// `mini-init` is an `init=` target: the kernel hands it whatever follows on the command line, and
/// it honors none of it. Rejecting rather than ignoring is law F1 applied to an applet's argv
/// exactly as to a config field — and it matters more here than elsewhere, because a silently
/// ignored argument on PID 1 is a guest that boots and then behaves as if the caller had said
/// nothing.
fn parse_mini_init_args(args: &[String]) -> Result<(), String> {
    if let Some(first) = args.first() {
        return Err(format!(
            "unexpected argument {first:?} — mini-init takes none; it assembles the guest root, \
             starts {MINI_INIT_STEWARD_PATH} as a service, restarts it when it exits, and reaps \
             everything"
        ));
    }
    Ok(())
}

/// Decides whether a steward exit is part of a crash-loop.
///
/// Pure so the cap is unit-testable without spawning anything: `run` for how long the steward
/// stayed up, `consecutive` for how many rapid failures preceded it. Returns the new count, and
/// `None` once the cap is reached — which the caller turns into a fail-loud power-off.
fn mini_init_next_failure_count(run: Duration, consecutive: u32) -> Option<u32> {
    if run >= MINI_INIT_FAILURE_WINDOW {
        // It stayed up. This is a restart, not a crash-loop — the counter resets, so a cell that
        // runs for hours and is then stopped does not inherit an old strike.
        return Some(0);
    }
    let next = consecutive.saturating_add(1);
    (next < MINI_INIT_MAX_RAPID_FAILURES).then_some(next)
}

/// The `mini-init` applet: rejects any argv it cannot honor, then runs as PID 1.
fn run_mini_init(args: &[String]) -> i32 {
    if let Err(msg) = parse_mini_init_args(args) {
        eprintln!("mini-init: {msg}");
        eprintln!("usage: mini-init");
        return EXIT_USAGE;
    }
    mini_init_forever()
}

/// Assembles the guest root, then supervises the steward forever.
///
/// The assembly is `vmcell_steward::assemble_guest_root` — the **same** function the `Pid1`
/// steward calls, not a second copy of the mount sequence (AGENTS.md: every duplicate so far has
/// diverged, and the tree's one deliberate guest-side duplication needed a divergence guard to stay
/// honest). The consequence is the point: a service-placement cell's filesystem is byte-for-byte
/// the one a `Pid1` cell gets, so the service-mode live legs differ from their `Pid1` twins in
/// exactly one variable — who is PID 1.
fn mini_init_forever() -> i32 {
    println!("mini-init: starting as pid {}", std::process::id());
    if let Err(e) = vmcell_steward::assemble_guest_root() {
        eprintln!("mini-init: could not assemble the guest root: {e}");
        return mini_init_power_off("guest root assembly failed");
    }

    let mut consecutive_failures: u32 = 0;
    loop {
        let started = std::time::Instant::now();
        let steward = match std::process::Command::new(MINI_INIT_STEWARD_PATH).spawn() {
            Ok(child) => child,
            Err(e) => {
                eprintln!("mini-init: could not start {MINI_INIT_STEWARD_PATH}: {e}");
                match mini_init_next_failure_count(started.elapsed(), consecutive_failures) {
                    Some(next) => {
                        consecutive_failures = next;
                        std::thread::sleep(Duration::from_millis(200));
                        continue;
                    }
                    None => return mini_init_power_off("the steward could not be started"),
                }
            }
        };
        let steward_pid = steward.id();
        println!("mini-init: started the steward as pid {steward_pid}");

        // Reap EVERYTHING, not just the steward: as PID 1 this process inherits every orphan in
        // the guest, and an init that waits only on its own child leaves the rest as zombies.
        // `wait()` blocks on any child, which is exactly the wake-on-exit an init wants — no
        // polling, no signal handler, and no missed exit.
        let status = loop {
            match mini_init_wait_any() {
                Some((pid, code)) if pid == steward_pid => break code,
                // Some other child of ours (an orphan re-parented here). Reaped; keep waiting.
                Some(_) => {}
                // No children at all, or an un-retryable wait error. The steward is gone and we
                // will not learn its status, so treat it as an exit and restart.
                None => break -1,
            }
        };
        println!("mini-init: the steward exited (status {status}); restarting it");

        match mini_init_next_failure_count(started.elapsed(), consecutive_failures) {
            Some(next) => consecutive_failures = next,
            None => {
                return mini_init_power_off(
                    "the steward exited repeatedly without staying up (rapid-failure cap)",
                );
            }
        }
    }
}

/// Blocks until any child exits, returning its pid and exit code.
///
/// `None` means "there is nothing left to wait for, or the wait itself failed un-retryably" — the
/// caller treats that as the steward being gone. `EINTR` is retried rather than reported, so a
/// stray signal cannot look like a child exit.
fn mini_init_wait_any() -> Option<(u32, i32)> {
    loop {
        match rustix::process::wait(rustix::process::WaitOptions::empty()) {
            Ok(Some((pid, status))) => {
                let code = status
                    .exit_status()
                    .unwrap_or_else(|| status.terminating_signal().map_or(-1, |sig| 128 + sig));
                return Some((pid.as_raw_nonzero().get().unsigned_abs(), code));
            }
            Ok(None) => return None,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => {
                eprintln!("mini-init: wait failed: {e}");
                return None;
            }
        }
    }
}

/// Powers the guest off, fail-loud, naming `why` on the serial console.
///
/// A crash-looping guest that stays up looks exactly like a healthy one to a host waiting on a
/// connect budget; a powered-off one with a reason on the console is a diagnosis. Never returns on
/// the success path; if `reboot(2)` itself fails, parks — PID 1 returning kernel-panics the guest,
/// which is a worse failure mode than a hang the host's teardown will force-kill anyway.
fn mini_init_power_off(why: &str) -> i32 {
    eprintln!("mini-init: FATAL: {why}; powering the guest off");
    let _flushed = std::io::stderr().flush();
    rustix::fs::sync();
    if let Err(e) = rustix::system::reboot(rustix::system::RebootCommand::PowerOff) {
        eprintln!("mini-init: power-off failed: {e}; parking so pid 1 never exits");
    }
    loop {
        std::thread::park();
    }
}

// ---------------------------------------------------------------------------
// `echo-server` — a real in-guest listener (§3.2 raw vsock dial, §6.5 segments).
// ---------------------------------------------------------------------------

/// Where an `echo-server` listens. Exactly one endpoint per invocation — the two
/// gates it serves want different transports, never both at once.
#[derive(Debug, PartialEq, Eq)]
enum EchoBind {
    /// AF_VSOCK on `VMADDR_CID_ANY:<port>` — what the host's `MicroVm::dial_vsock`
    /// reaches, with no IP stack in the guest at all.
    Vsock(u32),
    /// A guest TCP endpoint — the VM-to-VM segment gates' listener.
    Tcp(std::net::SocketAddr),
}

/// Parses `echo-server`'s arguments. Pure, so the accept/reject law is unit-tested
/// without a socket.
///
/// Every accepted input is honored or rejected here: an unknown flag, a missing
/// value, a malformed endpoint, port 0, or both endpoints at once are hard errors
/// naming the offender — never a silently ignored argument that leaves the server
/// listening somewhere the caller did not ask for.
fn parse_echo_args(args: &[String]) -> Result<EchoBind, String> {
    let mut bind: Option<EchoBind> = None;
    let set = |chosen: EchoBind, slot: &mut Option<EchoBind>| -> Result<(), String> {
        if let Some(prev) = slot.as_ref() {
            return Err(format!(
                "echo-server takes exactly one endpoint; {prev:?} was already given"
            ));
        }
        *slot = Some(chosen);
        Ok(())
    };

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--vsock" => {
                let raw = it
                    .next()
                    .ok_or_else(|| "--vsock needs a <port>".to_string())?;
                let port: u32 = raw
                    .parse()
                    .map_err(|e| format!("invalid --vsock port {raw:?}: {e}"))?;
                if port == 0 {
                    return Err("--vsock port 0 is VMADDR_PORT_ANY, not a listener".to_string());
                }
                set(EchoBind::Vsock(port), &mut bind)?;
            }
            "--tcp" => {
                let raw = it
                    .next()
                    .ok_or_else(|| "--tcp needs an <addr>:<port>".to_string())?;
                let addr: std::net::SocketAddr = raw
                    .parse()
                    .map_err(|e| format!("invalid --tcp endpoint {raw:?}: {e}"))?;
                if addr.port() == 0 {
                    return Err("--tcp port 0 asks the kernel to pick, not a listener".to_string());
                }
                set(EchoBind::Tcp(addr), &mut bind)?;
            }
            other => return Err(format!("unknown echo-server argument {other:?}")),
        }
    }

    bind.ok_or_else(|| "echo-server needs one of --vsock <port> / --tcp <addr>:<port>".to_string())
}

/// Serves an echo listener forever.
///
/// Returns only on a fatal error (a bad usage or a listener that cannot be bound).
/// This matters beyond exit codes: the applet is also usable as a custom `init=`
/// target, where PID 1 returning panics the guest kernel — so a *per-connection*
/// failure is logged and the loop continues, and only "there is no listener at all"
/// gives up.
fn run_echo_server(args: &[String]) -> i32 {
    let bind = match parse_echo_args(args) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("echo-server: {e}");
            eprintln!("usage: echo-server --vsock <port> | --tcp <addr>:<port>");
            return 2;
        }
    };
    match bind {
        EchoBind::Vsock(port) => serve_vsock(port),
        EchoBind::Tcp(addr) => serve_tcp(addr),
    }
}

/// Binds and listens on [`libc::VMADDR_CID_ANY`]`:<port>` over AF_VSOCK — bind on
/// whatever context id the VMM gave this guest, so the listener need not know its
/// own CID (the steward binds the same way). The constant is `libc`'s, never a
/// second local spelling of the same kernel ABI value.
///
/// Hand-rolled on `libc` rather than on the sync `vsock` crate the steward uses
/// (which is what design §18 delta 7 sketches): this crate already links `libc` for
/// its `ifreq` ioctls, and the three calls below (`socket`/`bind`/`listen`) are
/// exactly what a wrapper would make — recorded as a deviation in
/// `docs/implementation-notes.md` rather than taken silently.
fn vsock_listener(port: u32) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd as _;

    // SAFETY: `socket` takes three integers and returns a fresh fd or -1; it reads
    // and writes no memory through pointers. `SOCK_CLOEXEC` is set in the type
    // argument (not a later `fcntl`) so no `exec` in another thread can race the
    // window where the fd would otherwise be inheritable.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!(
            "socket(AF_VSOCK): {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` was just returned by `socket`, is >= 0, and is not owned or
    // closed anywhere else — this is its single owner from here on.
    let listener = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    // SAFETY: `sockaddr_vm` is a plain `#[repr(C)]` POD of integers and a padding
    // array, so the all-zero bit pattern is a valid, fully initialized value.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = port;
    addr.svm_cid = libc::VMADDR_CID_ANY;

    let addr_len = std::mem::size_of::<libc::sockaddr_vm>();
    let addr_len = libc::socklen_t::try_from(addr_len)
        .map_err(|e| format!("sockaddr_vm size does not fit socklen_t: {e}"))?;
    // SAFETY: `addr` is a live, fully initialized `sockaddr_vm` for the duration of
    // this call, and `addr_len` is that same struct's own size — the pointer/length
    // pair the kernel reads.
    let rc = unsafe {
        libc::bind(
            std::os::fd::AsRawFd::as_raw_fd(&listener),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc < 0 {
        return Err(format!(
            "bind(AF_VSOCK, port {port}): {}",
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: `listener` is a bound stream socket we own; `backlog` is a plain int.
    let rc = unsafe { libc::listen(std::os::fd::AsRawFd::as_raw_fd(&listener), 16) };
    if rc < 0 {
        return Err(format!(
            "listen(AF_VSOCK, port {port}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(listener)
}

/// How an accept loop paces itself after `consecutive` **consecutive** failed
/// `accept`s: how long to pause, and whether to log this one.
///
/// The **one** pacing law both echo listeners use. A listener fd that has gone
/// permanently bad — the shape §3.2 warns about, where a restore re-creates the
/// vhost-vsock device and a *user* listener gets no re-bind — otherwise turns the
/// accept loop into an unbounded busy loop whose every iteration writes a line to
/// the guest's stdout. That stdout is the **serial console**, which vmcell persists
/// as a per-VM log artifact, so the busy loop does not merely spin: it fills the
/// host's disk with the same message. Exiting instead is not an option — the applet
/// is also a custom `init=` target, where PID 1 returning panics the guest kernel.
///
/// So: the pause grows 50 ms → 1.6 s and stops there (bounded, and a listener that
/// recovers is picked up within 1.6 s), and only the first three failures plus every
/// fiftieth after them are logged, which bounds the artifact at a few lines per
/// minute while still recording that the listener is broken.
fn accept_error_pacing(consecutive: u32) -> (Duration, bool) {
    let doublings = consecutive.saturating_sub(1).min(5);
    let pause = Duration::from_millis(50u64 << doublings);
    let log = consecutive <= 3 || consecutive.is_multiple_of(50);
    (pause, log)
}

fn serve_vsock(port: u32) -> i32 {
    use std::os::fd::FromRawFd as _;

    let listener = match vsock_listener(port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("echo-server: {e}");
            return 1;
        }
    };
    // The host's dial races the listener coming up, so announce readiness on the
    // serial console — the one observable a custom-init guest still has.
    println!("echo-server: listening on vsock port {port}");
    if let Err(e) = std::io::stdout().flush() {
        eprintln!("echo-server: stdout flush: {e}");
    }

    let mut consecutive_errors: u32 = 0;
    loop {
        // SAFETY: the first argument is a listening socket we own; the null
        // address/length pair is the documented way to tell `accept4` not to write a
        // peer address, so no memory is written through either pointer; the flags
        // argument is a plain int. `accept4` + `SOCK_CLOEXEC` rather than `accept`:
        // the accepted fd is close-on-exec from birth, with no window an `exec` in
        // another thread could inherit it through.
        let fd = unsafe {
            libc::accept4(
                std::os::fd::AsRawFd::as_raw_fd(&listener),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR is not a failure — the syscall was interrupted, so retry it at
            // once and do not count it against the pacing.
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            consecutive_errors = consecutive_errors.saturating_add(1);
            let (pause, log) = accept_error_pacing(consecutive_errors);
            if log {
                eprintln!(
                    "echo-server: accept on vsock port {port} failed \
                     ({consecutive_errors} consecutive): {err}"
                );
            }
            std::thread::sleep(pause);
            continue;
        }
        consecutive_errors = 0;
        // SAFETY: `fd` was just returned by `accept`, is >= 0, and is owned by
        // nothing else — the connection's single owner.
        let conn = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        // A stream socket fd: `UnixStream` is an address-family-agnostic wrapper
        // over one, and only its `read`/`write`/`shutdown` (plain syscalls on the
        // fd) are used here — never anything that would parse a `sockaddr_un`.
        let stream = std::os::unix::net::UnixStream::from(conn);
        // Detached on purpose: connections are independent and this loop never
        // joins — it runs until the VM goes away.
        drop(std::thread::spawn(move || {
            if let Err(e) = echo_connection(stream) {
                eprintln!("echo-server: vsock connection: {e}");
            }
        }));
    }
}

fn serve_tcp(addr: std::net::SocketAddr) -> i32 {
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("echo-server: bind {addr}: {e}");
            return 1;
        }
    };
    println!("echo-server: listening on tcp {addr}");
    if let Err(e) = std::io::stdout().flush() {
        eprintln!("echo-server: stdout flush: {e}");
    }

    let mut consecutive_errors: u32 = 0;
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                consecutive_errors = 0;
                drop(std::thread::spawn(move || {
                    if let Err(e) = echo_connection(stream) {
                        eprintln!("echo-server: tcp connection: {e}");
                    }
                }));
            }
            // Never give up the listener: as PID 1 a return panics the kernel, and
            // as a test helper a single failed accept must not end the service. But
            // never spin on it either — the same `accept_error_pacing` law the vsock
            // loop uses bounds both the retry rate and the serial-log artifact.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                let (pause, log) = accept_error_pacing(consecutive_errors);
                if log {
                    eprintln!(
                        "echo-server: accept on tcp {addr} failed \
                         ({consecutive_errors} consecutive): {e}"
                    );
                }
                std::thread::sleep(pause);
            }
        }
    }
    // `incoming()` is infinite; reaching here means the listener died.
    eprintln!("echo-server: listener ended unexpectedly");
    1
}

/// One connection: echo every byte back until the peer half-closes, then half-close
/// this side so the peer observes EOF too.
///
/// The second half is load-bearing for the gates: a host asserting "EOF propagates
/// in both directions" only proves anything if the server actually shuts its write
/// side down instead of letting the socket close carry it.
fn echo_connection<S: EchoStream>(mut stream: S) -> std::io::Result<()> {
    echo_until_eof(&mut stream)?;
    stream.shutdown_write()
}

/// The stream operations the echo loop needs, so AF_VSOCK and TCP connections share
/// **one** echo implementation instead of two copies that could drift.
trait EchoStream: std::io::Read + std::io::Write + Send + 'static {
    /// Half-closes the write side, sending the peer an EOF.
    fn shutdown_write(&self) -> std::io::Result<()>;
}

impl EchoStream for std::os::unix::net::UnixStream {
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

impl EchoStream for std::net::TcpStream {
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

fn echo_until_eof<S: std::io::Read + std::io::Write>(stream: &mut S) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = buf.get(..n).ok_or_else(|| {
            std::io::Error::other(format!(
                "read reported {n} bytes into a {}-byte buffer",
                buf.len()
            ))
        })?;
        // `write_all` loops partial writes (a bare `write` would silently drop the
        // tail of a large echo).
        stream.write_all(chunk)?;
        stream.flush()?;
    }
}

// ---------------------------------------------------------------------------
// `ip` — read-only network state from sysfs/procfs, plus the one form that really
// writes (`ip link set … address`, the post-restore MAC rotation).
// ---------------------------------------------------------------------------

/// The `ip` invocations this shim implements, parsed and validated before any state is read or
/// written.
///
/// The pre-fix dispatch had a catch-all that printed the interface list and exited **0** for
/// every spelling it did not recognize — `ip -6 addr`, `ip tunnel add`, `ip link add veth0`, a
/// typo'd object. That is the accept-then-ignore hazard the `curl` and `ip link set` parsers were
/// already made fail-loud over, one step removed: a caller that asked for something the shim
/// cannot do got a success and a plausible-looking listing. Rejection *is* the faithful
/// emulation — an unimplemented form fails loudly, exactly as a missing real-`ip` feature would.
#[derive(Debug, PartialEq, Eq)]
enum IpCommand {
    /// List interfaces, narrowed to one device when the caller named one (`ip addr show eth0`).
    /// The filter is **honored**, not dropped: printing every interface for a caller that asked
    /// about one is how an assertion about `eth1` passes on `eth0`'s address.
    Links {
        /// The device to list, or `None` for all of them.
        dev: Option<String>,
    },
    /// Print the kernel routing table (`/proc/net/route`).
    Routes,
    /// Print the neighbour table (`/proc/net/arp`).
    Neigh,
    /// An address/route/neighbour **write** verb, deliberately accepted as a no-op so a caller's
    /// post-restore `ip addr …` chain succeeds without clobbering the boot-time (kernel `ip=`)
    /// address. In-guest IP rotation on restore is intentionally not performed (see the module
    /// docs / the zero-netlink invariant); only MAC rotation is applied, via `ip link set`. This
    /// is a recorded, deliberate exception to the honor-or-reject law, kept as it shipped — and
    /// it is why `ip link add`/`del` is *rejected* rather than folded in here: a shim that
    /// silently "succeeds" at creating an interface is a lie about the guest's topology, not a
    /// preserved boot-time address.
    NoOpWrite,
    /// `ip link set …` — the argv after `set`, for the one form that really writes.
    LinkSet(Vec<String>),
}

/// Parses `ip`'s argv. Pure, so the whole accept/reject matrix is unit-testable without an
/// interface, mirroring [`parse_ip_link_set`] and [`parse_curl_args`].
fn parse_ip_args(args: &[String]) -> Result<IpCommand, String> {
    let mut idx = 0;
    while let Some(arg) = args.get(idx) {
        if !arg.starts_with('-') {
            break;
        }
        match arg.as_str() {
            // Every vmcell guest datapath — the NAT /30, the privileged tap /30, and the segment
            // /24 — is IPv4-only, so `-4` is what already happens (the same reasoning the `curl`
            // shim's `-4` arm carries). `-6` is therefore un-honorable and rejected.
            "-4" => {}
            "-6" => {
                return Err("-6 cannot be honored: vmcell guest networking is IPv4-only".into());
            }
            other => {
                return Err(format!(
                    "unknown option {other} — this is vmcell's ip shim (/vmcell-tools/ip), not \
                     iproute2; it implements only `[-4] {{addr|link|route|neigh}} …`"
                ));
            }
        }
        idx += 1;
    }
    let rest = args.get(idx..).unwrap_or(&[]);
    // A bare `ip` (or `ip -4`) lists interfaces, as this shim has always done.
    let Some((object, tail)) = rest.split_first() else {
        return Ok(IpCommand::Links { dev: None });
    };
    match object.as_str() {
        "link" | "l" => match tail.split_first() {
            Some((verb, after)) if verb == "set" => Ok(IpCommand::LinkSet(after.to_vec())),
            Some((verb, _)) if is_write_verb(Some(verb)) => Err(format!(
                "`ip link {verb}` is not implemented: this shim reads interface state and sets \
                 an existing link's address/flags — it cannot create or destroy interfaces"
            )),
            _ => Ok(IpCommand::Links {
                dev: parse_listing_tail(tail)?,
            }),
        },
        "addr" | "a" | "address" => {
            if is_write_verb(tail.first()) {
                return Ok(IpCommand::NoOpWrite);
            }
            Ok(IpCommand::Links {
                dev: parse_listing_tail(tail)?,
            })
        }
        "route" | "r" => {
            if is_write_verb(tail.first()) {
                return Ok(IpCommand::NoOpWrite);
            }
            parse_unfiltered_listing(tail, "route", IpCommand::Routes)
        }
        "neigh" | "n" | "neighbour" | "neighbor" => {
            if is_write_verb(tail.first()) {
                return Ok(IpCommand::NoOpWrite);
            }
            parse_unfiltered_listing(tail, "neigh", IpCommand::Neigh)
        }
        other => Err(format!(
            "unknown object {other:?} — this is vmcell's ip shim (/vmcell-tools/ip), not \
             iproute2; it implements only `addr`, `link`, `route` and `neigh`"
        )),
    }
}

/// The listing verbs (`ip addr show`, `ip link list`) — read forms that take an optional device.
fn is_read_verb(tok: &str) -> bool {
    matches!(tok, "show" | "list" | "l" | "ls")
}

/// Parses a listing's tail: an optional read verb followed by an optional `[dev] <name>` filter
/// (`ip addr show eth0`, `ip addr show dev eth0`, `ip a eth0`, or nothing at all).
///
/// Anything else is rejected naming it, because the alternative — dropping it — is what let
/// `ip addr show eth0` print every interface and a caller assert on the wrong one's address.
fn parse_listing_tail(tail: &[String]) -> Result<Option<String>, String> {
    let rest = match tail.split_first() {
        None => return Ok(None),
        // `show`/`list` consume the verb slot; a bare token is the device itself.
        Some((verb, after)) if is_read_verb(verb) => after,
        Some(_) => tail,
    };
    let mut it = rest.iter();
    let Some(first) = it.next() else {
        return Ok(None);
    };
    let dev = if first == "dev" {
        it.next()
            .ok_or_else(|| "dev needs a device name".to_string())?
    } else if first.starts_with('-') {
        return Err(format!(
            "unknown option {first} — this is vmcell's ip shim (/vmcell-tools/ip); options go \
             before the object, and only `-4` is implemented"
        ));
    } else {
        first
    };
    if let Some(extra) = it.next() {
        return Err(format!(
            "unsupported argument {extra:?} — this is vmcell's ip shim (/vmcell-tools/ip), not \
             iproute2; a listing takes at most `[show] [dev] <name>`"
        ));
    }
    Ok(Some(dev.clone()))
}

/// Parses the tail of a listing this shim prints **whole** (`ip route`, `ip neigh`): the optional
/// read verb and nothing else. A filter it cannot apply is rejected rather than ignored — `ip
/// route show dev eth0` returning every route reads as "this route exists on eth0".
fn parse_unfiltered_listing(
    tail: &[String],
    object: &str,
    cmd: IpCommand,
) -> Result<IpCommand, String> {
    let rest = match tail.split_first() {
        None => return Ok(cmd),
        Some((verb, after)) if is_read_verb(verb) => after,
        Some(_) => tail,
    };
    match rest.first() {
        None => Ok(cmd),
        Some(extra) => Err(format!(
            "unsupported argument {extra:?} — this is vmcell's ip shim (/vmcell-tools/ip), not \
             iproute2; `ip {object}` prints the whole table and implements no selector"
        )),
    }
}

fn run_ip(args: &[String]) -> i32 {
    let cmd = match parse_ip_args(args) {
        Ok(cmd) => cmd,
        Err(msg) => {
            eprintln!("ip: {msg}");
            // 1, not `EXIT_USAGE`: the code this applet's `ip link set` rejection already uses.
            return 1;
        }
    };
    match cmd {
        IpCommand::Links { dev } => {
            print_links(dev.as_deref());
            0
        }
        IpCommand::Routes => {
            print_routes();
            0
        }
        IpCommand::Neigh => {
            print_neigh();
            0
        }
        IpCommand::NoOpWrite => 0,
        IpCommand::LinkSet(argv) => run_ip_link_set(&argv),
    }
}

fn is_write_verb(verb: Option<&String>) -> bool {
    matches!(
        verb.map(String::as_str),
        Some("add" | "del" | "delete" | "change" | "replace" | "flush")
    )
}

/// The `ip link set` forms this shim implements, parsed and **validated** before
/// any ioctl runs.
///
/// Every field is something the shim genuinely performs — the same law the `curl`
/// applet below already enforces (`curl-shim-silently-ignores-unknown-flags`).
/// The pre-fix parser had a catch-all that swallowed `mtu 9000`, `master br0` and
/// `promisc on` and still exited 0, and a bare `address` with no value became
/// `None`, which the consumer skipped: a test that asked for an MTU change, an
/// enslave, or a MAC rotation and then asserted on the result lost the property it
/// was written to assert. Rejection *is* the faithful emulation — an unimplemented
/// form fails loudly, exactly as a missing real-`ip` feature would.
struct IpLinkSet {
    dev: String,
    mac: Option<[u8; 6]>,
    up: Option<bool>,
}

/// Parses `ip link set …`'s argv (everything after `set`), or returns the message
/// to print before exiting 1.
///
/// Pure, so the whole accept/reject matrix is unit-testable without an interface.
fn parse_ip_link_set(args: &[String]) -> Result<IpLinkSet, String> {
    let mut dev: Option<String> = None;
    let mut mac: Option<[u8; 6]> = None;
    let mut up: Option<bool> = None;
    let mut it = args.iter();
    // Every value-consuming keyword goes through this, so a keyword at the end of
    // argv is a named rejection rather than a silently-dropped option.
    macro_rules! value {
        ($kw:expr) => {
            it.next().ok_or_else(|| format!("{} needs a value", $kw))?
        };
    }
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "dev" => dev = Some(value!("dev").clone()),
            "address" | "addr" => {
                let raw = value!("address");
                mac = Some(parse_mac(raw).ok_or_else(|| format!("invalid MAC address {raw:?}"))?);
            }
            "up" => up = Some(true),
            "down" => up = Some(false),
            other => {
                // `ip link set eth0 …` — the first bare token is the device.
                if dev.is_some() {
                    return Err(format!(
                        "unsupported argument {other:?} — this is vmcell's ip shim \
                         (/vmcell-tools/ip), not iproute2; it implements only \
                         `set [dev] <name> [address <mac>] [up|down]`"
                    ));
                }
                dev = Some(other.to_string());
            }
        }
    }
    let dev = dev.ok_or_else(|| "no device specified".to_string())?;
    Ok(IpLinkSet { dev, mac, up })
}

/// Applies `ip link set …` — `args` is the argv **after** `set`, as carried by
/// [`IpCommand::LinkSet`].
///
/// Implements `<dev> address <mac>` (and `up`/`down`) for real via interface
/// ioctls — the orchestrator's post-restore MAC rotation depends on it. Any form
/// the shim cannot honor is rejected by [`parse_ip_link_set`], never ignored.
fn run_ip_link_set(args: &[String]) -> i32 {
    let IpLinkSet { dev, mac, up } = match parse_ip_link_set(args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("ip link set: {msg}");
            return 1;
        }
    };

    if let Some(mac) = mac
        && let Err(e) = set_mac(&dev, mac)
    {
        eprintln!("ip link set {dev} address: {e}");
        return 1;
    }
    if let Some(up) = up {
        let fd = match open_inet_socket() {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("ip link set {dev}: {e}");
                return 1;
            }
        };
        let res = set_link_up(fd, &dev, up);
        // SAFETY: `fd` is a valid socket fd we opened above and no longer use.
        unsafe {
            libc::close(fd);
        }
        if let Err(e) = res {
            eprintln!("ip link set {dev}: {e}");
            return 1;
        }
    }
    0
}

/// Prints the interface listing, narrowed to `only` when the caller named a device.
///
/// The filter is HONORED, not dropped: printing every interface for a caller that asked about one is
/// how an assertion about `eth1` passes on `eth0`'s address. A named device that does not exist
/// prints nothing, which is what real `ip` reports through its non-zero exit — the shim's callers
/// assert on the emitted lines, so an empty listing is the observable difference.
fn print_links(only: Option<&str>) {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        println!("(no /sys/class/net)");
        return;
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| only.is_none_or(|want| want == name))
        .collect();
    names.sort();
    for (idx, name) in names.iter().enumerate() {
        let mac = read_trim(&format!("/sys/class/net/{name}/address")).unwrap_or_default();
        let state = read_trim(&format!("/sys/class/net/{name}/operstate")).unwrap_or_default();
        let mtu = read_trim(&format!("/sys/class/net/{name}/mtu")).unwrap_or_default();
        println!("{}: {}: state {} mtu {}", idx + 1, name, state, mtu);
        if !mac.is_empty() {
            println!("    link/ether {mac}");
        }
        // The IPv4 address the kernel configured (via IP-PNP `ip=` for eth0) — read over the
        // SIOCGIFADDR ioctl, so `ip a` reports the actual `inet` line like real `ip`. Absent on
        // an unconfigured interface (e.g. a down link), in which case no line is printed.
        if let Some((addr, prefix)) = read_ipv4(name) {
            println!(
                "    inet {}.{}.{}.{}/{}",
                addr[0], addr[1], addr[2], addr[3], prefix
            );
        }
    }
}

fn print_routes() {
    match std::fs::read_to_string("/proc/net/route") {
        Ok(contents) => print!("{contents}"),
        Err(e) => println!("(no /proc/net/route: {e})"),
    }
}

fn print_neigh() {
    match std::fs::read_to_string("/proc/net/arp") {
        Ok(contents) => print!("{contents}"),
        Err(e) => println!("(no /proc/net/arp: {e})"),
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

// --- interface ioctls for `ip link set … address` (restore MAC rotation) ---
//
// `ifreq-stack-duplicated-guest-tools` (docs/78 §6): this `IfReq` + link-ioctl
// stack is a SECOND copy of the one in `vmcell_steward::netif`, against the
// "kernel ABI structs are `#[repr(C)]`, defined once" rule. The review offered two
// routes; this is the RECORDED-deviation route (b), with a strengthened divergence
// guard. Why not route (a), consolidating onto the steward's lib target:
//
//   * `netif` deliberately exports only what PID 1 calls — `set_loopback_up` and
//     the one composed `resync_net`. Guest-tools additionally needs a general
//     `set_link_up(dev, up)` (for `ip link set … up|down`) and `read_ipv4`
//     (`SIOCGIFADDR`/`SIOCGIFNETMASK`, for `ip addr`'s `inet` line), neither of
//     which PID 1 has any use for. Consolidating means GROWING the audited PID-1
//     surface — and its `unsafe` blocks — with code PID 1 never executes, which is
//     the opposite of the lean-steward posture (§13 C1).
//   * guest-tools would link the steward's whole production graph (vsock, postcard,
//     rustix, signal-hook, tracing, tracing-subscriber, vmcell-protocol) to reuse
//     ~60 lines of `libc`. (The reverse direction is safe — the lean-steward gate
//     reads `cargo tree -e no-dev -p vmcell-steward`, i.e. the steward's own
//     subtree, which a dependent cannot enter — so that is not the objection.)
//
// The honest consolidation is a third `libc`-only crate both depend on; that is a
// workspace-layout change, recorded in `docs/implementation-notes.md` rather than
// taken silently here. Until it lands, the DIVERGENCE GUARD is field-by-field, not
// total-size-only: the request numbers below are `libc`'s (never a second local
// spelling of a kernel ABI value — the same rule this file already applies to
// `VMADDR_CID_ANY`), the union sub-offsets are named constants mirroring
// `netif::HWADDR_{FAMILY,MAC}_OFFSET`, and
// `ifreq_is_pinned_field_by_field_to_the_kernel_abi` pins offsets + sizes against
// `libc::ifreq`/`sockaddr`/`sockaddr_in`. Both copies are anchored to the same ABI,
// so a drift in either reddens in its own crate — the steward half now holds up its
// end too (m25): `netif` takes its request numbers from `libc` and pins them in
// `netif::tests::ioctl_requests_and_flags_are_pinned_to_the_kernel_abi`.
//
// The error-type divergence the review named IS resolved: this stack now returns
// `std::io::Result`, exactly as `netif` does, so the remaining difference between
// the copies is only the functions each consumer needs.

/// Offset of the `ifr_hwaddr`/`ifr_addr` sockaddr's `sa_family` within the `ifru`
/// union (mirrors `netif::HWADDR_FAMILY_OFFSET`).
const SOCKADDR_FAMILY_OFFSET: usize = 0;
/// Offset of the sockaddr's `sa_data` — the six MAC bytes for `ifr_hwaddr` — within
/// the `ifru` union: the `u16` family precedes it (mirrors
/// `netif::HWADDR_MAC_OFFSET`).
const SOCKADDR_DATA_OFFSET: usize = 2;
/// Offset of `sockaddr_in::sin_addr` within the `ifru` union: `sin_family` (2) plus
/// `sin_port` (2) precede it.
const SIN_ADDR_OFFSET: usize = 4;

/// `libc::IFF_UP` narrowed to the `short` the `ifr_flags` union arm actually carries.
/// A fixed ABI constant (1), not a wire value, so the narrowing is lossless — but it
/// is still derived from `libc` rather than re-spelled, and
/// `ioctl_requests_match_the_kernel_abi_values_netif_hardcodes` pins the round trip.
const IFF_UP: i16 = libc::IFF_UP as i16;

/// A `struct ifreq` (40 bytes on 64-bit Linux): the 16-byte interface name
/// followed by the `ifr_ifru` union, which we access as raw bytes for the three
/// shapes we use — `ifr_flags` (a `short` at offset 0), `ifr_hwaddr` and
/// `ifr_addr`/`ifr_netmask` (sockaddrs, hence the `SOCKADDR_*`/`SIN_ADDR_OFFSET`
/// constants above).
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    ifru: [u8; 24],
}

impl IfReq {
    fn new(dev: &str) -> std::io::Result<Self> {
        let bytes = dev.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("device name too long: {dev}"),
            ));
        }
        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        for (slot, &b) in name.iter_mut().zip(bytes) {
            *slot = b.cast_signed();
        }
        Ok(IfReq {
            name,
            ifru: [0u8; 24],
        })
    }
}

/// The current `errno` tagged with the syscall/ioctl that produced it, keeping the
/// [`std::io::ErrorKind`] intact.
///
/// `netif` returns the bare `last_os_error()`; guest-tools names the operation
/// because these strings are printed on the **serial console**, which vmcell
/// persists as the per-VM log artifact and is a restored guest's only observable
/// when `ip link set` fails. That naming is the one deliberate behavioral
/// difference between the two copies.
fn os_err(op: &str) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    std::io::Error::new(err.kind(), format!("{op}: {err}"))
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.trim().split(':') {
        // `get_mut` folds in the ">6 octets → reject" guard without indexing (denied crate-wide).
        let slot = out.get_mut(n)?;
        *slot = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    if n == 6 { Some(out) } else { None }
}

fn open_inet_socket() -> std::io::Result<libc::c_int> {
    // SAFETY: a constant, valid `socket(2)` call; the returned fd is checked.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(os_err("socket(AF_INET)"));
    }
    Ok(fd)
}

fn set_link_up(fd: libc::c_int, dev: &str, up: bool) -> std::io::Result<()> {
    let mut ifr = IfReq::new(dev)?;
    // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCGIFFLAGS reads the
    // name and writes `ifr_flags` into the union bytes.
    if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) } < 0 {
        return Err(os_err("SIOCGIFFLAGS"));
    }
    let mut flags = i16::from_ne_bytes([ifr.ifru[0], ifr.ifru[1]]);
    if up {
        flags |= IFF_UP;
    } else {
        flags &= !IFF_UP;
    }
    ifr.ifru[0..2].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: same struct, SIOCSIFFLAGS consumes name + ifr_flags.
    if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &mut ifr) } < 0 {
        return Err(os_err("SIOCSIFFLAGS"));
    }
    Ok(())
}

/// Builds the `ifreq` submitted to `SIOCSIFHWADDR` for `dev`+`mac`: the interface
/// name, `ARPHRD_ETHER` in the sockaddr family, then the six MAC bytes. Split out
/// so the byte layout is unit-testable without a live interface (M-GUEST-3),
/// mirroring the steward `netif::hwaddr_ifreq` helper.
fn hwaddr_ifreq(dev: &str, mac: [u8; 6]) -> std::io::Result<IfReq> {
    let mut ifr = IfReq::new(dev)?;
    // ifr_hwaddr: sa_family (host-order u16) then sa_data; first 6 data bytes are
    // the MAC. The offsets are the named ABI constants, not literals, so the pin
    // test can assert them against `libc::sockaddr` rather than restating them.
    ifr.ifru[SOCKADDR_FAMILY_OFFSET..SOCKADDR_FAMILY_OFFSET + 2]
        .copy_from_slice(&libc::ARPHRD_ETHER.to_ne_bytes());
    ifr.ifru[SOCKADDR_DATA_OFFSET..SOCKADDR_DATA_OFFSET + 6].copy_from_slice(&mac);
    Ok(ifr)
}

/// Extracts the four IPv4 address bytes from an `ifreq` union filled by `SIOCGIFADDR`/
/// `SIOCGIFNETMASK`: the union holds a `sockaddr_in` (`sin_family` u16 @0, `sin_port` u16 @2,
/// `sin_addr` @4). Split out so the offset is unit-testable without a live interface (M-GUEST-3,
/// mirroring `hwaddr_ifreq`).
fn ipv4_from_ifru(ifru: &[u8; 24]) -> [u8; 4] {
    let mut addr = [0u8; 4];
    addr.copy_from_slice(&ifru[SIN_ADDR_OFFSET..SIN_ADDR_OFFSET + 4]);
    addr
}

/// The CIDR prefix length of a contiguous IPv4 netmask (e.g. `255.255.255.252` → `30`).
fn netmask_to_prefix(mask: [u8; 4]) -> u8 {
    u32::from_be_bytes(mask).count_ones() as u8
}

/// Reads an interface's IPv4 address (`SIOCGIFADDR`) and netmask prefix (`SIOCGIFNETMASK`) via
/// ioctls on an `AF_INET` socket — the same dependency-free path the MAC ioctls use (no netlink).
/// Returns `None` when the interface has no IPv4 address (e.g. `lo` before configuration, or a
/// down link), which the `SIOCGIFADDR` ioctl reports as `EADDRNOTAVAIL`.
fn read_ipv4(dev: &str) -> Option<([u8; 4], u8)> {
    let fd = open_inet_socket().ok()?;
    let res = (|| {
        let mut ifr = IfReq::new(dev).ok()?;
        // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCGIFADDR reads the name and
        // writes the `ifr_addr` sockaddr into the union bytes.
        if unsafe { libc::ioctl(fd, libc::SIOCGIFADDR, &mut ifr) } < 0 {
            return None;
        }
        let addr = ipv4_from_ifru(&ifr.ifru);
        let mut mask_ifr = IfReq::new(dev).ok()?;
        // SAFETY: same struct shape; SIOCGIFNETMASK writes `ifr_netmask` (a sockaddr).
        let prefix = if unsafe { libc::ioctl(fd, libc::SIOCGIFNETMASK, &mut mask_ifr) } < 0 {
            32
        } else {
            netmask_to_prefix(ipv4_from_ifru(&mask_ifr.ifru))
        };
        Some((addr, prefix))
    })();
    // SAFETY: `fd` is the socket we opened and no longer use.
    unsafe {
        libc::close(fd);
    }
    res
}

/// Installs `mac` on `dev`. The address is already validated — [`parse_ip_link_set`]
/// rejects a malformed one before any ioctl runs, so this never sees a bad MAC.
fn set_mac(dev: &str, mac: [u8; 6]) -> std::io::Result<()> {
    let fd = open_inet_socket()?;
    let res = (|| -> std::io::Result<()> {
        // Some drivers require the link down to change its hardware address; bring
        // it down (best effort) then back up around the set. The `Result` is
        // deliberately discarded: a driver that refuses the down-transition may
        // still accept the hwaddr change, and the SIOCSIFHWADDR below is the check
        // that actually decides the outcome.
        let _ = set_link_up(fd, dev, false);

        let mut ifr = hwaddr_ifreq(dev, mac)?;
        // SAFETY: `ifr` is a correctly sized `struct ifreq`; SIOCSIFHWADDR reads
        // the name and the `ifr_hwaddr` sockaddr from the union bytes.
        if unsafe { libc::ioctl(fd, libc::SIOCSIFHWADDR, &mut ifr) } < 0 {
            let err = os_err("SIOCSIFHWADDR");
            // M-GUEST-2: the link was brought down above; re-raise it even on this
            // failure path so a failed (best-effort) MAC change never strands the
            // restored guest's eth0 administratively DOWN with no one to re-raise
            // it. The re-up is itself best-effort — the original error is returned.
            let _ = set_link_up(fd, dev, true);
            return Err(err);
        }

        set_link_up(fd, dev, true)?;
        Ok(())
    })();
    // SAFETY: `fd` is the socket we opened and no longer use.
    unsafe {
        libc::close(fd);
    }
    res
}

// ---------------------------------------------------------------------------
// `curl` — real HTTP(S) client (curl-flag subset).
// ---------------------------------------------------------------------------

/// The subset of curl's CLI this shim implements, parsed and **validated** before
/// any request is made.
///
/// Every field here is a flag the shim genuinely acts on. That is the whole point
/// of the type (`curl-shim-silently-ignores-unknown-flags`): the pre-fix parser
/// ignored unknown flags, swallowed a garbage `--max-time`, discarded `-o`/`-H`/
/// `-A`/`-X` values, and dropped an unparseable `--resolve` — so a test that
/// reached for a real-curl feature silently lost the property it was written to
/// assert (the `-k`-on-a-TLS-test hazard, one step removed). Rejection *is* the
/// faithful emulation: a flag this shim cannot honor exits 2 naming the offender,
/// exactly as a missing real-curl feature would fail loudly.
struct CurlArgs {
    insecure: bool,
    verbose: bool,
    max_time: Option<u64>,
    resolve: Vec<(String, u16, std::net::IpAddr)>,
    /// `-H Name: value` sets a header; `-H Name:` (empty value) *removes* it, the
    /// curl idiom for suppressing a header curl would otherwise add.
    headers: Vec<(String, Option<String>)>,
    method: Option<String>,
    body: Option<Vec<u8>>,
    output: Option<String>,
    write_out: Option<String>,
    follow: bool,
    url: String,
}

/// The `%{…}` variables `-w`/`--write-out` understands. Validated at *parse* time
/// so an unsupported variable fails before the request rather than rendering as
/// silent empty text.
const WRITE_OUT_VARS: &[&str] = &["http_code", "size_download"];

/// Renders a `-w`/`--write-out` format. `\n`/`\t`/`\\` are the escapes curl
/// documents; `%{var}` interpolates a [`WRITE_OUT_VARS`] entry; `%%` is a literal
/// `%`. Returns `Err` naming the offending variable, so the same predicate both
/// validates (at parse time, with placeholder values) and renders.
fn render_write_out(fmt: &str, http_code: u16, size_download: usize) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some(other) => return Err(format!("unsupported --write-out escape \\{other}")),
                None => return Err("trailing \\ in --write-out format".to_string()),
            },
            '%' => match chars.peek() {
                Some('%') => {
                    chars.next();
                    out.push('%');
                }
                Some('{') => {
                    chars.next();
                    let name: String = chars.by_ref().take_while(|c| *c != '}').collect();
                    match name.as_str() {
                        "http_code" => out.push_str(&http_code.to_string()),
                        "size_download" => out.push_str(&size_download.to_string()),
                        _ => {
                            return Err(format!(
                                "unsupported --write-out variable %{{{name}}} (supported: {})",
                                WRITE_OUT_VARS.join(", ")
                            ));
                        }
                    }
                }
                _ => return Err("bare % in --write-out format (use %% or %{var})".to_string()),
            },
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Parses the shim's curl-flag subset, or returns the message to print before
/// exiting 2. Pure and filesystem-free except for the `@file` body read, so the
/// whole accept/reject matrix is unit-testable without a network or a guest.
fn parse_curl_args(args: &[String]) -> Result<CurlArgs, String> {
    let mut parsed = CurlArgs {
        insecure: false,
        verbose: false,
        max_time: None,
        resolve: Vec::new(),
        headers: Vec::new(),
        method: None,
        body: None,
        output: None,
        write_out: None,
        follow: false,
        url: String::new(),
    };
    let mut url: Option<String> = None;
    let mut it = args.iter();
    // Every value-consuming arm goes through this so a flag at the end of argv is
    // a named rejection, never a silently-dropped option.
    macro_rules! value {
        ($flag:expr) => {
            it.next()
                .ok_or_else(|| format!("option {} needs a value", $flag))?
        };
    }
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-k" | "--insecure" => parsed.insecure = true,
            "-v" | "--verbose" => parsed.verbose = true,
            "-L" | "--location" => parsed.follow = true,
            // Honored by construction: this shim prints no progress meter (so
            // `-s` is always in effect) and always writes errors to stderr (so
            // `-S` is too).
            "-s" | "-S" | "-sS" | "--silent" | "--show-error" => {}
            // Every vmcell guest datapath — the NAT /30, the privileged tap /30,
            // and the segment /24 — is IPv4-only, so `-4` is what already happens.
            // `-6` is therefore un-honorable and rejected rather than ignored.
            "-4" => {}
            "--max-time" => {
                let raw = value!("--max-time");
                parsed.max_time = Some(
                    raw.parse()
                        .map_err(|_| format!("--max-time takes whole seconds, got {raw:?}"))?,
                );
            }
            "--resolve" => {
                let spec = value!("--resolve");
                parsed.resolve.push(
                    parse_resolve(spec)
                        .ok_or_else(|| format!("--resolve wants HOST:PORT:ADDR, got {spec:?}"))?,
                );
            }
            "-H" | "--header" => {
                let spec = value!("-H");
                let (name, value) = spec
                    .split_once(':')
                    .ok_or_else(|| format!("-H wants 'Name: value', got {spec:?}"))?;
                let name = name.trim();
                if name.is_empty() {
                    return Err(format!("-H has an empty header name: {spec:?}"));
                }
                let value = value.trim();
                parsed.headers.push((
                    name.to_string(),
                    (!value.is_empty()).then(|| value.to_string()),
                ));
            }
            "-A" | "--user-agent" => {
                let ua = value!("-A");
                parsed
                    .headers
                    .push(("user-agent".to_string(), Some(ua.clone())));
            }
            "-X" | "--request" => parsed.method = Some(value!("-X").clone()),
            "-o" | "--output" => parsed.output = Some(value!("-o").clone()),
            "-w" | "--write-out" => {
                let fmt = value!("-w");
                // Validate now, with placeholder values, so an unsupported
                // variable fails before the request instead of rendering empty.
                render_write_out(fmt, 0, 0)?;
                parsed.write_out = Some(fmt.clone());
            }
            // `--data-binary` sends the bytes verbatim; `--data-raw` never reads a
            // file. Plain `-d`/`--data` is deliberately NOT accepted: real curl
            // strips newlines from an `@file` there, and silently emulating that
            // difference is the trap this whole fix exists to close.
            "--data-binary" => {
                let spec = value!("--data-binary");
                parsed.body = Some(match spec.strip_prefix('@') {
                    Some(path) => std::fs::read(path)
                        .map_err(|e| format!("--data-binary cannot read {path}: {e}"))?,
                    None => spec.as_bytes().to_vec(),
                });
            }
            "--data-raw" => parsed.body = Some(value!("--data-raw").as_bytes().to_vec()),
            "-d" | "--data" => {
                return Err(
                    "-d/--data is not implemented (its @file newline-stripping differs \
                     from curl's); use --data-binary or --data-raw"
                        .to_string(),
                );
            }
            "-6" => {
                return Err(
                    "-6 cannot be honored: vmcell guest networking is IPv4-only".to_string()
                );
            }
            "--compressed" => {
                return Err(
                    "--compressed cannot be honored: this build links reqwest without \
                     decompression features"
                        .to_string(),
                );
            }
            other if other.starts_with('-') => {
                return Err(format!(
                    "unknown option {other} — this is vmcell's curl shim \
                     (/vmcell-tools/curl), not GNU curl; implement the flag or drop it"
                ));
            }
            other => {
                if let Some(first) = &url {
                    return Err(format!(
                        "more than one URL given ({first:?} and {other:?}); the shim \
                         performs exactly one transfer"
                    ));
                }
                url = Some(other.to_string());
            }
        }
    }
    parsed.url = url.ok_or_else(|| "no URL specified".to_string())?;
    Ok(parsed)
}

fn run_curl(args: &[String]) -> i32 {
    let CurlArgs {
        insecure,
        verbose,
        max_time,
        resolve,
        headers,
        method,
        body,
        output,
        write_out,
        follow,
        url,
    } = match parse_curl_args(args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("curl: {msg}");
            return 2;
        }
    };

    let mut builder = reqwest::blocking::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(secs) = max_time {
        builder = builder.timeout(Duration::from_secs(secs));
    }
    for (host, port, ip) in &resolve {
        builder = builder.resolve(host, std::net::SocketAddr::new(*ip, *port));
    }
    // reqwest follows up to 10 redirects by DEFAULT, i.e. the opposite of curl,
    // which follows none without `-L`. Pin curl's semantics explicitly so `-L`
    // means something and its absence means something too.
    builder = builder.redirect(if follow {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    });

    // Configure the proxy explicitly from the curl-style env vars, rather than
    // relying on reqwest's auto-detection (which proved unreliable here). The
    // egress tests steer traffic at the transparent proxy via http_proxy /
    // https_proxy.
    //
    // Order matters: reqwest applies proxies first-match, and `Proxy::all` matches
    // *every* scheme, so the scheme-specific `http`/`https` proxies MUST be added
    // BEFORE the `all_proxy` catch-all — otherwise `all_proxy` shadows a
    // scheme-specific `https_proxy` for HTTPS URLs, the opposite of curl's
    // precedence (scheme-specific wins over the catch-all) (PRIV-7).
    if let Some(p) = proxy_from_env(&["http_proxy", "HTTP_PROXY"]) {
        match reqwest::Proxy::http(&p) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => eprintln!("curl: bad http_proxy {p}: {e}"),
        }
    }
    if let Some(p) = proxy_from_env(&["https_proxy", "HTTPS_PROXY"]) {
        match reqwest::Proxy::https(&p) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => eprintln!("curl: bad https_proxy {p}: {e}"),
        }
    }
    if let Some(p) = proxy_from_env(&["all_proxy", "ALL_PROXY"]) {
        match reqwest::Proxy::all(&p) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => eprintln!("curl: bad all_proxy {p}: {e}"),
        }
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("curl: failed to build client: {e}");
            return 2;
        }
    };

    // curl's own default-method rule: GET, or POST once a body is given; `-X`
    // overrides either way.
    let default_method = if body.is_some() { "POST" } else { "GET" };
    let method_name = method.as_deref().unwrap_or(default_method).to_uppercase();
    let method = match reqwest::Method::from_bytes(method_name.as_bytes()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("curl: -X {method_name}: {e}");
            return 2;
        }
    };
    let mut request = client.request(method, &url);
    for (name, value) in &headers {
        // A `Name:` with no value is curl's "do not send this header". Nothing
        // here adds headers implicitly, so honoring it is simply not sending one
        // — never sending an empty-valued header, which is a different request.
        if let Some(v) = value {
            request = request.header(name.as_str(), v.as_str());
        }
    }
    if let Some(bytes) = body {
        request = request.body(bytes);
    }

    match request.send() {
        Ok(resp) => {
            let status = resp.status();
            if verbose {
                eprintln!(
                    "< HTTP/1.1 {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("")
                );
                for (name, value) in resp.headers() {
                    eprintln!("< {}: {}", name, value.to_str().unwrap_or(""));
                }
                eprintln!("<");
            }
            let body = resp.bytes().unwrap_or_default();
            // `-o` is HONORED, not consumed-and-dropped: the body goes to the file
            // and never to stdout, so a `-w` line is the only thing stdout carries.
            if let Some(path) = &output {
                if let Err(e) = std::fs::write(path, &body) {
                    eprintln!("curl: cannot write {path}: {e}");
                    return 23; // CURLE_WRITE_ERROR
                }
            } else {
                let _ = std::io::stdout().write_all(&body);
            }
            if let Some(fmt) = &write_out {
                // Validated at parse time, so a render error here is unreachable;
                // surface it rather than papering over it if that ever changes.
                match render_write_out(fmt, status.as_u16(), body.len()) {
                    Ok(rendered) => {
                        let _ = std::io::stdout().write_all(rendered.as_bytes());
                    }
                    Err(msg) => {
                        eprintln!("curl: {msg}");
                        return 2;
                    }
                }
            }
            let _ = std::io::stdout().flush();
            // curl exits 0 once a response is received (no `--fail`), regardless
            // of HTTP status — the blocked-egress test asserts on the 403 in the
            // verbose stderr, not the exit code.
            0
        }
        Err(e) => {
            // A blocked HTTPS domain makes the proxy refuse the CONNECT with a
            // non-2xx (403 + body); reqwest collapses that to an opaque "tunnel
            // error" without exposing the response. Real curl prints the proxy's
            // refusal (status to stderr, body to stdout), which the egress test
            // asserts on, so on an https-via-proxy failure we redo the CONNECT
            // manually to surface it.
            if url.starts_with("https://")
                && let Some(proxy) =
                    proxy_from_env(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"])
                && let Some((host, port)) = url_host_port(&url, 443)
                && probe_connect(&proxy, &host, port, max_time, verbose)
            {
                // The CONNECT tunnel established (2xx), so the proxy did NOT block
                // the domain — reqwest's error was therefore post-CONNECT, i.e. a
                // TLS-verify failure. Do not collapse that to exit 0 (gt-curl-tls):
                // real curl exits 60 (CURLE_PEER_FAILED_VERIFICATION) on a cert
                // verify failure; only -k/--insecure makes it a success.
                return tunnel_established_exit(insecure);
            }
            // Print the full error source chain — reqwest's top-level Display is
            // just "error sending request for url (...)".
            eprint!("curl: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                eprint!(": {s}");
                src = s.source();
            }
            eprintln!();
            // Transport failure → curl-style non-zero (CURLE_COULDNT_CONNECT).
            7
        }
    }
}

/// Parses `scheme://host[:port][/...]` into `(host, port)`.
fn url_host_port(url: &str, default_port: u16) -> Option<(String, u16)> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let mut parts = authority.rsplitn(2, ':');
    let first = parts.next()?;
    match parts.next() {
        Some(host) => Some((host.to_string(), first.parse().unwrap_or(default_port))),
        None => Some((first.to_string(), default_port)),
    }
}

/// Extracts the numeric status from an HTTP `CONNECT` response's status line
/// (`HTTP/1.1 <code> <reason>`). Returns `None` if the line is missing or the
/// code is not a parseable number.
fn parse_status_code(head: &str) -> Option<u16> {
    head.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// Whether a proxy `CONNECT` response head indicates the tunnel was established —
/// true only for a 2xx status. A non-2xx (e.g. a blocked domain's 403) is a real
/// failure — real curl exits non-zero — so this returns false and the caller must
/// not collapse it to exit 0 (H-GUEST-1).
fn connect_succeeded(head: &str) -> bool {
    parse_status_code(head).is_some_and(|code| (200..300).contains(&code))
}

/// The curl exit code when an https-via-proxy request failed but the manual
/// CONNECT re-probe found the tunnel *established* (2xx). The proxy did not block
/// the domain, so reqwest's error was post-CONNECT — a TLS cert-verify failure.
/// Real curl exits 60 (`CURLE_PEER_FAILED_VERIFICATION`) on a verify failure; only
/// `-k`/`--insecure` turns that into success (exit 0). Never collapse a verify
/// failure to 0 (gt-curl-tls, companion to H-GUEST-1).
fn tunnel_established_exit(insecure: bool) -> i32 {
    if insecure { 0 } else { 60 }
}

/// Performs a raw HTTP `CONNECT` to `proxy` for `host:port`, prints the proxy's
/// response — status line + headers to stderr (verbose), body to stdout — the way
/// curl does, and returns whether the tunnel was **established** (a 2xx status).
///
/// A non-2xx refusal (e.g. a blocked domain's 403) is still printed so the egress
/// test can observe it, but returns `false` so the caller surfaces the failure as
/// a non-zero exit instead of collapsing every https-via-proxy failure to exit 0
/// (H-GUEST-1: the banned any-error-to-success probe).
fn probe_connect(proxy: &str, host: &str, port: u16, max_time: Option<u64>, verbose: bool) -> bool {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let Some((phost, pport)) = url_host_port(proxy, 8080) else {
        return false;
    };
    // Bound the TCP connect by --max-time too (gt-maxtime): a blocking
    // `TcpStream::connect` uses the OS default (~2 min) and ignores --max-time, so a
    // firewalled proxy host would hang the fallback long past the deadline. Resolve
    // then `connect_timeout` with the same deadline used for the read/write timeouts.
    let timeout = Duration::from_secs(max_time.unwrap_or(10));
    let Some(paddr) = (phost.as_str(), pport)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    else {
        return false;
    };
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&paddr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                if buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        return false;
    }
    // Split status line + headers from the body on the first blank line.
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body): (&[u8], &[u8]) = match split {
        Some(i) => (
            buf.get(..i).unwrap_or_default(),
            buf.get(i + 4..).unwrap_or_default(),
        ),
        None => (&buf[..], &[]),
    };
    let head_str = String::from_utf8_lossy(head);
    if verbose {
        for line in head_str.lines() {
            eprintln!("< {line}");
        }
        eprintln!("<");
    } else if let Some(status_line) = head_str.lines().next() {
        // Ensure the status (e.g. "403") is observable even without -v.
        eprintln!("< {status_line}");
    }
    let _ = std::io::stdout().write_all(body);
    let _ = std::io::stdout().flush();
    // Success is a 2xx tunnel establishment ONLY. Returning `true` for any
    // response (the pre-fix behaviour) let a blocked domain's 403, a TLS failure,
    // or a mid-body RST collapse to exit 0 (H-GUEST-1).
    connect_succeeded(&head_str)
}

fn proxy_from_env(keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Ok(v) = std::env::var(k)
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    None
}

fn parse_resolve(spec: &str) -> Option<(String, u16, std::net::IpAddr)> {
    // Format: HOST:PORT:ADDR (tests use IPv4, so PORT and ADDR are unambiguous).
    let mut parts = spec.splitn(3, ':');
    let host = parts.next()?.to_string();
    let port: u16 = parts.next()?.parse().ok()?;
    let ip: std::net::IpAddr = parts.next()?.parse().ok()?;
    Some((host, port, ip))
}

#[cfg(test)]
mod tests {
    //! M-GUEST-3: guest-tools had ZERO unit tests, leaving the pure parsers and
    //! the duplicated `ifreq` layout unguarded. Each test below reddens on a
    //! specific inverse (see comments).
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    // v33 delta 5 (§3.5): `mini-init` is an `init=` target, so law F1 applies to its argv exactly
    // as to a config field — an accepted-but-ignored argument on PID 1 is a guest that boots and
    // then behaves as if the caller had said nothing. RED on re-registering it as
    // `|_args| mini_init_forever()`, the accept-then-discard shape `kvm-ok` was already fixed for.
    #[test]
    fn mini_init_rejects_every_argument() {
        assert!(parse_mini_init_args(&argv(&[])).is_ok());
        for bad in [
            vec!["--restart"],
            vec!["/usr/sbin/vmcell-steward"],
            vec!["-v", "2"],
        ] {
            let err = parse_mini_init_args(&argv(&bad))
                .expect_err("mini-init honors no argument, so it must reject every one");
            assert!(
                err.contains(&format!("{:?}", bad[0])),
                "the rejection must NAME the offending argument: {err}"
            );
        }
    }

    // The rapid-failure cap, pure. It is what keeps the restart policy honest: `Restart=always` is
    // what makes the service SIGTERM leg satisfiable at all, and without a cap a steward that
    // cannot start spins forever — a guest that spins silently looks exactly like a guest that
    // works, to a host waiting out a connect budget.
    //
    // RED on a cap that never trips (always `Some`), and on one that counts a long-lived steward's
    // ordinary exit as a strike (which would power off a healthy cell after five restarts).
    #[test]
    fn the_rapid_failure_cap_trips_only_on_a_crash_loop() {
        // Successive fast failures accumulate, then trip.
        let mut count = 0;
        for expected in 1..MINI_INIT_MAX_RAPID_FAILURES {
            count = mini_init_next_failure_count(Duration::from_millis(10), count)
                .expect("below the cap, a fast failure must be counted and tolerated");
            assert_eq!(count, expected);
        }
        assert_eq!(
            mini_init_next_failure_count(Duration::from_millis(10), count),
            None,
            "the {MINI_INIT_MAX_RAPID_FAILURES}th rapid failure must trip the cap, not be tolerated"
        );

        // A steward that STAYED UP resets the counter — its exit is a restart, not a crash-loop,
        // and it must not inherit an old strike.
        assert_eq!(
            mini_init_next_failure_count(
                MINI_INIT_FAILURE_WINDOW,
                MINI_INIT_MAX_RAPID_FAILURES - 1
            ),
            Some(0),
            "an exit after a full window is a restart; the counter resets"
        );
        assert_eq!(
            mini_init_next_failure_count(MINI_INIT_FAILURE_WINDOW * 100, 0),
            Some(0)
        );
    }

    // The steward path `mini-init` starts must be the one the rootfs injection manifest actually
    // writes. These are two crates with no shared constant, so this is the seam where a manifest
    // move would otherwise surface as a guest that boots and never comes up.
    #[test]
    fn mini_init_starts_the_injected_steward_path() {
        assert_eq!(MINI_INIT_STEWARD_PATH, "/usr/sbin/vmcell-steward");
    }

    // §3.2 / §6.5: the echo-server's two endpoint arms, parsed. Both are shipped
    // now, not just the vsock one the raw-dial gate exercises — the segment gates
    // consume `--tcp`, and an arm that exists only in the usage string is a trap.
    // RED on a parser that ignores the value, or that accepts one flag's spelling
    // for the other.
    #[test]
    fn parse_echo_args_accepts_both_endpoint_arms() {
        assert_eq!(
            parse_echo_args(&argv(&["--vsock", "7000"])),
            Ok(EchoBind::Vsock(7000))
        );
        assert_eq!(
            parse_echo_args(&argv(&["--tcp", "0.0.0.0:7100"])),
            Ok(EchoBind::Tcp("0.0.0.0:7100".parse().expect("addr")))
        );
    }

    // Fail loud: every accepted input is honored or REJECTED naming the offender.
    // RED on the accept-then-ignore shapes — an unknown flag skipped silently, a
    // missing value defaulted, a malformed endpoint deferred to bind() time, or a
    // second endpoint quietly overwriting the first.
    #[test]
    fn parse_echo_args_rejects_every_malformed_invocation() {
        for (args, needle) in [
            (vec!["--vsock"], "needs a <port>"),
            (vec!["--tcp"], "needs an <addr>"),
            (vec!["--vsock", "not-a-port"], "invalid --vsock port"),
            (vec!["--tcp", "7100"], "invalid --tcp endpoint"),
            (vec!["--vsock", "0"], "VMADDR_PORT_ANY"),
            (vec!["--udp", "7000"], "unknown echo-server argument"),
            (vec![], "needs one of"),
            (
                vec!["--vsock", "7000", "--tcp", "0.0.0.0:7100"],
                "exactly one endpoint",
            ),
        ] {
            let err = parse_echo_args(&argv(&args))
                .expect_err(&format!("{args:?} must be rejected, not accepted"));
            assert!(
                err.contains(needle),
                "{args:?} must be rejected naming the cause ({needle:?}), got {err:?}"
            );
        }
    }

    // The multicall roster is ONE list, and it is `vmcell_protocol::GUEST_TOOLS_APPLETS` —
    // the same const `vmcell`'s `rootfs_injection_manifest` derives its
    // `/vmcell-tools/<name>` symlinks from. No name is re-typed here: a third literal is
    // exactly what let the two real ones drift (docs/81 m22), so this walks the roster.
    //
    // The roster↔dispatch agreement itself is a COMPILE error (the `const _: () = assert!`
    // beside `APPLETS`), not this test — adding an applet to one side only does not reach a
    // test run at all. What this test still catches, and the const cannot: a broken
    // `applet`/`is_known` lookup (both negative controls below fail if it degenerates to
    // "always Some"), and a roster entry that the dispatch table cannot actually resolve
    // through the public lookup path.
    #[test]
    fn applet_roster_is_one_list_and_carries_echo_server() {
        assert!(
            !vmcell_protocol::GUEST_TOOLS_APPLETS.is_empty(),
            "an empty roster would make every assertion below vacuous"
        );
        for name in vmcell_protocol::GUEST_TOOLS_APPLETS {
            assert!(is_known(name), "{name} must be dispatchable by argv[0]");
            assert!(
                applet(name).is_some(),
                "{name} must resolve to a run function"
            );
        }
        // Negative controls: the multicall binary's own `argv[0]` must fall through to the
        // `<cmd>`-argument form, and an unknown name must not dispatch.
        assert!(!is_known("vmcell-guest-tools"));
        assert!(applet("nope").is_none());
    }

    // The echo data plane, over a real socket pair: every byte comes back, including
    // a payload larger than the 8 KiB read buffer (so a single-read echo that drops
    // the tail goes red), and the server half-closes so the peer sees EOF.
    #[test]
    fn echo_connection_returns_every_byte_then_half_closes() {
        use std::io::{Read as _, Write as _};

        let (client, server) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let worker = std::thread::spawn(move || echo_connection(server));

        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let mut writer = client.try_clone().expect("clone");
        let sent = payload.clone();
        let feeder = std::thread::spawn(move || {
            writer.write_all(&sent).expect("write payload");
            // Half-close so the echo loop sees EOF and stops.
            writer
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown");
        });

        let mut back = Vec::new();
        let mut reader = client;
        reader.read_to_end(&mut back).expect("read echo");

        feeder.join().expect("feeder");
        worker.join().expect("worker").expect("echo_connection");
        assert_eq!(
            back, payload,
            "every byte must be echoed back, including past the read buffer"
        );
        assert_eq!(back.len(), 40_000);
    }

    // The half-close itself, pinned where it is actually observable.
    //
    // It is NOT observable in the test above, and was measured not to be: dropping
    // `echo_connection`'s `shutdown_write` leaves that test green, because returning
    // drops the only handle and the full close delivers the same EOF. (The live
    // matrix leg cannot see it either, for the same reason — that mutation stayed
    // green on all four backends.) So here the connection is deliberately kept open
    // by a second handle, which is the only arrangement where "half-closed" and
    // "closed" differ.
    //
    // RED on a `echo_connection` that drops the `shutdown_write`: the follow-up read
    // then blocks on a peer that is still open, and the read timeout below turns
    // that hang into a named failure instead of a stuck test.
    #[test]
    fn echo_connection_half_closes_while_the_connection_stays_open() {
        use std::io::{Read as _, Write as _};

        let (client, server) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        // The worker gets a clone; `keepalive` holds the server end of the
        // connection open after `echo_connection` returns, so the only thing that
        // can end the client's read is the explicit half-close.
        let keepalive = server.try_clone().expect("clone server");
        let worker = std::thread::spawn(move || echo_connection(server));

        let mut stream = client;
        stream.write_all(b"ping").expect("write");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("client half-close");

        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).expect("read echo");
        assert_eq!(&echo, b"ping");

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut tail = [0u8; 1];
        let n = stream.read(&mut tail).expect(
            "the server's half-close must end the read; a blocked read here \
                     means echo_connection never shut its write side down",
        );
        assert_eq!(n, 0, "EOF, not data: {tail:?}");

        drop(keepalive);
        worker.join().expect("worker").expect("echo_connection");
    }

    // A permanently-bad listener fd must not become a busy loop that floods the
    // persisted serial-log artifact. Both properties of the ONE pacing law both
    // accept loops use are pinned here, because neither is observable from a test
    // that only drives a *healthy* listener.
    // RED on the pre-fix shape (`continue` with no sleep and an unconditional
    // `eprintln!`), which is `(ZERO, true)` for every `consecutive`: the first
    // assert catches the missing pause, the third the unbounded logging.
    #[test]
    fn accept_error_pacing_bounds_both_the_retry_rate_and_the_log() {
        // Every failure pauses — no arm returns a zero pause, which is the busy loop.
        for n in 1..500u32 {
            let (pause, _) = accept_error_pacing(n);
            assert!(
                pause >= Duration::from_millis(50),
                "failure #{n} must pause at least the floor, got {pause:?}"
            );
            assert!(
                pause <= Duration::from_millis(1600),
                "the pause must stay bounded so a recovered listener is picked up \
                 promptly; failure #{n} asked for {pause:?}"
            );
        }
        // It grows, then caps: the whole point of counting consecutive failures.
        assert_eq!(accept_error_pacing(1).0, Duration::from_millis(50));
        assert_eq!(accept_error_pacing(2).0, Duration::from_millis(100));
        assert_eq!(accept_error_pacing(6).0, Duration::from_millis(1600));
        assert_eq!(
            accept_error_pacing(1_000_000).0,
            Duration::from_millis(1600)
        );

        // The log is bounded: a broken listener writes a few lines a minute, not one
        // per iteration. At the 1.6 s cap, 500 failures span >13 minutes.
        let logged = (1..=500u32).filter(|n| accept_error_pacing(*n).1).count();
        assert!(
            (5..=15).contains(&logged),
            "500 consecutive failures must log a handful of lines, not flood the \
             serial-log artifact — logged {logged}"
        );
        // …but the first failures ARE logged: silence would hide a broken listener.
        assert!(
            accept_error_pacing(1).1 && accept_error_pacing(2).1,
            "the first failures must be reported"
        );
    }

    #[test]
    fn parse_mac_accepts_six_hex_octets() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        // Leading/trailing whitespace is trimmed before splitting.
        assert_eq!(
            parse_mac("  02:00:00:00:00:05\n"),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x05])
        );
    }

    #[test]
    fn parse_mac_rejects_malformed() {
        // Too few octets (5) — must NOT accept a short MAC.
        assert_eq!(parse_mac("ff:01:02:03:04"), None);
        // Too many octets (7) — the `n >= 6` guard must reject it.
        assert_eq!(parse_mac("00:01:02:03:04:05:06"), None);
        // A single token is not a MAC (RED on a bounds-free parser that accepts it).
        assert_eq!(parse_mac("ff"), None);
        // Non-hex octet.
        assert_eq!(parse_mac("zz:00:00:00:00:00"), None);
        assert_eq!(parse_mac(""), None);
    }

    /// `ip link set` argv as the applet receives it (everything after `set`).
    fn link_set(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| (*s).to_string()).collect()
    }

    // m5 — the `ip` shim REJECTS any `ip link set` spelling it cannot honor, the
    // same law the sibling `curl` applet enforces
    // (`curl-shim-silently-ignores-unknown-flags`, docs/78). The pre-fix catch-all
    // (`other => if dev.is_none() { dev = Some(other) }`) accepted every argv below
    // and exited 0 with nothing performed — an accepted-but-ignored flag is the
    // `-k`-on-a-TLS-test hazard one step removed, one applet over.
    //
    // RED on that catch-all: each of these parses Ok and the request vanishes.
    #[test]
    fn ip_link_set_rejects_argv_it_cannot_honor() {
        for argv in [
            // The three spellings the review named…
            vec!["eth0", "mtu", "9000"],
            vec!["eth0", "master", "br0"],
            vec!["eth0", "promisc", "on"],
            // …the same, past an explicit `dev`.
            vec!["dev", "eth0", "mtu", "9000"],
            // A second bare token is not a second device.
            vec!["eth0", "eth1"],
        ] {
            let err = parse_ip_link_set(&link_set(&argv))
                .err()
                .unwrap_or_else(|| panic!("{argv:?} must be rejected, not silently ignored"));
            assert!(
                err.contains("unsupported argument"),
                "{argv:?} must name the offender: {err}"
            );
        }
    }

    // A value-taking keyword at the end of argv is a named rejection, never a
    // silently-dropped option: bare `address` used to yield `mac: None`, which the
    // consumer skipped — the MAC rotation simply did not happen and exit 0 said it
    // had. RED on `mac = it.next().cloned()`.
    #[test]
    fn ip_link_set_rejects_a_keyword_with_no_value() {
        for (argv, want) in [
            (vec!["eth0", "address"], "address needs a value"),
            (vec!["eth0", "addr"], "address needs a value"),
            (vec!["dev"], "dev needs a value"),
        ] {
            let err = parse_ip_link_set(&link_set(&argv))
                .err()
                .unwrap_or_else(|| panic!("{argv:?} must be rejected"));
            assert_eq!(err, want, "{argv:?}");
        }
        // A malformed MAC is rejected at parse time, before any ioctl.
        let err = parse_ip_link_set(&link_set(&["eth0", "address", "zz:00"]))
            .err()
            .expect("a malformed MAC must be rejected");
        assert!(err.contains("invalid MAC address"), "{err}");
        // …and so is an argv naming no device at all.
        assert_eq!(
            parse_ip_link_set(&[]).err().as_deref(),
            Some("no device specified")
        );
    }

    // The positive control: every spelling the shim really does honor still parses,
    // with the value it will act on. Without this, "reject everything" would pass
    // the rejection tests above.
    #[test]
    fn ip_link_set_accepts_the_forms_it_implements() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let bare_dev = parse_ip_link_set(&link_set(&["eth0", "address", "aa:bb:cc:dd:ee:ff"]))
            .expect("bare-dev + address is implemented");
        assert_eq!(bare_dev.dev, "eth0");
        assert_eq!(bare_dev.mac, Some(mac));
        assert_eq!(bare_dev.up, None, "no up/down was asked for");

        let explicit = parse_ip_link_set(&link_set(&[
            "dev",
            "eth0",
            "addr",
            "aa:bb:cc:dd:ee:ff",
            "up",
        ]))
        .expect("`dev <name>` + `addr` + `up` is implemented");
        assert_eq!(explicit.dev, "eth0");
        assert_eq!(explicit.mac, Some(mac));
        assert_eq!(explicit.up, Some(true));

        let down = parse_ip_link_set(&link_set(&["eth0", "down"])).expect("down is implemented");
        assert_eq!(down.dev, "eth0");
        assert_eq!(down.mac, None);
        assert_eq!(down.up, Some(false));
    }

    // The applet itself consults the parser: a rejected form exits non-zero instead
    // of the pre-fix 0. (Only the reject path is driven here — the accept path would
    // reconfigure the *host's* interfaces.)
    #[test]
    fn run_ip_link_exits_nonzero_on_an_unhonorable_form() {
        let argv = link_set(&["eth0", "mtu", "9000"]);
        assert_eq!(
            run_ip_link_set(&argv),
            1,
            "an `ip link set` form the shim cannot honor must fail loudly"
        );
    }

    // The applet's own dispatch reaches the same rejection: `run_ip` must route
    // `ip link set …` to the validating path, not to a listing that exits 0. Red if
    // `IpCommand::LinkSet` is ever folded into `NoOpWrite`.
    #[test]
    fn run_ip_routes_an_unhonorable_link_set_to_the_rejecting_path() {
        let argv: Vec<String> = ["link", "set", "eth0", "mtu", "9000"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            run_ip(&argv),
            1,
            "`ip link set` must reach parse_ip_link_set through run_ip's dispatch"
        );
    }

    #[test]
    fn url_host_port_parses_scheme_host_port_path() {
        assert_eq!(
            url_host_port("http://host:123/path", 443),
            Some(("host".to_string(), 123))
        );
        // No explicit port → the default.
        assert_eq!(
            url_host_port("https://example.com/x", 443),
            Some(("example.com".to_string(), 443))
        );
        // No scheme, explicit port.
        assert_eq!(
            url_host_port("proxy.local:8080", 8080),
            Some(("proxy.local".to_string(), 8080))
        );
        // A non-numeric port falls back to the default rather than failing.
        assert_eq!(
            url_host_port("http://host:notaport/p", 443),
            Some(("host".to_string(), 443))
        );
    }

    #[test]
    fn parse_resolve_parses_host_port_addr() {
        let (host, port, ip) = parse_resolve("blocked.com:443:1.2.3.4").expect("valid resolve");
        assert_eq!(host, "blocked.com");
        assert_eq!(port, 443);
        assert_eq!(ip, "1.2.3.4".parse::<std::net::IpAddr>().unwrap());
        // Malformed: missing the address field, or a bad port/addr.
        assert!(parse_resolve("blocked.com:443").is_none());
        assert!(parse_resolve("blocked.com:notaport:1.2.3.4").is_none());
        assert!(parse_resolve("blocked.com:443:not.an.ip").is_none());
    }

    // `curl-shim-silently-ignores-unknown-flags` (docs/78 §6): the shim must
    // HONOR-OR-REJECT every accepted input, never silently drop one. Rejection is
    // the faithful emulation — a real-curl feature this shim lacks has to fail
    // loudly, or a test reaching for it quietly loses the property it asserts
    // (the `-k`-on-a-TLS-test hazard, one step removed). RED on the pre-fix
    // parser, whose `other if other.starts_with('-') => { /* ignore */ }` arm
    // swallowed every one of these.
    #[test]
    fn parse_curl_args_rejects_every_input_it_cannot_honor() {
        for (args, needle) in [
            (vec!["--fail", "http://h/"], "unknown option"),
            (vec!["--cacert", "/x", "http://h/"], "unknown option"),
            (vec!["--max-time", "soon", "http://h/"], "--max-time"),
            (vec!["--max-time"], "needs a value"),
            (vec!["--resolve", "garbage", "http://h/"], "--resolve"),
            (vec!["-H", "no-colon", "http://h/"], "-H"),
            (vec!["-o"], "needs a value"),
            (vec!["-6", "http://h/"], "IPv4-only"),
            (vec!["--compressed", "http://h/"], "decompression"),
            (vec!["-d", "x=1", "http://h/"], "--data-binary"),
            (vec!["-w", "%{elapsed}", "http://h/"], "%{elapsed}"),
            (vec!["http://a/", "http://b/"], "more than one URL"),
            (vec!["-s"], "no URL"),
        ] {
            let err = parse_curl_args(&argv(&args))
                .err()
                .unwrap_or_else(|| panic!("{args:?} must be rejected, not silently accepted"));
            assert!(
                err.contains(needle),
                "{args:?} must be rejected naming the cause ({needle:?}), got {err:?}"
            );
        }
    }

    // The positive control for the rejection matrix above: every flag the shim
    // DOES implement parses into the field that makes it act. A blanket "reject
    // everything" would pass the matrix and fail here.
    #[test]
    fn parse_curl_args_honors_the_flags_it_accepts() {
        let dir = std::env::temp_dir().join(format!("vmcell-curl-shim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let body_path = dir.join("body.bin");
        std::fs::write(&body_path, b"0123456789").expect("write body");

        let parsed = parse_curl_args(&argv(&[
            "-k",
            "-v",
            "-4",
            "-sS",
            "-L",
            "--max-time",
            "20",
            "--resolve",
            "example.com:443:1.2.3.4",
            "-H",
            "X-Trace: on",
            "-H",
            "Expect:",
            "-A",
            "vmcell/1",
            "-X",
            "PUT",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--data-binary",
            &format!("@{}", body_path.display()),
            "http://example.com/upload",
        ]))
        .expect("the accepted subset must parse");

        assert!(parsed.insecure && parsed.verbose && parsed.follow);
        assert_eq!(parsed.max_time, Some(20));
        assert_eq!(parsed.resolve.len(), 1);
        assert_eq!(
            parsed.headers,
            vec![
                ("X-Trace".to_string(), Some("on".to_string())),
                // `Expect:` is the REMOVE form, so it must not become an
                // empty-valued header (a different request on the wire).
                ("Expect".to_string(), None),
                ("user-agent".to_string(), Some("vmcell/1".to_string())),
            ]
        );
        assert_eq!(parsed.method.as_deref(), Some("PUT"));
        assert_eq!(parsed.output.as_deref(), Some("/dev/null"));
        assert_eq!(parsed.write_out.as_deref(), Some("%{http_code}"));
        // `@file` reads the file's exact bytes; `--data-raw` never does.
        assert_eq!(parsed.body.as_deref(), Some(&b"0123456789"[..]));
        assert_eq!(parsed.url, "http://example.com/upload");
        assert_eq!(
            parse_curl_args(&argv(&["--data-raw", "@literal", "http://h/"]))
                .expect("raw parses")
                .body
                .as_deref(),
            Some(&b"@literal"[..]),
            "--data-raw must never open a file"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    // The `-w` renderer is the half the M13 upload gate reads (`%{http_code}`
    // proves the sink replied). RED on a renderer that emits an unknown variable
    // as empty text — the silent-loss shape the whole fix targets.
    #[test]
    fn render_write_out_interpolates_and_rejects_unknown_variables() {
        assert_eq!(render_write_out("%{http_code}", 200, 7), Ok("200".into()));
        assert_eq!(
            render_write_out("code=%{http_code} n=%{size_download}\\n", 404, 12),
            Ok("code=404 n=12\n".into())
        );
        assert_eq!(render_write_out("100%%", 200, 0), Ok("100%".into()));
        assert!(render_write_out("%{time_total}", 200, 0).is_err());
        assert!(render_write_out("50% off", 200, 0).is_err());
        assert!(render_write_out("trailing\\", 200, 0).is_err());
    }

    #[test]
    fn is_write_verb_matches_only_write_verbs() {
        for v in ["add", "del", "delete", "change", "replace", "flush"] {
            let owned = v.to_string();
            assert!(is_write_verb(Some(&owned)), "{v} must be a write verb");
        }
        for v in ["up", "down", "show", "list"] {
            let owned = v.to_string();
            assert!(!is_write_verb(Some(&owned)), "{v} must NOT be a write verb");
        }
        assert!(!is_write_verb(None), "a read form (no verb) is not a write");
    }

    // `ifreq-stack-duplicated-guest-tools` (docs/78 §6) — the divergence guard for
    // the recorded duplication of `vmcell_steward::netif`'s ABI stack.
    //
    // Total size alone is NOT enough: it stays green while the union moves, while
    // the name array shrinks and the union grows to compensate, or while the fields
    // swap order — every one of which is the C-GUEST-1 shape (an ifreq whose layout
    // disagrees with what `copy_{from,to}_user` reads/writes). So every field fact
    // is pinned against `libc`'s own ABI types, which is what BOTH copies are
    // anchored to; a copy that drifts from the ABI reddens in its own crate.
    //
    // RED on: reordering `name`/`ifru` (both offset asserts), shrinking either field
    // (its size assert plus the total), spelling the name array `[c_char; 14]`
    // instead of `IFNAMSIZ`, or moving a `SOCKADDR_*`/`SIN_ADDR_OFFSET` constant.
    #[test]
    fn ifreq_is_pinned_field_by_field_to_the_kernel_abi() {
        use std::mem::{offset_of, size_of, size_of_val};

        let probe = IfReq::new("eth0").expect("ifreq");
        assert_eq!(
            size_of::<IfReq>(),
            size_of::<libc::ifreq>(),
            "IfReq must match the kernel `struct ifreq` size (40 bytes on x86-64)"
        );
        assert_eq!(
            offset_of!(IfReq, name),
            offset_of!(libc::ifreq, ifr_name),
            "ifr_name must start where the kernel's does"
        );
        assert_eq!(
            offset_of!(IfReq, ifru),
            offset_of!(libc::ifreq, ifr_ifru),
            "the ifr_ifru union must start where the kernel's does"
        );
        assert_eq!(
            size_of_val(&probe.name),
            offset_of!(libc::ifreq, ifr_ifru),
            "the name array must exactly fill the space before the union (IFNAMSIZ)"
        );
        assert_eq!(
            size_of_val(&probe.ifru),
            size_of::<libc::ifreq>() - offset_of!(libc::ifreq, ifr_ifru),
            "the ifru byte array must exactly cover the kernel's union"
        );
        assert!(
            size_of::<libc::sockaddr>() <= size_of_val(&probe.ifru),
            "the union must hold a whole sockaddr — the hwaddr/addr arms write one"
        );

        // The union sub-offsets this file writes/reads through, pinned to the real
        // sockaddr layouts rather than restated as literals.
        assert_eq!(
            SOCKADDR_FAMILY_OFFSET, 0,
            "sa_family is the first field of a sockaddr"
        );
        assert_eq!(
            SOCKADDR_DATA_OFFSET,
            offset_of!(libc::sockaddr, sa_data),
            "the MAC goes at the sockaddr's sa_data offset"
        );
        assert_eq!(
            SIN_ADDR_OFFSET,
            offset_of!(libc::sockaddr_in, sin_addr),
            "SIOCGIFADDR's address sits at sockaddr_in::sin_addr"
        );
    }

    // The five ioctl request numbers this file issues, plus the two ABI constants,
    // pinned to their kernel values — which are ALSO the literals the steward's
    // `netif` copy hardcodes (0x8913/0x8914/0x8924 there). Production code takes
    // them from `libc` (never a second local spelling of a kernel ABI value, the
    // rule this file already applies to `VMADDR_CID_ANY`), so this test is what
    // keeps the two copies' request numbers checkable against one another.
    // RED on any renumbering, and on an `IFF_UP` that does not survive the narrowing
    // to the `ifr_flags` `short`.
    #[test]
    fn ioctl_requests_match_the_kernel_abi_values_netif_hardcodes() {
        assert_eq!(libc::SIOCGIFFLAGS, 0x8913);
        assert_eq!(libc::SIOCSIFFLAGS, 0x8914);
        assert_eq!(libc::SIOCGIFADDR, 0x8915);
        assert_eq!(libc::SIOCGIFNETMASK, 0x891b);
        assert_eq!(libc::SIOCSIFHWADDR, 0x8924);
        assert_eq!(libc::ARPHRD_ETHER, 1);
        assert_eq!(IFF_UP, 0x1);
        assert_eq!(
            i32::from(IFF_UP),
            libc::IFF_UP,
            "IFF_UP must survive the narrowing to the ifr_flags short"
        );
    }

    // Pins the `ifr_hwaddr` byte layout SIOCSIFHWADDR consumes (parallel to
    // netif.rs). RED on a wrong hwaddr offset (MAC at 0) or a byte-swapped family.
    #[test]
    fn hwaddr_ifreq_layout() {
        let mac = [0x02, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let ifr = hwaddr_ifreq("eth0", mac).expect("ifreq");
        assert_eq!(
            &ifr.name[..4],
            &[
                b'e' as libc::c_char,
                b't' as libc::c_char,
                b'h' as libc::c_char,
                b'0' as libc::c_char
            ],
            "ifr_name must be the device"
        );
        assert_eq!(ifr.name[4], 0, "ifr_name must be NUL-terminated");
        assert_eq!(
            &ifr.ifru[0..2],
            &[0x01, 0x00],
            "sa_family must be ARPHRD_ETHER, little-endian"
        );
        assert_eq!(
            u16::from_ne_bytes([ifr.ifru[0], ifr.ifru[1]]),
            libc::ARPHRD_ETHER,
            "sa_family must decode to ARPHRD_ETHER"
        );
        assert_eq!(
            &ifr.ifru[2..8],
            &mac,
            "MAC must be at the hwaddr data offset"
        );
        // The rest of the union must stay zero: SIOCSIFHWADDR reads a whole
        // sockaddr, so a stray byte past the MAC is submitted to the kernel.
        assert!(
            ifr.ifru[8..].iter().all(|b| *b == 0),
            "no bytes beyond the MAC may be set"
        );
    }

    // Pins the `sockaddr_in` offset SIOCGIFADDR/SIOCGIFNETMASK fill: sin_family (2) + sin_port
    // (2) then the 4 address bytes at offset 4. A wrong offset would read port/family bytes as
    // the address and print a garbage `inet` line. Inverse: shift the slice and this reddens.
    #[test]
    fn ipv4_from_ifru_reads_sin_addr_at_offset_4() {
        let mut ifru = [0u8; 24];
        ifru[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes()); // sin_family
        ifru[2..4].copy_from_slice(&0u16.to_ne_bytes()); // sin_port
        ifru[4..8].copy_from_slice(&[10, 200, 23, 2]); // sin_addr
        assert_eq!(ipv4_from_ifru(&ifru), [10, 200, 23, 2]);
    }

    // A contiguous netmask maps to its CIDR prefix (the /30 the design's per-VM subnet uses).
    #[test]
    fn netmask_to_prefix_counts_bits() {
        assert_eq!(netmask_to_prefix([255, 255, 255, 252]), 30);
        assert_eq!(netmask_to_prefix([255, 255, 255, 255]), 32);
        assert_eq!(netmask_to_prefix([255, 255, 255, 0]), 24);
        assert_eq!(netmask_to_prefix([0, 0, 0, 0]), 0);
    }

    // A device name too long for IFNAMSIZ is rejected (not silently truncated),
    // matching netif.rs's IfReq::new — including the `InvalidInput` kind, which is
    // the error-type half of the divergence the duplication record names: both
    // copies now return `std::io::Result` with the same kind for the same input.
    #[test]
    fn ifreq_new_rejects_overlong_device() {
        let long = "x".repeat(libc::IFNAMSIZ);
        // `IfReq` is deliberately not `Debug` (it is a raw ABI buffer), so unwrap
        // the error arm by hand rather than via `expect_err`.
        let err = IfReq::new(&long)
            .err()
            .unwrap_or_else(|| panic!("an overlong device must be rejected"));
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "the rejection must carry netif's kind, not an opaque one"
        );
        assert!(
            err.to_string().contains(&long),
            "the rejection must name the offending device, got {err}"
        );
        // One under IFNAMSIZ is the longest accepted name (the NUL terminator).
        assert!(IfReq::new(&"x".repeat(libc::IFNAMSIZ - 1)).is_ok());
        assert!(IfReq::new("eth0").is_ok());
    }

    // H-GUEST-1: probe_connect treats ONLY a 2xx CONNECT as success. RED on the
    // pre-fix "any response ⇒ true": a blocked domain's 403 would be classified as
    // success and collapse to exit 0.
    #[test]
    fn connect_succeeded_only_on_2xx() {
        assert!(connect_succeeded("HTTP/1.1 200 Connection established\r\n"));
        assert!(connect_succeeded("HTTP/1.1 204 No Content"));
        assert!(!connect_succeeded(
            "HTTP/1.1 403 Forbidden\r\nProxy-Agent: x\r\n"
        ));
        assert!(!connect_succeeded("HTTP/1.1 502 Bad Gateway"));
        assert!(!connect_succeeded("garbage-with-no-code"));
        assert!(!connect_succeeded(""));
    }

    // gt-curl-tls: an https-via-proxy failure whose CONNECT tunnel established (2xx)
    // is a post-CONNECT TLS-verify failure. Without -k it must NOT collapse to exit 0
    // (real curl -> 60); -k/--insecure accepts it (exit 0). RED on the pre-fix
    // unconditional `return 0` at the fallback call site.
    #[test]
    fn tunnel_established_exit_60_without_insecure() {
        assert_eq!(
            tunnel_established_exit(false),
            60,
            "a post-CONNECT TLS-verify failure without -k must be curl exit 60, not 0"
        );
        assert_eq!(
            tunnel_established_exit(true),
            0,
            "-k/--insecure accepts the established tunnel (exit 0)"
        );
    }

    // gt-maxtime: --max-time must bound the fallback CONNECT's TCP connect. Point the
    // proxy at an unroutable SYN-black-hole (RFC 5737 TEST-NET-1) with max_time=1 and
    // assert the probe gives up promptly. RED on the pre-fix blocking
    // `TcpStream::connect`, which ignores max_time and hangs ~2 min on a dropped SYN.
    // CAVEAT: on hosts where 192.0.2.1 returns an immediate EHOSTUNREACH this becomes
    // non-discriminating (green-on-both, not a false red); on this KVM host it
    // black-holes the SYN, so the pre-fix connect hangs and this reddens.
    #[test]
    fn probe_connect_connect_is_bounded_by_max_time() {
        let start = std::time::Instant::now();
        let ok = probe_connect("http://192.0.2.1:9", "blocked.example", 443, Some(1), false);
        let elapsed = start.elapsed();
        assert!(!ok, "an unroutable proxy must not report a tunnel");
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "connect must be bounded by --max-time (~1s), not the OS default; took {elapsed:?}"
        );
    }

    #[test]
    fn parse_status_code_extracts_the_numeric_code() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/1.1 403 Forbidden"), Some(403));
        assert_eq!(
            parse_status_code("HTTP/1.0 500 Internal Server Error"),
            Some(500)
        );
        assert_eq!(parse_status_code("no-code-here"), None);
        assert_eq!(parse_status_code(""), None);
    }
}
