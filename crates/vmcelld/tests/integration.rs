//! Daemon integration tests (design v21 §D10).
//!
//! **The test binary itself runs under the blessed `vmcell-test-runner`** (nextest's target-runner,
//! wired by `just test-daemon`), so it holds the three caps in its effective/ambient set. It then
//! spawns `vmcelld` **directly** — the daemon inherits the ambient caps — which means the test owns the
//! daemon's process tree and is itself privileged enough to do advanced **setup** (plant an orphan
//! netns) and **inspection** (verify per-VM residue is gone after teardown). Each test seeds a temp
//! artifact store with the built kernel/rootfs and drives the daemon over HTTP, dogfooding
//! `vmcell-daemon-client`; the VM-booting ones start **real Cloud Hypervisor micro-VMs** and assert on
//! the data plane. (Manual poking, by contrast, launches `vmcelld` *through* the runner — `just
//! daemon` — since there is no privileged test process to inherit from; v21 §D2.)
//!
//! `#[ignore]` by default: they need KVM, the **blessed** runner (`just bless`), and built artifacts
//! (`target/vmcell-artifacts/{vmlinux,rootfs.erofs}`). Run them via `just test-daemon`, which wraps the
//! test binary with the runner and runs under a systemd-delegated cgroup scope so the `limits_enforced`
//! assertion sees enforcement. Without those preconditions the tests **fail loud** (a clear panic),
//! never a silent skip.

use std::io::Read as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use url::Url;
use vmcell_daemon_client::DaemonClient;
use vmcell_daemon_client::dto::{CreateVmRequest, ExecRequestDto, NetMode};

// ---- environment discovery ----

fn workspace_root() -> PathBuf {
    // <ws>/crates/vmcelld -> <ws>
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/vmcelld")
        .to_path_buf()
}

fn vmcelld_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vmcelld"))
}

/// The `vmcelld-ctl` binary (a sibling of `vmcelld` under `target/<profile>/`). `just test-daemon`
/// builds it; there is no `CARGO_BIN_EXE_vmcelld-ctl` in this (the `vmcelld`) crate's tests.
fn ctl_bin() -> PathBuf {
    vmcelld_bin()
        .parent()
        .expect("profile dir")
        .join("vmcelld-ctl")
}

/// Whether this **test process** holds the three privileged caps in its effective set. The suite runs
/// under the blessed runner (nextest target-runner, `just test-daemon`), which raises them into the
/// ambient set — so the test binary itself is privileged and can both do privileged *setup* (create an
/// orphan netns) and spawn `vmcelld` **directly** (the daemon inherits the ambient caps). Reads
/// `CapEff` from `/proc/self/status` (NET_ADMIN=12, SYS_ADMIN=21, DAC_OVERRIDE=1).
fn have_privileged_caps() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let Some(hex) = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:").map(str::trim))
    else {
        return false;
    };
    let Ok(mask) = u64::from_str_radix(hex, 16) else {
        return false;
    };
    [1u32, 12, 21].iter().all(|&b| (mask >> b) & 1 == 1)
}

fn artifacts_dir() -> PathBuf {
    std::env::var_os("VMCELL_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target/vmcell-artifacts"))
}

/// Resolves the `cloud-hypervisor` binary: `$VMCELL_CH_BIN`, else the first hit on `PATH`, else the
/// bare name (let `vmcelld` resolve it).
fn ch_bin() -> String {
    if let Some(v) = std::env::var_os("VMCELL_CH_BIN") {
        return v.to_string_lossy().into_owned();
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join("cloud-hypervisor");
            if cand.is_file() {
                return cand.to_string_lossy().into_owned();
            }
        }
    }
    "cloud-hypervisor".to_string()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Fails loud (with an actionable message) if the test process lacks the caps or the artifacts are
/// missing — the integration-suite "fail loud, never silent-skip" contract.
fn require_preconditions() {
    assert!(
        have_privileged_caps(),
        "this test binary lacks cap_net_admin/cap_sys_admin/cap_dac_override in its effective set. \
         Run via `just test-daemon`, which runs the suite under the blessed runner (nextest \
         target-runner) so the test binary — and the `vmcelld` it spawns — are privileged (v21 §D10)."
    );
    for a in ["vmlinux", "rootfs.erofs"] {
        let p = artifacts_dir().join(a);
        assert!(
            p.is_file(),
            "artifact {a} missing at {}; build it with `vmcell build` (see the validation runbook)",
            p.display()
        );
    }
}

// ---- delegation detection (for the limits assertion) ----

/// Whether the memory controller is delegated to where the per-VM cgroup will be created — i.e.
/// whether this process runs under a delegated scope (`just test-daemon`). Mirrors the orchestrator's
/// `/supervisor`-suffix stripping: the VM cgroup is created under the scope (a sibling of the
/// `supervisor/` leaf `with-delegated-scope.sh` moves us into), so the relevant `subtree_control` is
/// that base cgroup's.
fn delegation_available() -> bool {
    let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let Some(rel) = content
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_string))
    else {
        return false;
    };
    let base = rel.strip_suffix("/supervisor").unwrap_or(&rel);
    let subtree = PathBuf::from("/sys/fs/cgroup")
        .join(base.trim_start_matches('/'))
        .join("cgroup.subtree_control");
    std::fs::read_to_string(&subtree)
        .map(|s| s.split_whitespace().any(|c| c == "memory"))
        .unwrap_or(false)
}

// ---- the daemon harness ----

/// The daemon's auth mode for a test.
enum Auth {
    /// `--allow-unauthenticated` (loopback dev).
    Open,
    /// `--api-key-file` holding this key.
    Key(&'static str),
}

/// A spawned `vmcelld` process (a direct child of this privileged test) with its own temp store +
/// port. Killed on `Drop`.
struct Daemon {
    child: Child,
    _store: tempfile::TempDir,
    base: String,
    log_path: PathBuf,
}

impl Daemon {
    /// Spawns `vmcelld` as a direct child (inheriting this test's ambient caps) with the default
    /// resource prefix (`vmcell`) and waits for `/healthz`.
    async fn start(auth: Auth) -> Daemon {
        Self::start_with_prefix(auth, "vmcell").await
    }

    /// Like [`start`](Self::start) but with an explicit `--resource-prefix` (for the custom-prefix
    /// test).
    async fn start_with_prefix(auth: Auth, resource_prefix: &str) -> Daemon {
        require_preconditions();
        let store = tempfile::tempdir().expect("tempdir");
        // Symlink the artifacts into the store (no 150 MB copy per test); the store reads through
        // symlinks (`is_file()`/`read` follow them).
        for a in ["vmlinux", "rootfs.erofs"] {
            std::os::unix::fs::symlink(artifacts_dir().join(a), store.path().join(a))
                .expect("symlink artifact");
        }
        let port = free_port();
        let log_path = store.path().join("vmcelld.log");
        let log = std::fs::File::create(&log_path).expect("create log");
        let log_err = log.try_clone().expect("clone log");

        // Spawn `vmcelld` DIRECTLY (not through the runner): the test binary already holds the caps
        // (it runs under the runner as nextest's target-runner), so the child `vmcelld` inherits them
        // via the ambient set. Spawning directly means the test owns the daemon's process tree for
        // setup/teardown inspection (v21 §D10).
        let mut cmd = Command::new(vmcelld_bin());
        cmd.arg("--artifacts-dir")
            .arg(store.path())
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--ch-bin")
            .arg(ch_bin())
            .arg("--resource-prefix")
            .arg(resource_prefix)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));

        let mut key_file_guard = None;
        match auth {
            Auth::Open => {
                cmd.arg("--allow-unauthenticated");
            }
            Auth::Key(k) => {
                use std::os::unix::fs::PermissionsExt as _;
                let kf = store.path().join("api.key");
                std::fs::write(&kf, k).expect("write key");
                std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod key");
                cmd.arg("--api-key-file").arg(&kf);
                key_file_guard = Some(kf);
            }
        }
        let _ = key_file_guard; // kept alive by the store TempDir anyway

        let child = cmd.spawn().expect("spawn vmcelld via runner");
        let base = format!("http://127.0.0.1:{port}");
        let daemon = Daemon {
            child,
            _store: store,
            base,
            log_path,
        };
        daemon.wait_healthz().await;
        daemon
    }

    async fn wait_healthz(&self) {
        let http = reqwest::Client::new();
        let url = format!("{}/healthz", self.base);
        for _ in 0..80 {
            if let Ok(r) = http.get(&url).send().await {
                if r.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!(
            "vmcelld did not become healthy at {}/healthz within 20s.\n--- daemon log ---\n{}",
            self.base,
            self.read_log()
        );
    }

    fn read_log(&self) -> String {
        let mut s = String::new();
        if let Ok(mut f) = std::fs::File::open(&self.log_path) {
            let _ = f.read_to_string(&mut s);
        }
        s
    }

    fn client(&self, key: &str) -> DaemonClient {
        DaemonClient::new(Url::parse(&self.base).expect("url"), key).expect("client")
    }

    /// The `vmcelld` process id — used to construct the per-VM scratch-dir path
    /// (`<temp>/vmcell-vm-<pid>-<vmid>`) for residue checks.
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // GRACEFUL teardown: SIGTERM so `vmcelld`'s signal handler runs `shutdown_all`, which tears
        // down every owned VM (kills its Cloud Hypervisor process group). A bare `child.kill()`
        // (SIGKILL) would skip that and ORPHAN the CH VMs — the exact leak a panicking test (e.g. one
        // that fails before `destroy`) would otherwise cause. Fall back to SIGKILL if the daemon does
        // not exit within a few seconds so a wedged daemon can't hang the run.
        // SAFETY: `kill(2)` with a pid we own and a valid signal; no memory is touched.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        for _ in 0..50 {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- the tests ----

#[tokio::test]
#[ignore = "boots a real VM; needs KVM + blessed runner + artifacts (run via `just test-daemon`)"]
async fn healthz_and_artifact_list() {
    let d = Daemon::start(Auth::Open).await;
    let arts = d.client("").list_artifacts().await.expect("list artifacts");
    let names: Vec<&str> = arts.iter().map(|a| a.name.as_str()).collect();
    assert!(names.contains(&"vmlinux"), "artifacts: {names:?}");
    assert!(names.contains(&"rootfs.erofs"), "artifacts: {names:?}");
    // The store computed a real content digest (64 hex chars).
    let k = arts.iter().find(|a| a.name == "vmlinux").expect("vmlinux");
    assert_eq!(k.sha256.len(), 64, "sha256 should be 64 hex chars");
    assert!(
        k.size_bytes > 1_000_000,
        "kernel size looks wrong: {}",
        k.size_bytes
    );
}

#[tokio::test]
#[ignore = "boots a real VM; needs KVM + blessed runner + artifacts (run via `just test-daemon`)"]
async fn boots_vm_and_execs_data_plane() {
    let d = Daemon::start(Auth::Open).await;
    // `run` = create + exec + teardown. Assert on the DATA PLANE: the guest's captured stdout.
    let out = d
        .client("")
        .run(
            "vmlinux",
            "rootfs.erofs",
            vec!["/bin/echo".into(), "hello-daemon".into()],
        )
        .await
        .expect("run");
    assert_eq!(out.code, 0, "guest exit code");
    assert_eq!(out.stdout().expect("decode"), b"hello-daemon\n");
    // Ephemeral: the VM is gone afterward.
    assert!(
        d.client("").ls().await.expect("ls").is_empty(),
        "ephemeral VM torn down"
    );
}

#[tokio::test]
#[ignore = "boots a real VM; needs KVM + blessed runner + artifacts (run via `just test-daemon`)"]
async fn full_lifecycle_create_exec_stats_destroy() {
    let d = Daemon::start(Auth::Open).await;
    let c = d.client("");

    let vm = c.create("vmlinux", "rootfs.erofs").await.expect("create");
    assert_eq!(c.ls().await.expect("ls").len(), 1, "one owned VM");

    // Data-plane read from inside the guest.
    let out = c
        .exec(
            &vm.id,
            ExecRequestDto::new(vec!["/bin/sh".into(), "-c".into(), "echo $(id -un)".into()]),
        )
        .await
        .expect("exec");
    assert_eq!(out.code, 0);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout().expect("decode")).trim(),
        "root"
    );

    // Stats endpoint returns a usage struct (its detailed correctness — and the memory-metric /
    // delegation coupling — is asserted by `stats_limits_enforced_matches_delegation`).
    let _stats = c.stats(&vm.id).await.expect("stats");

    c.destroy(&vm.id).await.expect("destroy");
    assert!(
        c.ls().await.expect("ls").is_empty(),
        "VM cleared after destroy"
    );
}

#[tokio::test]
#[ignore = "spawns a real vmcelld; needs the blessed runner (run via `just test-daemon`)"]
async fn bearer_auth_401_403_200() {
    let d = Daemon::start(Auth::Key("s3cret-key")).await;
    let http = reqwest::Client::new();
    let vms = format!("{}/v1/vms", d.base);

    // No credential -> 401 with a WWW-Authenticate challenge.
    let r = http.get(&vms).send().await.expect("no-auth request");
    assert_eq!(r.status().as_u16(), 401, "no token must be 401");
    assert!(
        r.headers().get(reqwest::header::WWW_AUTHENTICATE).is_some(),
        "401 must carry a WWW-Authenticate challenge"
    );

    // Wrong credential -> 403.
    let r = http
        .get(&vms)
        .bearer_auth("nope")
        .send()
        .await
        .expect("wrong-auth request");
    assert_eq!(r.status().as_u16(), 403, "wrong token must be 403");

    // Correct credential -> 200.
    let r = http
        .get(&vms)
        .bearer_auth("s3cret-key")
        .send()
        .await
        .expect("auth request");
    assert_eq!(r.status().as_u16(), 200, "correct token must be 200");

    // The open route needs no credential.
    let r = http
        .get(format!("{}/healthz", d.base))
        .send()
        .await
        .expect("healthz");
    assert_eq!(r.status().as_u16(), 200, "healthz is open");
}

#[tokio::test]
#[ignore = "boots a real VM; run via `just test-daemon` (delegated scope) to assert limits enforced"]
async fn stats_limits_enforced_matches_delegation() {
    let d = Daemon::start(Auth::Open).await;
    let c = d.client("");
    let vm = c.create("vmlinux", "rootfs.erofs").await.expect("create");
    let stats = c.stats(&vm.id).await.expect("stats");

    // Both `limits_enforced` and `mem_read_ok` mean exactly "the memory controller is delegated into
    // the per-VM slice" (§7.2): under a delegated scope (`just test-daemon`) the daemon creates a slice
    // with `memory.*` present, so both are true and a real memory reading is visible; without
    // delegation those files don't exist, so both are honestly false (the daemon never claims
    // enforcement it lacks — that honesty is the property under test). Assert both track delegation.
    let delegated = delegation_available();
    assert_eq!(
        stats.limits_enforced, delegated,
        "limits_enforced ({}) must match delegation ({delegated}): {stats:?}",
        stats.limits_enforced
    );
    assert_eq!(
        stats.mem_read_ok, delegated,
        "mem_read_ok ({}) must match delegation ({delegated}): {stats:?}",
        stats.mem_read_ok
    );
    if delegated {
        assert!(
            stats.mem_current_mib > 0,
            "a booted VM under delegation reads nonzero memory: {stats:?}"
        );
    }

    c.destroy(&vm.id).await.expect("destroy");
}

/// The start-up orphan sweep (§D4) — a payoff of the inverted pattern: the **test** is privileged, so
/// it can plant a leaked netns (the residue a hard-killed daemon leaves) and assert the next daemon's
/// start-up sweep reclaims it. `vmcell-net-<vmid>` is the exact shape `sweep_orphans` matches.
#[tokio::test]
#[ignore = "creates a netns + spawns vmcelld; run via `just test-daemon` (needs caps)"]
async fn startup_sweep_reclaims_orphan_netns() {
    require_preconditions();
    // A vmid well outside the 1..=254 allocation range so it can never belong to a live VM.
    let orphan = "vmcell-net-60001";
    // Best-effort clean any leftover from a prior aborted run, then create the orphan (needs caps).
    let _ = Command::new("ip")
        .args(["netns", "delete", orphan])
        .status();
    let created = Command::new("ip")
        .args(["netns", "add", orphan])
        .status()
        .expect("run `ip netns add`");
    assert!(
        created.success(),
        "creating the orphan netns {orphan} failed (needs CAP_NET_ADMIN/SYS_ADMIN)"
    );
    assert!(
        netns_exists(orphan),
        "orphan netns should exist before the daemon starts"
    );

    // Starting the daemon runs the start-up sweep (empty live set) before it serves.
    let d = Daemon::start(Auth::Open).await;
    let _ = &d; // keep it alive through the assertion
    assert!(
        !netns_exists(orphan),
        "start-up sweep must have reclaimed the orphan netns {orphan} (§D4)"
    );
    // Belt-and-suspenders cleanup in case the assertion path changed.
    let _ = Command::new("ip")
        .args(["netns", "delete", orphan])
        .status();
}

/// Owning-and-`Drop` teardown (§D4): a VM's per-VM scratch dir (`<temp>/vmcell-vm-<pid>-<vmid>`) exists
/// while it is owned and is **gone after `destroy`** — the AGENTS.md residue rule, exercised end-to-end
/// through the daemon. Uses the daemon's own pid, so it is independent of the net mode.
#[tokio::test]
#[ignore = "boots a real VM; run via `just test-daemon`"]
async fn destroy_removes_per_vm_scratch_dir() {
    let d = Daemon::start(Auth::Open).await;
    let c = d.client("");
    let vm = c.create("vmlinux", "rootfs.erofs").await.expect("create");

    let scratch = std::env::temp_dir().join(format!("vmcell-vm-{}-{}", d.pid(), vm.vmid));
    assert!(
        scratch.is_dir(),
        "per-VM scratch dir {} should exist while the VM is owned",
        scratch.display()
    );

    c.destroy(&vm.id).await.expect("destroy");
    assert!(
        !scratch.exists(),
        "per-VM scratch dir {} must be gone after destroy (ordered teardown)",
        scratch.display()
    );
}

/// Whether a named netns exists under `/var/run/netns`.
fn netns_exists(name: &str) -> bool {
    Path::new("/var/run/netns").join(name).exists()
}

/// Whether the guest-tools `ip route` output (raw `/proc/net/route`: hex, tab/space-separated columns
/// `Iface Destination Gateway …`) contains a default route — a row whose Destination is `00000000`
/// (0.0.0.0) with a non-zero Gateway. The header row (`Destination`) and connected routes (zero
/// gateway) are skipped.
fn has_default_route(raw: &str) -> bool {
    raw.lines().any(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        cols.len() >= 3 && cols[1] == "00000000" && cols[2] != "00000000"
    })
}

/// Snapshot + restore-by-name (§D5.1): boot a snapshot-eligible VM (privileged net + `snapshotting`),
/// write a marker into its tmpfs, snapshot it into the store under a prefix, then **restore by name**
/// into a fresh VM and prove the marker survived — a genuine memory-image round-trip through the
/// daemon, and the payoff of the artifact store being the snapshot exchange surface.
#[tokio::test]
#[ignore = "boots + snapshots + restores real VMs; run via `just test-daemon`"]
async fn snapshot_then_restore_by_name_preserves_guest_state() {
    let d = Daemon::start(Auth::Open).await;
    let c = d.client("");

    let eligible = CreateVmRequest::create("vmlinux", "rootfs.erofs")
        .with_net(NetMode::Privileged)
        .with_snapshotting(true);
    let vm = c
        .create_vm(eligible)
        .await
        .expect("create snapshot-eligible VM")
        .vm;

    // Write a marker into the guest's tmpfs (part of the memory image the snapshot freezes).
    let w = c
        .exec(
            &vm.id,
            ExecRequestDto::new(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo snap-marker-42 > /tmp/marker".into(),
            ]),
        )
        .await
        .expect("write marker");
    assert_eq!(w.code, 0, "writing the marker should succeed");

    // Snapshot into the artifact store under a prefix, then tear the original down.
    let snap = c.snapshot(&vm.id, "snap-a").await.expect("snapshot");
    assert!(
        !snap.files.is_empty(),
        "snapshot should have written files: {snap:?}"
    );
    c.destroy(&vm.id).await.expect("destroy original");

    // Restore BY NAME into a fresh VM and read the marker back — proves the memory image restored.
    let restore = CreateVmRequest::create("vmlinux", "rootfs.erofs")
        .with_net(NetMode::Privileged)
        .with_snapshotting(true)
        .restoring_from("snap-a");
    let restored = c.create_vm(restore).await.expect("restore by name").vm;
    let r = c
        .exec(
            &restored.id,
            ExecRequestDto::new(vec!["/bin/cat".into(), "/tmp/marker".into()]),
        )
        .await
        .expect("read marker in restored VM");
    assert_eq!(r.code, 0, "marker file must exist in the restored VM");
    assert_eq!(
        String::from_utf8_lossy(&r.stdout().expect("decode")).trim(),
        "snap-marker-42",
        "the marker written before the snapshot must survive restore"
    );

    c.destroy(&restored.id).await.expect("destroy restored");
}

/// Privileged tap networking (§D5.1): a VM created with `net: privileged` gets a host **netns**
/// (`vmcell-net-<vmid>`, which the privileged test can observe) and the guest gets a **default route**
/// (the agent configures `eth0` from the kernel cmdline). Both sides confirm the privileged path ran.
#[tokio::test]
#[ignore = "boots a real VM with privileged tap networking; run via `just test-daemon`"]
async fn privileged_net_gives_host_netns_and_guest_default_route() {
    let d = Daemon::start(Auth::Open).await;
    let c = d.client("");
    let vm = c
        .create_vm(CreateVmRequest::create("vmlinux", "rootfs.erofs").with_net(NetMode::Privileged))
        .await
        .expect("create with privileged net")
        .vm;

    // Host side: the privileged path created this VM's netns.
    assert!(
        netns_exists(&format!("vmcell-net-{}", vm.vmid)),
        "privileged net must create host netns vmcell-net-{}",
        vm.vmid
    );

    // Guest side: the agent brought eth0 up with a /30 in the privileged subnet.
    let addr = c
        .exec(
            &vm.id,
            ExecRequestDto::new(vec![
                "/bin/sh".into(),
                "-c".into(),
                "ip -4 addr show".into(),
            ]),
        )
        .await
        .expect("ip addr in guest");
    let a = String::from_utf8_lossy(&addr.stdout().expect("decode")).into_owned();
    assert!(
        a.contains("eth0") && a.contains("state up") && a.contains("inet 10.200."),
        "guest eth0 should be up with a 10.200.x/30 under privileged net; `ip -4 addr show`: {a:?}"
    );

    // ...and a default route. The guest-tools `ip route` prints the raw `/proc/net/route` table (hex,
    // tab-separated), so a default route is a row with Destination `00000000` (0.0.0.0) and a non-zero
    // Gateway — not the literal string "default".
    let route = c
        .exec(
            &vm.id,
            ExecRequestDto::new(vec!["/bin/sh".into(), "-c".into(), "ip route".into()]),
        )
        .await
        .expect("ip route in guest");
    let r = String::from_utf8_lossy(&route.stdout().expect("decode")).into_owned();
    assert!(
        has_default_route(&r),
        "guest should have a default route under privileged net; `ip route`: {r:?}"
    );

    c.destroy(&vm.id).await.expect("destroy");
    // Residue check: destroying the VM removes its netns.
    assert!(
        !netns_exists(&format!("vmcell-net-{}", vm.vmid)),
        "destroy must remove the netns vmcell-net-{}",
        vm.vmid
    );
}

/// The `vmcelld-ctl` CLI end-to-end (§D7.2): drive a live daemon through the shipped binary — `run`
/// relays the guest stdout + exit code, `ls`/`artifact ls` return JSON. Folds the CLI path (previously
/// only manually checked) into the automated suite.
#[tokio::test]
#[ignore = "spawns a real vmcelld + boots a VM via vmcelld-ctl; run via `just test-daemon`"]
async fn vmcelld_ctl_drives_the_daemon() {
    let d = Daemon::start(Auth::Open).await;
    let ctl = ctl_bin();
    assert!(
        ctl.is_file(),
        "vmcelld-ctl not built at {}; `just test-daemon` builds it",
        ctl.display()
    );

    // `run` = create + exec + teardown; the CLI relays the guest's stdout and propagates its exit code.
    let out = Command::new(&ctl)
        .args([
            "--daemon-url",
            &d.base,
            "run",
            "--kernel",
            "vmlinux",
            "--rootfs",
            "rootfs.erofs",
            "/bin/echo",
            "hello-from-ctl",
        ])
        .output()
        .expect("run vmcelld-ctl");
    assert!(
        out.status.success(),
        "`vmcelld-ctl run` failed: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello-from-ctl",
        "ctl must relay the guest's stdout"
    );

    // `ls` and `artifact ls` return JSON; the artifact list shows the seeded kernel.
    let ls = Command::new(&ctl)
        .args(["--daemon-url", &d.base, "ls"])
        .output()
        .expect("vmcelld-ctl ls");
    assert!(
        ls.status.success(),
        "ls stderr: {}",
        String::from_utf8_lossy(&ls.stderr)
    );

    let arts = Command::new(&ctl)
        .args(["--daemon-url", &d.base, "artifact", "ls"])
        .output()
        .expect("vmcelld-ctl artifact ls");
    assert!(
        String::from_utf8_lossy(&arts.stdout).contains("vmlinux"),
        "artifact ls should list vmlinux: {}",
        String::from_utf8_lossy(&arts.stdout)
    );
}

/// The configurable resource prefix (§v21): a daemon run with `--resource-prefix acme` names its VMs'
/// host resources `acme-*` AND sweeps only `acme-*` — never another prefix's. This is the whole point
/// of the option (one value drives both naming and the sweep), and the isolation property.
#[tokio::test]
#[ignore = "creates netns + boots a real VM; run via `just test-daemon` (needs caps)"]
async fn custom_resource_prefix_names_and_sweeps_in_isolation() {
    require_preconditions();
    let mine = "acme-net-60002"; // an orphan under THIS daemon's prefix — must be swept
    let other = "vmcell-net-60003"; // an orphan under a DIFFERENT prefix — must be left alone
    for ns in [mine, other] {
        let _ = Command::new("ip").args(["netns", "delete", ns]).status();
        assert!(
            Command::new("ip")
                .args(["netns", "add", ns])
                .status()
                .expect("ip netns add")
                .success(),
            "create orphan netns {ns}"
        );
    }

    // The daemon's start-up sweep (with prefix `acme`) runs before it serves.
    let d = Daemon::start_with_prefix(Auth::Open, "acme").await;
    assert!(
        !netns_exists(mine),
        "the sweep must reclaim the acme-* orphan"
    );
    assert!(
        netns_exists(other),
        "the sweep must NOT touch a different prefix's netns (isolation)"
    );

    // A VM booted under this daemon is named with the custom prefix, not the default.
    let c = d.client("");
    let vm = c
        .create_vm(CreateVmRequest::create("vmlinux", "rootfs.erofs").with_net(NetMode::Privileged))
        .await
        .expect("create with privileged net")
        .vm;
    assert!(
        netns_exists(&format!("acme-net-{}", vm.vmid)),
        "the VM's netns must use the acme prefix"
    );
    assert!(
        !netns_exists(&format!("vmcell-net-{}", vm.vmid)),
        "the VM's netns must NOT use the default vmcell prefix"
    );

    c.destroy(&vm.id).await.expect("destroy");
    // Clean up the control orphan we planted under the other prefix.
    let _ = Command::new("ip").args(["netns", "delete", other]).status();
}
