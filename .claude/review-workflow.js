export const meta = {
  name: 'imp-testing-code-review',
  description: 'Privileged-aware code review of imp-testing: preflight gate → 17 domain finders → adversarial verification',
  phases: [
    { title: 'Preflight', detail: 'gate: privileged suites must be runnable (else BLOCK and ask for `just bless`)' },
    { title: 'Empirical ingest', detail: 'summarize an actual privileged/rootless test run as ground truth (optional)' },
    { title: 'Domain review', detail: '17 parallel sub-reviewers, one coherent file-slice each' },
    { title: 'Verify', detail: 'adversarial refutation of each Critical/High/Medium finding' },
  ],
}

// ===========================================================================
// PRIVILEGED-AWARE REVIEW — block-and-ask procedure (read before changing)
// ---------------------------------------------------------------------------
// This crate's host-facing findings (VMM lifecycle, snapshot/restore, cgroup
// limits, netns/tap, egress proxy) are only trustworthy if the privileged
// integration suites actually RAN. So the review runs a hard PREFLIGHT first
// (`scripts/review-preflight-priv.sh`: KVM + runner blessed +ep + artifacts +
// delegatable cgroup scope).
//
//   * If preflight is NOT ready, the workflow does NO expensive review work and
//     returns `{ blocked: true, remediation }`. The CALLER (main loop) MUST then
//     ask the maintainer to run the printed command (usually `just bless`) and
//     re-run — it must NOT silently fall back to a static-only review.
//   * To deliberately run a static-only review (e.g. no KVM host), invoke with
//     args = { mode: 'static' }.
//   * To fold in EMPIRICAL ground truth, first run the suites
//     (`just test-priv` / `just test-rootless` under the delegated scope) and
//     pass args = { privilegedLog: '<path>', residueLog: '<path>' }. Each
//     finding then carries an `empirical_status`. A finding in an UNtested path
//     is NOT refuted by a green run — it is `unverified-no-test-exercises-it`,
//     which itself substantiates a test-gap finding.
// ===========================================================================
const REVIEW_MODE = (typeof args !== 'undefined' && args && args.mode) || 'privileged'
let EMPIRICAL = '' // ground truth from an actual privileged/rootless run; injected into prompts when provided

const PREFLIGHT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ready: { type: 'boolean' },
    summary: { type: 'string' },
    remediation: { type: 'string' },
  },
  required: ['ready', 'summary', 'remediation'],
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const FINDING_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          title: { type: 'string', description: 'concise finding title' },
          severity: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low', 'Nit'] },
          category: { type: 'string', enum: ['divergence', 'correctness', 'test-gap', 'docs', 'rust-bp', 'code-quality'] },
          rubric_ref: { type: 'string', description: 'rubric item, e.g. B1/B4/A2/PartC; or "" if none' },
          design_ref: { type: 'string', description: 'design section, e.g. §9.2; or "" if none' },
          locations: { type: 'array', items: { type: 'string' }, description: 'file:line citations' },
          evidence: { type: 'string', description: 'quoted code or precise reasoning, <=8 lines' },
          red_test: { type: 'string', description: 'the buggy impl whose inverse a test should catch, or "no test guards this"' },
          suggested_direction: { type: 'string', description: 'fix direction only; do NOT apply' },
          is_justified_deviation: { type: 'boolean', description: 'true if this is a defensible deviation worth recording in impl-notes rather than reporting' },
          confidence: { type: 'number', description: '0..1' },
          empirical_status: {
            type: 'string',
            enum: ['confirmed-by-test', 'refuted-by-test', 'unverified-no-test-exercises-it', 'not-applicable'],
            description: 'Set from the EMPIRICAL GROUND TRUTH block if present; else "not-applicable". A finding in an untested path is "unverified-no-test-exercises-it" (NOT refuted).',
          },
        },
        required: ['title', 'severity', 'category', 'rubric_ref', 'design_ref', 'locations', 'evidence', 'red_test', 'suggested_direction', 'is_justified_deviation', 'confidence', 'empirical_status'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    verdict: { type: 'string', enum: ['confirmed', 'refuted', 'nuanced'] },
    corrected_severity: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low', 'Nit'] },
    is_justified_deviation: { type: 'boolean' },
    note: { type: 'string', description: 'what the code actually shows at the cited lines; why confirmed/refuted; <=6 lines' },
  },
  required: ['verdict', 'corrected_severity', 'is_justified_deviation', 'note'],
}

// ---------------------------------------------------------------------------
// Shared context for every reviewer
// ---------------------------------------------------------------------------
const REPO = '/home/pwnall/workspace/imp-testing'

const DONT_REPORT = `
DO-NOT-RE-REPORT BASELINE (already recorded in docs/implementation-notes.md as justified, or admitted/deferred). Do NOT raise these as NEW findings; you MAY confirm whether the code still matches them:
- Justified deviations: loom deferred; rootless-as-default migration still pending; Firecracker restore() returns a PAUSED VM (caller resumes); QEMU snapshot_restore=false in all configs; CLI subcommands run/exec/ls/rm/stats are placeholder stubs (BUT verify each returns a typed error + non-zero exit, NOT a silent Ok/printed success); agent protocol intentionally omits Hello/Ping (enum is non_exhaustive); hudsucker reconstructs the Certificate from the SAME loaded CA params/key (cache-once, not a per-call re-sign); TestVm injects CidAllocator+VmidAllocator+CgroupFs separately; deny.toml allows Unicode-3.0 & CDLA-Permissive-2.0; TPROXY drops UDP/QUIC dport 443 instead of intercepting (NET-7, deliberate to keep egress observable over TCP); exec_vsock::test_exec_vsock_mock runs in the default suite (pure codec mock).
- Known/deferred (admitted; not new findings): cargo-hack feature-powerset gate still RED (host-common module-gating debt); live pin resolution deferred (ResolvePinsStage loads committed pins.json, ARTIFACT-PIPELINE-5); OCI record/replay injectable seam deferred (ARTIFACT-PIPELINE-8); warm snapshot/restore vsock re-bind is a known gap on CH; rootfs OCI base may lack iproute2/curl; smoltcp host-NAT MAC collides with mac_math(254) (NET-2, recorded).
Your job: find what is NOT on this list, and verify the recorded items still hold.`

const PRINCIPLES = `
CROSS-CUTTING PRINCIPLES (rubric Part A) — reason from these:
A1 Fail loud, typed, early: no swallowed Result (let _ = without justifying comment), no Ok(()) on a failed/unsupported branch, no panic on a guest/network-driven path; errors visible, matchable (not Error::Other(String)), checked before a timeout masks them.
A2 Best-effort is the rare DECLARED exception; silent degradation is the default bug. A requested FUNCTIONAL op that can't run due to a missing capability must return a typed error (Error::CapabilityUnavailable{op,needed}), not a logged-and-ignored no-op returning Ok. Reads may degrade but must surface what was unavailable (e.g. limits_enforced flag). Only benchmark knobs (cpufreq/KSM) may no-op, and only with a VISIBLE warn!.
A3 Capabilities declared/probed/reported for host AND backend; operating mode selected from what the host offers, failing loud up front.
A4 Ownership owns cleanup — on panic AND on post-acquire failure. A resource acquired before a later fallible step must be owned by an RAII guard BEFORE that step (the classic leak: spawn VMM, then add_task()?/wait_for_socket()? before building the owner whose Drop reaps it).
A5 Contracts self-guard: a method whose correctness depends on "the caller checked capabilities() first" is a latent bug; check inside and return Error::Unsupported. Enforce a law at EVERY boundary it can be violated at.
A6 Validate at the boundary; return Err, don't assert/panic on an input path. Symmetric paths get symmetric handling (RX as graceful as TX).
A7 Determinism is tested, not assumed.
A8 Verify everything you ingest (pinned digests/signatures) before use; a wrong pin is rejected; a stale intermediate verify-or-purges.
A9 A seam you can't fake is a unit you can't test; the fake must be DRIVEN, not merely exist.

THE TEST QUESTION for every test-gap: "Write the buggy implementation. Does this test go red?" If no, it is theater.`

const PREAMBLE = `You are a skeptical senior Rust reviewer auditing the imp-testing crate (a micro-VM-per-test integration/eval platform; repo root ${REPO}). It has survived FIVE prior review passes where green CI masked real bugs, so be adversarial and verify against the ACTUAL SOURCE, not the design's claims.

Reference docs you may read as needed (do not dump them; read targeted sections):
- Rubric: docs/36-claude-code-review-rubric.md (the authoritative checklist; Parts A/B1-B9/C/D)
- Design: docs/35-claude-design-v13.md (use the section refs given in your focus)
- Impl notes: docs/implementation-notes.md (recorded deviations)

${PRINCIPLES}
${DONT_REPORT}

METHOD: Read your assigned files in full. For each issue, cite file:line, quote the offending code (<=8 lines), classify category+severity, give rubric_ref/design_ref, and state the "red_test" (the buggy impl a test should catch — or "no test guards this"). Provide a fix DIRECTION only; DO NOT edit any file. Mark is_justified_deviation=true only if it's a genuinely defensible deviation that belongs in impl-notes rather than the report. Be precise; an empty findings list is acceptable if the slice is genuinely clean. Prefer fewer high-confidence findings over speculation, but do not miss real bugs. Severity guide: Critical=correctness/safety/contract break that can corrupt results or crash a guest/host path; High=clear bug or rubric violation with real impact; Medium=correctness-adjacent, weak test, or notable divergence; Low/Nit=style/docs/code-quality.

For empirical_status: if an EMPIRICAL GROUND TRUTH block is present below, set it per that block (confirmed-by-test / refuted-by-test / unverified-no-test-exercises-it); otherwise set 'not-applicable'. A finding in an untested path is 'unverified-no-test-exercises-it', never 'refuted-by-test'.

Return ONLY the structured findings object.`

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------
const DOMAINS = [
  {
    key: 'vmm-backends',
    files: ['src/vmm/mod.rs', 'src/vmm/cloud_hypervisor.rs', 'src/vmm/firecracker.rs', 'src/vmm/qemu.rs'],
    focus: `VMM trait + 3 backends. Check: B1 process teardown uses a GROUP kill that WAITS (kill -9 -<pgid>, pgid cached at spawn, then reap) not start_kill() (leader-only) nor Child::id() after the child was awaited (returns None → kill no-ops); applies to ALL THREE backends. A4 a resource acquired before a later fallible step (spawn-then-wait_for_socket()?/add_task()?) is owned by an RAII guard BEFORE the ? — else the ? leaks a live VMM (shared reap helper). B3 Error::Unsupported{vmm,feature} for every capability gap — never panic, never Error::Vmm("...does not support..."); advertised capabilities are LIVE not dead flags (lazy_restore:true with no prefault plumbing is a lie). restore()/snapshot() self-guard on capabilities().snapshot_restore AND absence of any vhost-user device. create() rejects configs the backend can't honor (FC + vhost-user socket → error, not netless boot). B7 the spawn/netns-exec/readiness boilerplate, the HTTP-over-Unix client, and a QMP/JSON-"error" parser must each be ONE shared helper across CH/FC/QEMU (duplication hides per-backend divergence: a cgroup escape logged for CH but silent for QEMU); no hand-rolled HTTP (parse status numerically, loop the read, not one 4096-byte read prefix-matched). QEMU boot()/resume()/pause() must not swallow a QMP {"error":...} as Ok. Readiness loops check try_wait() and fail fast with the real cause. Contracts: §3.3 snapshot-eligibility law, §3.4 capability matrix, §9.2 restore, §10.2 Vmm/VmInstance traits.`,
  },
  {
    key: 'orchestrator',
    files: ['src/orchestrator.rs'],
    focus: `TestVm composition + Drop + allocators. Check: B1 TestVm::Drop performs the FULL ORDERED teardown VMM process-group → virtiofsd → netns/cgroup/overlay/sockets, and runs on panic AND early-return; releases BOTH CID and VMID; cgroup slice has an RAII guard (a construction-failure leak if not); spawned-forever workers hold a shutdown signal + JoinHandle and Drop joins WITHIN A TIMEOUT (unbounded join hangs teardown); request_shutdown() is not immediately followed by unconditional kill() (wait bounded first). A periodic sweeper + orphan registry reaps what a hard crash leaked (/var/run/netns/imp-net-* collisions). B6 IDs/time come from INJECTED allocators (CidAllocator, vmid allocator, Clock, CgroupFs) — no module-global static; release() operates on the ACTUAL allocator instance (not a fresh one — the no-op-release bug); skips reserved CIDs 0/1/2; wraps without colliding with live IDs. §7.2 the VM cgroup must be a SIBLING of the harness runner (strip /supervisor suffix), not a child; PID written directly via fs::write(cgroup.procs). agent() borrows TestVm mutably — read vmid/proxy into locals before calling agent(). Contracts: §10.2 TestVm, §7.2 cgroup delegation, §9.2 restore resync wiring.`,
  },
  {
    key: 'config',
    files: ['src/config.rs'],
    focus: `Pure config + builder. Check: B3 VmConfigBuilder::build() returns Result and REJECTS, with a NEGATIVE TEST FOR EACH: duplicate share tags; snapshotting + {virtio-fs rootfs, ANY virtio-fs data share, NetConfig::Unprivileged} (the §3.3 law — ALL THREE vhost-user cases, not just rootfs); vcpus==0; mem_mib below floor; empty kernel path; out-of-range vmid (return Err at the boundary, NOT assert! in create()). #[must_use] on builder methods, #[non_exhaustive] on the config types. A5 the snapshot-eligibility law must be enforced HERE (first boundary) for EVERY vhost-user device — the recorded review-34 bug was that a virtio-fs DATA SHARE slipped past build(). Verify the data-share case is actually rejected now. Contracts: §3.3, §10.2 VmConfig surface.`,
  },
  {
    key: 'snapshot-restore',
    files: ['src/artifact/snapshot.rs', 'src/orchestrator.rs', 'src/vmm/cloud_hypervisor.rs', 'src/vmm/firecracker.rs'],
    focus: `Snapshot/restore correctness (read snapshot.rs fully; read only the restore/snapshot fns in orchestrator + CH/FC). Check §9.2: post-restore resync fires ONCE on the first agent() call — (1) CID: assert "valid LIVE cid", NOT assert_ne!(old,new) (reuse is by design); (2) MAC rotation is DEVICE-LAYER ONLY (one ip link set eth0 address via SIOCSIFHWADDR), IP NOT rotated, no in-guest ip addr flush (would re-introduce netlink/break route); (3) entropy reseed surfaced per clone; (4) CLOCK resync is HOST-DRIVEN (host reads SystemTime::now() after vsock reconnect, pushes to guest) and the FakeClock must be driven on the FIRST post-restore call (the recorded smell: FakeClock read only where restored==false → assertion can't hold); (5) vsock reconnect is real (retries; guest re-binds), not a no-op. B3 restore()/snapshot() self-guard on capabilities + no vhost-user device. Whether the known CH warm-restore vsock-rebind GAP is handled or still open (don't re-report as new, but assess code state). Contracts: §3.3, §9.2.`,
  },
  {
    key: 'net-privileged',
    files: ['src/net/mod.rs', 'src/net/tap.rs', 'src/net_sys.rs'],
    focus: `Privileged tap/netns networking. Check: B6 the /30 host-IP math is in ONE unit-tested helper; the VMID→octet mapping (vmid % 254)+1 is applied CONSISTENTLY at every site (no %254 here, %256 there); the host NAT MAC is pinned OUTSIDE the mac_math(1..=254) range (recorded NET-2 collision at 254 — confirm whether fixed). B1 netns lifecycle: removing a netns while the VMM still holds interfaces hangs/leaks (reap VMM first); a sweeper reaps leaked imp-net-* namespaces. Design mandates rtnetlink, NOT the ip CLI. A6 out-of-range vmid returns Err, not assert!. net module should be #![forbid(unsafe_code)] with the one ioctl spot isolated in net_sys.rs. Look for string stand-ins (ends_with(".2/30") instead of asserting octets). Contracts: §6.1/§6.4.`,
  },
  {
    key: 'net-unprivileged',
    files: ['src/net/smoltcp.rs'],
    focus: `Unprivileged in-process smoltcp userspace NAT (vhost-user-net). Check: B1 the per-port socket/port-map pool (~512 KiB per distinct dst port) is BOUNDED and idle/closed mappings reclaimed — a flood of distinct destination ports is a guest-drivable memory DoS (recorded NET-5; assert the pool stays capped after N distinct ports). B2 NO .unwrap()/.expect() on the guest-driven packet loop and on BOTH the TX and RX vring paths — an .expect() on a guest-controlled descriptor index is a guest-drivable panic; degrade gracefully (log+continue/close). A1 fail-loud on real errors but never panic on guest input. Look for symmetric TX/RX handling. Contracts: §6.1.`,
  },
  {
    key: 'proxy',
    files: ['src/proxy/mod.rs', 'src/proxy/tls.rs', 'src/proxy/doubles.rs'],
    focus: `Transparent egress proxy (hyper+hudsucker MITM), TLS, test doubles. Check: B4 the MITM CA is generated ONCE and the parsed authority cached (the hudsucker reconstruct-from-same-params is the cache-once pattern, NOT a re-sign bug — do not flag that), written ATOMICALLY (temp-then-rename), 0600, per-run-scoped, and FROM THE SAME artifacts dir the rootfs CA was baked from (a per-pid /tmp CA breaks the guest trust chain). B7 no test-only logic in the production handler (no hardcoded example.net block — use the configurable deny list, which RECORDS blocked requests). No hand-rolled HTTP. HTTPS doubles must ignore CONNECT (let it fall through). Filter-block must be observable/recorded. Domain filter matches LABEL BOUNDARIES (bare ends_with over-blocks sibling domains). Contracts: §6.3.`,
  },
  {
    key: 'metrics-cgroup-cpufreq',
    files: ['src/metrics.rs', 'src/cpufreq.rs'],
    focus: `cgroup v2 metrics/limits + cpufreq. Check: A2/B2 a REQUESTED resource limit on an UNDELEGATED controller must FAIL LOUD (Error::CapabilityUnavailable), NOT silently no-op returning Ok; a READ may degrade but must surface limits_enforced=false. B1 the per-VM cgroup has an RAII guard. B7 the cgroup stats() reader is ONE shared helper (not triplicated per backend), and all cgroup logic lives in metrics.rs behind CgroupFs. B8 ResourceUsage io/net counters must be ACTUALLY READ (io.stat + net), not left always-zero (a v12 defect). §7.2 limits applied via DIRECT sysfs writes (not cgroups-rs builder), PID written via fs::write(cgroup.procs). cpufreq/KSM are the DECLARED best-effort exception: they may no-op but must warn! VISIBLY, never silently. CgroupFs is an injectable trait with a recording fake asserting exact limit-file contents. Contracts: §7.1 fail-loud contract, §7.2 delegation mechanics.`,
  },
  {
    key: 'pipeline-cache',
    files: ['src/artifact/mod.rs', 'src/artifact/kernel.rs'],
    focus: `Pipeline staging + cache keys + determinism. Check: B4 cache keys use a STABLE hasher (blake3/sha2, never DefaultHasher); inputs hashed in DETERMINISTIC order (sorted/BTreeMap, NEVER HashMap iteration order — spurious miss → forced rebuild); keys hash CONTENT + identity-that-travels, NOT absolute PathBufs under target/; embed a STAGE VERSION constant and the pinned source SHA; the guest-agent src hash AND guest-tools content fold into the ROOTFS key (a stale agent baked into rootfs is the tell). Cache validity is CONTENT-ADDRESSED (re-hash on every use, incl. a cached OCI blob on the cache-HIT path), not existence-of-file; a tampered artifact with intact .cache_key is REJECTED. A stale intermediate verify-or-PURGES (kernel tarball whose hash≠pin re-fetches, not errors). B5 Stage 0 isolates non-determinism (loads/propagates committed pins via StageOutputs — honestly documented as a lock); StageInputs/StageOutputs actually CARRY data (no empty structs, no IMP_KERNEL/IMP_ROOTFS env vars); each Stage declares its OWN output paths (not synthesized by pipeline from if name=="kernel"); Pipeline::build returns real Artifacts, not Artifacts{}; an artifact registered only on the warm path is lost on a cold build; reset_to(stage) removes that + all later outputs and ERRORS on an unknown stage name; no /tmp/vmlinux-style fallback masking a missing upstream. Contracts: §11.2 stage model, §11.1 artifacts.`,
  },
  {
    key: 'rootfs-provenance',
    files: ['src/artifact/rootfs/mod.rs', 'src/artifact/rootfs/oci.rs', 'src/artifact/rootfs/mmdebstrap.rs', 'src/artifact/tar2erofs.rs', 'src/artifact/guest_agent.rs', 'src/artifact/guest_tools.rs'],
    focus: `Rootfs construction + provenance + decode. Check: A8/B4 EVERY download (kernel tarball, OCI blobs, builder base) verified against its pinned hash BEFORE use; mismatch is a HARD STOP; image pulls are DIGEST-pinned, a tag fallback is an error; mmdebstrap enforces apt gpg verification AND a snapshot.debian.org timestamp pin. Decode paths COMPLETE: OCI gzip AND zstd (a zstd layer must not yield an empty rootfs); device-node rdev uses makedev(), NOT (major<<8)|minor. OCI whiteouts handled. The snapshot stage boots the EROFS rootfs, not a hardcoded Block. The injectable OCI pull seam is deferred (don't re-report) but confirm the hardcoded oci_client::Client. erofs packing is deterministic. Contracts: §5.1/§5.2, §8.2, §11.2 record/replay + signing.`,
  },
  {
    key: 'guest-agent',
    files: ['src/agent/mod.rs', 'src/agent/protocol.rs', 'src/bin/imp-guest-agent.rs', 'src/bin/imp-guest-tools.rs'],
    focus: `Guest PID-1 agent + protocol + guest-tools, and host-side AgentClient (in agent/mod.rs). Check: B2 PID-1 (imp-guest-agent) does NOT panic/.expect on a RECOVERABLE condition (a panic kernel-panics the guest): a missing optional virtio-fs share tag → log+skip; loopback ioctl failure → log+continue; ONLY the core mounts (overlay/proc/dev) are fatal. The PID-1 reaper (waitpid WNOHANG) must NOT steal the exec'd child's exit status from the dedicated child.wait() — that race reports a false exit 127 for a command that succeeded; coordinate them. ZERO-NETLINK in PID 1: no ip link/addr/route — the kernel ip= cmdline configures eth0; the restore path must not re-run ip in the guest (only a device-layer MAC ioctl allowed). Host AgentClient: connect() uses EXACT 1-byte reads, NEVER a BufReader (a buffer pre-fetches and silently discards the first framed payload); reads "OK <port>\n"; exec() has a PER-REQUEST timeout, not a global one; reconnect() post-restore; serial-panic fast-fail. Protocol enum is #[non_exhaustive], framed (Ready/Exec/Stdout/Stderr/Exit/PutFile), no dead Hello/Ping (recorded). Lean-agent: imp-guest-agent must NOT pull tokio/hyper/rtnetlink/host async stack. Contracts: §4.1/§4.3, §9.2, §10.2 AgentClient.`,
  },
  {
    key: 'cap-runner',
    files: ['src/bin/imp-test-runner.rs'],
    focus: `Privileged-window capability runner (B9 — stricter review; every line runs at elevated capability). Check: it checks the EFFECTIVE capability set (not permitted); the blessing message it prints is setcap ...+ep (NOT +p — a +p-only blessing leaves caps un-raised so the check still fails and the printed remediation is unfollowable). Privilege-drop ordering is correct and SINGULAR: drop the BOUNDING set (needs CAP_SETPCAP raised FIRST, else it silently no-ops — surface/declare best-effort) BEFORE raising AMBIENT; for the setuid form, change uid BEFORE raising ambient; trim P/E after; ONE drop path — NO dead second setuid block obscuring the ordering. Dependency-thin (rustix+capctl only, never links imp_testing lib); inits NO tracing/logging stack at full privilege. Standing caps are EXACTLY CAP_NET_ADMIN+CAP_SYS_ADMIN+CAP_DAC_OVERRIDE and no more (KVM is the kvm group, not a cap). Contracts: §12.8.`,
  },
  {
    key: 'fs-virtiofs',
    files: ['src/fs.rs', 'src/fs/in_process.rs'],
    focus: `virtiofsd supervision + in-process FUSE experiment. Check: B9/B4 virtiofsd launched with --sandbox namespace + a dedicated uid; RO shares ENFORCED read_only at the daemon (--readonly), NOT mounted rw with a warning. A2 in-process FUSE RO is FUNCTIONAL: a RO share that isn't actually enforced read-only must fail loud, not silently allow writes. One virtiofsd per share; bounded TIMEOUT on the socket wait (never fall through to success). fs.rs explicitly is NOT forbid-unsafe (pre_exec for pgid) — check the unsafe is documented (SAFETY) and minimal. Snapshot caveat: attaching virtiofsd makes a VM snapshot-INELIGIBLE (the law). Contracts: §5.2, §10.3 fs module.`,
  },
  {
    key: 'cli-bench',
    files: ['src/bin/imp-testing.rs', 'src/bin/bench-vm.rs', 'benches/micro.rs'],
    focus: `CLI binary + VM-level bench harness + criterion micro-bench. Check: B2 a CLI subcommand must NOT print success while doing nothing; the run/exec/ls/rm/stats stubs (recorded as stubs) must return a TYPED error + NON-ZERO exit, not Ok(())/printed success — verify the exit codes. bench-vm: numbers it emits should be real (not fabricated/defaulted); error paths fail loud. benches/micro.rs and any bench-coverage test must have LIVE assertions (not commented out). Anyhow at the CLI boundary is fine. Look for print_stdout/print_stderr in lib paths (should be in bins only). Contracts: §13 benchmark plan, §10.5 bin targets.`,
  },
  {
    key: 'api-hygiene',
    files: ['src/error.rs', 'src/lib.rs'],
    focus: `Cross-cutting public-API hygiene + error type (read error.rs and lib.rs fully; grep across all of src/ for the patterns). Check: B8 Error has per-subsystem variants with typed sources and #[from] (NOT String payloads and Error::Other everywhere); a #[from] variant for a FEATURE-GATED dep must ITSELF be #[cfg]-gated (an un-gated Hyper(#[from] hyper::Error) breaks the lean agent/test-runner builds — this was the review-34 headline bug; verify every #[from] for an optional dep is cfg-gated). Unused typed variants wired up or removed. #[non_exhaustive] on Error and every growable public type. #[must_use] on constructors/builders. No always-zero/never-read public fields. No pub leaking internals (Pipeline.stages, backend instance fields). Dead code removed (unreachable variants, restored fields never read, a dead second setuid block). B6 grep for module-global static Atomic/Mutex/OnceLock/OnceCell/Lazy outside the allocator module (and whether allow-global-state markers are justified). Per-module #![forbid(unsafe_code)] present on the I/O-free modules (config, agent::protocol, artifact cache_key, net). #![deny(missing_docs)] satisfied; Result fns have # Errors, panicking fns # Panics, unsafe blocks a real // SAFETY. Contracts: §10.2 API surface, §10.3 module responsibilities, error module.`,
  },
  {
    key: 'test-discipline',
    files: ['tests/common/mod.rs', 'tests/boot.rs', 'tests/concurrency.rs', 'tests/egress_proxy.rs', 'tests/exec_vsock.rs', 'tests/host_endpoint.rs', 'tests/lifecycle.rs', 'tests/metrics_limits.rs', 'tests/nested_virt.rs', 'tests/pipeline.rs', 'tests/proptests.rs', 'tests/shares_ro_rw.rs', 'tests/snapshot_restore.rs', 'tests/benchmark.rs'],
    focus: `TEST DISCIPLINE (rubric Part C — the meta-rubric; this is why bugs survived). For EVERY test, ask "write the buggy impl — does it go red?". Reject on sight and FLAG: (1) skip==pass — a test that return()s green when KVM/artifacts/caps are absent (skip must be VISIBLE; a zero-selection nextest filter is a CI failure); (2) asserts-nothing — discards the result / only println! / assertion commented out / a proptest that computes-and-drops; (3) dead-fake/wrong-target/self-fulfilling — the injected fake is never consulted on the path under test (FakeClock read only where restored==false); the assertion targets a path the code never uses (panic-residue on /sys/fs/cgroup/imp-vm-{vmid} when the real slice is nested under the delegated parent); order asserted by .contains("drop")/a count instead of a SEQUENCE; or the test PERFORMS the behavior itself then asserts a trivial outcome (runs its own RNG reseed, asserts code==0); (4) loose-or — OOM accepting 137||1||-1, or a guest-RAM OOM masquerading as a memory.max OOM (guest RAM <= cap → 137 regardless — must set guest RAM ABOVE cap and assert memory.events oom_kill>0); block-detection on "contains 403"; (5) coincidental-pass; (6) tests-the-opposite-of-its-name (tamper test that corrupts the .cache_key sidecar and asserts a REBUILD instead of corrupting artifact bytes and asserting abort); (7) mock-where-round-trip-required (put_file asserting bytes hit a UDS mock instead of reading the file back IN THE GUEST); (8) string-stand-ins (format!("imp-vm-{vmid}") instead of real socket paths, never varying pid; /30 ends_with(".2/30")); (9) determinism via a TRIVIAL/DummyStage rather than a real RootfsStage/SnapshotStage with a golden cross-process key. POSITIVE: serial from nextest serial-host group not #[serial_test::serial]; FakeVmm is a RECORDING fake that is actually DRIVEN (allocation order, retry/timeout, restore-vs-cold-boot selection, ordered teardown, no KVM); injected fakes CARRY assertions (Netlink fake records ZERO calls at boot AND restore; CgroupFs asserts exact limit-file contents + that an undelegated-controller limit fails loud); the per-VMM matrix consults capabilities() and the CH/primary path is NOT exempted; the required integration assertions are present AND SPECIFIC (snapshot reconnect incl guest re-bind + host-path rewrite; rotate live-CID/in-guest-MAC; reseed; resync FakeClock on FIRST post-restore call; HTTPS intercept logged + CONNECT falls through + filter-block recorded + intended-destination observed; ordered-Drop-on-panic ZERO residue on computed paths across ALL resource classes; N-VM concurrency distinct CID/VMID/socket; the pipeline tamper/cache-hit/determinism trio on REAL stages; zero-netlink). Flag the no-reason #[ignore]s (lifecycle force_kill, shares_ro_rw) as docs/test-hygiene. Use the test map; READ the test bodies — do not trust names.`,
  },
  {
    key: 'gates-partD',
    files: ['justfile', 'deny.toml', '.config/nextest.toml', '.github/workflows/ci.yml', 'scripts/ban-global-state.sh', 'scripts/with-delegated-scope.sh', 'Cargo.toml', 'src/lib.rs'],
    focus: `AUTOMATED GATES (rubric Part D). Confirm each gate exists and MATCHES the rubric, and flag gaps. Known partial: the "build AND clippy each build target" gate covers ONLY --features agent; there is NO --no-default-features --features test-runner and NO --features guest-tools build/clippy/tree assertion in ci.yml — confirm and report (a lean binary could re-couple to the host stack or fail to compile undetected; this is the SAME class as the review-34 broken-agent-build bug). Also verify: -D warnings is set the SAME way locally (justfile) and in CI; cargo-deny ignores each carry a real per-crate rationale (no bulk/stale); nextest has a PER-TEST timeout on BOTH profiles; semver-checks present; the --ignored integration matrix selects >0 tests in BOTH the rootless and privileged recipes (a filter matching no test name exiting "0 tests run" is a FAILURE not a pass — check test(rootless)|test(smoltcp) and its complement actually select tests given the test names); the global-state ban script pattern is correct and not trivially bypassable; the lint header in lib.rs matches the rubric's required deny set. The cargo-hack powerset is RED (known debt — note, don't re-litigate). Contracts: §12.1/§12.2 gates, design §10.5 single-host-feature rationale, rubric Part D table.`,
  },
]

// ---------------------------------------------------------------------------
// Phase 1 — domain finders (barrier; we dedupe across domains before verify)
// ---------------------------------------------------------------------------
function finderPrompt(d) {
  return `${PREAMBLE}

=== YOUR DOMAIN: ${d.key} ===
Assigned files (read them fully): ${d.files.join(', ')}
Focus & rubric items for this domain:
${d.focus}
${EMPIRICAL}

Review these files now and return your structured findings.`
}

// ---------------------------------------------------------------------------
// Phase 0 — privileged-readiness GATE (block-and-ask), then optional empirical ingest
// ---------------------------------------------------------------------------
if (REVIEW_MODE !== 'static') {
  phase('Preflight')
  const pf = await agent(
    `Run \`bash scripts/review-preflight-priv.sh\` from the repo root ${REPO} (use the Bash tool; the script is read-only). ` +
      `Report ready=true ONLY if it prints "PREFLIGHT: READY" and exits 0. Put its check lines in summary; if NOT ready, ` +
      `put the listed reasons + the remediation command (usually \`just bless\`) in remediation.`,
    { label: 'preflight:priv', phase: 'Preflight', schema: PREFLIGHT_SCHEMA }
  )
  if (!pf || !pf.ready) {
    const remediation = (pf && pf.remediation) || 'Run `just bless` (re-bless the capability runner; caps strip on rebuild), then re-run.'
    log('PREFLIGHT BLOCKED — privileged suites cannot run. ' + remediation)
    return {
      blocked: true,
      reason: 'privileged test suites are not runnable on this host (preflight failed)',
      remediation,
      preflight: pf || null,
      note: 'A privileged-aware review must NOT silently fall back to static-only. Remediate (usually `just bless`) and re-run, or invoke with args={mode:"static"} to deliberately run a static-only review.',
    }
  }
  log('Preflight READY — privileged suites can run.')

  if (typeof args !== 'undefined' && args && args.privilegedLog) {
    phase('Empirical ingest')
    const ev = await agent(
      `Read these test-run logs (use the Read tool) and produce a COMPACT ground-truth summary for a code review.\n` +
        `- privileged suite log: ${args.privilegedLog}\n` +
        (args.residueLog ? `- residue/leak log: ${args.residueLog}\n` : '') +
        `Report tersely: the nextest pass/fail/skip totals; EVERY failed test with its panic/assert message + file:line; ` +
        `which host-facing paths PASSED (boot/concurrency/snapshot+restore/metrics/proxy/teardown, per backend); and any ` +
        `residue/leaks. This is the ground truth reviewers use to set empirical_status.`,
      { label: 'ingest:test-results', phase: 'Empirical ingest' }
    )
    EMPIRICAL =
      '\n\n=== EMPIRICAL GROUND TRUTH (an ACTUAL privileged/rootless run on a KVM host) ===\n' +
      (ev || '(no summary produced)') +
      '\nUse this to set empirical_status: confirmed-by-test / refuted-by-test / unverified-no-test-exercises-it / ' +
      'not-applicable. A finding in an UNtested path is NOT refuted by a green run — mark unverified-no-test-exercises-it ' +
      '(that itself substantiates a test-gap). Only mark refuted-by-test when a test truly exercises the path and contradicts the finding.'
  }
}

phase('Domain review')
const finderResults = await parallel(
  DOMAINS.map((d) => () =>
    agent(finderPrompt(d), { label: `find:${d.key}`, phase: 'Domain review', schema: FINDING_SCHEMA })
  )
)

// Flatten + tag with domain + stable id
const all = []
finderResults.forEach((r, di) => {
  if (!r || !Array.isArray(r.findings)) return
  r.findings.forEach((f, fi) => {
    all.push(Object.assign({}, f, { domain: DOMAINS[di].key, _id: `${DOMAINS[di].key}-${fi}` }))
  })
})
log(`Phase 1 complete: ${all.length} raw findings across ${DOMAINS.length} domains.`)

// Light cross-domain dedupe: key on category + first-location-file + normalized title head.
function norm(s) { return (s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 48) }
function fileOf(loc) { return (loc || '').split(':')[0] }
const seen = new Map()
const deduped = []
for (const f of all) {
  const k = `${f.category}|${fileOf((f.locations || [])[0])}|${norm(f.title)}`
  if (seen.has(k)) {
    const keep = seen.get(k)
    keep._dupes = (keep._dupes || []).concat([f._id])
    if ((f.confidence || 0) > (keep.confidence || 0)) keep.confidence = f.confidence
    continue
  }
  seen.set(k, f)
  deduped.push(f)
}
log(`Deduped to ${deduped.length} findings (${all.length - deduped.length} merged).`)

// ---------------------------------------------------------------------------
// Phase 2 — adversarial verification
// ---------------------------------------------------------------------------
const LENSES = {
  correctness: 'Lens: CORRECTNESS. Read the cited code and the surrounding function. Does the bug actually occur on a reachable path? Trace it. Default to refuted if you cannot reproduce the reasoning from the code.',
  test: "Lens: DOES-THE-TEST-STAY-GREEN. If this is a test-gap, write the buggy implementation the test nominally guards and decide whether the existing test would still PASS (theater) — confirm only if a buggy impl survives. If a code bug, decide whether any existing test would catch it.",
  justified: 'Lens: IS-THIS-ALREADY-JUSTIFIED-OR-INTENDED. Check the do-not-re-report baseline and impl-notes; is this a defensible/intended deviation that belongs in impl-notes rather than the report? If so, mark is_justified_deviation=true with verdict=nuanced.',
}

function verifyPrompt(f, lensKey) {
  return `You are an adversarial verifier of a single code-review finding for the imp-testing crate (repo root ${REPO}). Your DEFAULT is to REFUTE: only confirm if the cited code genuinely shows the problem. Read the actual files at the cited locations (and enough surrounding context to judge reachability).

${DONT_REPORT}
${EMPIRICAL}

${LENSES[lensKey]}

FINDING UNDER TEST:
- title: ${f.title}
- domain: ${f.domain}
- severity(claimed): ${f.severity}
- category: ${f.category}
- rubric_ref: ${f.rubric_ref}   design_ref: ${f.design_ref}
- locations: ${(f.locations || []).join(', ')}
- evidence(claimed): ${f.evidence}
- red_test(claimed): ${f.red_test}

Verdict rules: "confirmed" = the problem is real as described; "refuted" = not a real problem (false positive, misread, or already-handled nearby); "nuanced" = partly real but mis-severity/mis-scoped or actually a justified deviation. Set corrected_severity to what you believe after reading the code. Set is_justified_deviation=true if it belongs in impl-notes. In note, state what the code ACTUALLY shows at the cited lines.`
}

phase('Verify')
const toVerify = deduped.filter((f) => ['Critical', 'High', 'Medium'].includes(f.severity))
const passthrough = deduped.filter((f) => !['Critical', 'High', 'Medium'].includes(f.severity))
log(`Verifying ${toVerify.length} findings (Critical/High get 3 lenses, Medium gets 1); ${passthrough.length} Low/Nit pass through unverified.`)

const verified = await parallel(
  toVerify.map((f) => () => {
    const lenses = ['Critical', 'High'].includes(f.severity)
      ? ['correctness', 'test', 'justified']
      : ['correctness']
    return parallel(
      lenses.map((L) => () =>
        agent(verifyPrompt(f, L), { label: `verify:${f._id}/${L}`, phase: 'Verify', effort: 'high', schema: VERDICT_SCHEMA })
      )
    ).then((vs) => {
      const verdicts = vs.filter(Boolean)
      const refuted = verdicts.filter((v) => v.verdict === 'refuted').length
      const confirmed = verdicts.filter((v) => v.verdict === 'confirmed').length
      const justified = verdicts.some((v) => v.is_justified_deviation)
      // majority refute => drop; else keep with the highest corrected severity reasoning
      const survives = verdicts.length === 0 ? true : refuted < verdicts.length / 2
      // corrected severity: take the modal/most-cautious among non-refute verdicts, fall back to claimed
      const sevRank = { Critical: 5, High: 4, Medium: 3, Low: 2, Nit: 1 }
      let corrected = f.severity
      const sevs = verdicts.filter((v) => v.verdict !== 'refuted').map((v) => v.corrected_severity)
      if (sevs.length) {
        corrected = sevs.reduce((a, b) => (sevRank[b] < sevRank[a] ? b : a), sevs[0])
      }
      return Object.assign({}, f, {
        verdict_summary: { confirmed, refuted, total: verdicts.length, survives, justified },
        corrected_severity: corrected,
        is_justified_deviation: f.is_justified_deviation || justified,
        verdict_notes: verdicts.map((v) => `${v.verdict}/${v.corrected_severity}: ${v.note}`),
      })
    })
  })
)

const verifiedOk = verified.filter(Boolean)
const survivors = verifiedOk.filter((f) => f.verdict_summary && f.verdict_summary.survives)
const dropped = verifiedOk.filter((f) => f.verdict_summary && !f.verdict_summary.survives)
log(`Verification done: ${survivors.length} survived, ${dropped.length} refuted/dropped.`)

// ---------------------------------------------------------------------------
// Return everything I need to synthesize the report.
// ---------------------------------------------------------------------------
return {
  counts: {
    raw: all.length,
    deduped: deduped.length,
    verified: verifiedOk.length,
    survived: survivors.length,
    dropped: dropped.length,
    passthrough: passthrough.length,
  },
  survivors,
  dropped,
  passthrough,
}
