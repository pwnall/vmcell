//! The §15.4 **handler** battery, live half (design §10.5, §18 delta 6b): register a `handlers`
//! entry, build the rootfs that bakes it, boot it, and have **that handler's own applet answer in
//! the guest**.
//!
//! This is delta 6b's own named gate. Its notes deferred it to delta 9, delta 9 shipped without it,
//! and what shipped instead was `vmcell build --handler-label <any>` producing a rootfs with **no
//! guest tools and no applet symlinks at all** — and reporting success. Every KVM-free leg in
//! `handler_registry.rs` was green throughout: the registry parsed the entry, the stage fetched and
//! digest-verified the binary, the stage published it under `guest_tools-<label>` — and the one
//! consumer, the rootfs pack tail, read the hardcoded default key and got `None`. An artifact-map key
//! is a `String`, so a producer registering under a name no consumer reads is not a compile error.
//!
//! # What the guest is asked, and why each question is here
//!
//! The reader is the registered handler's own `xattr` applet, which answers with a real
//! `listxattr(2)` on a path — so one applet proves both its own liveness and the presence or absence
//! of every other path the roster was supposed to produce:
//!
//! * `/vmcell-tools/xattr` — exit 0. The applet **ran in the guest** and answered. If the handler's
//!   binary had not been baked, there would be nothing to exec at all.
//! * `/vmcell-tools/kvm-ok` — exit 0. The roster's *second* entry, so "one symlink got emitted" is
//!   not mistaken for the roster.
//! * `/vmcell-tools/curl` — exit 1 (`ENOENT`). `curl` is in
//!   [`vmcell_protocol::GUEST_TOOLS_APPLETS`] but **not** in this entry's declared roster, so its
//!   absence is what proves the emitted symlinks came from the registry entry (data) rather than
//!   from vmcell's const. The positive control for that negative is the two legs above.
//! * `/vmcell-tools/vmcell-guest-tools` — exit 0. The multicall binary itself, at the dest the
//!   manifest names, which is the artifact H1 dropped.
//!
//! # The artifact map is deliberately missing the default key
//!
//! The pack below is handed `{steward, guest_tools-acme}` and **no** `guest_tools` — which is exactly
//! what `vmcell build --handler-label acme` composes, since that pipeline runs one handler stage.
//! With the pre-fix tail the image then carries no `/vmcell-tools` at all and the first exec fails,
//! which is the shape the defect shipped. Seeding the default key as well would let a tail reading
//! the literal bake vmcell's own binary and pass every leg but the `curl` one.
//!
//! CH-only, and `#[ignore]`d like every live leg: `just test-privileged` selects it
//! (`--run-ignored all` over `kind(test)`), and its KVM-free twin —
//! `handler_registry.rs::a_registered_handler_is_baked_into_the_rootfs`, which asserts the same
//! injection against the packed image's bytes — runs everywhere.

use vmcell::artifact::registry::UNPINNED_PATH_KEY;
use vmcell::config::{RootfsSource, VmConfig};

mod common;

/// The label this battery registers. Not `default`: the whole point is a handler a consumer named.
const HANDLER_LABEL: &str = "acme";

/// The applet roster the registered entry declares — a strict, deliberate **subset** of
/// [`vmcell_protocol::GUEST_TOOLS_APPLETS`].
///
/// A subset because that is what makes the roster's provenance provable in the guest: every name
/// here must exist under `/vmcell-tools`, and at least one name in the const but not here must not.
/// Both entries are real applets of the multicall binary, because a symlink whose name the binary
/// cannot dispatch exits 2 — and this battery is about the symlink being there, not about the
/// dispatch table, which is `const`-asserted host-side.
const DECLARED_APPLETS: [&str; 2] = ["xattr", "kvm-ok"];

/// A name in [`vmcell_protocol::GUEST_TOOLS_APPLETS`] that [`DECLARED_APPLETS`] does **not** carry.
const UNDECLARED_APPLET: &str = "curl";

/// The multicall binary's own dest inside the tools dir, as `rootfs_injection_manifest` writes it.
const TOOLS_BIN: &str = "/vmcell-tools/vmcell-guest-tools";

/// Packs a bootable rootfs whose handler is the **registered** `acme` entry, into `staging`.
///
/// Never into the canonical artifacts dir (M-BIN-6): packing there would clobber the image every
/// other suite boots.
///
/// The steward and the multicall binary are built by the real stages into `staging`, so the applet
/// answering in the guest is **this tree's**, freshly compiled — not whatever `vmcell build` last
/// published. The registered handler then points at that freshly built binary through the F7
/// `unpinned_path` shape, which is the one registration shape that needs no network; a digest entry
/// would differ only in how the bytes arrive, and everything this battery asserts happens after they
/// have arrived.
///
/// The OCI blob cache is sited on the artifacts dir, not on `staging`, so the base layers are a cache
/// hit off whatever the canonical build already pulled.
async fn pack_handler_rootfs(staging: &std::path::Path) -> std::path::PathBuf {
    use vmcell::artifact::Stage as _;

    std::fs::create_dir_all(staging).expect("create the staging dir");

    // The upstream half of the pipeline `vmcell build` runs: the pins, the steward, and the DEFAULT
    // handler — the last one only to produce a real multicall binary for the registration below to
    // point at.
    let built = vmcell::artifact::Pipeline::new(staging.to_path_buf())
        .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
            overlay_file: vmcell::artifact::pins_overlay_path(),
        }))
        .add_stage(Box::new(vmcell::artifact::steward::StewardStage {}))
        .add_stage(Box::new(
            vmcell::artifact::guest_tools::GuestToolsStage::new(),
        ))
        .build(&vmcell::artifact::Cache::default())
        .await
        .expect("building the steward + guest tools must succeed");
    let workspace_tools = built
        .paths
        .get(&vmcell::artifact::handler::handler_artifact_key(None))
        .expect("the default handler stage must publish a binary to register")
        .clone();
    assert!(
        workspace_tools.starts_with(staging),
        "the binary this battery registers must come from this run's staging dir ({}), so the applet \
         answering in the guest is THIS tree's — got {}",
        staging.display(),
        workspace_tools.display()
    );

    // Register it as a consumer would, and resolve it back through the ONE registry reader — so the
    // roster the pack emits is the one the entry declares, parsed by the shipped parser.
    let overlay_path = staging.join("handlers-overlay.json");
    std::fs::write(
        &overlay_path,
        format!(
            r#"{{ "handlers": {{ "{HANDLER_LABEL}": {{ "{UNPINNED_PATH_KEY}": "{}",
                 "applets": {} }} }} }}"#,
            workspace_tools.display(),
            serde_json::to_string(&DECLARED_APPLETS).expect("render the roster"),
        ),
    )
    .expect("write the handlers overlay");
    let entry = vmcell::artifact::resolve_handler_registry(Some(&overlay_path))
        .expect("the handlers overlay must resolve")
        .into_iter()
        .find(|e| e.label == HANDLER_LABEL)
        .unwrap_or_else(|| panic!("the `{HANDLER_LABEL}` handler entry"));
    assert_eq!(
        entry.applet_roster(),
        DECLARED_APPLETS.map(str::to_string).to_vec(),
        "the entry's own roster is what the pack must emit"
    );

    // The labelled handler stage, publishing under its own key.
    let handler_stage = vmcell::artifact::guest_tools::GuestToolsStage::labelled(
        Some(HANDLER_LABEL),
        Some(entry.source.clone()),
    );
    let handler_out = handler_stage.out_path(staging);
    let handler_outputs = handler_stage
        .run(&vmcell::artifact::StageInputs::default(), &handler_out)
        .await
        .expect("the registered handler must publish");

    // `{steward, guest_tools-acme}` and nothing else — see the module docs.
    let mut inputs = vmcell::artifact::StageInputs::default();
    inputs.artifacts.insert(
        "steward".to_string(),
        built
            .paths
            .get("steward")
            .expect("the steward stage must publish")
            .clone(),
    );
    inputs.artifacts.extend(handler_outputs.artifacts.clone());
    assert!(
        !inputs
            .artifacts
            .contains_key(&vmcell::artifact::handler::handler_artifact_key(None)),
        "the pack must be handed only the LABELLED handler, or a tail reading the default key would \
         bake vmcell's own binary and this battery would pass with the label ignored"
    );

    // The registered base's own layers, through the one pull→verify→decode law.
    let rootfs_entry = vmcell::artifact::resolve_rootfs_entry(
        None,
        vmcell::artifact::pins_overlay_path().as_deref(),
    )
    .expect("resolving the rootfs registry must succeed")
    .expect("the `default` rootfs label must be registered");
    let (image, digest) = match rootfs_entry.registration {
        vmcell::artifact::RootfsRegistration::Digest { image, digest } => (image, digest),
        other => panic!(
            "this battery bakes a handler into the DIGEST-pinned default base; `rootfs.default` \
             resolved to {other:?} instead"
        ),
    };
    let streams = vmcell::artifact::rootfs::oci::base_layer_tar_streams(&image, &digest)
        .await
        .expect("resolving the pinned base's layers must succeed");

    let out = staging.join("rootfs-handler.erofs");
    vmcell::artifact::rootfs::pack_rootfs_with_injection(
        streams,
        &inputs,
        &out,
        // THE two declarations under test: which handler, and which applets.
        &vmcell::artifact::rootfs::PackOptions::new()
            .with_handler_label(Some(HANDLER_LABEL))
            .with_applets(entry.applet_roster()),
    )
    .await
    .expect("packing the handler rootfs must succeed");
    assert!(out.exists(), "the pack must write {}", out.display());
    out
}

/// Execs `argv` in the guest and returns `(exit code, stdout lines, stderr)`.
///
/// Deliberately **without** the sibling batteries' "the applet is missing, rebuild" guard: here a
/// missing applet is the defect under test, and the test's own assertions name it.
#[cfg(feature = "cloud-hypervisor")]
async fn exec_lines(
    steward: &mut vmcell::StewardClient,
    argv: &[&str],
) -> (i32, Vec<String>, String) {
    let out = steward
        .exec(vmcell::ExecRequest::new(
            argv.iter().map(|s| (*s).to_string()).collect(),
        ))
        .await
        .unwrap_or_else(|e| panic!("exec {argv:?} failed: {e}"));
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    (
        out.code,
        lines,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// §18 delta 6b's live gate: **a registered handler boots and its applet answers in-guest**, and the
/// applet roster the guest carries is the registry entry's rather than vmcell's const.
///
/// RED on the inverse (restore `inputs.artifacts.get("guest_tools")` at the pack tail): the image
/// carries no `/vmcell-tools` at all, so the first exec — the registered handler's own `xattr`
/// applet — cannot run, and the leg fails naming it. RED on a tail that emitted no symlinks: the
/// `xattr`/`kvm-ok` legs fail while `TOOLS_BIN` still answers, which distinguishes "no binary" from
/// "no links". RED on a pack that ignored the declared roster and emitted the const's: the
/// `UNDECLARED_APPLET` leg exits 0.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn a_registered_handlers_applet_answers_in_the_guest() {
    // Ensure the canonical artifacts FIRST: that is what warms the shared OCI blob cache the pack
    // reuses (and it is at-most-once across the suite).
    let _ = common::get_rootfs();

    // A `TempDir`, so a panicking assertion cannot leave a ~100 MB image behind: cleanup is on the
    // panic path too.
    let staging_dir = tempfile::tempdir().expect("staging tempdir");
    let rootfs = pack_handler_rootfs(staging_dir.path()).await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let cfg = VmConfig::builder(common::get_vmlinux(), RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build()
        .expect("VmConfig");
    let mut vm = common::start_vm(&vmm, cfg).await;
    let steward = vm.steward(None).await.expect("steward");

    // 1. The registered handler's binary is baked, at the dest the manifest names. Asked first
    //    through the applet itself, so a failure here is unambiguous: the reader IS the artifact.
    let probe = format!("/vmcell-tools/{}", DECLARED_APPLETS[0]);
    let (code, lines, stderr) = exec_lines(steward, &[&probe, "list", TOOLS_BIN]).await;
    assert_eq!(
        code, 0,
        "the REGISTERED handler's `{}` applet must run in the guest and answer about {TOOLS_BIN} \
         (stdout {lines:?}, stderr {stderr:?}) — an exec failure here means the pack baked no \
         handler at all, which is what reading the default artifact key produced",
        DECLARED_APPLETS[0]
    );
    assert!(
        lines.is_empty(),
        "the image is packed `strip`, so the multicall binary carries no attributes: {lines:?}"
    );

    // 2. Every DECLARED applet's symlink is there — the roster reached the image, all of it.
    for applet in DECLARED_APPLETS {
        let path = format!("/vmcell-tools/{applet}");
        let (code, _, stderr) = exec_lines(steward, &[&probe, "list", &path]).await;
        assert_eq!(
            code, 0,
            "the declared roster's `{applet}` symlink must exist in the guest: {stderr}"
        );
    }

    // 3. The negative: a name in vmcell's const that this ENTRY did not declare is absent. This is
    //    what makes claim 2 a statement about the registry entry and not about the const.
    assert!(
        vmcell_protocol::GUEST_TOOLS_APPLETS.contains(&UNDECLARED_APPLET),
        "`{UNDECLARED_APPLET}` must be in the const roster for its absence to prove anything"
    );
    assert!(
        !DECLARED_APPLETS.contains(&UNDECLARED_APPLET),
        "`{UNDECLARED_APPLET}` must NOT be in the declared roster"
    );
    let undeclared_path = format!("/vmcell-tools/{UNDECLARED_APPLET}");
    let (code, lines, _) = exec_lines(steward, &[&probe, "list", &undeclared_path]).await;
    assert_eq!(
        code, 1,
        "a `GUEST_TOOLS_APPLETS` name this entry never declared must be ABSENT — a registered \
         handler's roster is data (§10.5), and the applet's own read must fail on it (stdout \
         {lines:?})"
    );

    vm.shutdown().await.expect("shutdown");
    // Drops the ~100 MB staging tree. The shared OCI blob cache lives in the artifacts dir, so the
    // next leg still gets its cache hit.
    drop(staging_dir);
}
