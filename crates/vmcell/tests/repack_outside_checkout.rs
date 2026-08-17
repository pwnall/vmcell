//! Repacking from **outside** a vmcell checkout (design §4.2; §18 delta 7) — the CLI half's one
//! hard checkout dependency, and its severance.
//!
//! `GuestToolsStage` ran `cargo build -p vmcell-guest-tools` against
//! [`workspace_root`](vmcell::artifact) unconditionally, in both `cache_key` and `run`, and
//! `workspace_root` *always answers* — falling back to the caller's own directory when no vmcell
//! sources are above it. From a consumer's workspace that meant one of two bad outcomes: a `cargo
//! build` fired into somebody else's workspace, or a bare "binary source missing at …" naming a
//! path the operator never wrote. Neither said what to pass. `--tools <path>` is what to pass.
//!
//! **No in-process test can see this.** `CARGO_MANIFEST_DIR` and the CWD are process-global and
//! both point INTO the checkout under cargo/nextest, and `PATH` — which decides whether `cargo` is
//! reached at all — is process-global too. So the parents below re-exec THIS test binary with the
//! position and the `PATH` they want, and fail with the child's own output. Same shape as
//! `kernel_toolkit.rs`'s `resolve_pins_runs_outside_the_vmcell_source_tree`, one stage over.
//!
//! KVM-free, network-free, and — this being the whole point — toolchain-free: the `cargo` on the
//! child's `PATH` is a stub that records that it was reached.

use std::path::{Path, PathBuf};

use vmcell::artifact::guest_tools::GuestToolsStage;
use vmcell::artifact::handler::HandlerSource;
use vmcell::artifact::{Stage, StageInputs};

mod common;

/// Env marker putting the re-exec'd child in the **consumer position**: no `CARGO_MANIFEST_DIR`,
/// and a CWD with no vmcell checkout above it.
const CONSUMER_POSITION: &str = "VMCELL_TEST_REPACK_CONSUMER_POSITION";

/// Env var naming the file the `cargo` stub on the child's `PATH` creates when it is reached.
/// Its presence or absence is how "did this shell out to cargo?" is answered — a question no
/// in-process assertion can ask.
const CARGO_MARKER: &str = "VMCELL_TEST_REPACK_CARGO_MARKER";

/// The guest-tools child test's exact libtest name (an integration-test binary namespaces nothing).
const TOOLS_CHILD: &str = "guest_tools_stage_honors_its_position";

/// The **ext4 producer's** child test (§18 delta 8: "the delta-7 from-outside-a-checkout leg
/// repeated for this producer"). A second child rather than more legs inside the first: the
/// question is about a different stage, and one child failing must not hide the other's verdict.
const EXT4_CHILD: &str = "ext4_pack_honors_its_position";

/// The bytes the `--tools` fixture carries; distinctive so "the published file" can never be
/// confused with a compiled binary that happens to be there.
const PREBUILT_BYTES: &[u8] = b"#!/bin/sh\necho vmcell-delta7-prebuilt-handler\n";

/// The child prints this plus the position it detected. The parents assert on it, because
/// `--exact <name>` matching **zero** tests exits 0 with "0 passed" — a re-exec gate that does not
/// check the child actually ran is the `--no-tests=fail` defect wearing a different hat.
const BANNER: &str = "delta7-child-position=";

/// Writes a `cargo` stub into `dir/bin` that touches `$CARGO_MARKER` and fails, and returns the
/// directory to prepend to `PATH`.
///
/// It **fails** (127, cargo's own "command not found" code) rather than succeeding: a stub that
/// exited 0 would let the workspace arm proceed to copy a binary that does not exist, and the
/// resulting error would be about the copy rather than about the build.
fn cargo_stub_dir(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).expect("create the stub bin dir");
    let stub = bin.join("cargo");
    std::fs::write(
        &stub,
        format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >> \"${CARGO_MARKER}\"\n\
             echo 'stub cargo: reached' >&2\nexit 127\n"
        ),
    )
    .expect("write the cargo stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the cargo stub");
    }
    bin
}

/// Re-execs this test binary running only [`CHILD`], with `PATH` prefixed by a `cargo` stub whose
/// marker file is `marker`. `consumer_position` decides whether `CARGO_MANIFEST_DIR` is cleared and
/// the CWD moved out of the checkout.
///
/// Returns the child's output so each parent can assert on it and print it on failure.
fn run_child(
    child: &str,
    root: &Path,
    marker: &Path,
    consumer_position: bool,
) -> std::process::Output {
    let exe = std::env::current_exe().expect("the running test binary's path");
    let stub_bin = cargo_stub_dir(root);
    let path = match std::env::var_os("PATH") {
        Some(p) => {
            let mut dirs = vec![stub_bin];
            dirs.extend(std::env::split_paths(&p));
            std::env::join_paths(dirs).expect("compose PATH")
        }
        None => stub_bin.into_os_string(),
    };
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["--exact", child, "--nocapture"])
        .args(["--test-threads", "1"])
        .env(CARGO_MARKER, marker)
        .env("PATH", path);
    if consumer_position {
        cmd.env_remove("CARGO_MANIFEST_DIR")
            .env(CONSUMER_POSITION, "1")
            .current_dir(root);
    }
    cmd.output().expect("re-exec the test binary")
}

/// Asserts the child succeeded **and ran the legs for `position`**, printing its own output when
/// it did not.
fn expect_child_ok(child: &str, out: &std::process::Output, position: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "`{child}` must pass in the {position} position, got {}\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status,
    );
    assert!(
        stdout.contains(&format!("{BANNER}{position}")),
        "the child must have RUN the {position}-position legs — a filter selecting zero tests \
         exits 0 too. Its output was:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}

// §4.2's gate, green half: from a directory with no vmcell checkout above it and no
// `CARGO_MANIFEST_DIR`, `--tools` produces the handler artifact — and does so **without reaching
// `cargo` at all**, which is the property the flag exists for.
//
// RED on the inverse, two ways: (a) point `run`'s `Prebuilt` arm at `publish_workspace_build` —
// the child's published bytes are wrong and the cargo marker appears; (b) restore
// `workspace_root()` in place of `require_source_checkout()` — the refusal leg's message stops
// naming `--tools`.
#[test]
fn the_tools_override_packs_a_handler_from_outside_a_checkout() {
    let outside = tempfile::tempdir().expect("tempdir");
    let marker = outside.path().join("cargo-was-reached");
    let out = run_child(TOOLS_CHILD, outside.path(), &marker, true);
    expect_child_ok(TOOLS_CHILD, &out, "consumer");
    assert!(
        !marker.exists(),
        "nothing in the consumer position may shell out to `cargo`: `--tools` is injected verbatim \
         and the workspace build is refused before it spawns anything. The stub recorded: {}",
        std::fs::read_to_string(&marker).unwrap_or_default()
    );
}

// The positive control for the leg above, and it is not decoration: "the cargo marker is absent"
// proves nothing unless the stub is genuinely on the path this code takes. Run the SAME child
// in the checkout position with the SAME stub — the workspace arm must reach it. This also pins
// that delta 7 did not quietly disable the workspace build for everyone.
//
// RED on the inverse (make `require_source_checkout` refuse unconditionally): the marker never
// appears and this reddens, while the consumer-position test above would still pass.
#[test]
fn the_workspace_build_still_reaches_cargo_inside_a_checkout() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let marker = scratch.path().join("cargo-was-reached");
    let out = run_child(TOOLS_CHILD, scratch.path(), &marker, false);
    expect_child_ok(TOOLS_CHILD, &out, "checkout");
    let recorded = std::fs::read_to_string(&marker).unwrap_or_else(|e| {
        panic!(
            "inside a checkout the workspace build must still reach `cargo` ({} unreadable: {e}) \
             — without this, the consumer-position gate's \"cargo was not reached\" is vacuous",
            marker.display()
        )
    });
    assert!(
        recorded.contains("vmcell-guest-tools"),
        "the stub must have been asked to build the handler crate, got: {recorded}"
    );
}

// The child. Which legs run is decided by the env the parents above set, and the `--tools` legs
// run in EVERY position on purpose — position-independence is the claim, so asserting it in only
// one position would leave the other free to rot.
#[tokio::test]
async fn guest_tools_stage_honors_its_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("prebuilt/vmcell-guest-tools");
    std::fs::create_dir_all(src.parent().expect("parent")).expect("mkdir");
    std::fs::write(&src, PREBUILT_BYTES).expect("write the --tools fixture");
    let inputs = StageInputs::default();

    // `--tools`: the bytes are published verbatim, wherever this is running from.
    let published = dir.path().join("out/guest_tools");
    GuestToolsStage::labelled(None, Some(HandlerSource::Prebuilt { path: src.clone() }))
        .run(&inputs, &published)
        .await
        .expect("`--tools` must publish its bytes from any position");
    assert_eq!(
        std::fs::read(&published).expect("read the published handler"),
        PREBUILT_BYTES,
        "the published handler must be `--tools`'s own bytes"
    );

    let consumer = std::env::var_os(CONSUMER_POSITION).is_some();
    println!(
        "{BANNER}{}",
        if consumer {
            "consumer"
        } else if std::env::var_os(CARGO_MARKER).is_some() {
            "checkout"
        } else {
            "undriven"
        }
    );
    if consumer {
        // The red half of §4.2's gate: no checkout and no `--tools` is a REFUSAL that names the
        // crate it cannot build and the flag that supplies it — never an image with no applets.
        let never = dir.path().join("out/workspace-build");
        let err = GuestToolsStage::new()
            .run(&inputs, &never)
            .await
            .expect_err("a workspace build outside a checkout must be refused");
        let msg = err.to_string();
        for needle in ["vmcell-guest-tools", "--tools"] {
            assert!(
                msg.contains(needle),
                "the refusal must name `{needle}`, or the operator cannot act on it: {msg}"
            );
        }
        assert!(
            !never.exists(),
            "a refused build must publish nothing at {}",
            never.display()
        );
        // …and it refused BEFORE spawning anything: the parent asserts this too, but asserting it
        // here makes the child's own failure name the position.
        let marker = std::env::var_os(CARGO_MARKER).expect("the parent sets the marker path");
        assert!(
            !Path::new(&marker).exists(),
            "the refusal must come before `cargo` is spawned"
        );
    } else if let Some(marker) = std::env::var_os(CARGO_MARKER) {
        // The checkout-position positive control (parent-driven, stubbed `cargo`).
        let out = dir.path().join("out/workspace-build");
        let err = GuestToolsStage::new()
            .run(&inputs, &out)
            .await
            .expect_err("the stubbed cargo exits 127, so the build fails");
        assert!(
            err.to_string().contains("vmcell-guest-tools"),
            "a failed workspace build must name the crate: {err}"
        );
        assert!(
            Path::new(&marker).exists(),
            "inside a checkout the workspace arm must reach `cargo`"
        );
    }
    // The remaining case — a plain `cargo test` run inside the checkout with no stub on `PATH` —
    // deliberately drives no workspace build: it would spend minutes in a real `cargo build`
    // for a claim the stubbed positive control above already makes. Stated so the omission reads
    // as a decision rather than an oversight; the `--tools` legs above still run here.
}

// -----------------------------------------------------------------------------------------------
// §18 delta 8: the same leg, for the ext4 producer.
// -----------------------------------------------------------------------------------------------

/// The one-member-plus-`libc6` layer the ext4 child packs.
///
/// Deliberately tiny and synthetic: this leg is about **position**, not about content, and pulling
/// an OCI base would make a network-free test network-bound. `usr/lib/libc.so.6` is there because
/// the one tail's `libc6` scan demands it whenever the default (glibc) steward is injected — the
/// same scan the erofs route runs, which is the point of there being one merge.
#[cfg(all(feature = "pipeline", feature = "ext4-producer"))]
fn ext4_probe_layer() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        for (path, bytes) in [
            ("usr/lib/libc.so.6", &b"so"[..]),
            ("opt/marker", &b"outside"[..]),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            b.append_data(&mut h, path, bytes).expect("append");
        }
        b.finish().expect("finish");
    }
    buf
}

// §18 delta 8's *Gate*, second clause: "the delta-7 from-outside-a-checkout leg repeated for this
// producer (R6's capability sentence covers both packers)". From a directory with no vmcell
// checkout above it and no `CARGO_MANIFEST_DIR`, the ONE tail packs an **ext4** image — and reaches
// `cargo` no more than the erofs route does.
//
// This is not a foregone conclusion just because the erofs leg passes: the ext4 route adds a
// process spawn (`mkfs.ext4`), a version probe that builds a scratch image, and a staging file
// written beside the output. Any of those could have anchored on the checkout.
//
// RED on the inverse: give `Ext4Producer::probe` a `workspace_root()`-anchored scratch path (or
// have `pack` stage its tar there) and the consumer-position child writes outside the tree it was
// pointed at; make the ext4 route reach `GuestToolsStage`'s workspace build and the marker appears.
#[cfg(all(feature = "pipeline", feature = "ext4-producer"))]
#[test]
fn the_ext4_producer_packs_from_outside_a_checkout() {
    // The **parent** asks the one law, not the child: a child that skipped would print no banner and
    // `expect_child_ok` would report it as "the filter selected zero tests", which is a true
    // statement about the wrong thing. Before this the file answered an absent `mkfs.ext4` with a
    // bare `println!("SKIP") + return` under a doc comment claiming to record a skip — docs/90 G3, a
    // green PASS with nothing in the manifest for the reviewer to see.
    if common::probe_ext4_or_record_skip().is_none() {
        return;
    }
    let outside = tempfile::tempdir().expect("tempdir");
    let marker = outside.path().join("cargo-was-reached");
    let out = run_child(EXT4_CHILD, outside.path(), &marker, true);
    expect_child_ok(EXT4_CHILD, &out, "consumer");
    assert!(
        !marker.exists(),
        "packing an ext4 rootfs from the consumer position must not shell out to `cargo`. The \
         stub recorded: {}",
        std::fs::read_to_string(&marker).unwrap_or_default()
    );
    // …and it anchored on the position it was given: with no checkout above the CWD,
    // `workspace_root()` falls back to that CWD, so every artifacts-dir-relative side effect the
    // tail has (the deployment CA under the `proxy` feature) lands inside the consumer's own tree.
    // Without this the "no cargo" assertion above would still pass for a pack that had quietly
    // written into the vmcell checkout's `target/`.
    #[cfg(feature = "proxy")]
    assert!(
        outside.path().join("target/vmcell-artifacts").is_dir(),
        "the consumer-position pack must anchor its artifacts dir on the consumer's own position \
         ({}), not on the vmcell checkout",
        outside.path().display()
    );
}

// The positive control for the leg above, one stage over from the guest-tools pair: the SAME child,
// the SAME stub, run INSIDE the checkout. It proves the pack really runs (rather than the consumer
// leg passing because nothing happened) and that delta 8 did not quietly break the in-checkout
// route while making the out-of-checkout one work.
#[cfg(all(feature = "pipeline", feature = "ext4-producer"))]
#[test]
fn the_ext4_producer_still_packs_inside_a_checkout() {
    // The parent asks — see the sibling leg above for why it is not the child.
    if common::probe_ext4_or_record_skip().is_none() {
        return;
    }
    let scratch = tempfile::tempdir().expect("tempdir");
    let marker = scratch.path().join("cargo-was-reached");
    let out = run_child(EXT4_CHILD, scratch.path(), &marker, false);
    expect_child_ok(EXT4_CHILD, &out, "checkout");
}

// The ext4 child. Which position it is in is decided by the env the parents set; the pack itself
// runs identically in both, because position-independence is the claim and asserting it in one
// position only would leave the other free to rot.
//
// Undriven (a plain `cargo test` with no parent), it prints its banner and packs nothing: without
// the parent's `CARGO_MARKER` there is no stub on `PATH` to observe, so the run would spend a
// `mkfs.ext4` on a claim nothing is watching.
#[cfg(all(feature = "pipeline", feature = "ext4-producer"))]
#[tokio::test]
async fn ext4_pack_honors_its_position() {
    let consumer = std::env::var_os(CONSUMER_POSITION).is_some();
    let driven = std::env::var_os(CARGO_MARKER).is_some();
    println!(
        "{BANNER}{}",
        if consumer {
            "consumer"
        } else if driven {
            "checkout"
        } else {
            "undriven"
        }
    );
    if !driven {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    // A stand-in steward: the tail injects whatever `inputs.artifacts["steward"]` names, and this
    // leg is about where the PACK runs, not about what it bakes. Building a real steward here would
    // make a toolchain-free test need a toolchain — the exact dependency delta 7 severed.
    let steward = dir.path().join("vmcell-steward");
    std::fs::write(&steward, b"#!/bin/sh\nexit 0\n").expect("write the stand-in steward");
    let mut inputs = StageInputs::default();
    inputs
        .artifacts
        .insert("steward".to_string(), steward.clone());

    let out = dir.path().join("rootfs.ext4");
    vmcell::artifact::rootfs::pack_rootfs_with_injection(
        vec![Box::new(std::io::Cursor::new(ext4_probe_layer()))],
        &inputs,
        &out,
        &vmcell::artifact::rootfs::PackOptions::new()
            .with_format(vmcell::artifact::RootfsFormat::Ext4),
    )
    .await
    .expect("the one tail must pack an ext4 image from any position");

    // A data-plane assertion, not `out.exists()`: `mkfs.ext4` is handed a file the producer
    // `set_len`s first, so a producer that spawned nothing at all would still leave a
    // correctly-sized file behind. The magic is what says a filesystem was written into it.
    let bytes = std::fs::read(&out).expect("read the produced image");
    assert!(
        bytes.len() > 2048,
        "the produced image is too small to hold a superblock: {} bytes",
        bytes.len()
    );
    assert_eq!(
        &bytes[1080..1082],
        &[0x53, 0xef],
        "the ext2/3/4 superblock magic (0xEF53, little-endian at offset 0x438) must be present — \
         without it this leg would pass on the empty file the producer pre-sizes"
    );
}
