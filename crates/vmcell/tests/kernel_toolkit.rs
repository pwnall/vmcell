//! The downstream kernel-toolkit build surface (design §5.5–§5.6, §10.1; §18 delta 3), exercised
//! from **outside** the crate — the position a git-dep consumer builds from.
//!
//! Every test here is KVM-free, network-free and toolchain-free: they cover the pins-registry
//! reader (labels, fragments, its rejections), the pinned build order, the library build entry
//! point's pre-flight, the pipeline behavior the resolved-config sidecar depends on, and — by
//! re-execing this binary from outside the checkout — that Stage 0 actually RUNS in the consumer
//! position (it did not; see the implementation notes' delta-3 F1 record).
//!
//! What stays out of reach here is `make` itself: the sidecar's copy and content are pinned in
//! `artifact::kernel`'s unit tests, but only a real build shows which symbols `olddefconfig` KEPT,
//! which is the whole reason the sidecar exists. That fragment build ran live once during the
//! delta-3 review-fix pass (`vmlinux-ikconfig`, 347 s, both `CONFIG_IKCONFIG*` symbols present in
//! the published `.config`); as a standing gate it is delta 5's example-workspace CI job. Do NOT
//! land it here as an `#[ignore]`d test — `just test-privileged` runs `--run-ignored all` over
//! `kind(test)` and would pull a networked kernel compile into the privileged suite.

use std::path::{Path, PathBuf};
use vmcell::artifact::{
    Cache, CacheKey, Pipeline, Stage, StageInputs, StageOutputs, build_labelled_kernel,
    resolve_kernel_labels, resolve_kernel_registry,
};
use vmcell::error::{Error, Result};

/// Writes an overlay document into `dir` and returns its path.
fn write_overlay(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("overlay.json");
    std::fs::write(&path, body).expect("write overlay");
    path
}

/// The registry error message for an overlay, or a panic naming what came back instead.
fn registry_err(overlay: &Path) -> String {
    match resolve_kernel_registry(Some(overlay)) {
        Err(Error::Artifact(m)) => m,
        other => panic!("expected an Artifact rejection, got {other:?}"),
    }
}

// §5.5/§5.6 GATE (delta 3): a `kernels.<label>` entry may declare `fragments: [<NAME>, …]`, and
// that is what makes the LABEL ALONE determine the build — before v30 a fragment set was reachable
// only by constructing a `KernelStage` programmatically, so `vmcell build-kernels <label>` could
// never build one. RED on the inverse (a reader that ignores the `fragments` key, i.e. today's flatten,
// which drops every key inside a registry entry it does not name): `fragments` comes back empty.
#[test]
fn kernel_registry_entry_declares_its_fragments() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let overlay = write_overlay(
        tmp.path(),
        r#"{
            "kernel_fragments": { "IKCONFIG": "CONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=y\n" },
            "kernels": {
                "ikconfig": {
                    "source_url": "https://d.example/linux.tar.xz",
                    "source_sha256": "aa",
                    "fragments": ["IKCONFIG"]
                }
            }
        }"#,
    );
    let registry = resolve_kernel_registry(Some(&overlay)).expect("registry resolves");
    let entry = registry
        .iter()
        .find(|e| e.label == "ikconfig")
        .expect("the overlay-added label is in the merged registry");
    assert_eq!(
        entry.fragments,
        vec!["IKCONFIG".to_string()],
        "the label's declared fragment set must survive resolution"
    );

    // Migration promise (§18 delta 3): an entry with NO `fragments` key keeps today's behavior —
    // an empty set, not a failure and not an invented one. The committed baseline's own entries
    // are the fixture.
    let baseline = resolve_kernel_registry(None).expect("baseline resolves");
    assert!(
        !baseline.is_empty(),
        "fixture premise: the committed pins carry a kernels registry"
    );
    // Scoped to the entries that carry no `fragments` key — v30 delta 9 added a committed
    // entry (`usbhost`) that DOES declare one, which is the feature above working.
    for label in ["6.6.143", "6.12.94"] {
        let entry = baseline
            .iter()
            .find(|e| e.label == label)
            .unwrap_or_else(|| panic!("fixture premise: the committed pins carry `{label}`"));
        assert!(
            entry.fragments.is_empty(),
            "a committed entry with no `fragments` key must resolve to an empty set"
        );
    }
}

// §5.5 GATE (delta 3): the observable build-order contract — byte-lexicographic on the label
// (NOT version order: `6.12.94` precedes `6.6.143`), and the roster is exactly the registry's
// labels in that order.
//
// Honest scope: dropping the explicit sort does NOT redden this test today, because
// `serde_json`'s default `BTreeMap` map backing already iterates sorted — that accidental
// agreement IS the unpinned-order hazard §5.5 names. What this test does redden on is a different
// COLLATION (a "fix" to version order breaks the dotted assertion below) or any post-hoc reorder;
// the "sorted on purpose, not by accident" half is guarded where it can go red, on
// `sort_kernel_registry` directly (`kernel_registry_is_sorted_byte_lexicographically`, a unit test
// over a deliberately reversed input).
#[test]
fn kernel_registry_order_is_pinned_sorted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let overlay = write_overlay(
        tmp.path(),
        r#"{
            "kernels": {
                "zz": { "source_url": "https://d.example/z.tar.xz", "source_sha256": "z" },
                "aa": { "source_url": "https://d.example/a.tar.xz", "source_sha256": "a" }
            }
        }"#,
    );
    let labels = resolve_kernel_labels(Some(&overlay)).expect("labels resolve");
    let mut expected = labels.clone();
    expected.sort();
    assert_eq!(labels, expected, "the roster must be in sorted label order");
    let aa = labels.iter().position(|l| l == "aa").expect("aa");
    let zz = labels.iter().position(|l| l == "zz").expect("zz");
    assert!(aa < zz, "sorted order, not document order: {labels:?}");

    // The baseline's dotted labels pin the *byte* collation explicitly, so nobody "fixes" this
    // into a version collation without changing this test on purpose.
    let baseline = resolve_kernel_labels(None).expect("baseline resolves");
    assert_eq!(
        baseline,
        vec![
            "6.12.94".to_string(),
            "6.6.143".to_string(),
            // v30 delta 9's capability-gate kernel — after the digits in byte order.
            "usbhost".to_string(),
        ],
        "byte-lexicographic label order: 6.12.94 builds before 6.6.143"
    );

    // The roster and the registry cannot drift: the labels ARE the registry's labels, in order.
    let registry = resolve_kernel_registry(Some(&overlay)).expect("registry resolves");
    assert_eq!(
        labels,
        registry
            .iter()
            .map(|e| e.label.clone())
            .collect::<Vec<String>>()
    );
}

// §5.5 (delta 3), fail-loud: `fragments` is an ACCEPTED INPUT, so a wrong-shaped one is rejected
// naming the label — never dropped. Silently ignoring it would build an UNINSTRUMENTED kernel and
// report success, which is the accept-then-ignore class on the exact key a downstream fragment
// author writes. RED on the inverse (return `Ok(Vec::new())` for anything that is not an array of
// strings): all three overlays resolve green.
#[test]
fn malformed_fragments_are_rejected_naming_the_label() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let not_an_array = write_overlay(
        tmp.path(),
        r#"{ "kernels": { "lbl": { "source_url": "u", "source_sha256": "s",
             "fragments": "KASAN" } } }"#,
    );
    let msg = registry_err(&not_an_array);
    assert!(
        msg.contains("kernels.lbl.fragments") && msg.contains("array"),
        "the rejection must name the label's key and the expected shape, got: {msg}"
    );

    let non_string_element = write_overlay(
        tmp.path(),
        r#"{ "kernels": { "lbl": { "source_url": "u", "source_sha256": "s",
             "fragments": ["KASAN", 7] } } }"#,
    );
    let msg = registry_err(&non_string_element);
    assert!(
        msg.contains("kernels.lbl.fragments") && msg.contains('7'),
        "the rejection must name the offending element, got: {msg}"
    );

    let empty_name = write_overlay(
        tmp.path(),
        r#"{ "kernels": { "lbl": { "source_url": "u", "source_sha256": "s",
             "fragments": [""] } } }"#,
    );
    let msg = registry_err(&empty_name);
    assert!(
        msg.contains("kernels.lbl.fragments"),
        "an empty fragment name must be rejected naming the label, got: {msg}"
    );

    // Positive control: the correctly-shaped document resolves.
    let ok = write_overlay(
        tmp.path(),
        r#"{ "kernel_fragments": { "KASAN": "CONFIG_KASAN=y\n" },
             "kernels": { "lbl": { "source_url": "u", "source_sha256": "s",
             "fragments": ["KASAN"] } } }"#,
    );
    let registry = resolve_kernel_registry(Some(&ok)).expect("a well-formed entry resolves");
    assert!(registry.iter().any(|e| e.fragments == vec!["KASAN"]));
}

// §5.6 (delta 3): the library build entry point pre-flights the label against the MERGED registry
// and names the labels that do exist. Without it the pipeline ran and died deep inside the stage
// with `Missing kernel_<label>_source_url pin` — technically loud, but it never tells the caller
// which labels its overlay actually contributes. RED on the inverse (skip the lookup and hand the
// label straight to a `KernelStage`): the error is the pin message with no roster in it.
#[tokio::test]
async fn build_labelled_kernel_rejects_an_unknown_label() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let overlay = write_overlay(
        tmp.path(),
        r#"{ "kernels": { "only-this": { "source_url": "u", "source_sha256": "s" } } }"#,
    );
    let res = build_labelled_kernel("nosuch", tmp.path(), Some(&overlay)).await;
    match res {
        Err(Error::Artifact(m)) => {
            assert!(
                m.contains("nosuch") && m.contains("only-this"),
                "the refusal must name the unknown label AND the known roster, got: {m}"
            );
        }
        other => panic!("expected an unknown-label refusal, got {other:?}"),
    }
    // Nothing was built for the rejected label.
    assert!(!tmp.path().join("vmlinux-nosuch").exists());
}

/// Env marker the parent below sets on its re-exec'd child, putting that child process in the
/// **consumer position**: no `CARGO_MANIFEST_DIR`, and a CWD with no vmcell checkout above it.
const CONSUMER_POSITION: &str = "VMCELL_TEST_CONSUMER_POSITION";

/// The child test's exact libtest name (an integration-test binary namespaces nothing).
const CONSUMER_POSITION_CHILD: &str = "resolve_pins_in_the_consumer_position";

// §10.4 GATE (delta 3, F1): the toolkit's Stage 0 must RUN from the position the contract
// advertises. `build_labelled_kernel` assembles `ResolvePinsStage → KernelStage`, and
// `ResolvePinsStage` used to hash the steward source closure out of the vmcell tree
// unconditionally — so every git-dep consumer died before any kernel work with
// "steward binary source missing at <their-workspace>/crates/vmcell-steward/src/main.rs".
// No in-process test can see that: `CARGO_MANIFEST_DIR` and the CWD are process-global and both
// point INTO the checkout under cargo. So this re-execs THIS test binary with
// `CARGO_MANIFEST_DIR` cleared and its CWD outside the checkout, and fails with the child's own
// output when the child fails.
// RED on the inverse (restore `steward_closure_hash(&workspace_root())?` in
// `ResolvePinsStage::run`): the child exits non-zero with that exact message and this test prints
// it.
#[test]
fn resolve_pins_runs_outside_the_vmcell_source_tree() {
    let outside = tempfile::tempdir().expect("tempdir");
    let exe = std::env::current_exe().expect("the running test binary's path");
    let out = std::process::Command::new(&exe)
        .args(["--exact", CONSUMER_POSITION_CHILD, "--nocapture"])
        .args(["--test-threads", "1"])
        .env_remove("CARGO_MANIFEST_DIR")
        .env(CONSUMER_POSITION, "1")
        .current_dir(outside.path())
        .output()
        .expect("re-exec the test binary in the consumer position");
    assert!(
        out.status.success(),
        "`{CONSUMER_POSITION_CHILD}` must pass from a consumer workspace ({}), got {}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        outside.path().display(),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// The two halves of the gate above, in ONE test so neither position can rot alone. Which half runs
// is decided by `$CONSUMER_POSITION`, which only the parent's re-exec sets:
//   * set   — the consumer position: `ResolvePinsStage::run` must SUCCEED and must not carry the
//             rootfs-lineage `steward_src_hash` pin (there is no steward source to hash).
//   * unset — a direct run under cargo/nextest, i.e. inside this checkout: the POSITIVE CONTROL
//             that the closure really is folded here, so the absence above is the predicate
//             answering, not the pin quietly disappearing everywhere.
#[tokio::test]
async fn resolve_pins_in_the_consumer_position() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("resolved_pins.json");
    let stage = vmcell::artifact::ResolvePinsStage { overlay_file: None };
    let inputs = StageInputs::default();
    let outputs = stage
        .run(&inputs, &out)
        .await
        .expect("resolving pins must not require a vmcell source checkout");
    assert!(
        out.is_file(),
        "the resolved-pins artifact must be published at {}",
        out.display()
    );
    assert!(
        outputs.pins.contains_key("kernel_source_url"),
        "the `kernel_*` pins the labelled-kernel build reads must travel in both positions"
    );
    let steward_pin = outputs.pins.get("steward_src_hash");
    if std::env::var_os(CONSUMER_POSITION).is_some() {
        assert_eq!(
            steward_pin, None,
            "outside a vmcell checkout the steward pin must be absent, not fabricated"
        );
    } else {
        assert!(
            steward_pin.is_some_and(|h| !h.is_empty()),
            "positive control: inside the checkout the steward source closure IS folded \
             (H-CACHE-1); got {steward_pin:?}"
        );
    }
}

/// A stage that writes its payload plus a **sibling** artifact, counting its runs — the shape of a
/// compiling kernel producer and its resolved-config sidecar (§5.6).
struct SidecarStage {
    runs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl Stage for SidecarStage {
    fn name(&self) -> &str {
        "sidecar_stage"
    }

    fn out_path(&self, target_dir: &Path) -> PathBuf {
        target_dir.join("payload")
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        CacheKey::new("sidecar-stage-v1".to_string())
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::fs::write(out, b"payload").map_err(Error::Io)?;
        let sidecar = vmcell::artifact::kernel::resolved_config_path(out);
        std::fs::write(&sidecar, b"CONFIG_X=y\n").map_err(Error::Io)?;
        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert("payload".into(), out.to_path_buf());
        outputs.artifacts.insert("payload-config".into(), sidecar);
        Ok(outputs)
    }
}

// §5.6 GATE (delta 3): a stage's SIBLING artifact is only content-addressed with its payload if a
// vanished sibling forces a rebuild — `Pipeline::build` hash-verifies the payload alone and never
// calls `run()` on a hit, so a deleted `vmlinux-<label>.config` would otherwise be republished as a
// dangling path forever. RED on the inverse (drop the registered-artifact existence re-check):
// the second build below is a cache hit, `runs` stays 1 and the sidecar never comes back.
#[tokio::test]
async fn a_vanished_registered_artifact_forces_a_rebuild() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pipeline = || {
        Pipeline::new(tmp.path().to_path_buf()).add_stage(Box::new(SidecarStage {
            runs: std::sync::Arc::clone(&runs),
        }))
    };

    pipeline().build(&Cache::default()).await.expect("cold");
    let payload = tmp.path().join("payload");
    let sidecar = vmcell::artifact::kernel::resolved_config_path(&payload);
    assert!(sidecar.exists(), "the cold build writes the sidecar");
    assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Warm: everything present → a genuine cache hit, no rebuild.
    pipeline().build(&Cache::default()).await.expect("warm");
    assert_eq!(
        runs.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an intact cache must not rebuild"
    );

    // The sidecar is deleted while the payload and its key sidecar stay valid.
    std::fs::remove_file(&sidecar).expect("delete the sidecar");
    let artifacts = pipeline().build(&Cache::default()).await.expect("re-run");
    assert_eq!(
        runs.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "a missing registered artifact must re-run the stage"
    );
    assert!(sidecar.exists(), "the rebuild restores the sidecar");
    assert_eq!(
        artifacts.paths.get("payload-config").map(PathBuf::as_path),
        Some(sidecar.as_path()),
        "the sidecar is published under its own artifact key"
    );
}
