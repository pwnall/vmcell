#!/usr/bin/env bash
# Red-on-inverse self-test for scripts/ban-root-disk-writability-literal.sh (v33 delta 8).
#
# A ban that cannot go red is theater (AGENTS.md rule 2), and a source scan's characteristic failure
# is passing VACUOUSLY. Every arm is driven:
#
#   * a tree where every wiring site reads both laws passes                → an over-broad match reddens;
#   * a backend that names `effective_image` and hardcodes writability
#     is flagged, by path                                                  → deleting arm 1 reddens;
#   * the law's own DEFINITION site is not flagged                         → an exemption by path
#                                                                            instead of by detection reddens;
#   * a NON-wiring reader of `effective_image` (the real `resolve_cell_features`
#     shape: it locates a feature sidecar and never touches attachment) is
#     not flagged                                                          → dropping the
#                                                                            writability-token half of
#                                                                            the site test reddens;
#   * a test file that names only `effective_image` is not flagged         → scanning outside `src` reddens;
#   * a tree with no wiring site is a misconfiguration, not "ok"           → the vacuity arm reddens.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ban="$here/ban-root-disk-writability-literal.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The clean baseline: the definition site, two compliant backends, and a test that asks one law.
mk_clean_tree() {
  root="$1"
  mkdir -p "$root/crates/vmcell/src/vmm" "$root/crates/vmcell/tests" \
           "$root/crates/vmcell-qemu/src" "$root/crates/vmcell-crosvm/src"
  # The definition site: names `effective_image` AND declares the writability law. Exempt by
  # detection (it carries `pub fn root_device_read_only`), never by path.
  {
    printf 'impl RootfsSource {\n'
    printf '    pub fn effective_image(&self) -> &Path { unimplemented!() }\n'
    printf '    pub fn root_device_read_only(&self) -> bool {\n'
    printf '        match self { Erofs { .. } => true, Block { .. } => true }\n    }\n}\n'
  } > "$root/crates/vmcell/src/config.rs"
  # A compliant backend: both laws read at the wiring site.
  {
    printf 'fn build_ch_disks(cfg: &VmConfig) -> Vec<ChDisk> {\n'
    printf '    vec![ChDisk { path: cfg.rootfs.effective_image().to_path_buf(),\n'
    printf '                  readonly: cfg.rootfs.root_device_read_only() }]\n}\n'
  } > "$root/crates/vmcell/src/vmm/cloud_hypervisor.rs"
  # A second one, composing an argv token rather than a struct field.
  {
    printf 'fn args(cfg: &VmConfig) -> Vec<String> {\n'
    printf '    let img = cfg.rootfs.effective_image().display().to_string();\n'
    printf '    let ro = if cfg.rootfs.root_device_read_only() { ",ro=true" } else { "" };\n'
    printf '    vec![format!("path={img}{ro}")]\n}\n'
  } > "$root/crates/vmcell-crosvm/src/lib.rs"
  # A NON-wiring reader of the which-file law — the shipped `resolve_cell_features` shape. It names
  # `effective_image` to find the feature sidecar beside the file the guest mounts and never touches
  # attachment, so it is not a wiring site and must not be flagged.
  {
    printf 'fn resolve_cell_features(cfg: &VmConfig) -> Result<FeatureSet> {\n'
    printf '    let image = cfg.rootfs.effective_image();\n'
    printf '    FeatureDeclaration::load_beside(image, Source::Rootfs(image.into()))\n}\n'
  } > "$root/crates/vmcell/src/orchestrator.rs"
  # A TEST that asks only the which-file law. Outside `src`, so it must not be scanned: a test is
  # allowed to assert one law at a time.
  {
    printf '#[test]\n'
    printf 'fn root_is_the_effective_image() {\n'
    printf '    assert_eq!(disks[0].readonly, false);\n'
    printf '    assert_eq!(disks[0].path, cfg.rootfs.effective_image());\n}\n'
  } > "$root/crates/vmcell/tests/extra_block.rs"
}

run_ban() { # run_ban <root> -> sets $out/$rc
  set +e
  out="$("$ban" "$1" 2>&1)"
  rc=$?
  set -e
}

fail=0
expect_rc()    { if [[ $rc -ne $1 ]]; then echo "FAIL: $2: exit code = $rc, expected $1"; fail=1; fi; }
expect_flag()  { if ! grep -q "$1" <<<"$out"; then echo "FAIL: expected '$1' to be flagged"; fail=1; fi; }
expect_clean() { if   grep -q "$1" <<<"$out"; then echo "FAIL: '$1' must NOT be flagged"; fail=1; fi; }
dump()         { echo "---- scanner output ($1) ----"; printf '%s\n' "$out"; }

# --- Case 1: the compliant tree MUST pass (the positive control) ----------------------------------
mk_clean_tree "$work/good"
run_ban "$work/good"
expect_rc 0 "every wiring site reads both laws"
if ! grep -q '^ok: ' <<<"$out"; then echo "FAIL: expected an 'ok:' verdict on the clean tree"; fail=1; fi
if [[ $fail -ne 0 ]]; then dump "case 1"; fi

# --- Case 2: the exact pre-delta-8 regression — a backend hardcoding the root's writability -------
mk_clean_tree "$work/bad"
mkdir -p "$work/bad/crates/vmcell-firecracker/src"
{
  printf 'fn build_fc_drives(cfg: &VmConfig) -> Vec<Drive> {\n'
  printf '    let is_root_read_only = match &cfg.rootfs {\n'
  printf '        RootfsSource::Erofs { .. } => true,\n'
  printf '        RootfsSource::Block { .. } => false,\n    };\n'
  printf '    vec![Drive { path_on_host: cfg.rootfs.effective_image().to_path_buf(),\n'
  printf '                 is_read_only: is_root_read_only }]\n}\n'
} > "$work/bad/crates/vmcell-firecracker/src/lib.rs"
run_ban "$work/bad"
before=$fail
expect_rc 1 "a backend deciding writability on its own"
expect_flag 'vmcell-firecracker/src/lib.rs'
# The compliant sites, the definition site and the test stay clean.
expect_clean 'vmcell-crosvm/src/lib.rs'
expect_clean 'cloud_hypervisor.rs'
expect_clean 'config.rs'
expect_clean 'orchestrator.rs'
expect_clean 'tests/extra_block.rs'
if [[ $fail -ne $before ]]; then dump "case 2"; fi

# --- Case 3: a tree naming the which-file law nowhere is a misconfiguration, not a pass -----------
mkdir -p "$work/empty/crates/vmcell/src"
# Names the which-file law but never talks about attachment: not a wiring site, so the tree has
# none — which must be reported as a misconfiguration, not as a pass.
printf 'fn sidecar(cfg: &VmConfig) { let _ = cfg.rootfs.effective_image(); }\n' > "$work/empty/crates/vmcell/src/lib.rs"
run_ban "$work/empty"
before=$fail
expect_rc 1 "no wiring site in the scanned tree"
expect_flag 'gate misconfigured'
if [[ $fail -ne $before ]]; then dump "case 3"; fi

if [[ $fail -ne 0 ]]; then
  echo "ban-root-disk-writability-literal self-test FAILED"
  exit 1
fi
echo "ok: ban-root-disk-writability-literal self-test passed"
