#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use vmcell::artifact::rootfs::{ExtraFile, fuzz_validate_extra_files, is_reserved_injection_path};

// The rootfs injection-dest law (invariant F5): the pack tail's `validate_extra_files`, over
// `is_reserved_injection_path` and the packer's own `normalize_path`.
//
// WHO SUPPLIES THE BYTES: a downstream toolkit consumer's build configuration — `ExtraFile::dest`
// (`vmcell build --inject`), which is named contract surface. This is LOCAL config, not off-host
// input, and the target is ranked accordingly: what F5 protects is a consumer silently clobbering
// the steward, the CA trust store or the guest-tools directory, which is a supply-chain
// invariant rather than a remote-exploit boundary. It earns a slot because the law has a real
// evasion history — `/usr/sbin/./vmcell-steward` and `/opt/.` both defeated earlier spellings
// of it — and every one of those evasions was a NORMAL-FORM mismatch, which is exactly what a
// fuzzer over arbitrary path strings explores.
//
// PRODUCTION PRECONDITION MIRRORED: none needed — `validate_extra_files` is the validation boundary
// itself (an `ExtraFile` never passes through `VmConfig`), it runs before any injection is baked,
// and it reads no file: the `src` path is opened by the packer, never by the validator. So the
// harness may hand it a `src` that does not exist, exactly as a rejected build would.
//
// PROPERTY: for every ACCEPTED dest —
//   * it is absolute and carries no `..` component (a `..` would silently mean a different path
//     than it reads as, since the packer's normalizer POPS it);
//   * `is_reserved_injection_path` refuses it, however it is spelled — the half of the law that is
//     already public, checked here against the shapes that defeated it;
//   * no two accepted dests collapse to the same normalized key, so the "last writer silently wins"
//     case cannot survive validation.
// The reference normal form is recomputed in the harness (drop root and `.` components; there is no
// `..` left to pop, since those are rejected above). That is a DIFFERENTIAL against the packer's
// own `normalize_path`, which is the point: a divergence between the validator's view of a dest and
// the packer's key IS the evasion class.
//
// WHAT WOULD BE A FINDING: an accepted dest that normalizes onto a vmcell-owned injection path, or
// two accepted dests that normalize onto each other.

/// The packer's normal form, recomputed: root and `.` components dropped. `..` never appears here
/// because an accepted dest carries none.
fn reference_normalize(dest: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in Path::new(dest).components() {
        if let Component::Normal(c) = comp {
            out.push(c);
        }
    }
    out
}

fuzz_target!(|dests: Vec<&str>| {
    if dests.len() > 8 {
        return;
    }
    let extra: Vec<ExtraFile> = dests
        .iter()
        .map(|d| ExtraFile::new(*d, "/nonexistent/fuzz-src", 0o644))
        .collect();

    let Ok(accepted) = fuzz_validate_extra_files(&extra) else {
        return;
    };

    let mut normalized: HashSet<PathBuf> = HashSet::new();
    for (dest, _src, mode) in &accepted {
        assert!(
            dest.starts_with('/'),
            "accepted injection dest {dest:?} is not an absolute in-guest path"
        );
        assert!(
            !Path::new(dest)
                .components()
                .any(|c| matches!(c, Component::ParentDir)),
            "accepted injection dest {dest:?} carries a `..` component, which the packer's \
             normalizer would POP into a different path than the dest reads as"
        );
        assert!(
            !is_reserved_injection_path(dest),
            "accepted injection dest {dest:?} normalizes onto a vmcell-owned injection path (the \
             steward, the CA trust store, or the guest-tools directory)"
        );
        let key = reference_normalize(dest);
        assert!(
            !key.as_os_str().is_empty(),
            "accepted injection dest {dest:?} normalizes to the empty path — it names a directory, \
             not a file"
        );
        assert!(
            normalized.insert(key.clone()),
            "two accepted injection dests normalize onto the same key {key:?}; the last writer \
             would silently win"
        );
        assert!(
            *mode <= 0o7777,
            "accepted injection dest {dest:?} kept out-of-range mode {mode:#o}"
        );
    }

    // Positive control in the same body: the shapes a real consumer uses are still accepted, and a
    // vmcell-owned dest is still refused.
    let good = ExtraFile::new("/usr/local/bin/acme-daemon", "/nonexistent/fuzz-src", 0o755);
    assert!(fuzz_validate_extra_files(std::slice::from_ref(&good)).is_ok());
    let owned = ExtraFile::new(
        "/usr/sbin/./vmcell-steward",
        "/nonexistent/fuzz-src",
        0o755,
    );
    assert!(fuzz_validate_extra_files(std::slice::from_ref(&owned)).is_err());
});
