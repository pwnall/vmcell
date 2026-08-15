#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::{Component, Path};
use vmcell_daemon::name::{SHA256_SIDECAR_SUFFIX, is_reserved_sidecar_name, resolve_artifact_path};

// The ONE predicate that turns a client-supplied artifact name into a filesystem path (invariant
// P3). Every store verb resolves through it (`ArtifactStore::{create,info,delete,list}`), as do the
// VM-API artifact references (`kernel`, `rootfs`, every `extra_disks[].name`) and the snapshot /
// `restore_from` prefixes.
//
// WHO SUPPLIES THE BYTES: a remote REST client — as a URL path segment or as a JSON string field.
// An escape here is an arbitrary file read or clobber as the daemon uid.
//
// PRODUCTION PRECONDITION MIRRORED: axum percent-decodes the path segment and validates UTF-8
// before the handler sees it, so the predicate only ever receives a `&str`; `from_utf8_lossy` is
// the faithful adaptation of arbitrary decoded bytes into that domain (it can only ever hand the
// predicate MORE shapes than production, never fewer).
//
// PROPERTY, not no-panic — a bare no-panic check here would miss a traversal escape entirely, since
// the predicate is a pure allowlist that cannot panic. The law asserted is CONTAINMENT, stated over
// the RESOLVED PATH's components rather than over the name string:
//   * the resolved path's parent is exactly the store dir;
//   * everything beyond the store dir is exactly ONE `Component::Normal` — so no subdirectory, no
//     `..`, no absolute path and no prefix is representable;
//   * the reserved digest-sidecar suffix is refused on EVERY verb, because the reservation lives in
//     the name law itself rather than in one verb's manners.
// Each half is red on a real buggy relaxation: admitting `/` breaks the parent check, admitting
// `..` breaks the single-Normal-component check, admitting an absolute name breaks both.
//
// WHAT WOULD BE A FINDING: any accepted name whose resolved path is not a direct child of the
// store dir, or any accepted name ending in `.sha256`.

const STORE_DIR: &str = "/var/lib/vmcell/artifacts";

fuzz_target!(|data: &[u8]| {
    let dir = Path::new(STORE_DIR);
    let name = String::from_utf8_lossy(data);

    if let Ok(p) = resolve_artifact_path(dir, &name) {
        assert_eq!(
            p.parent(),
            Some(dir),
            "accepted name {name:?} resolved to {p:?}, which is not a direct child of the store dir"
        );
        let rest: Vec<Component<'_>> = p
            .strip_prefix(dir)
            .expect("a resolved path must stay under the store dir")
            .components()
            .collect();
        assert_eq!(
            rest.len(),
            1,
            "accepted name {name:?} resolved to {p:?}: exactly one path component may follow the store dir"
        );
        assert!(
            matches!(rest.first(), Some(Component::Normal(_))),
            "accepted name {name:?} resolved to {p:?}: the trailing component must be a normal one, never `..`, `/` or a prefix"
        );
        assert!(
            !is_reserved_sidecar_name(&name),
            "accepted name {name:?} ends in the reserved {SHA256_SIDECAR_SUFFIX} sidecar suffix"
        );
    }

    // Positive control in the same body (a negative security result needs one): the real names the
    // store uses are still accepted, and land exactly where the store expects them.
    let good = resolve_artifact_path(dir, "vmlinux-6.12.94").expect("a real artifact name");
    assert_eq!(good, dir.join("vmlinux-6.12.94"));
});
