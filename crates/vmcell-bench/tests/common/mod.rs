//! Shared harness for the `bench-vm` subprocess tests.
//!
//! The artifact getters are re-exported from `vmcell_artifact_validator::harness` — the single
//! source of truth also used by `vmcell`'s integration suite (design §5.4/§8.5) — so the
//! `#[ignore]`d KVM benchmark tests trigger the same at-most-once rootfs/kernel build before
//! shelling out to `bench-vm`. Lives under `tests/common/` (a subdir, not `tests/common.rs`) so
//! cargo does not compile it as its own test target.
pub use vmcell_artifact_validator::harness::{get_rootfs, get_vmlinux};
