use vmcell_artifact_validator::{ArtifactSet, checks};

mod common;

// The concurrent-boot identity contract (distinct vmid/CID/vsock under a shared-allocator race)
// is the extracted `checks::concurrency_distinct_ids` the validator runs (§12.0). Driving it
// here keeps one implementation of the distinctness assertions.
vmm_matrix_test!(concurrency, |vmm| {
    let artifacts = ArtifactSet::new(common::get_vmlinux(), common::get_rootfs());
    checks::concurrency_distinct_ids(&vmm, &artifacts)
        .await
        .expect("concurrent boots must get distinct vmid/CID/vsock and each exec");
});
