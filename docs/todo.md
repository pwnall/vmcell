* Add OCI registry image support, use it for low-dependency rootfs build;
  redesign the `mmdebootstrap` rootfs building process to work in a micro-VM
  (using our infrastructure); this way, the host doesn't need to be able to
  run `mmdebootstrap` -- we remove the shell problem and maybe some package
  dependencies
* Performance benchmarking
* Trait implementations for the firecracker backend
* Trait implementations for the QEMU backend
* Benchmarks for all backends
