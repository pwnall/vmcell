# Implementation Notes

## Network Namespace and Passt
- We tried running `passt` for rootless networking with `cloud-hypervisor` using `--net vhost_user=true`.
- Inside a network namespace, `passt` fails with `accept4() -> EACCES (Permission denied)` when `cloud-hypervisor` tries to connect to the `vhost-user` socket.
- This happens because `passt`'s seccomp filter does not allow `accept4` with `0` as flags (it requires `SOCK_NONBLOCK` or `SOCK_CLOEXEC`), and `seccomp` triggers an `EACCES` return code for unallowed system calls. Or alternatively, it could be a limitation in the testing environment.
- As a result, we recommend running integration tests that require networking (like `test_egress_proxy.rs`) with the `NetConfig::Privileged` configuration (which uses TAP interfaces and requires `sudo`).

## Snapshot and Restore
- `cloud-hypervisor`'s `/api/v1/vm.snapshot` API requires the VM to be paused first using `/api/v1/vm.pause`. Resuming after snapshot with `/api/v1/vm.resume` is not strictly necessary if the VM is immediately shut down, but is generally good practice.
- When a VM is restored from a snapshot (via `--restore source_url=file:///...`), the guest's state is fully resumed. The VM does NOT require an explicit `/api/v1/vm.create` or `/api/v1/vm.boot` API call. Trying to boot a restored VM returns a `500 VM is already created` error from `cloud-hypervisor`.
- Instead, for restored VMs, we just call `/api/v1/vm.resume` to ensure execution continues.

## Guest Agent Vsock Connection
- When the VM is snapshotted and restored, the original vsock connection (between the host test runner and the guest agent) is severed because the host-side `vhost-vsock` device is re-created with a new socket.
- As a result, the guest agent receives an EOF on the vsock stream.
- The guest agent's connection handling loop must properly detect this EOF and exit the `handle_connection` loop so that it can `accept` a new connection from the test runner after the restore completes.
- We switched the guest agent serialization to use `postcard` consistently with the host, ensuring length-delimited framing works correctly.

## Dependencies
- `mmdebstrap` uses `dash` by default on Ubuntu, but `dash` fails. Setting `SHELL=/bin/bash` in the environment works around this limitation.
- It's also important to ensure `/bin/sh` points to `/bin/bash` when using `mmdebstrap` directly without `SHELL` environment overrides. The `imp-testing build` script explicitly checks for this symlink and halts execution if it's not configured correctly.

## Rootfs and EROFS
- `mkfs.erofs` is used to build the root filesystem. The kernel needs `CONFIG_EROFS_FS=y` built-in, otherwise it panics when attempting to mount the rootfs.
- If `imp-guest-agent` is dynamically linked in the EROFS image, it will work because `mmdebstrap` via `minbase` installs `libc6`. Attempting to statically link against `musl` requires `musl-tools` installed on the host, which is not available without root on some test environments.
