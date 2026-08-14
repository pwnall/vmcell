//! Host USB passthrough: claiming a host device for a guest, and giving it back.
//!
//! `usb_host_passthrough` is a [`VmmCapabilities`](crate::vmm::VmmCapabilities) flag, so the split
//! follows the crate's usual one: the **backend** owns what is backend-shaped (QEMU's
//! `-device qemu-xhci` + `-device usb-host,vendorid=…,productid=…` argv), and everything
//! unified lives here — resolving a `vid:pid` to its usbfs node, proving that node openable,
//! recording which host driver each interface had, and putting those drivers back at
//! teardown. A second backend gaining the capability inherits all of it and writes only its
//! own argv.
//!
//! **Why giving it back is vmcell's job.** Claiming a host device detaches its kernel driver
//! (QEMU does this via libusb to take the device), and nothing puts it back on the paths
//! vmcell drives: teardown ends in a process-group SIGKILL, and a killed VMM runs no release
//! path at all. Measured (2026-08-14): passing a laptop camera left `Driver=[none]` on both
//! of its interfaces with no `/dev/video*`, and the kernel never re-attached on its own.
//! vmcell caused the detach, so vmcell restores it — ownership owns cleanup.
//!
//! **The rule is _restore what we displaced_, never _make the device work_.** Only interfaces
//! that had a driver when the claim was taken are recorded. An operator who blacklisted a
//! driver, wrote a udev rule, or keeps a device permanently unbound for passthrough gets that
//! state back untouched.
//!
//! **No extra privilege is introduced.** Re-binding needs write access to
//! `/sys/bus/usb/drivers/<driver>/bind` (`0200 root:root`), i.e. `CAP_DAC_OVERRIDE` — which
//! every context that can spawn a passthrough VM already holds (the blessed test runner; the
//! daemon's broker child, which owns VM teardown). Measured: the same write is `EACCES`
//! unprivileged and succeeds through the blessed runner. A dedicated privileged helper would
//! re-acquire, from a new attack surface, a capability the caller has in hand — and `modprobe`
//! would be both the wrong operation and a far wider one, since the module never unloaded:
//! only the interface binding was removed.
//!
//! **Explicit detach** has no implementation here because no shipping backend needs one —
//! QEMU's libusb detaches implicitly as it claims the device. If a backend ever does,
//! [`claim_usb_host_devices`](crate::vmm::usb::claim_usb_host_devices) is its designated home,
//! so the detach and the restore stay one law rather than drifting apart across two crates.

use crate::config::UsbHostDevice;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The sysfs USB device root: one directory per device (`3-7`) and per interface (`3-7:1.0`).
const SYSFS_USB_DEVICES: &str = "/sys/bus/usb/devices";

/// The usbfs mount whose `<bus>/<dev>` character devices a VMM opens to claim a device.
const USBFS_ROOT: &str = "/dev/bus/usb";

/// The sysfs USB driver root, whose `<driver>/bind` files re-attach an interface.
const USB_DRIVERS_ROOT: &str = "/sys/bus/usb/drivers";

/// How long [`UsbHostClaim::restore`] keeps retrying a re-bind, and how often it polls.
///
/// The retry is not defensive padding: measured (2026-08-14), a bind issued the instant the
/// VMM leader is reaped **fails**, and the interface is still driverless ten seconds later,
/// while the same write a moment later succeeds. Closing the usbfs fd starts an asynchronous
/// release/reset of the device, and until that settles the interface cannot be bound. Bounded
/// because teardown must never hang, and only entered at all while a binding is still missing.
const REBIND_BUDGET: Duration = Duration::from_secs(5);
const REBIND_POLL: Duration = Duration::from_millis(100);

/// A host USB device resolved from its `vid:pid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUsbDevice {
    /// `/dev/bus/usb/<bus>/<dev>` — the node the VMM opens read-write.
    pub node: PathBuf,
    /// `/sys/bus/usb/devices/<name>` — the device directory whose `<name>:<cfg>.<if>`
    /// siblings carry the bound-driver symlinks.
    pub sysfs_dir: PathBuf,
}

/// One host USB interface and the kernel driver bound to it **before** passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbInterfaceBinding {
    /// The sysfs interface name, e.g. `3-7:1.0` — the token written to a driver's `bind`.
    pub interface: String,
    /// The driver bound when the claim was taken, e.g. `uvcvideo`.
    pub driver: String,
}

/// The host driver bindings one VM's passthrough displaced, and the means to put them back.
///
/// Taken by [`claim_usb_host_devices`] **before** the VMM spawns — the last moment the
/// bindings exist, since the sysfs `driver` symlink is gone once the VMM has claimed the
/// device — and consumed by [`restore`](Self::restore) after the VMM is reaped.
///
/// There is deliberately **no `Drop` impl**: the restore must run *after* the VMM process is
/// gone (re-binding while it still holds the device would race it) and *before* a graceful
/// `kill()` returns, so the ordering belongs at the call site with the rest of the backend's
/// ordered teardown, visible rather than implied by field-drop order. Empty for every VM
/// without passthrough, so the teardown step costs nothing on the ordinary path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsbHostClaim {
    bindings: Vec<UsbInterfaceBinding>,
}

impl UsbHostClaim {
    /// The recorded bindings, in stable interface order.
    #[must_use]
    pub fn bindings(&self) -> &[UsbInterfaceBinding] {
        &self.bindings
    }

    /// Whether this VM displaced no host driver (the ordinary, no-passthrough case).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Re-binds every displaced host driver, logging what it could not restore.
    ///
    /// Best-effort by design: teardown must complete, so a failure is **warned** with the
    /// interface, the driver and the manual command — never swallowed, and never promoted to
    /// an error that would abort the rest of the ordered teardown. The live gate
    /// (`usb_passthrough_qemu`) is what makes a regression here loud.
    ///
    /// Call it **after** the VMM process has been reaped.
    pub fn restore(&self) {
        if self.bindings.is_empty() {
            return;
        }
        let failed = restore_bindings_at(
            Path::new(SYSFS_USB_DEVICES),
            Path::new(USB_DRIVERS_ROOT),
            &self.bindings,
            REBIND_BUDGET,
        );
        for b in &failed {
            tracing::warn!(
                interface = %b.interface,
                driver = %b.driver,
                "host USB passthrough: could not re-bind the host driver this VM displaced; \
                 the device is left driverless on the host. Re-bind with: \
                 echo -n {} | sudo tee {}/{}/bind",
                b.interface,
                USB_DRIVERS_ROOT,
                b.driver
            );
        }
    }
}

/// Resolves every requested device, proves it openable, and records the host drivers the
/// spawn is about to displace.
///
/// Run this **before** the spawn, for both reasons: a misnamed or absent device must never
/// boot a guest that silently lacks it, and the interface→driver map cannot be read once the
/// VMM has claimed the device.
///
/// `vmm` names the backend in the errors, so a refusal says which backend asked (§7.2).
///
/// # Errors
/// [`Error::Vmm`] if a device is absent, ambiguous, or its usbfs node cannot be opened
/// read-write — the three ways a VMM otherwise starts with an empty USB bus and says nothing.
pub fn claim_usb_host_devices(vmm: &str, devices: &[UsbHostDevice]) -> Result<UsbHostClaim> {
    claim_usb_host_devices_at(
        vmm,
        Path::new(SYSFS_USB_DEVICES),
        Path::new(USBFS_ROOT),
        devices,
    )
}

/// [`claim_usb_host_devices`] against injected sysfs/usbfs roots, so the whole
/// resolve-prove-record path is unit-testable against a synthetic tree.
fn claim_usb_host_devices_at(
    vmm: &str,
    sysfs_root: &Path,
    usbfs_root: &Path,
    devices: &[UsbHostDevice],
) -> Result<UsbHostClaim> {
    let mut bindings = Vec::new();
    for device in devices {
        let resolved = resolve_usb_device_node(vmm, sysfs_root, usbfs_root, *device)?;
        tracing::debug!(
            "host USB passthrough: {:04x}:{:04x} -> {}",
            device.vendor_id,
            device.product_id,
            resolved.node.display()
        );
        bindings.extend(capture_bindings(sysfs_root, &resolved.sysfs_dir));
    }
    Ok(UsbHostClaim { bindings })
}

/// Resolves the usbfs node of the one host device matching `device`, and proves it openable.
///
/// A VMM asked to attach a device that matches nothing starts normally and prints **nothing**
/// (measured, QEMU 10.2.1), delivering an empty USB bus to the guest — so absence, ambiguity
/// and permission are all turned into loud errors here, before the spawn.
///
/// # Errors
/// [`Error::Vmm`] naming which of the three it was.
fn resolve_usb_device_node(
    vmm: &str,
    sysfs_root: &Path,
    usbfs_root: &Path,
    device: UsbHostDevice,
) -> Result<ResolvedUsbDevice> {
    let (vid, pid) = (device.vendor_id, device.product_id);
    let entries = std::fs::read_dir(sysfs_root).map_err(|e| {
        Error::Vmm(format!(
            "host USB passthrough ({vmm}): cannot enumerate {} ({e}) — the host kernel exposes \
             no USB devices, so {vid:04x}:{pid:04x} cannot be passed through",
            sysfs_root.display()
        ))
    })?;

    let mut matches: Vec<ResolvedUsbDevice> = Vec::new();
    for entry in entries {
        let dir = entry
            .map_err(|e| {
                Error::Vmm(format!(
                    "host USB passthrough ({vmm}): reading {sysfs_root:?}: {e}"
                ))
            })?
            .path();
        // Interface directories (`3-7:1.0`) carry no `idVendor`; only devices do.
        let (Some(found_vid), Some(found_pid)) = (
            read_usb_hex_attr(&dir, "idVendor"),
            read_usb_hex_attr(&dir, "idProduct"),
        ) else {
            continue;
        };
        if (found_vid, found_pid) != (vid, pid) {
            continue;
        }
        let (Some(bus), Some(dev)) = (
            read_usb_dec_attr(&dir, "busnum"),
            read_usb_dec_attr(&dir, "devnum"),
        ) else {
            return Err(Error::Vmm(format!(
                "host USB passthrough ({vmm}): {} matches {vid:04x}:{pid:04x} but has no \
                 readable busnum/devnum, so its {} node cannot be named",
                dir.display(),
                usbfs_root.display()
            )));
        };
        matches.push(ResolvedUsbDevice {
            node: usbfs_root
                .join(format!("{bus:03}"))
                .join(format!("{dev:03}")),
            // The sysfs device dir is kept because it is the ONLY place the interface→driver
            // map can be read, and it must be read BEFORE the VMM detaches those drivers —
            // afterwards the information is simply gone.
            sysfs_dir: dir.clone(),
        });
    }
    matches.sort_by(|a, b| a.node.cmp(&b.node));

    let [resolved] = matches.as_slice() else {
        if matches.is_empty() {
            return Err(Error::Vmm(format!(
                "host USB passthrough ({vmm}): no host device matches {vid:04x}:{pid:04x} under \
                 {} — the VMM would start with an empty USB bus and never report it",
                sysfs_root.display()
            )));
        }
        let nodes: Vec<&PathBuf> = matches.iter().map(|m| &m.node).collect();
        return Err(Error::Vmm(format!(
            "host USB passthrough ({vmm}): {vid:04x}:{pid:04x} is ambiguous — {} host devices \
             carry those ids ({nodes:?}); the VMM would attach an arbitrary one",
            matches.len()
        )));
    };

    // Prove the access the VMM needs, here, where the error can name the node.
    let node = &resolved.node;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(node)
        .map_err(|e| {
            Error::Vmm(format!(
                "host USB passthrough ({vmm}): cannot open {} read-write for \
                 {vid:04x}:{pid:04x} ({e}) — usbfs nodes are typically 0664 root:root, so this \
                 needs a udev rule or the blessed runner's ambient CAP_DAC_OVERRIDE",
                node.display()
            ))
        })?;
    Ok(resolved.clone())
}

/// Reads the interface→driver map of `device_dir` — every `<dev>:<cfg>.<if>` sibling that
/// currently has a driver bound.
///
/// Interfaces with no driver are deliberately **not** recorded: that is the
/// restore-what-we-displaced rule, and it is what keeps a blacklisted or deliberately-unbound
/// device unbound.
fn capture_bindings(sysfs_root: &Path, device_dir: &Path) -> Vec<UsbInterfaceBinding> {
    let Some(dev_name) = device_dir.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{dev_name}:");
    let Ok(entries) = std::fs::read_dir(sysfs_root) else {
        return Vec::new();
    };
    let mut bindings: Vec<UsbInterfaceBinding> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            // `3-7:1.0` is an interface of `3-7`; `3-7.1` is a DIFFERENT device behind a hub
            // at that port, whose drivers are its own business.
            if !name.starts_with(&prefix) {
                return None;
            }
            let driver = bound_driver(&e.path())?;
            Some(UsbInterfaceBinding {
                interface: name,
                driver,
            })
        })
        .collect();
    // Stable order, so the recorded set does not depend on readdir order.
    bindings.sort_by(|a, b| a.interface.cmp(&b.interface));
    bindings
}

/// The driver currently bound to a sysfs interface dir, via its `driver` symlink.
fn bound_driver(iface_dir: &Path) -> Option<String> {
    std::fs::read_link(iface_dir.join("driver"))
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_string)
}

/// Re-binds every interface not currently bound to the driver it had at capture time, by
/// writing the interface name to `<drivers_root>/<driver>/bind`.
///
/// Returns the interfaces it could NOT restore within `budget`, so the caller can warn with
/// them named. Re-reads the live binding before each write, so an interface that came back on
/// its own is skipped rather than written and spuriously reported — a driver claiming a
/// multi-interface device binds them together, so re-binding one can bring its siblings.
fn restore_bindings_at(
    sysfs_root: &Path,
    drivers_root: &Path,
    bindings: &[UsbInterfaceBinding],
    budget: Duration,
) -> Vec<UsbInterfaceBinding> {
    let deadline = std::time::Instant::now() + budget;
    let mut pending: Vec<&UsbInterfaceBinding> = bindings.iter().collect();
    loop {
        pending.retain(|b| {
            let iface_dir = sysfs_root.join(&b.interface);
            if bound_driver(&iface_dir).as_deref() == Some(b.driver.as_str()) {
                return false; // already back; nothing to do and nothing to report
            }
            let bind_path = drivers_root.join(&b.driver).join("bind");
            let wrote = std::fs::OpenOptions::new()
                .write(true)
                .open(&bind_path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, b.interface.as_bytes()));
            // A write can also fail *because* the interface got bound between the check and
            // the write; re-read before believing the error.
            wrote.is_err() && bound_driver(&iface_dir).as_deref() != Some(b.driver.as_str())
        });
        if pending.is_empty() || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(REBIND_POLL);
    }
    pending.into_iter().cloned().collect()
}

/// Reads a hex sysfs attribute (`idVendor`), or `None` if absent/unparseable.
fn read_usb_hex_attr(dir: &Path, name: &str) -> Option<u16> {
    let raw = std::fs::read_to_string(dir.join(name)).ok()?;
    u16::from_str_radix(raw.trim(), 16).ok()
}

/// Reads a decimal sysfs attribute (`busnum`), or `None` if absent/unparseable.
fn read_usb_dec_attr(dir: &Path, name: &str) -> Option<u32> {
    let raw = std::fs::read_to_string(dir.join(name)).ok()?;
    raw.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a fake sysfs USB device + its usbfs node.
    fn fake_usb_device(sysfs: &Path, usbfs: &Path, name: &str, ids: (u16, u16), at: (u32, u32)) {
        let dir = sysfs.join(name);
        std::fs::create_dir_all(&dir).expect("sysfs dir");
        std::fs::write(dir.join("idVendor"), format!("{:04x}\n", ids.0)).expect("idVendor");
        std::fs::write(dir.join("idProduct"), format!("{:04x}\n", ids.1)).expect("idProduct");
        std::fs::write(dir.join("busnum"), format!("{}\n", at.0)).expect("busnum");
        std::fs::write(dir.join("devnum"), format!("{}\n", at.1)).expect("devnum");
        let bus = usbfs.join(format!("{:03}", at.0));
        std::fs::create_dir_all(&bus).expect("usbfs bus dir");
        std::fs::write(bus.join(format!("{:03}", at.1)), b"node").expect("usbfs node");
    }

    /// Adds interface `<name>:<iface>` bound to `driver` when given, creating that driver's
    /// writable `bind` file.
    fn fake_usb_interface(
        sysfs: &Path,
        drivers: &Path,
        name: &str,
        iface: &str,
        driver: Option<&str>,
    ) {
        let idir = sysfs.join(format!("{name}:{iface}"));
        std::fs::create_dir_all(&idir).expect("iface dir");
        if let Some(d) = driver {
            let ddir = drivers.join(d);
            std::fs::create_dir_all(&ddir).expect("driver dir");
            std::fs::write(ddir.join("bind"), b"").expect("bind file");
            std::os::unix::fs::symlink(&ddir, idir.join("driver")).expect("driver symlink");
        }
    }

    // The fail-loud host-device precheck. MEASURED premise (QEMU 10.2.1, 2026-08-11):
    // `-device usb-host,vendorid=…` for a device that is absent or ambiguous starts the VMM
    // normally and prints NOTHING, so an advertised `usb_host_passthrough` would silently
    // deliver an empty USB bus. Each arm below is one of the ways that happens.
    //
    // RED on the inverse: a precheck that returns Ok() when nothing matches (or that takes
    // the first of several matches) fails the absent/ambiguous arms; one that skips the
    // open() fails the permission arm.
    #[test]
    fn usb_device_node_resolution_is_fail_loud() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (sysfs, usbfs) = (tmp.path().join("sysfs"), tmp.path().join("usbfs"));
        std::fs::create_dir_all(&sysfs).expect("sysfs root");
        std::fs::create_dir_all(&usbfs).expect("usbfs root");

        fake_usb_device(&sysfs, &usbfs, "3-7", (0x0bda, 0x5634), (3, 2));
        // Two root hubs share ids — the ambiguity a bare vid:pid cannot resolve.
        fake_usb_device(&sysfs, &usbfs, "usb1", (0x1d6b, 0x0002), (1, 1));
        fake_usb_device(&sysfs, &usbfs, "usb3", (0x1d6b, 0x0002), (3, 1));

        // Positive control: the unique device resolves, and the sysfs dir travels with it
        // (it is where the interface→driver map the restore replays is read from).
        let resolved =
            resolve_usb_device_node("qemu", &sysfs, &usbfs, UsbHostDevice::new(0x0bda, 0x5634))
                .expect("a present, unique, openable device must resolve");
        assert_eq!(resolved.node, usbfs.join("003").join("002"));
        assert_eq!(resolved.sysfs_dir, sysfs.join("3-7"));

        let err =
            resolve_usb_device_node("qemu", &sysfs, &usbfs, UsbHostDevice::new(0xdead, 0xbeef))
                .expect_err("an absent device must be refused, not silently dropped");
        assert!(
            format!("{err}").contains("no host device matches"),
            "absent must say so: {err}"
        );

        let err =
            resolve_usb_device_node("qemu", &sysfs, &usbfs, UsbHostDevice::new(0x1d6b, 0x0002))
                .expect_err("an ambiguous id must be refused, never resolved arbitrarily");
        assert!(
            format!("{err}").contains("ambiguous"),
            "ambiguous must say so: {err}"
        );

        // Unopenable: remove the node the device resolves to.
        std::fs::remove_file(usbfs.join("003").join("002")).expect("rm node");
        let err =
            resolve_usb_device_node("qemu", &sysfs, &usbfs, UsbHostDevice::new(0x0bda, 0x5634))
                .expect_err("an unopenable node must be refused before the spawn");
        assert!(
            format!("{err}").contains("cannot open"),
            "permission must say so: {err}"
        );
    }

    // The capture half. The VMM detaches each interface's driver to claim the device and the
    // sysfs `driver` symlink is gone once it has — so if this is not read BEFORE the spawn
    // there is nothing left to put back, which is exactly how a passed-through webcam was
    // left driverless.
    //
    // Pins the three rules that make the restore safe rather than merely effective:
    // interfaces of THIS device only, driverless interfaces NOT recorded (an operator's
    // blacklist must stay), and a stable order.
    //
    // RED on the inverse: match on `starts_with(dev_name)` instead of `"{dev_name}:"` and the
    // hub-child leaks in; record driverless interfaces and the blacklisted one appears.
    #[test]
    fn capture_records_only_this_devices_bound_interfaces() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (sysfs, drivers) = (tmp.path().join("devices"), tmp.path().join("drivers"));
        std::fs::create_dir_all(&sysfs).expect("sysfs");
        std::fs::create_dir_all(&drivers).expect("drivers");
        std::fs::create_dir_all(sysfs.join("3-7")).expect("device dir");

        fake_usb_interface(&sysfs, &drivers, "3-7", "1.0", Some("uvcvideo"));
        fake_usb_interface(&sysfs, &drivers, "3-7", "1.1", Some("uvcvideo"));
        // Deliberately unbound (blacklisted / reserved for passthrough): not ours to bind.
        fake_usb_interface(&sysfs, &drivers, "3-7", "1.2", None);
        // A DIFFERENT device behind a hub on the same port.
        fake_usb_interface(&sysfs, &drivers, "3-7.1", "1.0", Some("usbhid"));

        assert_eq!(
            capture_bindings(&sysfs, &sysfs.join("3-7")),
            vec![
                UsbInterfaceBinding {
                    interface: "3-7:1.0".into(),
                    driver: "uvcvideo".into()
                },
                UsbInterfaceBinding {
                    interface: "3-7:1.1".into(),
                    driver: "uvcvideo".into()
                },
            ]
        );
    }

    // The restore half, against a real (temp) tree. Covers the three states teardown actually
    // meets: still detached (must be re-bound), already back on its own (the VMM released it,
    // or binding a sibling interface re-attached this one — measured on the laptop camera,
    // where binding 3-7:1.0 brought 3-7:1.1 with it), and unrestorable, which must be
    // REPORTED rather than silently swallowed.
    //
    // RED on the inverse: drop the write and the detached interface stays unbound; drop the
    // already-bound short-circuit and the second arm writes a spurious bind; return an empty
    // failure list and the third arm's warning disappears.
    #[test]
    fn restore_rebinds_only_what_is_still_detached_and_reports_what_it_cannot() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (sysfs, drivers) = (tmp.path().join("devices"), tmp.path().join("drivers"));
        std::fs::create_dir_all(&sysfs).expect("sysfs");
        std::fs::create_dir_all(&drivers).expect("drivers");

        // (a) detached: interface dir exists, no `driver` symlink; its driver has a bind.
        fake_usb_interface(&sysfs, &drivers, "3-7", "1.0", None);
        std::fs::create_dir_all(drivers.join("uvcvideo")).expect("driver dir");
        std::fs::write(drivers.join("uvcvideo").join("bind"), b"").expect("bind");
        // (b) already back on its own.
        fake_usb_interface(&sysfs, &drivers, "3-7", "1.1", Some("uvcvideo"));
        // (c) driver gone entirely (module unloaded under us) — unrestorable.
        fake_usb_interface(&sysfs, &drivers, "3-8", "1.0", None);

        let recorded = vec![
            UsbInterfaceBinding {
                interface: "3-7:1.0".into(),
                driver: "uvcvideo".into(),
            },
            UsbInterfaceBinding {
                interface: "3-7:1.1".into(),
                driver: "uvcvideo".into(),
            },
            UsbInterfaceBinding {
                interface: "3-8:1.0".into(),
                driver: "vanished".into(),
            },
        ];
        // ZERO budget = exactly one pass, so the unit gate stays instant and still pins the
        // decision logic; the retry itself is the live gate's business.
        let failed = restore_bindings_at(&sysfs, &drivers, &recorded, Duration::ZERO);

        assert_eq!(
            std::fs::read_to_string(drivers.join("uvcvideo").join("bind")).expect("read bind"),
            "3-7:1.0",
            "the still-detached interface must be re-bound, and ONLY it"
        );
        assert_eq!(
            failed,
            vec![UsbInterfaceBinding {
                interface: "3-8:1.0".into(),
                driver: "vanished".into()
            }],
            "an unrestorable interface must be surfaced so teardown can warn with it named"
        );
    }

    // The claim ties resolve + prove + capture together, and a VM with no USB devices must
    // take an EMPTY claim whose restore is a no-op — the ordinary path must cost nothing.
    #[test]
    fn claim_records_the_devices_bindings_and_is_empty_without_passthrough() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (sysfs, usbfs, drivers) = (
            tmp.path().join("sysfs"),
            tmp.path().join("usbfs"),
            tmp.path().join("drivers"),
        );
        for d in [&sysfs, &usbfs, &drivers] {
            std::fs::create_dir_all(d).expect("root");
        }
        fake_usb_device(&sysfs, &usbfs, "3-7", (0x0bda, 0x5634), (3, 2));
        fake_usb_interface(&sysfs, &drivers, "3-7", "1.0", Some("uvcvideo"));

        let claim = claim_usb_host_devices_at("qemu", &sysfs, &usbfs, &[])
            .expect("no device requested, no check");
        assert!(
            claim.is_empty(),
            "a VM without passthrough displaces nothing"
        );
        claim.restore(); // no-op, and must not touch the filesystem

        let claim = claim_usb_host_devices_at(
            "qemu",
            &sysfs,
            &usbfs,
            &[UsbHostDevice::new(0x0bda, 0x5634)],
        )
        .expect("a present, openable device must claim");
        assert_eq!(
            claim.bindings(),
            [UsbInterfaceBinding {
                interface: "3-7:1.0".into(),
                driver: "uvcvideo".into()
            }]
        );
    }
}
