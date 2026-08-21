//! TAP interface and network namespace management.
//!
//! This module provides the `NetNamespace` struct for creating and managing
//! Linux network namespaces and TAP interfaces used by virtual machines.

use crate::error::{Error, Result};
use futures::stream::TryStreamExt;

/// Extracts a human-readable message from a thread panic payload (N-NET-4).
///
/// `std::thread::JoinHandle::join` returns the panic value as a
/// `Box<dyn Any + Send>`; the common `panic!("literal")` / `panic!("{}", …)`
/// payloads are a `&str` or `String`. Downcasting to those recovers the real
/// cause instead of collapsing every panic to one fixed string.
fn panic_payload_str(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// The directory `iproute2`/`netns_rs` bind named network namespaces into.
///
/// The **only** spelling of that layout in this crate's production code, from which [`netns_path`]
/// and every enumerating sweep compose. Four call sites outside this module used to spell the
/// literal themselves (the proxy's namespace entry, `build_vmm_cmd`'s pre-allocated NUL-terminated
/// path, and the orphan scanner's two `read_dir`s); all four now go through [`netns_path`] /
/// [`netns_dir`], and this module's `netns_layout_gate` scans the tree so a new one is a red gate
/// rather than a claim that quietly ages into fiction — which is exactly how the "spelled in one
/// place" wording came to be false the first time.
const NETNS_DIR: &str = "/var/run/netns";

/// The directory named network namespaces live in, for callers that **enumerate** it rather than
/// name one member ([`cleanup_orphan_netns`] and the orphan scanner's per-VM and per-segment
/// `read_dir`s in [`HostOrphanScanner`](crate::orchestrator::HostOrphanScanner)).
pub(crate) fn netns_dir() -> &'static std::path::Path {
    std::path::Path::new(NETNS_DIR)
}

/// The bind-mount path of the named network namespace (`/var/run/netns/<name>`).
///
/// One law, one predicate, and now actually one: [`in_netns`], [`cleanup_orphan_netns`],
/// [`crate::net::NetSegment::netns_path`], the §6.4 proxy's namespace entry, `build_vmm_cmd`'s
/// pre-fork C string and the orphan scanner's two sweeps all reach the layout through this function
/// or its [`netns_dir`] sibling, both of which read [`NETNS_DIR`]. The shape a caller needs differs
/// (a `PathBuf` to open, a `read_dir` root, a NUL-terminated `String`); the fact does not, so none
/// of them may re-spell it — `netns_layout_gate` is the scan that enforces that.
pub(crate) fn netns_path(name: &str) -> std::path::PathBuf {
    netns_dir().join(name)
}

/// Runs `f` **inside** the network namespace `netns`, on a thread that exists only for this call.
///
/// The one namespace-move discipline for this module (`ns-run-on-pooled-tokio-worker`). Every
/// caller here is reached synchronously from the async `setup_env`, so the thread that would be
/// moved is a pooled tokio runtime worker — exactly what [`crate::net_sys::setns_net`]'s contract
/// forbids: `setns(CLONE_NEWNET)` moves the *calling thread*, and a worker left behind in a VM's
/// namespace silently originates every later socket the runtime schedules on it. The previous
/// spelling, `netns_rs`'s `NetNs::run`, is `enter()?; f(self); src_ns.enter()?` with **no**
/// `catch_unwind`, so a panic inside `f` (reachable: the closures below spawn threads, and
/// `thread::scope`'s `spawn` panics when the OS refuses one) skipped the restore and stranded that
/// worker in the VM's namespace for the life of the process.
///
/// A dedicated thread makes both halves structural: nothing else can be scheduled on it, and it
/// **terminates** when `f` returns, so there is no namespace to restore and no un-restored state a
/// panic can leave behind. `NetSegment::dial_tcp` and the §6.4 proxy already work this way; this is
/// the same law, not a second copy. A panic in `f` is caught by the join and surfaced as
/// [`Error::Network`] carrying the real payload.
///
/// # Errors
/// [`Error::Network`] if the namespace cannot be opened or entered, or if `f` panicked.
fn in_netns<F, T>(netns: &str, f: F) -> Result<T>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    let path = netns_path(netns);
    on_dedicated_thread(netns, || {
        use std::os::fd::AsRawFd;
        let ns = std::fs::File::open(&path)
            .map_err(|e| Error::Network(format!("netns open failed ({}): {e}", path.display())))?;
        crate::net_sys::setns_net(ns.as_raw_fd())
            .map_err(|e| Error::Network(format!("setns into netns {}: {e}", path.display())))?;
        Ok(f())
    })
}

/// Runs `f` on a thread created for this call and joined before returning, converting a panic in
/// `f` into an [`Error::Network`] naming `what` instead of unwinding into the caller.
///
/// The thread half of [`in_netns`], extracted so the discipline it enforces — *not the caller's
/// thread*, and *no panic escapes* — is drivable without privileges. `netns_rs`'s `NetNs::run` had
/// neither property.
fn on_dedicated_thread<F, T>(what: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        scope.spawn(f).join().unwrap_or_else(|panic| {
            Err(Error::Network(format!(
                "netns worker thread panicked in {what}: {}",
                panic_payload_str(panic.as_ref())
            )))
        })
    })
}

fn run_in_tokio<F, Fut, T>(f: F) -> std::result::Result<T, String>
where
    F: FnOnce() -> Fut + Send,
    Fut: std::future::Future<Output = std::result::Result<T, String>>,
    T: Send,
{
    // The `Netlink` trait is synchronous, but the orchestrator that drives it is
    // async — so this may be called from within a tokio runtime, where building
    // and `block_on`-ing a nested runtime on the current (worker) thread panics
    // ("Cannot start a runtime from within a runtime"). Run the blocking work on a
    // dedicated OS thread, which is never a runtime worker, so a fresh
    // current-thread runtime is always safe.
    std::thread::scope(|s| {
        s.spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio build failed: {e}"))?;
            rt.block_on(f())
        })
        .join()
        .map_err(|panic| {
            format!(
                "netlink worker thread panicked: {}",
                panic_payload_str(panic.as_ref())
            )
        })?
    })
}

fn run_with_rtnetlink<F, Fut, T>(f: F) -> std::result::Result<T, String>
where
    F: FnOnce(rtnetlink::Handle) -> Fut + Send,
    Fut: std::future::Future<Output = std::result::Result<T, String>>,
    T: Send,
{
    run_in_tokio(move || async move {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| format!("rtnetlink connect failed: {e}"))?;
        tokio::spawn(connection);
        f(handle).await
    })
}

/// Sweeps orphaned network namespaces left behind by killed or failed
/// privileged test runs.
///
/// Enumerates `/var/run/netns` and removes every namespace whose name starts
/// with `prefix` (e.g. `vmcell-net-`). Intended to run at the start of a
/// privileged/netns test so a namespace leaked by a prior aborted run cannot
/// collide with this run's vmid (`netns add … Operation not permitted`). It runs
/// under the capability runner's `CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`, so it needs
/// no `sudo`.
///
/// Safe only when no live VM owns a matching namespace: the privileged suite
/// serializes these tests (`serial-host`), and orphans have no live interfaces,
/// so the removal does not hang. A per-namespace failure is logged and skipped
/// rather than propagated, so one stuck namespace cannot block the rest. Returns
/// the names of the namespaces it successfully removed.
pub fn cleanup_orphan_netns(prefix: &str) -> Vec<String> {
    let mut removed = Vec::new();
    let Ok(dir) = std::fs::read_dir(netns_dir()) else {
        return removed; // no netns dir → nothing to sweep
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(prefix) {
            continue;
        }
        match netns_rs::NetNs::get(&name).and_then(netns_rs::NetNs::remove) {
            Ok(()) => removed.push(name),
            Err(e) => {
                tracing::warn!("cleanup_orphan_netns: failed to remove {}: {}", name, e);
            }
        }
    }
    removed
}

/// Resolves an interface index by name inside the current namespace.
///
/// One helper for every `link().get().match_name(..)` lookup in this module — the tap path, the
/// `lo` bring-ups, and the segment bridge/enslave path — so a future lookup cannot drift.
async fn link_index(handle: &rtnetlink::Handle, name: &str) -> std::result::Result<u32, String> {
    Ok(handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await
        .map_err(|e| format!("get link {name} err: {e}"))?
        .ok_or_else(|| format!("link {name} not found"))?
        .header
        .index)
}

/// Brings the interface at `index` up (`IFF_UP`).
///
/// rtnetlink 0.21: `link().set(..)` takes a fully-built `LinkMessage` (the fluent `.set(idx).up()`
/// builder was removed), so the message is built here — once, for every caller.
async fn link_up(handle: &rtnetlink::Handle, index: u32) -> std::result::Result<(), String> {
    handle
        .link()
        .set(
            rtnetlink::LinkMessageBuilder::<rtnetlink::LinkUnspec>::new()
                .index(index)
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(|e| format!("link {index} up err: {e}"))
}

/// Creates `tap_name` inside the namespace `netns`, makes it persistent (`TUNSETPERSIST`), and
/// drops our fd.
///
/// A non-multi-queue tap allows a single opener and the VMM must be it (otherwise CH fails with
/// "Open tap device failed: Device or resource busy"), so the interface is persisted and the
/// creating fd released. One helper for both the per-VM tap ([`Netlink::setup_tap`]) and the
/// segment member tap ([`Netlink::setup_tap_on_bridge`]) — the two differ only in addressing.
/// (Both ioctls live in `crate::net_sys` because this module is `#![forbid(unsafe_code)]`.)
///
/// The whole of the create — the `/dev/net/tun` open **and** the `TUNSETIFF` — happens inside the
/// [`in_netns`] closure, because the tap's namespace is captured when the device is opened, not
/// when the ioctl runs. [`crate::net_sys::create_tap_in_current_netns`] carries that law and the
/// gate on it; do not split it so the open can be hoisted out of here.
fn create_persistent_tap_in_ns(netns: &str, tap_name: &str) -> Result<()> {
    let tap = in_netns(netns, || {
        crate::net_sys::create_tap_in_current_netns(tap_name)
    })?
    .map_err(|e| Error::Network(format!("tap create fail: {e}")))?;
    {
        use std::os::fd::AsRawFd;
        crate::net_sys::set_tun_persist(tap.as_raw_fd())
            .map_err(|e| Error::Network(format!("TUNSETPERSIST on tap failed: {e}")))?;
    }
    drop(tap);
    Ok(())
}

/// Interface for executing netlink operations.
pub trait Netlink: Send + Sync {
    /// Creates a network namespace.
    ///
    /// # Errors
    /// Returns an error if the namespace creation fails.
    fn add_netns(&self, name: &str) -> Result<()>;
    /// Sets up the TAP interface and IP address inside the namespace.
    ///
    /// Returns **nothing**: the tap is `TUNSETPERSIST`'d inside `netns` and the creating fd is
    /// dropped, because a non-multi-queue tap allows a single opener and the VMM must be it
    /// (`setup-tap-returns-dead-option`). The previous `Result<Option<tun_tap::Iface>>` was always
    /// `Ok(None)` and read by nobody, while forcing every out-of-tree implementor of this ledgered
    /// seam to depend on `tun-tap` (which `vmcell` does not re-export) and teaching them to hold
    /// the tap fd open — the one thing that breaks the single-opener discipline.
    ///
    /// # Errors
    /// Returns an error if setting up the TAP interface or assigning the IP fails.
    fn setup_tap(&self, netns: &str, tap_name: &str, vmid: u32) -> Result<()>;
    /// Creates a Linux **bridge** inside `netns`, gives it `gateway`/`prefix_len`, and brings it
    /// (and `lo`) up — the segment's shared L2 domain (§6.5, VM-to-VM segments).
    ///
    /// # Errors
    /// Returns an error if the namespace or any `rtnetlink` operation fails.
    fn create_bridge(
        &self,
        netns: &str,
        bridge: &str,
        gateway: std::net::Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()>;
    /// Creates a **member** tap inside `netns`, enslaves it to `bridge`, and brings it up —
    /// deliberately assigning it **no** address (§6.5: the bridge holds the gateway; an address on
    /// a bridge port would put a second subnet on the segment).
    ///
    /// The tap is `TUNSETPERSIST`'d and our fd dropped, exactly as [`Netlink::setup_tap`] does, so
    /// the VMM is the single opener.
    ///
    /// **Cleanup contract:** on error this leaves behind exactly what it found — if it created the
    /// tap and a later step failed it removes that tap, and if the tap creation itself failed
    /// (typically because an interface of that name is already there) it removes **nothing**. The
    /// caller must not clean up by name: a segment namespace is shared and pre-existing, so the
    /// interface of that name may be a live sibling member's (§6.5).
    ///
    /// # Errors
    /// Returns an error if the namespace, the tap creation, or any `rtnetlink` operation fails.
    fn setup_tap_on_bridge(&self, netns: &str, tap_name: &str, bridge: &str) -> Result<()>;
    /// Deletes a link (e.g. a member tap) inside `netns`.
    ///
    /// A segment member releases its tap this way on teardown — the segment netns outlives the
    /// member, so a left-behind persistent tap would collide when its vmid is reused (§6.5).
    ///
    /// # Errors
    /// Returns an error if the namespace or the `rtnetlink` delete fails.
    fn delete_link(&self, netns: &str, link: &str) -> Result<()>;
    /// Deletes a network namespace.
    ///
    /// # Errors
    /// Returns an error if deleting the namespace fails.
    fn delete_netns(&self, name: &str) -> Result<()>;
    /// Sets up TPROXY routing policy in the namespace.
    ///
    /// # Errors
    /// Returns an error if the `rtnetlink` rule/route operations fail.
    fn setup_tproxy_routing(&self, netns: &str) -> Result<()>;
}

/// Interface for applying nftables rules.
pub trait NftApplier: Send + Sync {
    /// Applies the given nftables rules in the specified network namespace.
    ///
    /// # Errors
    /// Returns an error if the rules fail to apply.
    fn apply_rules(&self, netns: &str, rules: &str) -> Result<()>;
}

/// The Netlink implementation using pure Rust `rtnetlink` and `netns-rs`.
pub struct RtNetlink;

impl Netlink for RtNetlink {
    fn add_netns(&self, name: &str) -> Result<()> {
        netns_rs::NetNs::new(name).map_err(|e| Error::Network(format!("netns add failed: {e}")))?;
        Ok(())
    }

    fn setup_tap(&self, netns: &str, tap_name: &str, vmid: u32) -> Result<()> {
        create_persistent_tap_in_ns(netns, tap_name)?;

        let tap_name = tap_name.to_string();
        let (ip, _, _) = crate::net::ip_math(vmid)?;

        let res = in_netns(netns, move || {
            run_with_rtnetlink(|handle| async move {
                let link_idx = link_index(&handle, &tap_name).await?;

                handle
                    .address()
                    .add(link_idx, std::net::IpAddr::V4(ip), 30)
                    .execute()
                    .await
                    .map_err(|e| format!("addr add err: {e}"))?;

                link_up(&handle, link_idx).await?;

                let lo_idx = link_index(&handle, "lo").await?;
                link_up(&handle, lo_idx).await?;

                Ok(())
            })
        })?;

        // The tap is persistent in the netns and our fd is already dropped, so there is nothing to
        // hand back — the VMM opens the interface by name.
        res.map_err(Error::Network)
    }

    fn create_bridge(
        &self,
        netns: &str,
        bridge: &str,
        gateway: std::net::Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let bridge_name = bridge.to_string();

        let res = in_netns(netns, move || {
            run_with_rtnetlink(|handle| async move {
                // rtnetlink 0.21's typed bridge builder — the first bridge in the tree.
                handle
                    .link()
                    .add(rtnetlink::LinkBridge::new(&bridge_name).build())
                    .execute()
                    .await
                    .map_err(|e| format!("bridge add err: {e}"))?;

                let br_idx = link_index(&handle, &bridge_name).await?;
                handle
                    .address()
                    .add(br_idx, std::net::IpAddr::V4(gateway), prefix_len)
                    .execute()
                    .await
                    .map_err(|e| format!("bridge addr add err: {e}"))?;
                link_up(&handle, br_idx).await?;

                let lo_idx = link_index(&handle, "lo").await?;
                link_up(&handle, lo_idx).await?;

                Ok(())
            })
        })?;

        res.map_err(Error::Network)
    }

    fn setup_tap_on_bridge(&self, netns: &str, tap_name: &str, bridge: &str) -> Result<()> {
        // Nothing exists yet if this fails — an `EBUSY` means the interface of that name is
        // someone else's, and its opener holds it — so it returns without any cleanup. (`EEXIST`
        // is NOT reachable from here: the kernel returns it only for a second `TUNSETIFF` on the
        // *same* fd, which this path never issues. The converse does not hold either — see the
        // create-or-attach note in `docs/implementation-notes.md`.)
        create_persistent_tap_in_ns(netns, tap_name)?;

        let name_for_cleanup = tap_name.to_string();
        let tap_name = tap_name.to_string();
        let bridge_name = bridge.to_string();

        let res = in_netns(netns, move || {
            run_with_rtnetlink(|handle| async move {
                let tap_idx = link_index(&handle, &tap_name).await?;
                let br_idx = link_index(&handle, &bridge_name).await?;

                // Enslave, and bring up — but assign NO address: the bridge holds
                // `10.201.<s>.1`, and an address on a bridge port would silently put a
                // second subnet on the segment (§6.5). This is the one deliberate
                // difference from `setup_tap`.
                handle
                    .link()
                    .set(
                        rtnetlink::LinkMessageBuilder::<rtnetlink::LinkUnspec>::new()
                            .index(tap_idx)
                            .controller(br_idx)
                            .up()
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|e| format!("tap enslave err: {e}"))?;

                Ok(())
            })
        });

        let enslaved = match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::Network(e)),
            Err(e) => Err(e),
        };
        if let Err(e) = enslaved {
            // We created this tap moments ago, so deleting it removes only what we made — the
            // cleanup contract on `Netlink::setup_tap_on_bridge`. The caller cannot do this:
            // it cannot tell our half-created tap from a live sibling's interface of the same
            // name in this shared namespace.
            if let Err(cleanup_err) = self.delete_link(netns, name_for_cleanup.as_str()) {
                tracing::warn!(
                    "setup_tap_on_bridge: failed to remove the tap {} we created in {} after an \
                     enslave error ({}): {}",
                    name_for_cleanup,
                    netns,
                    e,
                    cleanup_err
                );
            }
            return Err(e);
        }
        Ok(())
    }

    fn delete_link(&self, netns: &str, link: &str) -> Result<()> {
        let link_name = link.to_string();

        let res = in_netns(netns, move || {
            run_with_rtnetlink(|handle| async move {
                let idx = link_index(&handle, &link_name).await?;
                handle
                    .link()
                    .del(idx)
                    .execute()
                    .await
                    .map_err(|e| format!("link {link_name} del err: {e}"))?;
                Ok(())
            })
        })?;

        res.map_err(Error::Network)
    }

    fn delete_netns(&self, name: &str) -> Result<()> {
        let ns = netns_rs::NetNs::get(name)
            .map_err(|e| Error::Network(format!("netns get failed: {e}")))?;
        ns.remove()
            .map_err(|e| Error::Network(format!("netns remove failed: {e}")))?;
        Ok(())
    }

    fn setup_tproxy_routing(&self, netns: &str) -> Result<()> {
        let inner_res = in_netns(netns, || {
            run_with_rtnetlink(|handle| async move {
                let lo_idx = handle
                    .link()
                    .get()
                    .match_name("lo".to_string())
                    .execute()
                    .try_next()
                    .await
                    .map_err(|e| format!("get lo err: {e}"))?
                    .ok_or_else(|| "lo not found".to_string())?
                    .header
                    .index;

                let mut rule = handle.rule().add();
                let msg = rule.message_mut();
                // An FIB rule message with no address family is rejected by the
                // kernel with EAFNOSUPPORT; `rule().add()` leaves it AF_UNSPEC, so
                // set AF_INET explicitly (equivalent to rtnetlink's `.v4()`).
                msg.header.family = netlink_packet_route::AddressFamily::Inet;
                msg.header.table = 100;
                msg.header.action = netlink_packet_route::rule::RuleAction::ToTable;
                msg.attributes
                    .push(netlink_packet_route::rule::RuleAttribute::FwMark(1));
                rule.execute()
                    .await
                    .map_err(|e| format!("rule add err: {e}"))?;

                // rtnetlink 0.21: `route().add(..)` now requires a `RouteMessage`; pass a
                // default and overwrite every header field below, so the emitted netlink
                // bytes are identical to the pre-0.15 `add()` + `message_mut()` path.
                let mut route = handle
                    .route()
                    .add(netlink_packet_route::route::RouteMessage::default());
                let msg = route.message_mut();
                // Same as the rule above: an unset address family is rejected with
                // EAFNOSUPPORT. This is an IPv4 local route into table 100.
                msg.header.address_family = netlink_packet_route::AddressFamily::Inet;
                msg.header.table = 100;
                // RTPROT_KERNEL (value 2). The previous `Other(2)` carried a
                // comment mislabeling 2 as RTPROT_BOOT — boot is 3; 2 is kernel.
                msg.header.protocol = netlink_packet_route::route::RouteProtocol::Kernel;
                // RTN_LOCAL requires scope >= RT_SCOPE_HOST: the kernel's
                // fib_create_info rejects fib_props[RTN_LOCAL].scope (HOST) >
                // fc_scope with EINVAL, so RT_SCOPE_LINK is invalid for a local
                // route (iproute2 also forces HOST for `ip route add local`).
                msg.header.scope = netlink_packet_route::route::RouteScope::Host;
                msg.header.kind = netlink_packet_route::route::RouteType::Local;
                msg.attributes
                    .push(netlink_packet_route::route::RouteAttribute::Oif(lo_idx));
                route
                    .execute()
                    .await
                    .map_err(|e| format!("route add err: {e}"))?;

                Ok(())
            })
        })?;
        if let Err(e) = inner_res {
            return Err(Error::Network(e));
        }
        Ok(())
    }
}

/// The default NftApplier implementation using the `nft` command.
pub struct DefaultNftApplier;
impl NftApplier for DefaultNftApplier {
    fn apply_rules(&self, netns: &str, rules: &str) -> Result<()> {
        let rules_str = rules.to_string();

        let inner_res = in_netns(netns, move || {
            use std::io::Write;
            let mut child = std::process::Command::new("nft")
                .args(["-f", "-"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("nft spawn failed: {e}"))?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(rules_str.as_bytes())
                    .map_err(|e| format!("nft write failed: {e}"))?;
                // `stdin` is dropped here, closing the pipe so nft sees EOF.
            }

            // NET-8: capture nft's exit code and stderr so a rule-load failure is
            // diagnosable instead of an opaque "failed".
            let output = child
                .wait_with_output()
                .map_err(|e| format!("nft wait failed: {e}"))?;
            if !output.status.success() {
                let code = output
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "terminated by signal".to_string());
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!(
                    "nft rules application failed (exit {}): {}",
                    code,
                    stderr.trim()
                ));
            }
            Ok::<(), String>(())
        })?;

        inner_res.map_err(Error::Subprocess)
    }
}

/// Network namespace management for privileged VMs.
pub struct NetNamespace {
    /// The name of the netns.
    pub name: String,
    /// The name of the TAP interface.
    pub tap_name: String,
    /// The VM ID associated with this netns.
    pub vmid: u32,
    /// The Netlink implementation
    netlink: Box<dyn Netlink>,
    /// Whether `delete()` has already torn down the namespace. Makes `delete()`
    /// idempotent so an explicit teardown followed by `Drop` (or a double
    /// `delete()`) is a silent no-op rather than a spurious teardown warning
    /// (M-NET-3); the NET-8 warning is then reserved for genuine failures.
    deleted: bool,
}

impl std::fmt::Debug for NetNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetNamespace")
            .field("name", &self.name)
            .field("tap_name", &self.tap_name)
            .field("vmid", &self.vmid)
            .finish()
    }
}

impl NetNamespace {
    /// Creates a new network namespace and TAP interface for the given VM ID, named from `prefix`
    /// (`<prefix>-net-<vmid>` / `<prefix>-tap-<vmid>`, composed via [`crate::naming`]).
    ///
    /// # Errors
    /// Returns an error if the `rtnetlink` operations fail.
    pub fn create(prefix: &str, vmid: u32, netlink: Box<dyn Netlink>) -> Result<Self> {
        let name = crate::naming::netns_name(prefix, vmid);
        let tap_name = crate::naming::tap_name(prefix, vmid);

        netlink.add_netns(&name)?;

        // H-QEMU-1 (netns sibling): the netns now exists. If setup_tap fails, `Self`
        // is never constructed, so `Drop` cannot reclaim it — tear the namespace
        // back down here. Removing the netns also reaps any half-created persistent
        // tap that setup_tap left inside it, so a failed create() leaks nothing.
        if let Err(e) = netlink.setup_tap(&name, &tap_name, vmid) {
            if let Err(cleanup_err) = netlink.delete_netns(&name) {
                tracing::warn!(
                    "NetNamespace::create: failed to clean up netns {} after setup_tap error: {}",
                    name,
                    cleanup_err
                );
            }
            return Err(e);
        }

        Ok(Self {
            name,
            tap_name,
            vmid,
            netlink,
            deleted: false,
        })
    }

    /// Deletes the network namespace and associated interfaces.
    ///
    /// Idempotent: once a `delete()` has succeeded, further calls (including the
    /// one in `Drop`) are silent no-ops, so a successful explicit teardown does
    /// not provoke a spurious `Drop` warning (M-NET-3).
    ///
    /// # Errors
    /// Returns an error if removing the namespace (via `netns_rs`) fails.
    pub fn delete(&mut self) -> Result<()> {
        if self.deleted {
            return Ok(());
        }
        // Nothing to release before the namespace: the tap is persistent inside it and this
        // process holds no fd on it (`setup-tap-returns-dead-option`) — removing the namespace
        // reaps the interface.
        self.netlink.delete_netns(&self.name)?;
        // Only mark deleted after a successful teardown: a failed delete_netns
        // leaves `deleted` false so `Drop` retries and the NET-8 warning still
        // surfaces a genuine teardown failure.
        self.deleted = true;
        Ok(())
    }

    /// Returns the host IP address in this namespace.
    ///
    /// # Errors
    /// Returns an error if the VMID is out of range.
    pub fn host_ip(&self) -> Result<String> {
        let (ip, _, _) = crate::net::ip_math(self.vmid)?;
        Ok(ip.to_string())
    }

    /// Render the TPROXY ruleset for nftables.
    ///
    /// The prerouting chain defaults to `policy drop`. It TPROXY-redirects guest
    /// TCP destined for ports 80 and 443 into the egress proxy, and additionally
    /// accepts guest traffic addressed to the proxy itself (`gateway:proxy_port`)
    /// so a guest steered with `http_proxy=<gateway>:<proxy_port>` reaches the
    /// same filtering front-end (the explicit-proxy MITM variant of H-PROXY-1).
    /// Every other packet from the guest tap is dropped, so no egress escapes the
    /// proxy.
    ///
    /// **No `log` statement** (`tproxy-drop-log-never-emitted`). The catch-all rule
    /// carried `log prefix "vmcell-drop: "` for years and emitted nothing: netfilter
    /// suppresses the syslog `LOG` target in a **non-init** network namespace unless
    /// the host-global `net.netfilter.nf_log_all_netns` sysctl is `1` (it is `0` by
    /// default, and the kernel's own nft selftests set it before asserting on such a
    /// prefix). Every vmcell drop happens in a per-VM namespace, so the rule was a
    /// promise the kernel never kept. Setting that sysctl is the one alternative and
    /// it is refused deliberately: it is host-global, so it would route *every* other
    /// namespace's netfilter logs — other tenants' included — into the host kernel log,
    /// trading a diagnostic for a cross-namespace disclosure and a flood channel a
    /// guest can drive. The security property (default-drop) is unchanged and stays
    /// live-asserted; the diagnostic is simply not promised.
    ///
    /// NET-7 (recorded deviation): this deliberately drops UDP/443 (QUIC). QUIC
    /// cannot be transparently intercepted by the TCP-oriented egress proxy, so
    /// blocking it forces clients to fall back to interceptable TCP/TLS, keeping
    /// all egress observable. This is an intentional posture, not an oversight.
    pub fn render_tproxy_rules(&self, proxy_port: u16, gateway: &str) -> String {
        format!(
            "table ip proxy {{\n\
            \tchain prerouting {{\n\
            \t\ttype filter hook prerouting priority mangle; policy drop;\n\
            \t\tiifname \"{tap}\" tcp dport {{ 80, 443 }} tproxy to :{port} meta mark set 1 accept\n\
            \t\tiifname \"{tap}\" ip daddr {gw} tcp dport {port} accept\n\
            \t\t{drop}\n\
            \t}}\n\
            }}",
            tap = self.tap_name,
            port = proxy_port,
            gw = gateway,
            drop = self.render_catch_all_drop(),
        )
    }

    /// The catch-all drop rule both rendered rulesets end with — the one place the
    /// "everything off this tap that was not explicitly accepted is dropped" law is
    /// spelled, so [`Self::render_tproxy_rules`] and [`Self::render_blocked_rules`]
    /// cannot drift (and neither can grow a `log` statement the kernel discards, see
    /// [`Self::render_tproxy_rules`]).
    fn render_catch_all_drop(&self) -> String {
        format!("iifname \"{tap}\" drop", tap = self.tap_name)
    }

    /// Render the **accepts-nothing** ruleset for
    /// [`Egress::Blocked`](crate::config::Egress::Blocked).
    ///
    /// [`Self::render_tproxy_rules`]'s shape minus both of its accept rules: a
    /// `policy drop` prerouting chain whose only rule drops everything arriving on
    /// the guest tap. `Egress::Blocked`'s rustdoc says "all egress traffic is
    /// blocked", and until this existed the privileged arm installed **no table at
    /// all**, leaving the per-VM namespace on the kernel's default `accept` policy —
    /// so `Blocked` was strictly *more* permissive than `Filtered` and
    /// indistinguishable from `Open` (`egress-blocked-is-a-silent-no-op`). What it
    /// admitted is design §6.3's privileged host-endpoint mechanism: a host process
    /// placed inside the VM's namespace, reachable at the tap gateway, which
    /// `Filtered` drops.
    ///
    /// There is no `tproxy` statement and no accept, so — unlike
    /// [`Self::emit_proxy_rules`] — applying this needs no proxy and no policy route.
    #[must_use]
    pub fn render_blocked_rules(&self) -> String {
        format!(
            "table ip proxy {{\n\
            \tchain prerouting {{\n\
            \t\ttype filter hook prerouting priority mangle; policy drop;\n\
            \t\t{drop}\n\
            \t}}\n\
            }}",
            drop = self.render_catch_all_drop(),
        )
    }

    /// Configures nftables rules to forward traffic to the proxy using TPROXY.
    ///
    /// # Errors
    /// Returns an error if the nftables rules fail to apply.
    pub fn emit_proxy_rules(&self, proxy_port: u16, applier: &dyn NftApplier) -> Result<()> {
        let gateway = self.host_ip()?;
        let rules = self.render_tproxy_rules(proxy_port, &gateway);
        applier.apply_rules(&self.name, &rules)?;
        self.netlink.setup_tproxy_routing(&self.name)?;
        Ok(())
    }

    /// Applies the accepts-nothing ruleset of [`Self::render_blocked_rules`] in this VM's
    /// namespace — the privileged arm's honoring of
    /// [`Egress::Blocked`](crate::config::Egress::Blocked).
    ///
    /// It installs **no** TPROXY policy routing: that route exists to deliver
    /// `tproxy`-marked packets to a local proxy socket, and a blocked VM has no proxy and
    /// no accepted packet to deliver. Adding it anyway would be an unreachable route
    /// whose presence implied an interception path that is not there.
    ///
    /// # Errors
    /// Returns an error if the nftables rules fail to apply.
    pub fn emit_blocked_rules(&self, applier: &dyn NftApplier) -> Result<()> {
        let rules = self.render_blocked_rules();
        applier.apply_rules(&self.name, &rules)?;
        Ok(())
    }
}

impl Drop for NetNamespace {
    fn drop(&mut self) {
        // NET-8: Drop cannot propagate errors; surface a teardown failure as a
        // warning rather than silently discarding it.
        if let Err(e) = self.delete() {
            tracing::warn!(
                "NetNamespace drop: failed to delete netns {}: {}",
                self.name,
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    pub(super) struct FakeNetlink {
        pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        /// Records the vmid forwarded to each `setup_tap` call, in order, so a
        /// test can assert that `create()` passes the requested vmid into the
        /// tap /30 host-IP math (where the real `RtNetlink` derives the address).
        pub setup_tap_vmids: std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
        /// When true, `setup_tap` records and then returns an error, to drive the
        /// post-`add_netns` cleanup path in `create()` (H-QEMU-1).
        pub fail_setup_tap: bool,
    }

    impl FakeNetlink {
        pub(super) fn new() -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                setup_tap_vmids: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                fail_setup_tap: false,
            }
        }

        /// A fake whose `setup_tap` fails (after recording its call), used to
        /// exercise `create()`'s cleanup-on-failure path.
        pub(super) fn new_failing_setup_tap() -> Self {
            Self {
                fail_setup_tap: true,
                ..Self::new()
            }
        }
    }

    impl Netlink for FakeNetlink {
        fn add_netns(&self, name: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("add_netns({name})"));
            Ok(())
        }
        fn setup_tap(&self, netns: &str, tap_name: &str, vmid: u32) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("setup_tap({netns}, {tap_name})"));
            self.setup_tap_vmids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(vmid);
            if self.fail_setup_tap {
                return Err(Error::Network("injected setup_tap failure".to_string()));
            }
            Ok(())
        }
        fn create_bridge(
            &self,
            netns: &str,
            bridge: &str,
            gateway: std::net::Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!(
                    "create_bridge({netns}, {bridge}, {gateway}/{prefix_len})"
                ));
            Ok(())
        }
        fn setup_tap_on_bridge(&self, netns: &str, tap_name: &str, bridge: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!(
                    "setup_tap_on_bridge({netns}, {tap_name}, {bridge})"
                ));
            Ok(())
        }
        fn delete_link(&self, netns: &str, link: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("delete_link({netns}, {link})"));
            Ok(())
        }
        fn delete_netns(&self, name: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("delete_netns({name})"));
            Ok(())
        }
        fn setup_tproxy_routing(&self, netns: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("setup_tproxy_routing({netns})"));
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub(super) struct FakeNftApplier {
        pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        /// The ruleset TEXT of each call, in order, so a test can assert *what* was applied and
        /// not merely that something was — the difference between gating the `Egress::Blocked`
        /// ruleset and gating that some ruleset reached the applier.
        pub rules: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[allow(dead_code)]
    impl FakeNftApplier {
        pub(super) fn new() -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                rules: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    impl NftApplier for FakeNftApplier {
        fn apply_rules(&self, netns: &str, rules: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("apply_rules({netns})"));
            self.rules
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(rules.to_string());
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn test_path_injectivity(vmid1 in 1u32..255, vmid2 in 1u32..255) {
            prop_assume!(vmid1 != vmid2);
            let ns1 = NetNamespace::create("vmcell", vmid1, Box::new(FakeNetlink::new())).unwrap();
            let ns2 = NetNamespace::create("vmcell", vmid2, Box::new(FakeNetlink::new())).unwrap();

            assert_ne!(ns1.name, ns2.name);
            assert_ne!(ns1.tap_name, ns2.tap_name);
            assert_ne!(ns1.host_ip().unwrap(), ns2.host_ip().unwrap());
        }
    }

    #[test]
    fn test_host_ip_math() {
        let ns = NetNamespace {
            name: "test".into(),
            tap_name: "test".into(),
            vmid: 42,
            netlink: Box::new(FakeNetlink::new()),
            deleted: false,
        };
        assert_eq!(ns.host_ip().unwrap(), "10.200.43.1");
    }

    // M-NET-3 / NET-6: pin the rendered TPROXY ruleset with a GOLDEN-EQUALITY
    // assertion, not substring `contains` checks. A contains-based test cannot
    // fail when a *fifth*, more permissive rule (e.g. an `iifname … accept` or a
    // `udp dport 443 accept` QUIC hole) is inserted above the catch-all drop —
    // the golden equality does. vmid 9 maps to gateway 10.200.10.1 via ip_math.
    #[test]
    fn render_tproxy_rules_intercepts_web_and_drops_rest() {
        let ns = ns_for_render();
        let gw = ns.host_ip().unwrap();
        assert_eq!(gw, "10.200.10.1", "vmid 9 must map to gateway 10.200.10.1");
        let rules = ns.render_tproxy_rules(5000, &gw);

        let expected = "table ip proxy {\n\
            \tchain prerouting {\n\
            \t\ttype filter hook prerouting priority mangle; policy drop;\n\
            \t\tiifname \"vmcell-tap-9\" tcp dport { 80, 443 } tproxy to :5000 meta mark set 1 accept\n\
            \t\tiifname \"vmcell-tap-9\" ip daddr 10.200.10.1 tcp dport 5000 accept\n\
            \t\tiifname \"vmcell-tap-9\" drop\n\
            \t}\n\
            }";
        assert_eq!(
            rules, expected,
            "TPROXY ruleset drifted from its golden text; any inserted/reordered rule must be reviewed"
        );

        // NET-7 (recorded deviation): UDP/443 (QUIC) is deliberately NOT accepted;
        // pin its absence explicitly so a re-introduced QUIC hole reddens loudly.
        assert!(
            !rules.contains("udp dport 443"),
            "QUIC (UDP/443) must remain un-accepted so all egress stays interceptable: {rules}"
        );

        // `tproxy-drop-log-never-emitted`: no `log` statement, in either ruleset. netfilter
        // discards the syslog LOG target in a non-init netns unless the host-global
        // `net.netfilter.nf_log_all_netns` is 1, and vmcell will not flip a host-global sysctl
        // that would route every other namespace's netfilter logs into the host kernel log. A
        // re-added `log prefix …` promises a diagnostic the kernel throws away — RED here.
        for (what, ruleset) in [
            ("tproxy", rules.as_str()),
            ("blocked", &ns.render_blocked_rules()),
        ] {
            assert!(
                !ruleset.contains("log"),
                "the {what} ruleset must carry no `log` statement (suppressed in a non-init \
                 netns): {ruleset}"
            );
        }
    }

    /// The namespace both render gates pin their golden text against: vmid 9, whose `ip_math`
    /// gateway is `10.200.10.1`.
    fn ns_for_render() -> NetNamespace {
        NetNamespace {
            name: "vmcell-net-9".into(),
            tap_name: "vmcell-tap-9".into(),
            vmid: 9,
            netlink: Box::new(FakeNetlink::new()),
            deleted: false,
        }
    }

    // `egress-blocked-is-a-silent-no-op` (M1): pin the accepts-nothing ruleset with the same
    // GOLDEN-EQUALITY discipline as its TPROXY sibling — it is `render_tproxy_rules`' shape minus
    // both accept rules. RED on the inverse in both directions: on the pre-fix `Blocked` (which
    // emitted NO table at all, leaving the kernel's default-accept policy) there is no text to
    // compare, and on any ruleset that grows an `accept` — including a re-added
    // `gateway:proxy_port` hole, which is exactly what `Blocked` must not admit — the equality and
    // the explicit no-`accept` assertion below both go red.
    #[test]
    fn render_blocked_rules_accepts_nothing() {
        let ns = ns_for_render();
        let rules = ns.render_blocked_rules();

        let expected = "table ip proxy {\n\
            \tchain prerouting {\n\
            \t\ttype filter hook prerouting priority mangle; policy drop;\n\
            \t\tiifname \"vmcell-tap-9\" drop\n\
            \t}\n\
            }";
        assert_eq!(
            rules, expected,
            "the Egress::Blocked ruleset drifted from its golden text"
        );
        assert!(
            !rules.contains("accept"),
            "`Egress::Blocked` must accept nothing — not even the tap gateway (§6.3's privileged \
             host endpoint, which is what made Blocked more permissive than Filtered): {rules}"
        );
        assert!(
            !rules.contains("tproxy"),
            "a blocked VM has no proxy to redirect into: {rules}"
        );
        assert!(
            rules.contains("policy drop"),
            "the chain must default-drop: {rules}"
        );
        // The catch-all drop is the SAME composed rule the TPROXY ruleset ends with (one law):
        // a divergence between the two spellings would let one of them stop matching the tap.
        let gw = ns.host_ip().unwrap();
        let tproxy = ns.render_tproxy_rules(5000, &gw);
        let drop_rule = ns.render_catch_all_drop();
        assert!(
            rules.contains(&drop_rule) && tproxy.contains(&drop_rule),
            "both rulesets must end with the one composed catch-all drop ({drop_rule})"
        );
    }

    // M1: `emit_blocked_rules` applies the accepts-nothing ruleset in THIS VM's netns and installs
    // NO tproxy policy routing (there is no proxy socket to deliver to). RED on the inverse in
    // both directions: the pre-fix `Blocked` arm applied no ruleset at all (the applier records
    // nothing), and an implementation that copy-pasted `emit_proxy_rules` would record a
    // `setup_tproxy_routing` call that must not be there.
    #[test]
    fn emit_blocked_rules_applies_accepts_nothing_and_no_tproxy_route() {
        let netlink = FakeNetlink::new();
        let netlink_calls = netlink.calls.clone();
        let ns = NetNamespace::create("vmcell", 7, Box::new(netlink)).unwrap();

        let applier = FakeNftApplier::new();
        let applier_calls = applier.calls.clone();
        let applier_rules = applier.rules.clone();

        ns.emit_blocked_rules(&applier).unwrap();

        // Snapshot before asserting: a panic while holding one of these guards would poison the
        // mutex the fake re-locks from `NetNamespace::drop`, turning a readable assertion failure
        // into an abort inside a destructor.
        let calls = applier_calls.lock().unwrap().clone();
        let rules = applier_rules.lock().unwrap().clone();
        let nc = netlink_calls.lock().unwrap().clone();

        assert_eq!(
            calls,
            vec!["apply_rules(vmcell-net-7)".to_string()],
            "the blocked ruleset must be applied exactly once, in this VM's netns"
        );
        assert_eq!(
            rules,
            vec![ns.render_blocked_rules()],
            "the applied text must be the composed blocked ruleset, not a second copy"
        );
        assert!(
            !nc.iter().any(|c| c.starts_with("setup_tproxy_routing")),
            "a blocked VM gets no TPROXY policy route (nothing is delivered to a proxy): {nc:?}"
        );
    }

    // `ns-run-on-pooled-tokio-worker` (m14): every namespace move in this module runs on a thread
    // created for that one call, and a panic inside it is converted, never propagated. Both halves
    // are what `netns_rs::NetNs::run` — `enter()?; f(self); src_ns.enter()?`, with no
    // `catch_unwind` — did NOT provide: it moved the CALLER's thread (a pooled tokio worker, since
    // every caller is reached synchronously from the async `setup_env`) and, on a panic in `f`,
    // skipped the restore, stranding that worker inside the VM's namespace forever.
    //
    // RED on the inverse: an `on_dedicated_thread` that simply calls `f()` inline reports the
    // caller's own `ThreadId` (first assert) and lets the panic unwind out of the helper, so the
    // second half never returns an `Err` at all — it aborts the test with the panic.
    #[test]
    fn namespace_moves_run_on_a_dedicated_thread_and_contain_panics() {
        let caller = std::thread::current().id();
        let worker = on_dedicated_thread("probe", || Ok(std::thread::current().id()))
            .expect("the closure must run");
        assert_ne!(
            worker, caller,
            "a namespace move must not `setns` the calling (pooled runtime) thread"
        );

        let contained = on_dedicated_thread("probe", || -> Result<()> {
            panic!("worker-boom");
        });
        match contained {
            Err(Error::Network(msg)) => {
                assert!(
                    msg.contains("worker-boom") && msg.contains("probe"),
                    "a contained panic must name its payload and its site: {msg}"
                );
            }
            other => panic!("a panicking namespace worker must surface a typed error: {other:?}"),
        }
    }

    // The unprivileged-observable arm of the real helper: an absent namespace is a typed
    // `Error::Network` naming the `/var/run/netns` path, and the closure never runs — no panic, no
    // half-entered thread. RED on an impl that unwraps the open or runs `f` before the `setns`.
    #[test]
    fn in_netns_reports_an_absent_namespace_without_running_the_closure() {
        let ran = std::sync::atomic::AtomicBool::new(false);
        let missing = format!("vmcell-no-such-netns-{}", std::process::id());
        let res = in_netns(&missing, || {
            ran.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        match res {
            Err(Error::Network(msg)) => assert!(
                msg.contains(&missing) && msg.contains("/var/run/netns"),
                "the error must name the namespace path it could not enter: {msg}"
            ),
            other => panic!("an absent namespace must fail typed: {other:?}"),
        }
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "the closure must not run when the namespace could not be entered"
        );
        // One law: the path the helper reports is the one composer everything else uses.
        assert_eq!(
            netns_path(&missing),
            std::path::Path::new("/var/run/netns").join(&missing)
        );
    }

    // N-NET-4: a netlink-worker panic must surface its real payload, not a fixed
    // string. Buggy impl guarded: the pre-fix `map_err(|_| "…panicked".into())`
    // discards the payload, so neither substring below would be recoverable.
    #[test]
    fn panic_payload_str_extracts_message() {
        let p = std::panic::catch_unwind(|| panic!("netlink-boom")).unwrap_err();
        assert!(
            panic_payload_str(p.as_ref()).contains("netlink-boom"),
            "must recover a &str panic payload"
        );
        let p = std::panic::catch_unwind(|| panic!("{}", format!("dyn-{}", 7))).unwrap_err();
        assert!(
            panic_payload_str(p.as_ref()).contains("dyn-7"),
            "must recover a String panic payload"
        );
    }

    // NET-6: drive the recording fakes and assert that emit_proxy_rules applies
    // the ruleset and sets up the policy route, in dependency order. Buggy impl
    // guarded: forgetting setup_tproxy_routing leaves the policy route absent
    // (no TPROXY delivery); reordering would break the inequalities.
    #[test]
    fn emit_proxy_rules_applies_ruleset_and_sets_up_routing_in_order() {
        let netlink = FakeNetlink::new();
        let netlink_calls = netlink.calls.clone();
        let ns = NetNamespace::create("vmcell", 7, Box::new(netlink)).unwrap();

        let applier = FakeNftApplier::new();
        let applier_calls = applier.calls.clone();

        ns.emit_proxy_rules(1234, &applier).unwrap();

        // The nft applier is invoked exactly once, for this VM's netns.
        let ac = applier_calls.lock().unwrap();
        assert_eq!(*ac, vec!["apply_rules(vmcell-net-7)".to_string()]);

        // setup_tproxy_routing is invoked, after the netns and tap exist.
        let nc = netlink_calls.lock().unwrap();
        let pos_add = nc
            .iter()
            .position(|c| c.starts_with("add_netns"))
            .expect("add_netns recorded");
        let pos_tap = nc
            .iter()
            .position(|c| c.starts_with("setup_tap"))
            .expect("setup_tap recorded");
        let pos_tproxy = nc
            .iter()
            .position(|c| c == "setup_tproxy_routing(vmcell-net-7)")
            .expect("setup_tproxy_routing recorded");
        assert!(
            pos_add < pos_tap,
            "netns must be created before tap: {:?}",
            *nc
        );
        assert!(
            pos_tap < pos_tproxy,
            "tap must exist before tproxy routing: {:?}",
            *nc
        );
    }

    // M-NET-3: delete() is idempotent — an explicit delete() followed by a second
    // delete() and by Drop must reach the netlink layer exactly once, so the NET-8
    // teardown warning is reserved for genuine failures. Buggy impl guarded:
    // without the `deleted` guard, delete_netns fires on every call (here 3×), so
    // the spurious-re-teardown warning would fire on every VM teardown.
    #[test]
    fn delete_is_idempotent_single_teardown() {
        let netlink = FakeNetlink::new();
        let calls = netlink.calls.clone();
        let mut ns = NetNamespace::create("vmcell", 5, Box::new(netlink)).unwrap();

        ns.delete().unwrap();
        ns.delete().unwrap(); // second explicit call: must be a no-op
        drop(ns); // Drop calls delete() again: must also be a no-op

        let c = calls.lock().unwrap();
        let deletes = c
            .iter()
            .filter(|s| s.as_str() == "delete_netns(vmcell-net-5)")
            .count();
        assert_eq!(
            deletes, 1,
            "delete must reach netlink exactly once across delete()+delete()+Drop: {:?}",
            *c
        );
    }

    // H-QEMU-1 (netns sibling): when setup_tap fails after add_netns, create() must
    // tear the namespace back down rather than leak it — `Self` is never constructed
    // on this path, so `Drop` cannot reclaim it. Buggy impl guarded: a create() that
    // returns the setup_tap error without deleting the netns records no
    // delete_netns, so the post-add_netns leak goes unnoticed.
    #[test]
    fn create_cleans_up_netns_when_setup_tap_fails() {
        let netlink = FakeNetlink::new_failing_setup_tap();
        let calls = netlink.calls.clone();

        let res = NetNamespace::create("vmcell", 11, Box::new(netlink));
        assert!(res.is_err(), "create must propagate the setup_tap failure");

        let c = calls.lock().unwrap();
        let pos_add = c.iter().position(|s| s == "add_netns(vmcell-net-11)");
        let pos_del = c.iter().position(|s| s == "delete_netns(vmcell-net-11)");
        assert!(pos_add.is_some(), "add_netns must have run: {:?}", *c);
        assert!(
            pos_del.is_some() && pos_add < pos_del,
            "create must delete the netns after setup_tap fails: {:?}",
            *c
        );
    }

    // LOW (tap.rs:468–479): the recording fake must capture the vmid that create()
    // forwards into setup_tap, where the real RtNetlink derives the tap /30 host IP
    // via ip_math. Buggy impl guarded: a fake that discards the vmid (`_vmid`) — or
    // a create() that forwards a constant instead of the requested vmid — makes the
    // wrong-vmid→tap-IP defect invisible; the forwarding assertion below goes red on
    // it. The boundary cases assert the exact /30 host octet and reject overflow.
    #[test]
    fn create_forwards_vmid_to_setup_tap_for_correct_host_octet() {
        // In-range /30 boundaries map to distinct, specific host octets.
        for (vmid, expected_host) in [(1u32, "10.200.2.1"), (254u32, "10.200.1.1")] {
            let netlink = FakeNetlink::new();
            let vmids = netlink.setup_tap_vmids.clone();
            let ns = NetNamespace::create("vmcell", vmid, Box::new(netlink)).unwrap();

            // create() forwards exactly the requested vmid (not a constant) into
            // setup_tap, and stores the same vmid on the namespace.
            assert_eq!(*vmids.lock().unwrap(), vec![vmid]);
            assert_eq!(ns.vmid, vmid);

            // The forwarded vmid yields the expected /30 host octet via shared math.
            let recorded = vmids.lock().unwrap()[0];
            let (host, _, _) = crate::net::ip_math(recorded).unwrap();
            assert_eq!(
                host.to_string(),
                expected_host,
                "vmid {vmid} must map to host {expected_host}"
            );
        }

        // Out-of-range vmids overflow the /30 host math and must be rejected, not
        // silently wrapped into a colliding octet.
        for vmid in [0u32, 255u32] {
            assert!(
                crate::net::ip_math(vmid).is_err(),
                "vmid {vmid} must be rejected by the /30 host-IP math"
            );
        }
    }
}

/// Call-site gate for the netns-layout law ([`NETNS_DIR`]): **no** production site outside this
/// module spells the `/var/run/netns` layout, pinned in both directions.
///
/// [`netns_path`]'s rustdoc claimed the layout was spelled "in exactly one place" while four other
/// production sites composed it — the claim aged into fiction because nothing could see it age. The
/// four are closed (the §6.4 proxy's namespace entry, `build_vmm_cmd`'s pre-fork C string, and the
/// orphan scanner's two `read_dir`s all compose from [`netns_path`]/[`netns_dir`] now), so this gate
/// states the law rather than a to-do list: a **new** occurrence anywhere under `src` reddens it, and
/// so does the law's own literal moving, vanishing or gaining a twin.
///
/// A source scan, not a type: the closed holdouts each needed a different *shape* of the same fact
/// (a `read_dir` root, a NUL-terminated C string for the post-fork `open`), so no signature can force
/// a future call site through the composer — only a scan can see it.
#[cfg(test)]
mod netns_layout_gate {
    use std::collections::BTreeMap;

    /// `(file relative to `crates/vmcell/src`, production occurrences of the layout literal)`.
    ///
    /// One row, because there is one law: `net/tap.rs` — 1, [`super::NETNS_DIR`] itself. Any second
    /// row this gate reports is a call site that must compose from [`super::netns_path`] /
    /// [`super::netns_dir`] instead.
    const ROSTER: &[(&str, usize)] = &[("net/tap.rs", 1)];

    /// Files the scan must have read for its verdict to mean anything.
    ///
    /// The law's own file, the three that held the four closed holdouts, and `net/segment.rs` — the
    /// law's other consumer. Non-vacuity cannot ride on the roster any more: with one row the
    /// both-directions `assert_eq!` agrees with a walk that reached almost nothing, where it could
    /// not while the roster still listed every violating file. These are the files a re-spelling is
    /// most likely to land in, so they are the ones the scan must prove it opened.
    const MUST_SCAN: &[&str] = &[
        "net/tap.rs",
        "net/segment.rs",
        "orchestrator.rs",
        "proxy/mod.rs",
        "vmm/mod.rs",
    ];

    /// Every `.rs` file under this crate's `src`, as `(relative path, production text)`.
    ///
    /// "Production" is everything before a file's unit-test module: a test that recomputes the
    /// layout independently is the *judge* of the law (`in_netns_reports_an_absent_namespace…`,
    /// `segment_names_and_gateway_come_from_the_shared_laws`), not a violation of it.
    fn production_sources() -> Vec<(String, String)> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
            for entry in entries {
                let path = entry.unwrap_or_else(|e| panic!("src entry: {e}")).path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                let production = match text.split_once("mod tests {") {
                    Some((before, _)) => before.to_string(),
                    None => text,
                };
                let rel = path
                    .strip_prefix(&src)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, production));
            }
        }
        out
    }

    #[test]
    fn the_netns_layout_is_spelled_only_by_the_law() {
        // Composed from the law itself, so this gate's own text is never what it counts and a change
        // to the layout cannot leave the needle behind.
        let needle = format!("\"{}", super::NETNS_DIR);
        let sources = production_sources();
        // Non-vacuity: the scan must have actually reached this crate's tree. With a one-row roster
        // the comparison below agrees with an almost-empty walk, so the guard is the named
        // `MUST_SCAN` set rather than the roster — a walk over the wrong directory reddens here.
        for must_be_scanned in MUST_SCAN {
            assert!(
                sources.iter().any(|(rel, _)| rel == must_be_scanned),
                "the scan never read {must_be_scanned}; it is walking the wrong tree and would \
                 pass vacuously"
            );
        }

        let found: BTreeMap<String, usize> = sources
            .iter()
            .map(|(rel, text)| (rel.clone(), text.matches(&needle).count()))
            .filter(|(_, count)| *count > 0)
            .collect();
        let expected: BTreeMap<String, usize> = ROSTER
            .iter()
            .map(|(rel, count)| ((*rel).to_string(), *count))
            .collect();

        assert_eq!(
            found, expected,
            "the netns layout must be spelled ONLY by `NETNS_DIR`. An extra entry is a production \
             call site that has to compose from `netns_path`/`netns_dir` instead — whatever shape it \
             needs (a `PathBuf`, a `read_dir` root, a NUL-terminated string) it composes from the law. \
             A missing or moved entry means the law itself was renamed or relocated; move the row with \
             it in the same change"
        );
    }

    #[test]
    fn the_gate_reddens_on_a_re_planted_inline_layout() {
        // The scan's own predicate, driven against text the roster does not record: a re-planted
        // occurrence must be visible as a difference, or the law above is decoration.
        let needle = format!("\"{}", super::NETNS_DIR);
        let smuggled = format!("let p = std::fs::read_dir({needle}\").unwrap();");
        assert_eq!(
            smuggled.matches(&needle).count(),
            1,
            "an inline layout literal must be countable — this is the comparison the roster rests on"
        );
        // …and a comment or a prose diagnostic mentioning the path is NOT a call site: the needle
        // includes the opening quote, so only a literal that *starts* with the layout counts.
        let prose = "// no /var/run/netns → the privileged datapath has nowhere to keep namespaces";
        assert_eq!(prose.matches(&needle).count(), 0);
    }
}
