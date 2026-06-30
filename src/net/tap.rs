//! TAP interface and network namespace management.
//!
//! This module provides the `NetNamespace` struct for creating and managing
//! Linux network namespaces and TAP interfaces used by virtual machines.

use crate::error::{Error, Result};
use futures::stream::TryStreamExt;

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
                .map_err(|e| format!("tokio build failed: {}", e))?;
            rt.block_on(f())
        })
        .join()
        .map_err(|_| "netlink worker thread panicked".to_string())?
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
            rtnetlink::new_connection().map_err(|e| format!("rtnetlink connect failed: {}", e))?;
        tokio::spawn(connection);
        f(handle).await
    })
}

/// Sweeps orphaned network namespaces left behind by killed or failed
/// privileged test runs.
///
/// Enumerates `/var/run/netns` and removes every namespace whose name starts
/// with `prefix` (e.g. `imp-net-`). Intended to run at the start of a
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
    let Ok(dir) = std::fs::read_dir("/var/run/netns") else {
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

/// Interface for executing netlink operations.
pub trait Netlink: Send + Sync {
    /// Creates a network namespace.
    ///
    /// # Errors
    /// Returns an error if the namespace creation fails.
    fn add_netns(&self, name: &str) -> Result<()>;
    /// Sets up the TAP interface and IP address inside the namespace.
    ///
    /// # Errors
    /// Returns an error if setting up the TAP interface or assigning the IP fails.
    fn setup_tap(&self, netns: &str, tap_name: &str, vmid: u32) -> Result<Option<tun_tap::Iface>>;
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
        netns_rs::NetNs::new(name)
            .map_err(|e| Error::Network(format!("netns add failed: {}", e)))?;
        Ok(())
    }

    fn setup_tap(&self, netns: &str, tap_name: &str, vmid: u32) -> Result<Option<tun_tap::Iface>> {
        let ns = netns_rs::NetNs::get(netns)
            .map_err(|e| Error::Network(format!("netns get failed: {}", e)))?;
        let tn = tap_name.to_string();

        let tap = ns
            .run(move |_| tun_tap::Iface::without_packet_info(&tn, tun_tap::Mode::Tap))
            .map_err(|e| Error::Network(format!("ns run tap fail: {:?}", e)))?
            .map_err(|e| Error::Network(format!("tap create fail: {}", e)))?;

        // Make the tap persistent, then release our fd: a non-multi-queue tap can be
        // opened by only one process, and the VMM must be the opener (otherwise CH
        // fails with "Open tap device failed: Device or resource busy"). The
        // persistent interface lives in the netns until it is torn down. (The
        // ioctl lives in `crate::net_sys` because this module is
        // `#![forbid(unsafe_code)]` via `net`.)
        {
            use std::os::fd::AsRawFd;
            crate::net_sys::set_tun_persist(tap.as_raw_fd())
                .map_err(|e| Error::Network(format!("TUNSETPERSIST on tap failed: {}", e)))?;
        }
        drop(tap);

        let tap_name = tap_name.to_string();
        let (ip, _, _) = crate::net::ip_math(vmid)?;

        let res = ns.run(move |_| {
            run_with_rtnetlink(|handle| async move {
                let link_idx = handle
                    .link()
                    .get()
                    .match_name(tap_name.clone())
                    .execute()
                    .try_next()
                    .await
                    .map_err(|e| format!("get link err: {}", e))?
                    .ok_or_else(|| format!("link {} not found", tap_name))?
                    .header
                    .index;

                handle
                    .address()
                    .add(link_idx, std::net::IpAddr::V4(ip), 30)
                    .execute()
                    .await
                    .map_err(|e| format!("addr add err: {}", e))?;

                handle
                    .link()
                    .set(link_idx)
                    .up()
                    .execute()
                    .await
                    .map_err(|e| format!("link up err: {}", e))?;

                let lo_idx = handle
                    .link()
                    .get()
                    .match_name("lo".to_string())
                    .execute()
                    .try_next()
                    .await
                    .map_err(|e| format!("get lo err: {}", e))?
                    .ok_or_else(|| "lo not found".to_string())?
                    .header
                    .index;

                handle
                    .link()
                    .set(lo_idx)
                    .up()
                    .execute()
                    .await
                    .map_err(|e| format!("lo up err: {}", e))?;

                Ok(())
            })
        });

        match res {
            // The tap is persistent in the netns and our fd is already dropped, so
            // there is no handle to return — the VMM opens the interface by name.
            Ok(Ok(())) => Ok(None),
            Ok(Err(e)) => Err(Error::Network(e)),
            Err(e) => Err(Error::Network(format!("ns run err: {:?}", e))),
        }
    }

    fn delete_netns(&self, name: &str) -> Result<()> {
        let ns = netns_rs::NetNs::get(name)
            .map_err(|e| Error::Network(format!("netns get failed: {}", e)))?;
        ns.remove()
            .map_err(|e| Error::Network(format!("netns remove failed: {}", e)))?;
        Ok(())
    }

    fn setup_tproxy_routing(&self, netns: &str) -> Result<()> {
        let ns = netns_rs::NetNs::get(netns)
            .map_err(|e| Error::Network(format!("netns get failed: {}", e)))?;
        let inner_res = ns
            .run(|_| {
                run_with_rtnetlink(|handle| async move {
                    let lo_idx = handle
                        .link()
                        .get()
                        .match_name("lo".to_string())
                        .execute()
                        .try_next()
                        .await
                        .map_err(|e| format!("get lo err: {}", e))?
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
                    msg.header.action = netlink_packet_route::rule::RuleAction::Other(1); // FR_ACT_TO_TBL
                    msg.attributes
                        .push(netlink_packet_route::rule::RuleAttribute::FwMark(1));
                    rule.execute()
                        .await
                        .map_err(|e| format!("rule add err: {}", e))?;

                    let mut route = handle.route().add();
                    let msg = route.message_mut();
                    // Same as the rule above: an unset address family is rejected with
                    // EAFNOSUPPORT. This is an IPv4 local route into table 100.
                    msg.header.address_family = netlink_packet_route::AddressFamily::Inet;
                    msg.header.table = 100;
                    msg.header.protocol = netlink_packet_route::route::RouteProtocol::Other(2); // RTPROT_BOOT
                    // RTN_LOCAL requires scope >= RT_SCOPE_HOST: the kernel's
                    // fib_create_info rejects fib_props[RTN_LOCAL].scope (HOST) >
                    // fc_scope with EINVAL, so RT_SCOPE_LINK is invalid for a local
                    // route (iproute2 also forces HOST for `ip route add local`).
                    msg.header.scope = netlink_packet_route::route::RouteScope::Other(254); // RT_SCOPE_HOST
                    msg.header.kind = netlink_packet_route::route::RouteType::Other(2); // RTN_LOCAL
                    msg.attributes
                        .push(netlink_packet_route::route::RouteAttribute::Oif(lo_idx));
                    route
                        .execute()
                        .await
                        .map_err(|e| format!("route add err: {}", e))?;

                    Ok(())
                })
            })
            .map_err(|e| Error::Network(format!("ns run err: {:?}", e)))?;
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
        let ns = netns_rs::NetNs::get(netns)
            .map_err(|e| Error::Subprocess(format!("netns get failed: {}", e)))?;
        let rules_str = rules.to_string();

        let inner_res = ns.run(move |_| {
            use std::io::Write;
            let mut child = std::process::Command::new("nft")
                .args(["-f", "-"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("nft spawn failed: {}", e))?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(rules_str.as_bytes())
                    .map_err(|e| format!("nft write failed: {}", e))?;
                // `stdin` is dropped here, closing the pipe so nft sees EOF.
            }

            // NET-8: capture nft's exit code and stderr so a rule-load failure is
            // diagnosable instead of an opaque "failed".
            let output = child
                .wait_with_output()
                .map_err(|e| format!("nft wait failed: {}", e))?;
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
        });

        match inner_res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::Subprocess(e)),
            Err(e) => Err(Error::Subprocess(format!("ns run err: {}", e))),
        }
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
    /// Held tap fd. Now always `None`: the tap is made persistent in the netns
    /// (`TUNSETPERSIST`) and our fd is dropped so the VMM can open the interface.
    _tap: Option<tun_tap::Iface>,
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
    /// Creates a new network namespace and TAP interface for the given VM ID.
    ///
    /// # Errors
    /// Returns an error if the `rtnetlink` operations fail.
    pub fn create(vmid: u32, netlink: Box<dyn Netlink>) -> Result<Self> {
        let name = format!("imp-net-{}", vmid);
        let tap_name = format!("imp-tap-{}", vmid);

        netlink.add_netns(&name)?;

        // H-QEMU-1 (netns sibling): the netns now exists. If setup_tap fails, `Self`
        // is never constructed, so `Drop` cannot reclaim it — tear the namespace
        // back down here. Removing the netns also reaps any half-created persistent
        // tap that setup_tap left inside it, so a failed create() leaks nothing.
        let tap = match netlink.setup_tap(&name, &tap_name, vmid) {
            Ok(tap) => tap,
            Err(e) => {
                if let Err(cleanup_err) = netlink.delete_netns(&name) {
                    tracing::warn!(
                        "NetNamespace::create: failed to clean up netns {} after setup_tap error: {}",
                        name,
                        cleanup_err
                    );
                }
                return Err(e);
            }
        };

        Ok(Self {
            name,
            tap_name,
            vmid,
            netlink,
            _tap: tap,
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
        self._tap.take();
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
    /// Every other packet from the guest tap is logged and dropped, so no egress
    /// escapes the proxy.
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
            \t\tiifname \"{tap}\" log prefix \"imp-drop: \" drop\n\
            \t}}\n\
            }}",
            tap = self.tap_name,
            port = proxy_port,
            gw = gateway
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

    pub struct FakeNetlink {
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
        pub fn new() -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                setup_tap_vmids: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                fail_setup_tap: false,
            }
        }

        /// A fake whose `setup_tap` fails (after recording its call), used to
        /// exercise `create()`'s cleanup-on-failure path.
        pub fn new_failing_setup_tap() -> Self {
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
                .unwrap()
                .push(format!("add_netns({})", name));
            Ok(())
        }
        fn setup_tap(
            &self,
            netns: &str,
            tap_name: &str,
            vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("setup_tap({}, {})", netns, tap_name));
            self.setup_tap_vmids.lock().unwrap().push(vmid);
            if self.fail_setup_tap {
                return Err(Error::Network("injected setup_tap failure".to_string()));
            }
            Ok(None)
        }
        fn delete_netns(&self, name: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_netns({})", name));
            Ok(())
        }
        fn setup_tproxy_routing(&self, netns: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("setup_tproxy_routing({})", netns));
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub struct FakeNftApplier {
        pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[allow(dead_code)]
    impl FakeNftApplier {
        pub fn new() -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    impl NftApplier for FakeNftApplier {
        fn apply_rules(&self, netns: &str, _rules: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("apply_rules({})", netns));
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn test_path_injectivity(vmid1 in 1u32..255, vmid2 in 1u32..255) {
            prop_assume!(vmid1 != vmid2);
            let ns1 = NetNamespace::create(vmid1, Box::new(FakeNetlink::new())).unwrap();
            let ns2 = NetNamespace::create(vmid2, Box::new(FakeNetlink::new())).unwrap();

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
            _tap: None,
            deleted: false,
        };
        assert_eq!(ns.host_ip().unwrap(), "10.200.43.1");
    }

    // NET-6: assert the rendered TPROXY ruleset. Buggy impl guarded: dropping the
    // default-drop policy or pointing TPROXY at the wrong port would silently let
    // guest traffic bypass the egress proxy.
    #[test]
    fn render_tproxy_rules_intercepts_web_and_drops_rest() {
        let ns = NetNamespace {
            name: "imp-net-9".into(),
            tap_name: "imp-tap-9".into(),
            vmid: 9,
            netlink: Box::new(FakeNetlink::new()),
            _tap: None,
            deleted: false,
        };
        let gw = ns.host_ip().unwrap();
        let rules = ns.render_tproxy_rules(5000, &gw);
        assert!(
            rules.contains("type filter hook prerouting priority mangle; policy drop;"),
            "ruleset missing default-drop policy: {}",
            rules
        );
        assert!(
            rules.contains("iifname \"imp-tap-9\" tcp dport { 80, 443 } tproxy to :5000"),
            "ruleset missing TPROXY redirect: {}",
            rules
        );
        assert!(
            rules.contains(&format!(
                "iifname \"imp-tap-9\" ip daddr {} tcp dport 5000 accept",
                gw
            )),
            "ruleset missing explicit-proxy accept for the gateway: {}",
            rules
        );
        assert!(
            rules.contains("iifname \"imp-tap-9\" log prefix \"imp-drop: \" drop"),
            "ruleset missing catch-all drop: {}",
            rules
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
        let ns = NetNamespace::create(7, Box::new(netlink)).unwrap();

        let applier = FakeNftApplier::new();
        let applier_calls = applier.calls.clone();

        ns.emit_proxy_rules(1234, &applier).unwrap();

        // The nft applier is invoked exactly once, for this VM's netns.
        let ac = applier_calls.lock().unwrap();
        assert_eq!(*ac, vec!["apply_rules(imp-net-7)".to_string()]);

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
            .position(|c| c == "setup_tproxy_routing(imp-net-7)")
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
        let mut ns = NetNamespace::create(5, Box::new(netlink)).unwrap();

        ns.delete().unwrap();
        ns.delete().unwrap(); // second explicit call: must be a no-op
        drop(ns); // Drop calls delete() again: must also be a no-op

        let c = calls.lock().unwrap();
        let deletes = c
            .iter()
            .filter(|s| s.as_str() == "delete_netns(imp-net-5)")
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

        let res = NetNamespace::create(11, Box::new(netlink));
        assert!(res.is_err(), "create must propagate the setup_tap failure");

        let c = calls.lock().unwrap();
        let pos_add = c.iter().position(|s| s == "add_netns(imp-net-11)");
        let pos_del = c.iter().position(|s| s == "delete_netns(imp-net-11)");
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
            let ns = NetNamespace::create(vmid, Box::new(netlink)).unwrap();

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
                "vmid {} must map to host {}",
                vmid,
                expected_host
            );
        }

        // Out-of-range vmids overflow the /30 host math and must be rejected, not
        // silently wrapped into a colliding octet.
        for vmid in [0u32, 255u32] {
            assert!(
                crate::net::ip_math(vmid).is_err(),
                "vmid {} must be rejected by the /30 host-IP math",
                vmid
            );
        }
    }
}
