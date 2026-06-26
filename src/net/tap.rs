//! TAP interface and network namespace management.
//!
//! This module provides the `NetNamespace` struct for creating and managing
//! Linux network namespaces and TAP interfaces used by virtual machines.

use crate::error::{Error, Result};
use futures::stream::TryStreamExt;

fn run_in_tokio<F, Fut, T>(f: F) -> std::result::Result<T, String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, String>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio build failed: {}", e))?;
    rt.block_on(f())
}

fn run_with_rtnetlink<F, Fut, T>(f: F) -> std::result::Result<T, String>
where
    F: FnOnce(rtnetlink::Handle) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, String>>,
{
    run_in_tokio(|| async {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| format!("rtnetlink connect failed: {}", e))?;
        tokio::spawn(connection);
        f(handle).await
    })
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
    /// Returns an error if applying the ip commands fails.
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
            Ok(Ok(())) => Ok(Some(tap)),
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
                    msg.header.table = 100;
                    msg.header.action = netlink_packet_route::rule::RuleAction::Other(1); // FR_ACT_TO_TBL
                    msg.attributes
                        .push(netlink_packet_route::rule::RuleAttribute::FwMark(1));
                    rule.execute()
                        .await
                        .map_err(|e| format!("rule add err: {}", e))?;

                    let mut route = handle.route().add();
                    let msg = route.message_mut();
                    msg.header.table = 100;
                    msg.header.protocol = netlink_packet_route::route::RouteProtocol::Other(2); // RTPROT_BOOT
                    msg.header.scope = netlink_packet_route::route::RouteScope::Other(253); // RT_SCOPE_LINK
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
                .spawn()
                .map_err(|e| format!("nft spawn failed: {}", e))?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(rules_str.as_bytes())
                    .map_err(|e| format!("nft write failed: {}", e))?;
            }

            let status = child
                .wait()
                .map_err(|e| format!("nft wait failed: {}", e))?;
            if !status.success() {
                return Err("nft rules application failed".to_string());
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
    /// The persistent TAP interface handle, keeping it alive.
    _tap: Option<tun_tap::Iface>,
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

        let tap = netlink.setup_tap(&name, &tap_name, vmid)?;

        Ok(Self {
            name,
            tap_name,
            vmid,
            netlink,
            _tap: tap,
        })
    }

    /// Deletes the network namespace and associated interfaces.
    ///
    /// # Errors
    /// Returns an error if the `ip netns delete` command fails.
    pub fn delete(&mut self) -> Result<()> {
        self._tap.take();
        self.netlink.delete_netns(&self.name)?;
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

    /// Render TPROXY ruleset for nftables
    pub fn render_tproxy_rules(&self, proxy_port: u16) -> String {
        format!(
            "table ip proxy {{\n\
            \tchain prerouting {{\n\
            \t\ttype filter hook prerouting priority mangle; policy drop;\n\
            \t\tiifname \"{}\" tcp dport {{ 80, 443 }} tproxy to :{} meta mark set 1 accept\n\
            \t\tiifname \"{}\" log prefix \"imp-drop: \" drop\n\
            \t}}\n\
            }}",
            self.tap_name, proxy_port, self.tap_name
        )
    }

    /// Configures nftables rules to forward traffic to the proxy using TPROXY.
    ///
    /// # Errors
    /// Returns an error if the nftables rules fail to apply.
    pub fn emit_proxy_rules(&self, proxy_port: u16, applier: &dyn NftApplier) -> Result<()> {
        let rules = self.render_tproxy_rules(proxy_port);
        applier.apply_rules(&self.name, &rules)?;
        self.netlink.setup_tproxy_routing(&self.name)?;
        Ok(())
    }
}

impl Drop for NetNamespace {
    fn drop(&mut self) {
        let _ = self.delete();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    pub struct FakeNetlink {
        pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl FakeNetlink {
        pub fn new() -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
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
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("setup_tap({}, {})", netns, tap_name));
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
        };
        assert_eq!(ns.host_ip().unwrap(), "10.200.43.1");
    }
}
