//! TAP interface and network namespace management.
//!
//! This module provides the `NetNamespace` struct for creating and managing
//! Linux network namespaces and TAP interfaces used by virtual machines.

use crate::error::{Error, Result};
use futures::stream::TryStreamExt;
use std::net::Ipv4Addr;
use std::process::Command;

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
        assert!(vmid <= 254, "vmid must be <= 254 for network configuration");
        let ip: Ipv4Addr = format!("10.200.{}.1", vmid)
            .parse()
            .map_err(|e| Error::Network(format!("invalid IP: {}", e)))?;

        let res = ns.run(move |_| {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return Err(format!("tokio build failed: {}", e)),
            };
            rt.block_on(async {
                let (connection, handle, _) = rtnetlink::new_connection()
                    .map_err(|e| format!("rtnetlink connect failed: {}", e))?;
                tokio::spawn(connection);

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
                let _ = std::process::Command::new("ip")
                    .args(["rule", "add", "fwmark", "1", "lookup", "100"])
                    .status();
                let _ = std::process::Command::new("ip")
                    .args([
                        "route", "add", "local", "default", "dev", "lo", "table", "100",
                    ])
                    .status();
                Ok::<(), String>(())
            })
            .map_err(|e| Error::Network(format!("ns run err: {:?}", e)))?;
        if let Err(e) = inner_res {
            return Err(Error::Network(format!("ip rule add err: {}", e)));
        }
        Ok(())
    }
}

/// The default NftApplier implementation using the `nft` command.
pub struct DefaultNftApplier;
impl NftApplier for DefaultNftApplier {
    fn apply_rules(&self, netns: &str, rules: &str) -> Result<()> {
        use std::io::Write;
        let mut child = Command::new("ip")
            .args(["netns", "exec", netns, "nft", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Subprocess(format!("nft spawn failed: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(rules.as_bytes())
                .map_err(|e| Error::Subprocess(format!("nft write failed: {}", e)))?;
        }

        let status = child
            .wait()
            .map_err(|e| Error::Subprocess(format!("nft wait failed: {}", e)))?;
        if !status.success() {
            return Err(Error::Subprocess(
                "nft rules application failed".to_string(),
            ));
        }
        Ok(())
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
    /// # Panics
    /// Panics if `vmid` > 254.
    pub fn host_ip(&self) -> String {
        assert!(self.vmid <= 254, "vmid must be <= 254 for host_ip");
        format!("10.200.{}.1", self.vmid)
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

    struct MockNetlink;
    impl Netlink for MockNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(
            &self,
            _netns: &str,
            _tap_name: &str,
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            Ok(None)
        }
        fn delete_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn test_path_injectivity(vmid1 in 1u32..255, vmid2 in 1u32..255) {
            prop_assume!(vmid1 != vmid2);
            let ns1 = NetNamespace::create(vmid1, Box::new(MockNetlink)).unwrap();
            let ns2 = NetNamespace::create(vmid2, Box::new(MockNetlink)).unwrap();

            assert_ne!(ns1.name, ns2.name);
            assert_ne!(ns1.tap_name, ns2.tap_name);
            assert_ne!(ns1.host_ip(), ns2.host_ip());
        }
    }

    #[test]
    fn test_host_ip_math() {
        let ns = NetNamespace {
            name: "test".into(),
            tap_name: "test".into(),
            vmid: 42,
            netlink: Box::new(MockNetlink),
            _tap: None,
        };
        assert_eq!(ns.host_ip(), "10.200.42.1");
    }
}
