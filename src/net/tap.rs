//! TAP interface and network namespace management.
//!
//! This module provides the `NetNamespace` struct for creating and managing
//! Linux network namespaces and TAP interfaces used by virtual machines.

use crate::error::{Error, Result};
use std::process::Command;

/// Network namespace management for privileged VMs.


/// Interface for executing netlink/ip commands.
pub trait Netlink: Send + Sync {
    /// Executes a command with the given arguments.
    fn run(&self, args: &[&str]) -> Result<()>;
}

/// Interface for applying nftables rules.
pub trait NftApplier: Send + Sync {
    /// Applies the given nftables rules in the specified network namespace.
    fn apply_rules(&self, netns: &str, rules: &str) -> Result<()>;
}

/// The default Netlink implementation using the `ip` command.
pub struct DefaultNetlink;
impl Netlink for DefaultNetlink {
    fn run(&self, args: &[&str]) -> Result<()> {
        let status = Command::new("ip")
            .args(args)
            .status()
            .map_err(|e| Error::Other(format!("ip command failed: {}", e)))?;
        if !status.success() {
            return Err(Error::Other(format!("ip {} failed", args.join(" "))));
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
            .map_err(|e| Error::Other(format!("nft spawn failed: {}", e)))?;
        
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(rules.as_bytes()).map_err(|e| Error::Other(format!("nft write failed: {}", e)))?;
        }
        
        let status = child.wait().map_err(|e| Error::Other(format!("nft wait failed: {}", e)))?;
        if !status.success() {
            return Err(Error::Other("nft rules application failed".to_string()));
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
    pub fn create(vmid: u32, netlink: Box<dyn Netlink>) -> Result<Self> {
        let name = format!("imp-net-{}", vmid);
        let tap_name = format!("imp-tap-{}", vmid);

        // ip netns add
        let _ = netlink.run(&["netns", "add", &name]);
        // ip netns exec imp-net-X ip tuntap add mode tap imp-tap-X
        netlink.run(&[
            "netns", "exec", &name, "ip", "tuntap", "add", "mode", "tap", &tap_name,
        ])?;
        // ip netns exec imp-net-X ip addr add 10.200.X.1/30 dev imp-tap-X
        let host_ip = format!("10.200.{}.1/30", vmid);
        netlink.run(&[
            "netns", "exec", &name, "ip", "addr", "add", &host_ip, "dev", &tap_name,
        ])?;
        // ip netns exec imp-net-X ip link set imp-tap-X up
        netlink.run(&["netns", "exec", &name, "ip", "link", "set", &tap_name, "up"])?;
        // ip netns exec imp-net-X ip link set lo up
        netlink.run(&["netns", "exec", &name, "ip", "link", "set", "lo", "up"])?;

        Ok(Self {
            name,
            tap_name,
            vmid,
            netlink,
        })
    }

    /// Deletes the network namespace and associated interfaces.
    pub fn delete(&self) -> Result<()> {
        let _ = self.netlink.run(&["netns", "delete", &self.name]);
        Ok(())
    }

    /// Returns the host IP address in this namespace.
    pub fn host_ip(&self) -> String {
        format!("10.200.{}.1", self.vmid)
    }

    /// Render TPROXY ruleset for nftables
    pub fn render_tproxy_rules(&self, proxy_port: u16) -> String {
        format!(
            "table ip proxy {{\n\
            \tchain prerouting {{\n\
            \t\ttype filter hook prerouting priority mangle; policy accept;\n\
            \t\tiifname \"{}\" tcp dport {{ 80, 443 }} tproxy to :{} meta mark set 1 accept\n\
            \t}}\n\
            }}",
            self.tap_name, proxy_port
        )
    }

    /// Configures nftables rules to forward traffic to the proxy using TPROXY.
    pub fn emit_proxy_rules(&self, proxy_port: u16, applier: &dyn NftApplier) -> Result<()> {
        let rules = self.render_tproxy_rules(proxy_port);
        applier.apply_rules(&self.name, &rules)
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

    #[test]
    fn test_host_ip_math() {
        let ns = NetNamespace {
            name: "imp-net-5".to_string(),
            tap_name: "imp-tap-5".to_string(),
            vmid: 5,
            netlink: Box::new(DefaultNetlink),
        };
        assert_eq!(ns.host_ip(), "10.200.5.1");
    }
}
