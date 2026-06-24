//! TAP interface and network namespace management.
//!
//! This module provides the `NetNamespace` struct for creating and managing
//! Linux network namespaces and TAP interfaces used by virtual machines.

use crate::error::{Error, Result};
use std::process::Command;

/// Network namespace management for privileged VMs.
#[derive(Debug)]
pub struct NetNamespace {
    /// The name of the netns.
    pub name: String,
    /// The name of the TAP interface.
    pub tap_name: String,
    /// The VM ID associated with this netns.
    pub vmid: u32,
}

impl NetNamespace {
    /// Creates a new network namespace and TAP interface for the given VM ID.
    ///
    /// # Errors
    /// Returns an error if the `ip` commands fail.
    pub fn create(vmid: u32) -> Result<Self> {
        let name = format!("imp-net-{}", vmid);
        let tap_name = format!("imp-tap-{}", vmid);

        let run = |args: &[&str]| -> Result<()> {
            let status = Command::new("ip")
                .args(args)
                .status()
                .map_err(|e| Error::Other(format!("ip command failed: {}", e)))?;
            if !status.success() {
                return Err(Error::Other(format!("ip {} failed", args.join(" "))));
            }
            Ok(())
        };

        // ip netns add
        let _ = run(&["netns", "add", &name]);
        // ip netns exec imp-net-X ip tuntap add mode tap imp-tap-X
        run(&[
            "netns", "exec", &name, "ip", "tuntap", "add", "mode", "tap", &tap_name,
        ])?;
        // ip netns exec imp-net-X ip addr add 10.200.X.1/30 dev imp-tap-X
        let host_ip = format!("10.200.{}.1/30", vmid);
        run(&[
            "netns", "exec", &name, "ip", "addr", "add", &host_ip, "dev", &tap_name,
        ])?;
        // ip netns exec imp-net-X ip link set imp-tap-X up
        run(&["netns", "exec", &name, "ip", "link", "set", &tap_name, "up"])?;
        // ip netns exec imp-net-X ip link set lo up
        run(&["netns", "exec", &name, "ip", "link", "set", "lo", "up"])?;

        Ok(Self {
            name,
            tap_name,
            vmid,
        })
    }

    /// Deletes the network namespace and associated interfaces.
    ///
    /// # Errors
    /// Returns an error if the network namespace cannot be deleted, though currently ignoring failure.
    pub fn delete(&self) -> Result<()> {
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.name])
            .status();
        Ok(())
    }

    /// Returns the host IP address in this namespace.
    pub fn host_ip(&self) -> String {
        format!("10.200.{}.1", self.vmid)
    }

    /// Configures iptables rules to forward traffic to the proxy.
    ///
    /// # Errors
    /// Returns an error if the `iptables` command fails.
    pub fn emit_proxy_rules(&self, proxy_port: u16) -> Result<()> {
        let status = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.name,
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                &self.tap_name,
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                &proxy_port.to_string(),
            ])
            .status()
            .map_err(|e| Error::Other(format!("iptables failed: {}", e)))?;
        if !status.success() {
            return Err(Error::Other("iptables command failed".to_string()));
        }
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

    #[test]
    fn test_host_ip_math() {
        let ns = NetNamespace {
            name: "imp-net-5".to_string(),
            tap_name: "imp-tap-5".to_string(),
            vmid: 5,
        };
        assert_eq!(ns.host_ip(), "10.200.5.1");
    }
}
