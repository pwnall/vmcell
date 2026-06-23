use crate::error::{Error, Result};
use std::process::Command;

pub struct NetNamespace {
    pub name: String,
    pub tap_name: String,
    pub vmid: u32,
}

impl NetNamespace {
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

    pub fn delete(&self) -> Result<()> {
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.name])
            .status();
        Ok(())
    }

    pub fn host_ip(&self) -> String {
        format!("10.200.{}.1", self.vmid)
    }

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
