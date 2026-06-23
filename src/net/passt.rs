use crate::error::{Error, Result};
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;

pub struct PasstProcess {
    pub socket_path: PathBuf,
    pub pid_file: PathBuf,
    process: Child,
}

impl PasstProcess {
    pub fn start(vmid: u32) -> Result<Self> {
        let socket_path = PathBuf::from(format!("/tmp/imp-passt-{}.sock", vmid));
        let pid_file = PathBuf::from(format!("/tmp/imp-passt-{}.pid", vmid));

        // Cleanup old socket if exists
        let _ = std::fs::remove_file(&socket_path);

        let guest_ip = format!("10.200.{}.2", vmid);
        let host_ip = format!("10.200.{}.1", vmid);
        let mac = format!("02:00:00:00:00:{:02x}", vmid);

        let mut cmd = Command::new("strace");
        cmd.args([
            "-o",
            &format!("/tmp/imp-passt-strace-{}.log", vmid),
            "-f",
            "passt",
            "--vhost-user",
            "--socket",
            socket_path.to_str().unwrap(),
            "--pid",
            pid_file.to_str().unwrap(),
            "--foreground",
            "--stderr",
        ]);

        let process = cmd
            .spawn()
            .map_err(|e| Error::Other(format!("Failed to start passt: {}", e)))?;

        // Wait for socket to be created
        let mut retries = 50;
        while !socket_path.exists() && retries > 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            retries -= 1;
        }

        if !socket_path.exists() {
            return Err(Error::Other("passt socket not created".to_string()));
        }

        Ok(Self {
            socket_path,
            pid_file,
            process,
        })
    }
}

impl Drop for PasstProcess {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(&self.pid_file);
    }
}
