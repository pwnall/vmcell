use hudsucker::certificate_authority::RcgenAuthority;
use rcgen::{CertificateParams, KeyPair, DistinguishedName, DnType};
use rustls::crypto::aws_lc_rs;
use std::path::PathBuf;
use crate::error::{Error, Result};

/// Manages the MITM proxy's Certificate Authority (CA)
pub struct CaManager {
    ca_cert_pem: String,
    ca_key_pem: String,
}

impl CaManager {
    /// Initializes the CA Manager, loading or generating the root CA
    pub fn new() -> Result<Self> {
        let dir = std::env::var("IMP_ARTIFACTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/imp-artifacts"));
        std::fs::create_dir_all(&dir)?;

        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            let ca_cert_pem = std::fs::read_to_string(&cert_path)?;
            let ca_key_pem = std::fs::read_to_string(&key_path)?;
            Ok(Self { ca_cert_pem, ca_key_pem })
        } else {
            let key_pair = KeyPair::generate().map_err(|e| Error::Other(e.to_string()))?;
            let mut params = CertificateParams::default();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let mut dn = DistinguishedName::new();
            dn.push(DnType::OrganizationName, "Imp Testing Framework");
            dn.push(DnType::CommonName, "Imp MITM CA");
            params.distinguished_name = dn;
            let cert = params.self_signed(&key_pair).map_err(|e| Error::Other(e.to_string()))?;
            let ca_cert_pem = cert.pem();
            let ca_key_pem = key_pair.serialize_pem();

            std::fs::write(&cert_path, &ca_cert_pem)?;
            
            use std::os::unix::fs::OpenOptionsExt;
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            let mut f = opts.open(&key_path)?;
            f.write_all(ca_key_pem.as_bytes())?;

            Ok(Self { ca_cert_pem, ca_key_pem })
        }
    }

    /// Returns the CA certificate in PEM format for baking into the rootfs
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Returns the `RcgenAuthority` for use with `hudsucker`
    pub fn authority(&self) -> Result<RcgenAuthority> {
        let key_pair = KeyPair::from_pem(&self.ca_key_pem).map_err(|e| Error::Other(e.to_string()))?;
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Imp Testing Framework");
        dn.push(DnType::CommonName, "Imp MITM CA");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key_pair).map_err(|e| Error::Other(e.to_string()))?;
        
        let auth = RcgenAuthority::new(key_pair, cert, 1_000, aws_lc_rs::default_provider());
        Ok(auth)
    }
}
