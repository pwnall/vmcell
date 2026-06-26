#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use hudsucker::certificate_authority::{CertificateAuthority, RcgenAuthority};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::crypto::aws_lc_rs;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Manages the MITM proxy's Certificate Authority (CA)
pub struct CaManager {
    ca_cert_pem: String,
}

/// A cloneable wrapper for `RcgenAuthority` to be shared across proxy instances.
#[derive(Clone)]
pub struct SharedAuthority(Arc<RcgenAuthority>);

impl CertificateAuthority for SharedAuthority {
    async fn gen_server_config(
        &self,
        authority: &http::uri::Authority,
    ) -> Arc<tokio_rustls::rustls::ServerConfig> {
        self.0.gen_server_config(authority).await
    }
}

static CA_CACHE: OnceLock<(String, Arc<RcgenAuthority>)> = OnceLock::new();

impl CaManager {
    /// Initializes the CA Manager, loading or generating the root CA
    ///
    /// # Errors
    /// Returns an error if filesystem operations or key generation fail.
    pub fn new() -> Result<Self> {
        if let Some((cert_pem, _)) = CA_CACHE.get() {
            return Ok(Self {
                ca_cert_pem: cert_pem.clone(),
            });
        }

        let dir = std::env::var("IMP_ARTIFACTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(format!("/tmp/imp-artifacts-{}", std::process::id()))
            });
        std::fs::create_dir_all(&dir)?;

        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");

        let (ca_cert_pem, key_pair, cert) = if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            let key_pem = std::fs::read_to_string(&key_path)?;

            let key_pair = KeyPair::from_pem(&key_pem).map_err(|e| Error::Proxy(e.to_string()))?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)
                .map_err(|e| Error::Proxy(e.to_string()))?;
            let cert = params
                .self_signed(&key_pair)
                .map_err(|e| Error::Proxy(e.to_string()))?;

            (cert_pem, key_pair, cert)
        } else {
            let key_pair = KeyPair::generate().map_err(|e| Error::Proxy(e.to_string()))?;
            let mut params = CertificateParams::default();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let mut dn = DistinguishedName::new();
            dn.push(DnType::OrganizationName, "Imp Testing Framework");
            dn.push(DnType::CommonName, "Imp MITM CA");
            params.distinguished_name = dn;
            let cert = params
                .self_signed(&key_pair)
                .map_err(|e| Error::Proxy(e.to_string()))?;
            let cert_pem = cert.pem();
            let key_pem = key_pair.serialize_pem();

            let cert_tmp = cert_path.with_extension("pem.tmp");
            let key_tmp = key_path.with_extension("key.tmp");
            std::fs::write(&cert_tmp, &cert_pem)?;

            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            let mut f = opts.open(&key_tmp)?;
            f.write_all(key_pem.as_bytes())?;
            f.sync_all()?;

            std::fs::rename(&key_tmp, &key_path)?;
            std::fs::rename(&cert_tmp, &cert_path)?;

            // Re-create key_pair as self_signed borrows it but we need an owned one for hudsucker
            let key_pair2 = KeyPair::from_pem(&key_pem).map_err(|e| Error::Proxy(e.to_string()))?;

            (cert_pem, key_pair2, cert)
        };

        let auth = RcgenAuthority::new(key_pair, cert, 1_000, aws_lc_rs::default_provider());

        // Initialize the cache if multiple threads race, just use the generated one
        let _ = CA_CACHE.set((ca_cert_pem.clone(), Arc::new(auth)));

        Ok(Self { ca_cert_pem })
    }

    /// Returns the CA certificate in PEM format for baking into the rootfs
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Returns the `SharedAuthority` for use with `hudsucker`
    ///
    /// # Errors
    /// Returns an error if CA not initialized.
    pub fn authority(&self) -> Result<SharedAuthority> {
        if let Some((_, auth)) = CA_CACHE.get() {
            return Ok(SharedAuthority(Arc::clone(auth)));
        }
        Err(Error::Proxy("CA not initialized".to_string()))
    }
}
