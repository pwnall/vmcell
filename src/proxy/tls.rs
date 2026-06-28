#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use hudsucker::certificate_authority::{CertificateAuthority, RcgenAuthority};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::crypto::aws_lc_rs;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

/// Manages the MITM proxy's Certificate Authority (CA)
pub struct CaManager {
    ca_cert_pem: String,
    dir: PathBuf,
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

/// Process-global cache of materialized CAs, keyed by the artifacts directory
/// they were generated/loaded in.
///
/// Keying on the directory is load-bearing for correctness: a second `new()`
/// invoked with a different `IMP_ARTIFACTS_DIR` must mint (or load) the CA for
/// *that* directory rather than reuse one from an unrelated directory, so the
/// CA baked into a rootfs matches the authority the proxy presents. Within a
/// single directory the cache also lets concurrent proxy instances agree on one
/// authority. The map only grows by one small entry per distinct directory and
/// holds no borrowed state, so the process-global lifetime is sound.
/// Materialized CA cache: artifacts dir -> (CA PEM, parsed authority).
type CaCacheMap = HashMap<PathBuf, (String, Arc<RcgenAuthority>)>;

static CA_CACHE: OnceLock<Mutex<CaCacheMap>> = OnceLock::new(); // allow-global-state: CA cache keyed by artifacts dir (see doc above); no borrowed state, sound

fn ca_cache() -> &'static Mutex<CaCacheMap> {
    CA_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn artifacts_dir() -> PathBuf {
    std::env::var("IMP_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(format!("/tmp/imp-artifacts-{}", std::process::id())))
}

impl CaManager {
    /// Initializes the CA Manager, loading or generating the root CA
    ///
    /// # Errors
    /// Returns an error if filesystem operations or key generation fail.
    pub fn new() -> Result<Self> {
        Self::new_in(artifacts_dir())
    }

    /// Initializes the CA Manager for an explicit artifacts directory.
    ///
    /// # Errors
    /// Returns an error if filesystem operations or key generation fail.
    fn new_in(dir: PathBuf) -> Result<Self> {
        // Fast path: a CA was already materialized for this directory.
        {
            let cache = ca_cache().lock().unwrap_or_else(|e| e.into_inner());
            if let Some((cert_pem, _)) = cache.get(&dir) {
                return Ok(Self {
                    ca_cert_pem: cert_pem.clone(),
                    dir,
                });
            }
        }

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

        // Publish under this directory's key. If another thread raced us, keep
        // the entry it inserted so every instance for this directory agrees on
        // one authority.
        let ca_cert_pem = {
            let mut cache = ca_cache().lock().unwrap_or_else(|e| e.into_inner());
            let entry = cache
                .entry(dir.clone())
                .or_insert_with(|| (ca_cert_pem.clone(), Arc::new(auth)));
            entry.0.clone()
        };

        Ok(Self { ca_cert_pem, dir })
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
        let cache = ca_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, auth)) = cache.get(&self.dir) {
            return Ok(SharedAuthority(Arc::clone(auth)));
        }
        Err(Error::Proxy("CA not initialized".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Buggy impl guarded (PROXY-6): a process-global cache that is not keyed on
    // the artifacts dir makes a second `new()` with a *different* dir reuse the
    // first CA — the two certs would be equal and `assert_ne!` would go red.
    #[test]
    fn ca_cache_is_keyed_on_artifacts_dir() {
        let dir1 = tempfile::tempdir().expect("tempdir1");
        let dir2 = tempfile::tempdir().expect("tempdir2");

        let ca1 = CaManager::new_in(dir1.path().to_path_buf()).expect("ca1");
        let ca2 = CaManager::new_in(dir2.path().to_path_buf()).expect("ca2");

        // Distinct directories must yield distinct CAs (no cross-dir reuse).
        assert_ne!(
            ca1.ca_cert_pem(),
            ca2.ca_cert_pem(),
            "a different artifacts dir must not reuse the first CA"
        );

        // The same directory must reuse its cached CA.
        let ca1_again = CaManager::new_in(dir1.path().to_path_buf()).expect("ca1 again");
        assert_eq!(
            ca1.ca_cert_pem(),
            ca1_again.ca_cert_pem(),
            "the same artifacts dir must reuse its cached CA"
        );

        // The authority is resolvable per directory.
        assert!(ca1.authority().is_ok());
        assert!(ca2.authority().is_ok());
    }
}
