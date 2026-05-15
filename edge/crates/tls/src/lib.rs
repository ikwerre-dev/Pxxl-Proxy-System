use async_trait::async_trait;
use rcgen::{Certificate, CertificateParams, DnType};
use rustls::{pki_types::CertificateDer, ServerConfig};
use std::{
    fs::File,
    io::{BufReader, Cursor},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::fs;
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("failed to create certificate directory {path}: {source}")]
    CreateDir {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to read certificate file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to write certificate file {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to generate local certificate: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("failed to parse PEM file: {0}")]
    Pem(#[from] std::io::Error),
    #[error("private key file did not contain a supported key")]
    MissingPrivateKey,
    #[error("failed to build rustls server config: {0}")]
    Rustls(#[from] rustls::Error),
}

pub type Result<T> = std::result::Result<T, TlsError>;

#[derive(Debug, Clone)]
pub struct CertificateBundle {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub domains: Vec<String>,
}

#[async_trait]
pub trait CertificateIssuer: Send + Sync {
    async fn ensure_certificate(&self, domains: &[String]) -> Result<CertificateBundle>;
}

#[derive(Debug, Clone)]
pub struct LocalCertificateStore {
    cert_dir: PathBuf,
}

impl LocalCertificateStore {
    pub fn new(cert_dir: impl Into<PathBuf>) -> Self {
        Self {
            cert_dir: cert_dir.into(),
        }
    }

    pub fn cert_dir(&self) -> &Path {
        &self.cert_dir
    }

    pub fn cert_path(&self) -> PathBuf {
        self.cert_dir.join("local-dev-cert.pem")
    }

    pub fn key_path(&self) -> PathBuf {
        self.cert_dir.join("local-dev-key.pem")
    }

    pub async fn server_config(&self, domains: &[String]) -> Result<Arc<ServerConfig>> {
        let bundle = self.ensure_certificate(domains).await?;
        self.server_config_from_bundle(&bundle)
    }

    pub async fn regenerate_certificate(&self, domains: &[String]) -> Result<CertificateBundle> {
        fs::create_dir_all(&self.cert_dir)
            .await
            .map_err(|source| TlsError::CreateDir {
                path: self.cert_dir.display().to_string(),
                source,
            })?;

        let cert_path = self.cert_path();
        let key_path = self.key_path();
        let (cert_pem, key_pem, domains) = generate_certificate(domains)?;

        fs::write(&cert_path, cert_pem)
            .await
            .map_err(|source| TlsError::Write {
                path: cert_path.display().to_string(),
                source,
            })?;
        fs::write(&key_path, key_pem)
            .await
            .map_err(|source| TlsError::Write {
                path: key_path.display().to_string(),
                source,
            })?;

        info!(cert = %cert_path.display(), "regenerated local development certificate");

        Ok(CertificateBundle {
            cert_path,
            key_path,
            domains,
        })
    }

    pub fn server_config_from_bundle(
        &self,
        bundle: &CertificateBundle,
    ) -> Result<Arc<ServerConfig>> {
        let certs = load_certs(&bundle.cert_path)?;
        let key = load_private_key(&bundle.key_path)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

#[async_trait]
impl CertificateIssuer for LocalCertificateStore {
    async fn ensure_certificate(&self, domains: &[String]) -> Result<CertificateBundle> {
        fs::create_dir_all(&self.cert_dir)
            .await
            .map_err(|source| TlsError::CreateDir {
                path: self.cert_dir.display().to_string(),
                source,
            })?;

        let cert_path = self.cert_path();
        let key_path = self.key_path();

        if cert_path.exists() && key_path.exists() {
            return Ok(CertificateBundle {
                cert_path,
                key_path,
                domains: domains.to_vec(),
            });
        }

        let (cert_pem, key_pem, sans) = generate_certificate(domains)?;

        fs::write(&cert_path, cert_pem)
            .await
            .map_err(|source| TlsError::Write {
                path: cert_path.display().to_string(),
                source,
            })?;
        fs::write(&key_path, key_pem)
            .await
            .map_err(|source| TlsError::Write {
                path: key_path.display().to_string(),
                source,
            })?;

        info!(cert = %cert_path.display(), "generated local development certificate");

        Ok(CertificateBundle {
            cert_path,
            key_path,
            domains: sans,
        })
    }
}

fn generate_certificate(domains: &[String]) -> Result<(String, String, Vec<String>)> {
    let mut sans = domains.to_vec();
    for default in ["localhost", "pxxlhost", "*.pxxlhost"] {
        if !sans.iter().any(|value| value == default) {
            sans.push(default.to_string());
        }
    }
    sans.sort();
    sans.dedup();

    let mut params = CertificateParams::new(sans.clone());
    params
        .distinguished_name
        .push(DnType::CommonName, "Pxxl Proxy Local Development");
    let cert = Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();
    Ok((cert_pem, key_pem, sans))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let mut reader = Cursor::new(bytes);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(TlsError::Pem)
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|source| TlsError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(TlsError::Pem)?
        .ok_or(TlsError::MissingPrivateKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generates_and_reuses_local_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCertificateStore::new(dir.path());
        let domains = vec!["app.pxxlhost".to_string()];

        let first = store.ensure_certificate(&domains).await.unwrap();
        let second = store.ensure_certificate(&domains).await.unwrap();

        assert!(first.cert_path.exists());
        assert!(first.key_path.exists());
        assert_eq!(first.cert_path, second.cert_path);
    }
}
