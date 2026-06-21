use anyhow::{anyhow, bail, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    env,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    time,
};
use tracing::{debug, info};

const DB_PROXY_CONNECTION_TIMEOUT_SECONDS: u64 = 300;
const DB_PROXY_MAX_CONNECTIONS: usize = 4096;
const POSTGRES_SSL_REQUEST_CODE: u32 = 80877103;
const POSTGRES_GSSENC_REQUEST_CODE: u32 = 80877104;
const POSTGRES_STARTUP_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseProxyRoute {
    pub database_type: String,
    pub key: String,
    pub upstream: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
}

#[derive(Clone, Debug, Default)]
pub struct DatabaseRouteRegistry {
    routes: Arc<RwLock<BTreeMap<String, BTreeMap<String, String>>>>,
    metadata: Arc<RwLock<BTreeMap<String, BTreeMap<String, DatabaseProxyRoute>>>>,
    routes_by_port: Arc<RwLock<BTreeMap<u16, String>>>,
}

impl DatabaseRouteRegistry {
    pub fn new(routes: impl IntoIterator<Item = DatabaseProxyRoute>) -> Self {
        let registry = Self::default();
        for route in routes {
            registry.upsert(route);
        }
        registry
    }

    pub fn upsert(&self, route: DatabaseProxyRoute) {
        let database_type = normalize_database_type(&route.database_type);
        let key = normalize_route_key(&route.key);
        let upstream = route.upstream.trim().to_string();
        let public_port = route.public_port;
        if database_type.is_empty() || key.is_empty() || upstream.is_empty() {
            return;
        }
        self.routes
            .write()
            .entry(database_type.clone())
            .or_default()
            .insert(key.clone(), upstream.clone());
        let mut route = route;
        route.database_type = normalize_database_type(&route.database_type);
        route.key = normalize_route_key(&route.key);
        self.metadata
            .write()
            .entry(route.database_type.clone())
            .or_default()
            .insert(route.key.clone(), route);
        if let Some(public_port) = public_port {
            self.routes_by_port.write().insert(public_port, upstream);
        }
    }

    pub fn delete(&self, database_type: &str, key: &str) -> bool {
        let database_type = normalize_database_type(database_type);
        let key = normalize_route_key(key);
        let mut routes = self.routes.write();
        let Some(by_key) = routes.get_mut(&database_type) else {
            return false;
        };
        let deleted = by_key.remove(&key).is_some();
        if let Some(by_key) = self.metadata.write().get_mut(&database_type) {
            if let Some(route) = by_key.remove(&key) {
                if let Some(public_port) = route.public_port {
                    self.routes_by_port.write().remove(&public_port);
                }
            }
        }
        if by_key.is_empty() {
            routes.remove(&database_type);
        }
        deleted
    }

    pub fn list(&self) -> Vec<DatabaseProxyRoute> {
        self.metadata
            .read()
            .iter()
            .flat_map(|(_, by_key)| by_key.values().cloned())
            .collect()
    }

    pub fn resolve(&self, database_type: &str, key: &str) -> Option<String> {
        self.routes
            .read()
            .get(&normalize_database_type(database_type))
            .and_then(|by_key| by_key.get(&normalize_route_key(key)).cloned())
    }

    pub fn resolve_only_route(&self, database_type: &str) -> Option<String> {
        let routes = self.routes.read();
        let by_key = routes.get(&normalize_database_type(database_type))?;
        if by_key.len() == 1 {
            by_key.values().next().cloned()
        } else {
            None
        }
    }

    pub fn resolve_public_port(&self, public_port: u16) -> Option<String> {
        self.routes_by_port.read().get(&public_port).cloned()
    }
}

pub async fn run_database_proxy(
    database_type: impl Into<String>,
    addr: SocketAddr,
    registry: DatabaseRouteRegistry,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let database_type = normalize_database_type(&database_type.into());
    let listener = TcpListener::bind(addr).await?;
    let limiter = Arc::new(Semaphore::new(DB_PROXY_MAX_CONNECTIONS));
    info!(%database_type, %addr, "database proxy listening");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    debug!(%peer, %database_type, "database proxy connection limit reached");
                    continue;
                };
                let registry = registry.clone();
                let database_type = database_type.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = time::timeout(
                        Duration::from_secs(DB_PROXY_CONNECTION_TIMEOUT_SECONDS),
                        handle_database_connection(database_type, stream, peer, registry),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow!("database proxy connection timed out")))
                    {
                        debug!(%peer, %error, "database proxy connection closed");
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!(%database_type, "stopping database proxy listener");
                    break;
                }
            }
        }
    }

    Ok(())
}

pub async fn run_database_proxy_public_port(
    addr: SocketAddr,
    registry: DatabaseRouteRegistry,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let limiter = Arc::new(Semaphore::new(DB_PROXY_MAX_CONNECTIONS));
    info!(%addr, "database public-port proxy listening");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    debug!(%peer, %addr, "database public-port proxy connection limit reached");
                    continue;
                };
                let registry = registry.clone();
                let public_port = addr.port();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = time::timeout(
                        Duration::from_secs(DB_PROXY_CONNECTION_TIMEOUT_SECONDS),
                        handle_public_port_connection(public_port, stream, peer, registry),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow!("database public-port proxy connection timed out")))
                    {
                        debug!(%peer, %error, public_port, "database public-port proxy connection closed");
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    info!(%addr, "stopping database public-port proxy listener");
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_public_port_connection(
    public_port: u16,
    mut inbound: TcpStream,
    peer: SocketAddr,
    registry: DatabaseRouteRegistry,
) -> Result<()> {
    let upstream = registry
        .resolve_public_port(public_port)
        .ok_or_else(|| anyhow!("no database proxy route for public_port={public_port}"))?;
    let mut outbound = TcpStream::connect(&upstream)
        .await
        .with_context(|| format!("connecting to database upstream {upstream}"))?;
    debug!(%peer, public_port, %upstream, "database public-port proxy connected");
    let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

async fn handle_database_connection(
    database_type: String,
    mut inbound: TcpStream,
    peer: SocketAddr,
    registry: DatabaseRouteRegistry,
) -> Result<()> {
    let mut prelude = Vec::new();
    let route_key = match database_type.as_str() {
        "postgres" | "postgresql" => {
            let startup = read_postgres_startup_packet(&mut inbound, &mut prelude).await?;
            require_database_proxy_token(&startup)?;
            startup.route_key()
        }
        _ => None,
    };

    let upstream = route_key
        .as_deref()
        .and_then(|key| registry.resolve(&database_type, key))
        .or_else(|| registry.resolve_only_route(&database_type))
        .ok_or_else(|| {
            anyhow!(
                "no database proxy route for type={} key={}",
                database_type,
                route_key.as_deref().unwrap_or("<none>")
            )
        })?;

    let mut outbound = TcpStream::connect(&upstream)
        .await
        .with_context(|| format!("connecting to database upstream {upstream}"))?;
    if !prelude.is_empty() {
        outbound.write_all(&prelude).await?;
    }
    debug!(%peer, %database_type, ?route_key, %upstream, "database proxy connected");
    let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

fn require_database_proxy_token(startup: &PostgresStartup) -> Result<()> {
    let expected = env::var("PXXL_DATABASE_PROXY_TOKEN")
        .context("PXXL_DATABASE_PROXY_TOKEN is required for database proxy auth")?;
    let provided = startup
        .parameters
        .get("pxxl_proxy_token")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing database proxy token"))?;
    if provided != expected {
        bail!("invalid database proxy token");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresStartup {
    pub user: Option<String>,
    pub database: Option<String>,
    pub parameters: HashMap<String, String>,
}

impl PostgresStartup {
    fn route_key(&self) -> Option<String> {
        self.database
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                self.user
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
            })
            .map(normalize_route_key)
    }
}

async fn read_postgres_startup_packet(
    stream: &mut TcpStream,
    prelude: &mut Vec<u8>,
) -> Result<PostgresStartup> {
    loop {
        let mut len_buf = [0_u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = u32::from_be_bytes(len_buf) as usize;
        if !(8..=POSTGRES_STARTUP_MAX_BYTES).contains(&packet_len) {
            bail!("invalid postgres startup packet length {packet_len}");
        }

        let mut rest = vec![0_u8; packet_len - 4];
        stream.read_exact(&mut rest).await?;
        let code = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);

        if code == POSTGRES_SSL_REQUEST_CODE || code == POSTGRES_GSSENC_REQUEST_CODE {
            stream.write_all(b"N").await?;
            continue;
        }

        prelude.extend_from_slice(&len_buf);
        prelude.extend_from_slice(&rest);
        return parse_postgres_startup_parameters(&rest[4..]);
    }
}

pub fn parse_postgres_startup_parameters(bytes: &[u8]) -> Result<PostgresStartup> {
    let mut parts = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty());
    let mut parameters = HashMap::new();

    while let Some(key) = parts.next() {
        let Some(value) = parts.next() else {
            break;
        };
        let key = std::str::from_utf8(key)
            .context("postgres startup key was not UTF-8")?
            .to_string();
        let value = std::str::from_utf8(value)
            .context("postgres startup value was not UTF-8")?
            .to_string();
        parameters.insert(key, value);
    }

    Ok(PostgresStartup {
        user: parameters.get("user").cloned(),
        database: parameters.get("database").cloned(),
        parameters,
    })
}

fn normalize_database_type(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "postgresql" => "postgres".to_string(),
        "dragonflydb" => "dragonfly".to_string(),
        other => other.to_string(),
    }
}

fn normalize_route_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_postgres_database_and_user_from_startup_packet() {
        let params = b"user\0pxxluser\0database\0pxxldb\0application_name\0psql\0\0";
        let startup = parse_postgres_startup_parameters(params).unwrap();

        assert_eq!(startup.user.as_deref(), Some("pxxluser"));
        assert_eq!(startup.database.as_deref(), Some("pxxldb"));
        assert_eq!(startup.route_key().as_deref(), Some("pxxldb"));
    }

    #[test]
    fn registry_normalizes_database_type_and_key() {
        let registry = DatabaseRouteRegistry::new([DatabaseProxyRoute {
            database_type: "postgresql".to_string(),
            key: "PxxlDB".to_string(),
            upstream: "127.0.0.1:40001".to_string(),
            route_host: None,
            public_port: None,
        }]);

        assert_eq!(
            registry.resolve("postgres", "pxxldb").as_deref(),
            Some("127.0.0.1:40001")
        );
    }
}
