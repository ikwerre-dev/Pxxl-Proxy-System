use anyhow::Result;
use futures_util::StreamExt;
use pxxl_common::{normalize_domain, Route, RouteSource};
use pxxl_ddos::{BlacklistCommand, BlacklistEngine};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RedisBlacklistSync {
    url: String,
    channel: String,
}

#[derive(Debug, Clone)]
pub struct RedisRouteStore {
    url: String,
    key: String,
}

#[derive(Debug, Clone)]
pub struct RedisTokenStore {
    url: String,
    key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTokenRecord {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub created_at_unix_ms: u64,
    pub last_used_unix_ms: Option<u64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminTokenView {
    pub id: String,
    pub name: String,
    pub created_at_unix_ms: u64,
    pub last_used_unix_ms: Option<u64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedAdminToken {
    pub record: AdminTokenView,
    pub token: String,
}

impl RedisRouteStore {
    pub fn new(url: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            key: key.into(),
        }
    }

    pub async fn load_routes(&self) -> Result<Vec<Route>> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let values: Vec<String> = connection.hvals(&self.key).await?;
        values
            .into_iter()
            .map(|value| {
                let mut route: Route = serde_json::from_str(&value)?;
                route.source = RouteSource::Api;
                route.domain = normalize_domain(&route.domain);
                Ok(route)
            })
            .collect()
    }

    pub async fn upsert_route(&self, route: &Route) -> Result<()> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let mut persisted = route.clone();
        persisted.source = RouteSource::Api;
        persisted.domain = normalize_domain(&persisted.domain);
        let payload = serde_json::to_string(&persisted)?;
        let _: usize = connection
            .hset(&self.key, persisted.domain.clone(), payload)
            .await?;
        Ok(())
    }

    pub async fn delete_domain(&self, domain: &str) -> Result<bool> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let removed: usize = connection.hdel(&self.key, normalize_domain(domain)).await?;
        Ok(removed > 0)
    }
}

impl RedisTokenStore {
    pub fn new(url: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            key: key.into(),
        }
    }

    pub async fn create_token(&self, name: impl Into<String>) -> Result<CreatedAdminToken> {
        let id = Uuid::new_v4().to_string();
        let token = format!("pxxl_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let record = AdminTokenRecord {
            id: id.clone(),
            name: name.into(),
            token_hash: hash_token(&token),
            created_at_unix_ms: now_unix_ms(),
            last_used_unix_ms: None,
            enabled: true,
        };

        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(&record)?;
        let _: usize = connection.hset(&self.key, id, payload).await?;

        Ok(CreatedAdminToken {
            record: record.into(),
            token,
        })
    }

    pub async fn list_tokens(&self) -> Result<Vec<AdminTokenView>> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let values: Vec<String> = connection.hvals(&self.key).await?;
        let mut records = values
            .into_iter()
            .map(|value| serde_json::from_str::<AdminTokenRecord>(&value).map(AdminTokenView::from))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        records.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(records)
    }

    pub async fn revoke_token(&self, id: &str) -> Result<bool> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let removed: usize = connection.hdel(&self.key, id).await?;
        Ok(removed > 0)
    }

    pub async fn verify_token(&self, token: &str) -> Result<bool> {
        let token_hash = hash_token(token);
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let values: Vec<String> = connection.hvals(&self.key).await?;

        for value in values {
            let mut record: AdminTokenRecord = serde_json::from_str(&value)?;
            if record.enabled
                && constant_time_eq(record.token_hash.as_bytes(), token_hash.as_bytes())
            {
                record.last_used_unix_ms = Some(now_unix_ms());
                let payload = serde_json::to_string(&record)?;
                let _: usize = connection
                    .hset(&self.key, record.id.clone(), payload)
                    .await?;
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl From<AdminTokenRecord> for AdminTokenView {
    fn from(record: AdminTokenRecord) -> Self {
        Self {
            id: record.id,
            name: record.name,
            created_at_unix_ms: record.created_at_unix_ms,
            last_used_unix_ms: record.last_used_unix_ms,
            enabled: record.enabled,
        }
    }
}

impl RedisBlacklistSync {
    pub fn new(url: impl Into<String>, channel: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            channel: channel.into(),
        }
    }

    pub async fn publish(&self, command: &BlacklistCommand) -> Result<()> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(command)?;
        let _: usize = connection.publish(&self.channel, payload).await?;
        Ok(())
    }

    pub async fn subscribe_forever(&self, blacklist: Arc<BlacklistEngine>) -> Result<()> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.subscribe(&self.channel).await?;
        info!(channel = %self.channel, "subscribed to Redis blacklist channel");

        let mut stream = pubsub.on_message();
        while let Some(message) = stream.next().await {
            let payload: String = message.get_payload()?;
            let command: BlacklistCommand = serde_json::from_str(&payload)?;
            blacklist.apply(command);
        }

        Ok(())
    }
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
