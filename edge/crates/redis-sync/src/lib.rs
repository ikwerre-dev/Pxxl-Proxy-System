use anyhow::Result;
use chrono::{Datelike, Utc};
use futures_util::StreamExt;
use pxxl_common::{normalize_domain, Route, RouteSource, MAX_ROUTES_PER_SOURCE};
use pxxl_ddos::{BlacklistCommand, BlacklistEngine};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};
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
    hash_index_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTokenRecord {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    #[serde(default = "default_admin_scopes")]
    pub scopes: Vec<String>,
    pub created_at_unix_ms: u64,
    pub last_used_unix_ms: Option<u64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminTokenView {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
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
        if values.len() > MAX_ROUTES_PER_SOURCE {
            warn!(
                count = values.len(),
                max = MAX_ROUTES_PER_SOURCE,
                "persisted Redis routes exceed quota; loading the first quota-sized set"
            );
        }
        values
            .into_iter()
            .take(MAX_ROUTES_PER_SOURCE)
            .map(|value| {
                let mut route: Route = serde_json::from_str(&value)?;
                route.source = RouteSource::Api;
                route.domain = normalize_domain(&route.domain);
                route
                    .validate_for_dynamic_control_plane()
                    .map_err(|reason| {
                        anyhow::anyhow!("invalid persisted route {}: {reason}", route.domain)
                    })?;
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
        persisted
            .validate_for_dynamic_control_plane()
            .map_err(|reason| anyhow::anyhow!("invalid route {}: {reason}", persisted.domain))?;
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
        let key = key.into();
        Self {
            url: url.into(),
            hash_index_key: format!("{key}:hash_index"),
            key,
        }
    }

    pub async fn create_token(&self, name: impl Into<String>) -> Result<CreatedAdminToken> {
        self.create_token_with_scopes(name, default_admin_scopes())
            .await
    }

    pub async fn create_token_with_scopes(
        &self,
        name: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<CreatedAdminToken> {
        let id = Uuid::new_v4().to_string();
        let token = format!("pxxl_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let record = AdminTokenRecord {
            id: id.clone(),
            name: name.into(),
            token_hash: hash_token(&token),
            scopes: normalize_scopes(scopes),
            created_at_unix_ms: now_unix_ms(),
            last_used_unix_ms: None,
            enabled: true,
        };

        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(&record)?;
        let _: usize = connection.hset(&self.key, id, payload).await?;
        let _: usize = connection
            .hset(
                &self.hash_index_key,
                record.token_hash.clone(),
                record.id.clone(),
            )
            .await?;

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
        let existing: Option<String> = connection.hget(&self.key, id).await?;
        if let Some(existing) = existing {
            let record: AdminTokenRecord = serde_json::from_str(&existing)?;
            let _: usize = connection
                .hdel(&self.hash_index_key, record.token_hash)
                .await?;
        }
        let removed: usize = connection.hdel(&self.key, id).await?;
        Ok(removed > 0)
    }

    pub async fn revoke_tokens_by_name(&self, name: &str) -> Result<usize> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let values: Vec<String> = connection.hvals(&self.key).await?;
        let mut removed = 0;

        for value in values {
            let record: AdminTokenRecord = serde_json::from_str(&value)?;
            if record.name != name {
                continue;
            }

            let _: usize = connection
                .hdel(&self.hash_index_key, record.token_hash)
                .await?;
            let deleted: usize = connection.hdel(&self.key, record.id).await?;
            removed += deleted;
        }

        Ok(removed)
    }

    pub async fn verify_token(&self, token: &str) -> Result<Option<AdminTokenView>> {
        let token_hash = hash_token(token);
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let id: Option<String> = connection.hget(&self.hash_index_key, &token_hash).await?;
        let Some(id) = id else {
            return Ok(None);
        };
        let value: Option<String> = connection.hget(&self.key, &id).await?;
        let Some(value) = value else {
            let _: usize = connection.hdel(&self.hash_index_key, token_hash).await?;
            return Ok(None);
        };
        let mut record: AdminTokenRecord = serde_json::from_str(&value)?;
        if record.enabled && constant_time_eq(record.token_hash.as_bytes(), token_hash.as_bytes()) {
            record.last_used_unix_ms = Some(now_unix_ms());
            let payload = serde_json::to_string(&record)?;
            let _: usize = connection
                .hset(&self.key, record.id.clone(), payload)
                .await?;
            return Ok(Some(record.into()));
        }

        Ok(None)
    }
}

impl From<AdminTokenRecord> for AdminTokenView {
    fn from(record: AdminTokenRecord) -> Self {
        Self {
            id: record.id,
            name: record.name,
            scopes: normalize_scopes(record.scopes),
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

fn default_admin_scopes() -> Vec<String> {
    vec!["admin".to_string()]
}

fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut scopes = scopes
        .into_iter()
        .map(|scope| scope.trim().to_ascii_lowercase())
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        default_admin_scopes()
    } else {
        scopes
    }
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

#[derive(Debug, Clone)]
pub struct RedisBandwidthTracker {
    url: String,
    key_prefix: String,
}

impl RedisBandwidthTracker {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            key_prefix: "pxxl:bandwidth".to_string(),
        }
    }

    fn get_monthly_key(&self, domain: &str) -> String {
        let now = Utc::now();
        format!(
            "{}:{}:{}-{:02}",
            self.key_prefix,
            domain,
            now.year(),
            now.month()
        )
    }

    fn get_daily_key(&self, domain: &str) -> String {
        let now = Utc::now();
        format!(
            "{}:{}:{}-{:02}-{:02}",
            self.key_prefix,
            domain,
            now.year(),
            now.month(),
            now.day()
        )
    }

    pub async fn record_bandwidth(&self, domain: &str, bytes: u64) -> Result<()> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;

        let monthly_key = self.get_monthly_key(domain);
        let daily_key = self.get_daily_key(domain);

        let _: u64 = connection.incr(&monthly_key, bytes).await?;
        let _: u64 = connection.incr(&daily_key, bytes).await?;

        let _: bool = connection.expire(&monthly_key, 90 * 24 * 3600).await?;
        let _: bool = connection.expire(&daily_key, 7 * 24 * 3600).await?;

        Ok(())
    }

    pub async fn get_monthly_usage(&self, domain: &str) -> Result<u64> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let monthly_key = self.get_monthly_key(domain);
        let bytes: Option<u64> = connection.get(&monthly_key).await?;
        Ok(bytes.unwrap_or(0))
    }

    pub async fn get_daily_usage(&self, domain: &str) -> Result<u64> {
        let client = redis::Client::open(self.url.as_str())?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let daily_key = self.get_daily_key(domain);
        let bytes: Option<u64> = connection.get(&daily_key).await?;
        Ok(bytes.unwrap_or(0))
    }

    pub async fn check_limit(
        &self,
        domain: &str,
        monthly_limit: Option<u64>,
        daily_limit: Option<u64>,
    ) -> Result<bool> {
        if let Some(limit) = monthly_limit {
            let usage = self.get_monthly_usage(domain).await?;
            if usage >= limit {
                return Ok(false);
            }
        }

        if let Some(limit) = daily_limit {
            let usage = self.get_daily_usage(domain).await?;
            if usage >= limit {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
