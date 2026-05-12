use anyhow::Result;
use futures_util::StreamExt;
use pxxl_common::{normalize_domain, Route, RouteSource};
use pxxl_ddos::{BlacklistCommand, BlacklistEngine};
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::info;

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
