use anyhow::Result;
use futures_util::StreamExt;
use pxxl_ddos::{BlacklistCommand, BlacklistEngine};
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Clone)]
pub struct RedisBlacklistSync {
    url: String,
    channel: String,
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
