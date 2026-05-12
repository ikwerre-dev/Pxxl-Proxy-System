use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage backend is not initialized in Phase 1 MVP")]
    NotInitialized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEndpoints {
    pub postgres_url: String,
    pub clickhouse_url: String,
}

impl StorageEndpoints {
    pub fn new(postgres_url: impl Into<String>, clickhouse_url: impl Into<String>) -> Self {
        Self {
            postgres_url: postgres_url.into(),
            clickhouse_url: clickhouse_url.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAnalyticsEvent {
    pub domain: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u128,
    pub upstream: Option<String>,
    pub remote_ip: Option<String>,
}
