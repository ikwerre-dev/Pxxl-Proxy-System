use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::{Bytes, BytesMut};
use http::{header::AUTHORIZATION, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use pxxl_core::RequestObservation;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage backend is not initialized in Phase 1 MVP")]
    NotInitialized,
}

const CLICKHOUSE_ERROR_BODY_LIMIT_BYTES: u64 = 16 * 1024;
const CLICKHOUSE_REQUEST_TIMEOUT_SECONDS: u64 = 5;

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
    pub request_id: String,
    pub domain: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u128,
    pub upstream: Option<String>,
    pub remote_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClickHouseAnalytics {
    endpoint: ClickHouseEndpoint,
    client: Client<HttpConnector, Full<Bytes>>,
}

#[derive(Debug, Clone)]
struct ClickHouseEndpoint {
    uri: Uri,
    authorization: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClickHouseAccessLogRow {
    request_id: String,
    timestamp_unix_ms: u64,
    domain: String,
    method: String,
    path: String,
    status: u16,
    latency_ms: u64,
    upstream: Option<String>,
    remote_ip: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    continent_code: Option<String>,
    continent_name: Option<String>,
    region: Option<String>,
    city: Option<String>,
    geo_source: String,
}

impl ClickHouseAnalytics {
    pub fn new(url: impl AsRef<str>) -> Result<Self> {
        let endpoint = ClickHouseEndpoint::parse(url.as_ref())?;
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { endpoint, client })
    }

    pub async fn ensure_schema(&self) -> Result<()> {
        self.post_sql(
            r#"
CREATE TABLE IF NOT EXISTS pxxl_access_logs (
  request_id String,
  timestamp_unix_ms UInt64,
  domain String,
  method String,
  path String,
  status UInt16,
  latency_ms UInt64,
  upstream Nullable(String),
  remote_ip Nullable(String),
  country_code Nullable(String),
  country_name Nullable(String),
  continent_code Nullable(String),
  continent_name Nullable(String),
  region Nullable(String),
  city Nullable(String),
  geo_source String
) ENGINE = MergeTree
ORDER BY (domain, timestamp_unix_ms, request_id)
"#,
        )
        .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD COLUMN IF NOT EXISTS request_id String")
            .await
    }

    pub async fn insert_request(&self, event: RequestObservation) -> Result<()> {
        let row = ClickHouseAccessLogRow {
            request_id: event.request_id,
            timestamp_unix_ms: event.timestamp_unix_ms,
            domain: event.domain,
            method: event.method,
            path: event.path,
            status: event.status,
            latency_ms: event.latency_ms,
            upstream: event.upstream,
            remote_ip: event.remote_ip.map(|ip| ip.to_string()),
            country_code: event.location.country_code,
            country_name: event.location.country_name,
            continent_code: event.location.continent_code,
            continent_name: event.location.continent_name,
            region: event.location.region,
            city: event.location.city,
            geo_source: event.location.source,
        };
        let payload = format!(
            "INSERT INTO pxxl_access_logs FORMAT JSONEachRow\n{}",
            serde_json::to_string(&row)?
        );
        self.post_sql(&payload).await
    }

    async fn post_sql(&self, sql: &str) -> Result<()> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(self.endpoint.uri.clone())
            .header("content-type", "text/plain; charset=utf-8");
        if let Some(value) = &self.endpoint.authorization {
            builder = builder.header(AUTHORIZATION, value);
        }
        let request = builder.body(Full::new(Bytes::from(sql.to_string())))?;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(CLICKHOUSE_REQUEST_TIMEOUT_SECONDS),
            self.client.request(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ClickHouse request timed out"))??;
        let status = response.status();
        let body =
            collect_body_limited(response.into_body(), CLICKHOUSE_ERROR_BODY_LIMIT_BYTES).await?;
        if !status.is_success() {
            anyhow::bail!(
                "ClickHouse returned {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        Ok(())
    }
}

async fn collect_body_limited(mut body: hyper::body::Incoming, max_bytes: u64) -> Result<Bytes> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            if collected.len() as u64 + data.len() as u64 > max_bytes {
                collected.extend_from_slice(b"<truncated>");
                break;
            }
            collected.extend_from_slice(data);
        }
    }
    Ok(collected.freeze())
}

impl ClickHouseEndpoint {
    fn parse(raw: &str) -> Result<Self> {
        let mut parsed = Url::parse(raw).context("parsing ClickHouse URL")?;
        let authorization = if parsed.username().is_empty() {
            None
        } else {
            let password = parsed.password().unwrap_or_default();
            let credentials = format!("{}:{password}", parsed.username());
            Some(format!("Basic {}", STANDARD.encode(credentials)))
        };
        let _ = parsed.set_username("");
        let _ = parsed.set_password(None);
        let uri = parsed.as_str().parse::<Uri>()?;
        Ok(Self { uri, authorization })
    }
}

pub async fn run_clickhouse_writer(
    clickhouse_url: String,
    mut receiver: mpsc::Receiver<RequestObservation>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let analytics = ClickHouseAnalytics::new(clickhouse_url)?;
    match analytics.ensure_schema().await {
        Ok(()) => info!("ClickHouse analytics table is ready"),
        Err(error) => warn!(%error, "could not ensure ClickHouse analytics table"),
    }

    loop {
        tokio::select! {
            maybe_event = receiver.recv() => {
                let Some(event) = maybe_event else {
                    break;
                };
                if let Err(error) = analytics.insert_request(event).await {
                    debug!(%error, "failed to persist request analytics event");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}
