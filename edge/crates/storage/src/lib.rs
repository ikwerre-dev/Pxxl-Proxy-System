use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::{Bytes, BytesMut};
use chrono::{Datelike, Utc};
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
    bytes_sent: u64,
    bytes_received: u64,
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
  geo_source String,
  bytes_sent UInt64,
  bytes_received UInt64
) ENGINE = MergeTree
ORDER BY (domain, timestamp_unix_ms, request_id)
"#,
        )
        .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD COLUMN IF NOT EXISTS request_id String")
            .await?;
        self.post_sql(
            "ALTER TABLE pxxl_access_logs ADD COLUMN IF NOT EXISTS bytes_sent UInt64 DEFAULT 0",
        )
        .await?;
        self.post_sql(
            "ALTER TABLE pxxl_access_logs ADD COLUMN IF NOT EXISTS bytes_received UInt64 DEFAULT 0",
        )
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
            bytes_sent: event.bytes_sent,
            bytes_received: event.bytes_received,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthUsage {
    pub domain: String,
    pub period: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bandwidth: u64,
    pub request_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthQuota {
    pub domain: String,
    pub current_month: String,
    pub bytes_used: u64,
    pub bytes_limit: Option<u64>,
    pub percentage_used: f64,
    pub reset_date: String,
    pub exceeded: bool,
}

impl ClickHouseAnalytics {
    pub async fn get_bandwidth_usage(
        &self,
        domain: &str,
        start_timestamp: u64,
        end_timestamp: u64,
    ) -> Result<BandwidthUsage> {
        let query = format!(
            r#"
SELECT 
    domain,
    sum(bytes_sent) as bytes_sent,
    sum(bytes_received) as bytes_received,
    sum(bytes_sent + bytes_received) as total_bandwidth,
    count(*) as request_count
FROM pxxl_access_logs
WHERE domain = '{}' 
  AND timestamp_unix_ms >= {}
  AND timestamp_unix_ms < {}
GROUP BY domain
"#,
            domain, start_timestamp, end_timestamp
        );

        let result = self.query_json(&query).await?;
        if result.is_empty() {
            return Ok(BandwidthUsage {
                domain: domain.to_string(),
                period: format!("{}-{}", start_timestamp, end_timestamp),
                bytes_sent: 0,
                bytes_received: 0,
                total_bandwidth: 0,
                request_count: 0,
            });
        }

        serde_json::from_value(result[0].clone())
            .context("failed to parse bandwidth usage from ClickHouse")
    }

    pub async fn get_bandwidth_history(
        &self,
        domain: &str,
        months: u32,
    ) -> Result<Vec<BandwidthUsage>> {
        let query = format!(
            r#"
SELECT 
    domain,
    formatDateTime(toStartOfMonth(toDateTime(timestamp_unix_ms / 1000)), '%Y-%m') as period,
    sum(bytes_sent) as bytes_sent,
    sum(bytes_received) as bytes_received,
    sum(bytes_sent + bytes_received) as total_bandwidth,
    count(*) as request_count
FROM pxxl_access_logs
WHERE domain = '{}'
  AND timestamp_unix_ms >= toUnixTimestamp(now() - INTERVAL {} MONTH) * 1000
GROUP BY domain, period
ORDER BY period DESC
"#,
            domain, months
        );

        let result = self.query_json(&query).await?;
        result
            .into_iter()
            .map(|row| serde_json::from_value(row).context("failed to parse bandwidth history row"))
            .collect()
    }

    pub async fn get_bandwidth_realtime(
        &self,
        domain: &str,
        hours: u32,
    ) -> Result<Vec<BandwidthUsage>> {
        let query = format!(
            r#"
SELECT 
    domain,
    formatDateTime(toStartOfHour(toDateTime(timestamp_unix_ms / 1000)), '%Y-%m-%dT%H:00:00Z') as period,
    sum(bytes_sent) as bytes_sent,
    sum(bytes_received) as bytes_received,
    sum(bytes_sent + bytes_received) as total_bandwidth,
    count(*) as request_count
FROM pxxl_access_logs
WHERE domain = '{}'
  AND timestamp_unix_ms >= toUnixTimestamp(now() - INTERVAL {} HOUR) * 1000
GROUP BY domain, period
ORDER BY period ASC
"#,
            domain, hours
        );

        let result = self.query_json(&query).await?;
        result
            .into_iter()
            .map(|row| {
                serde_json::from_value(row).context("failed to parse bandwidth realtime row")
            })
            .collect()
    }

    async fn query_json(&self, sql: &str) -> Result<Vec<serde_json::Value>> {
        let query_with_format = format!("{} FORMAT JSONEachRow", sql);
        let mut builder = Request::builder()
            .method("POST")
            .uri(self.endpoint.uri.clone())
            .header("content-type", "text/plain; charset=utf-8");
        if let Some(value) = &self.endpoint.authorization {
            builder = builder.header(AUTHORIZATION, value);
        }
        let request = builder.body(Full::new(Bytes::from(query_with_format)))?;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(CLICKHOUSE_REQUEST_TIMEOUT_SECONDS),
            self.client.request(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ClickHouse query timed out"))??;
        let status = response.status();
        let body =
            collect_body_limited(response.into_body(), CLICKHOUSE_ERROR_BODY_LIMIT_BYTES).await?;
        if !status.is_success() {
            anyhow::bail!(
                "ClickHouse returned {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }

        let body_str = String::from_utf8_lossy(&body);
        let rows: Vec<serde_json::Value> = body_str
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

pub fn calculate_bandwidth_quota(
    bytes_used: u64,
    bytes_limit: Option<u64>,
    reset_day: u8,
) -> BandwidthQuota {
    let now = Utc::now();
    let current_month = format!("{}-{:02}", now.year(), now.month());

    let next_reset = if now.day() >= reset_day as u32 {
        let next_month = if now.month() == 12 {
            chrono::NaiveDate::from_ymd_opt(now.year() + 1, 1, reset_day as u32)
        } else {
            chrono::NaiveDate::from_ymd_opt(now.year(), now.month() + 1, reset_day as u32)
        };
        next_month
            .unwrap_or_else(|| chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap())
    } else {
        chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), reset_day as u32)
            .unwrap_or_else(|| chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap())
    };

    let reset_date = format!("{}T00:00:00Z", next_reset);
    let percentage_used = if let Some(limit) = bytes_limit {
        if limit > 0 {
            (bytes_used as f64 / limit as f64) * 100.0
        } else {
            0.0
        }
    } else {
        0.0
    };

    let exceeded = if let Some(limit) = bytes_limit {
        bytes_used >= limit
    } else {
        false
    };

    BandwidthQuota {
        domain: String::new(),
        current_month,
        bytes_used,
        bytes_limit,
        percentage_used,
        reset_date,
        exceeded,
    }
}
