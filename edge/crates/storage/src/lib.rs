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
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, watch};
use tokio::time::{self, Duration};
use tracing::{info, warn};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage backend is not initialized in Phase 1 MVP")]
    NotInitialized,
}

const CLICKHOUSE_ERROR_BODY_LIMIT_BYTES: u64 = 16 * 1024;
const CLICKHOUSE_QUERY_BODY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
const CLICKHOUSE_REQUEST_TIMEOUT_SECONDS: u64 = 5;
const CLICKHOUSE_BATCH_MAX_EVENTS: usize = 250;
const CLICKHOUSE_BATCH_FLUSH_MS: u64 = 1_000;
const CLICKHOUSE_SPOOL_REPLAY_MAX_FILES: usize = 16;

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

fn access_log_row_from_observation(event: RequestObservation) -> ClickHouseAccessLogRow {
    ClickHouseAccessLogRow {
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
    }
}

fn clickhouse_string_literal(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

fn add_empty_stats_lists(value: &mut serde_json::Value) {
    if let Some(object) = value.as_object_mut() {
        normalize_number_field(object, "requests_total");
        normalize_number_field(object, "responses_2xx");
        normalize_number_field(object, "responses_3xx");
        normalize_number_field(object, "responses_4xx");
        normalize_number_field(object, "responses_5xx");
        normalize_number_field(object, "average_latency_ms");
        normalize_number_field(object, "total_bytes_sent");
        normalize_number_field(object, "total_bytes_received");
        normalize_number_field(object, "total_bandwidth");
        normalize_number_field(object, "last_status");
        normalize_number_field(object, "last_seen_unix_ms");
        object
            .entry("top_countries")
            .or_insert_with(|| serde_json::json!([]));
        object
            .entry("top_continents")
            .or_insert_with(|| serde_json::json!([]));
        object
            .entry("top_paths")
            .or_insert_with(|| serde_json::json!([]));
        object
            .entry("top_upstreams")
            .or_insert_with(|| serde_json::json!([]));
    }
}

fn normalize_number_field(object: &mut serde_json::Map<String, serde_json::Value>, key: &str) {
    let Some(value) = object.get(key).cloned() else {
        return;
    };
    let Some(text) = value.as_str() else {
        return;
    };
    if let Ok(number) = text.parse::<u64>() {
        object.insert(key.to_string(), serde_json::Value::Number(number.into()));
        return;
    }
    if let Ok(number) = text.parse::<f64>() {
        if let Some(number) = serde_json::Number::from_f64(number) {
            object.insert(key.to_string(), serde_json::Value::Number(number));
        }
    }
}

fn normalized_row_value(row: &serde_json::Value, key: &str) -> serde_json::Value {
    let Some(value) = row.get(key).cloned() else {
        return serde_json::Value::Null;
    };
    let Some(text) = value.as_str() else {
        return value;
    };
    if let Ok(number) = text.parse::<u64>() {
        return serde_json::Value::Number(number.into());
    }
    if let Ok(number) = text.parse::<f64>() {
        return serde_json::Number::from_f64(number)
            .map(serde_json::Value::Number)
            .unwrap_or(value);
    }
    value
}

fn normalize_bandwidth_row(row: &mut serde_json::Value) {
    if let Some(object) = row.as_object_mut() {
        normalize_number_field(object, "bytes_sent");
        normalize_number_field(object, "bytes_received");
        normalize_number_field(object, "total_bandwidth");
        normalize_number_field(object, "request_count");
    }
}

fn access_log_row_to_visit(row: serde_json::Value) -> serde_json::Value {
    let location = serde_json::json!({
        "country_code": row.get("country_code").cloned().unwrap_or(serde_json::Value::Null),
        "country_name": row.get("country_name").cloned().unwrap_or(serde_json::Value::Null),
        "continent_code": row.get("continent_code").cloned().unwrap_or(serde_json::Value::Null),
        "continent_name": row.get("continent_name").cloned().unwrap_or(serde_json::Value::Null),
        "region": row.get("region").cloned().unwrap_or(serde_json::Value::Null),
        "city": row.get("city").cloned().unwrap_or(serde_json::Value::Null),
        "source": row
            .get("geo_source")
            .cloned()
            .unwrap_or_else(|| serde_json::json!("unknown")),
    });
    serde_json::json!({
        "request_id": row.get("request_id").cloned().unwrap_or(serde_json::Value::Null),
        "domain": row.get("domain").cloned().unwrap_or(serde_json::Value::Null),
        "method": row.get("method").cloned().unwrap_or(serde_json::Value::Null),
        "path": row.get("path").cloned().unwrap_or(serde_json::Value::Null),
        "status": normalized_row_value(&row, "status"),
        "latency_ms": normalized_row_value(&row, "latency_ms"),
        "upstream": row.get("upstream").cloned().unwrap_or(serde_json::Value::Null),
        "remote_ip": row.get("remote_ip").cloned().unwrap_or(serde_json::Value::Null),
        "location": location,
        "timestamp_unix_ms": normalized_row_value(&row, "timestamp_unix_ms"),
        "bytes_sent": normalized_row_value(&row, "bytes_sent"),
        "bytes_received": normalized_row_value(&row, "bytes_received"),
    })
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
PARTITION BY toYYYYMM(toDateTime(timestamp_unix_ms / 1000))
ORDER BY (domain, timestamp_unix_ms, request_id)
"#,
        )
        .await?;
        self.ensure_access_rollup_schema().await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD COLUMN IF NOT EXISTS request_id String")
            .await?;
        self.post_sql(
            "ALTER TABLE pxxl_access_logs ADD COLUMN IF NOT EXISTS bytes_sent UInt64 DEFAULT 0",
        )
        .await?;
        self.post_sql(
            "ALTER TABLE pxxl_access_logs ADD COLUMN IF NOT EXISTS bytes_received UInt64 DEFAULT 0",
        )
        .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD INDEX IF NOT EXISTS idx_status status TYPE set(256) GRANULARITY 4")
            .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD INDEX IF NOT EXISTS idx_path path TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4")
            .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD INDEX IF NOT EXISTS idx_remote_ip remote_ip TYPE bloom_filter(0.01) GRANULARITY 4")
            .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD INDEX IF NOT EXISTS idx_country_code country_code TYPE set(512) GRANULARITY 4")
            .await
    }

    async fn ensure_access_rollup_schema(&self) -> Result<()> {
        self.post_sql(
            r#"
CREATE TABLE IF NOT EXISTS pxxl_access_rollup_day (
  day Date,
  domain String,
  country_code String,
  country_name String,
  continent_code String,
  continent_name String,
  region String,
  city String,
  status_class UInt16,
  requests SimpleAggregateFunction(sum, UInt64),
  blocked SimpleAggregateFunction(sum, UInt64),
  errors SimpleAggregateFunction(sum, UInt64),
  bytes_sent SimpleAggregateFunction(sum, UInt64),
  bytes_received SimpleAggregateFunction(sum, UInt64),
  latency_ms_sum SimpleAggregateFunction(sum, UInt64),
  unique_ips AggregateFunction(uniqCombined64, String)
) ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (domain, day, country_code, continent_code, region, city, status_class)
"#,
        )
        .await?;
        self.post_sql(
            r#"
CREATE MATERIALIZED VIEW IF NOT EXISTS pxxl_access_rollup_day_mv
TO pxxl_access_rollup_day AS
SELECT
  toDate(toDateTime(timestamp_unix_ms / 1000)) AS day,
  domain,
  ifNull(country_code, '') AS country_code,
  ifNull(country_name, '') AS country_name,
  ifNull(continent_code, '') AS continent_code,
  ifNull(continent_name, '') AS continent_name,
  ifNull(region, '') AS region,
  ifNull(city, '') AS city,
  toUInt16(intDiv(status, 100) * 100) AS status_class,
  count() AS requests,
  countIf(status >= 400) AS blocked,
  countIf(status >= 500) AS errors,
  sum(bytes_sent) AS bytes_sent,
  sum(bytes_received) AS bytes_received,
  sum(latency_ms) AS latency_ms_sum,
  uniqCombined64State(ifNull(remote_ip, '')) AS unique_ips
FROM pxxl_access_logs
GROUP BY
  day,
  domain,
  country_code,
  country_name,
  continent_code,
  continent_name,
  region,
  city,
  status_class
"#,
        )
        .await
    }

    pub async fn insert_request(&self, event: RequestObservation) -> Result<()> {
        self.insert_requests(std::iter::once(event)).await
    }

    pub async fn insert_requests<I>(&self, events: I) -> Result<()>
    where
        I: IntoIterator<Item = RequestObservation>,
    {
        let rows = events
            .into_iter()
            .map(access_log_row_from_observation)
            .map(|row| serde_json::to_string(&row))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.is_empty() {
            return Ok(());
        }
        let payload = format!(
            "INSERT INTO pxxl_access_logs SETTINGS async_insert=0, wait_for_async_insert=1 FORMAT JSONEachRow\n{}",
            rows.join("\n")
        );
        self.post_sql(&payload).await
    }

    pub async fn get_domain_stats_snapshot(
        &self,
        domain: &str,
    ) -> Result<Option<serde_json::Value>> {
        let domain = clickhouse_string_literal(domain);
        let query = format!(
            r#"
SELECT
    domain,
    count() AS requests_total,
    countIf(status >= 200 AND status < 300) AS responses_2xx,
    countIf(status >= 300 AND status < 400) AS responses_3xx,
    countIf(status >= 400 AND status < 500) AS responses_4xx,
    countIf(status >= 500) AS responses_5xx,
    if(count() = 0, 0, avg(latency_ms)) AS average_latency_ms,
    sum(bytes_sent) AS total_bytes_sent,
    sum(bytes_received) AS total_bytes_received,
    sum(bytes_sent + bytes_received) AS total_bandwidth,
    argMax(status, timestamp_unix_ms) AS last_status,
    max(timestamp_unix_ms) AS last_seen_unix_ms
FROM pxxl_access_logs
WHERE domain = {domain}
GROUP BY domain
"#
        );
        let mut rows = self.query_json(&query).await?;
        let Some(mut stats) = rows.pop() else {
            return Ok(None);
        };
        add_empty_stats_lists(&mut stats);
        Ok(Some(stats))
    }

    pub async fn get_domain_stats_snapshots(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let limit = limit.clamp(1, 50_000);
        let query = format!(
            r#"
SELECT
    domain,
    count() AS requests_total,
    countIf(status >= 200 AND status < 300) AS responses_2xx,
    countIf(status >= 300 AND status < 400) AS responses_3xx,
    countIf(status >= 400 AND status < 500) AS responses_4xx,
    countIf(status >= 500) AS responses_5xx,
    if(count() = 0, 0, avg(latency_ms)) AS average_latency_ms,
    sum(bytes_sent) AS total_bytes_sent,
    sum(bytes_received) AS total_bytes_received,
    sum(bytes_sent + bytes_received) AS total_bandwidth,
    argMax(status, timestamp_unix_ms) AS last_status,
    max(timestamp_unix_ms) AS last_seen_unix_ms
FROM pxxl_access_logs
GROUP BY domain
ORDER BY last_seen_unix_ms DESC
LIMIT {limit}
"#
        );
        let mut rows = self.query_json(&query).await?;
        for row in &mut rows {
            add_empty_stats_lists(row);
        }
        Ok(rows)
    }

    pub async fn get_recent_visits(
        &self,
        domain: Option<&str>,
        request_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let limit = limit.clamp(1, 5_000);
        let mut filters = Vec::new();
        if let Some(domain) = domain {
            filters.push(format!("domain = {}", clickhouse_string_literal(domain)));
        }
        if let Some(request_id) = request_id {
            filters.push(format!(
                "request_id = {}",
                clickhouse_string_literal(request_id)
            ));
        }
        let where_clause = if filters.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", filters.join(" AND "))
        };
        let query = format!(
            r#"
SELECT
    request_id,
    domain,
    method,
    path,
    status,
    latency_ms,
    upstream,
    remote_ip,
    country_code,
    country_name,
    continent_code,
    continent_name,
    region,
    city,
    geo_source,
    timestamp_unix_ms,
    bytes_sent,
    bytes_received
FROM pxxl_access_logs
{where_clause}
ORDER BY timestamp_unix_ms DESC
LIMIT {limit}
"#
        );
        let rows = self.query_json(&query).await?;
        Ok(rows.into_iter().map(access_log_row_to_visit).collect())
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
        let body_limit = if status.is_success() {
            CLICKHOUSE_QUERY_BODY_LIMIT_BYTES
        } else {
            CLICKHOUSE_ERROR_BODY_LIMIT_BYTES
        };
        let body = collect_body_limited(response.into_body(), body_limit).await?;
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
    let spool_dir = analytics_spool_dir();
    match analytics.ensure_schema().await {
        Ok(()) => info!("ClickHouse analytics table is ready"),
        Err(error) => warn!(%error, "could not ensure ClickHouse analytics table"),
    }

    let mut buffer = Vec::with_capacity(CLICKHOUSE_BATCH_MAX_EVENTS);
    let mut flush_interval = time::interval(Duration::from_millis(CLICKHOUSE_BATCH_FLUSH_MS));
    loop {
        tokio::select! {
            maybe_event = receiver.recv() => {
                let Some(event) = maybe_event else {
                    flush_clickhouse_events(&analytics, &spool_dir, &mut buffer).await;
                    break;
                };
                buffer.push(event);
                if buffer.len() >= CLICKHOUSE_BATCH_MAX_EVENTS {
                    flush_clickhouse_events(&analytics, &spool_dir, &mut buffer).await;
                }
            }
            _ = flush_interval.tick() => {
                replay_clickhouse_spool(&analytics, &spool_dir).await;
                flush_clickhouse_events(&analytics, &spool_dir, &mut buffer).await;
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    while let Ok(event) = receiver.try_recv() {
                        buffer.push(event);
                        if buffer.len() >= CLICKHOUSE_BATCH_MAX_EVENTS {
                            flush_clickhouse_events(&analytics, &spool_dir, &mut buffer).await;
                        }
                    }
                    flush_clickhouse_events(&analytics, &spool_dir, &mut buffer).await;
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn flush_clickhouse_events(
    analytics: &ClickHouseAnalytics,
    spool_dir: &Path,
    buffer: &mut Vec<RequestObservation>,
) {
    if buffer.is_empty() {
        return;
    }
    let count = buffer.len();
    let events = std::mem::take(buffer);
    if let Err(error) = analytics.insert_requests(events.clone()).await {
        warn!(
            %error,
            count,
            "failed to persist request analytics batch, retrying once"
        );
        time::sleep(Duration::from_millis(250)).await;
        if let Err(error) = analytics.insert_requests(events.clone()).await {
            warn!(
                %error,
                count,
                path = %spool_dir.display(),
                "spooling request analytics batch after retry failure"
            );
            if let Err(spool_error) = spool_clickhouse_events(spool_dir, &events).await {
                warn!(%spool_error, count, "failed to spool request analytics batch");
            }
        }
    }
}

fn analytics_spool_dir() -> PathBuf {
    std::env::var("PXXL_ANALYTICS_SPOOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/data/analytics-spool"))
}

async fn spool_clickhouse_events(dir: &Path, events: &[RequestObservation]) -> Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    let stamp = Utc::now().timestamp_millis();
    let filename = format!("analytics-{stamp}-{}.jsonl", std::process::id());
    let final_path = dir.join(filename);
    let temp_path = final_path.with_extension("jsonl.tmp");
    let mut payload = String::new();
    for event in events {
        payload.push_str(&serde_json::to_string(event)?);
        payload.push('\n');
    }
    tokio::fs::write(&temp_path, payload).await?;
    tokio::fs::rename(&temp_path, final_path).await?;
    Ok(())
}

async fn replay_clickhouse_spool(analytics: &ClickHouseAnalytics, dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    let mut files = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("jsonl") {
            files.push(path);
        }
    }
    files.sort();
    for path in files.into_iter().take(CLICKHOUSE_SPOOL_REPLAY_MAX_FILES) {
        let Ok(contents) = tokio::fs::read_to_string(&path).await else {
            continue;
        };
        let mut events = Vec::new();
        for line in contents.lines().filter(|line| !line.trim().is_empty()) {
            match serde_json::from_str::<RequestObservation>(line) {
                Ok(event) => events.push(event),
                Err(error) => {
                    warn!(%error, path = %path.display(), "skipping corrupt analytics spool row");
                }
            }
        }
        if events.is_empty() {
            let _ = tokio::fs::remove_file(&path).await;
            continue;
        }
        match analytics.insert_requests(events).await {
            Ok(()) => {
                if let Err(error) = tokio::fs::remove_file(&path).await {
                    warn!(%error, path = %path.display(), "could not remove replayed analytics spool file");
                }
            }
            Err(error) => {
                warn!(%error, path = %path.display(), "analytics spool replay paused");
                break;
            }
        }
    }
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
            clickhouse_string_literal(domain),
            start_timestamp,
            end_timestamp
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

        let mut row = result[0].clone();
        normalize_bandwidth_row(&mut row);
        serde_json::from_value(row).context("failed to parse bandwidth usage from ClickHouse")
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
WHERE domain = {}
  AND timestamp_unix_ms >= toUnixTimestamp(now() - INTERVAL {} MONTH) * 1000
GROUP BY domain, period
ORDER BY period DESC
"#,
            clickhouse_string_literal(domain),
            months
        );

        let result = self.query_json(&query).await?;
        result
            .into_iter()
            .map(|mut row| {
                normalize_bandwidth_row(&mut row);
                serde_json::from_value(row).context("failed to parse bandwidth history row")
            })
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
WHERE domain = {}
  AND timestamp_unix_ms >= toUnixTimestamp(now() - INTERVAL {} HOUR) * 1000
GROUP BY domain, period
ORDER BY period ASC
"#,
            clickhouse_string_literal(domain),
            hours
        );

        let result = self.query_json(&query).await?;
        result
            .into_iter()
            .map(|mut row| {
                normalize_bandwidth_row(&mut row);
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
        let body_limit = if status.is_success() {
            CLICKHOUSE_QUERY_BODY_LIMIT_BYTES
        } else {
            CLICKHOUSE_ERROR_BODY_LIMIT_BYTES
        };
        let body = collect_body_limited(response.into_body(), body_limit).await?;
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
            .map(serde_json::from_str)
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
