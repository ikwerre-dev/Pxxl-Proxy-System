use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::{Bytes, BytesMut};
use chrono::{Datelike, Duration as ChronoDuration, NaiveDate, Utc};
use http::{header::AUTHORIZATION, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use pxxl_core::RequestObservation;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
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
const CLICKHOUSE_READ_CACHE_TTL_SECONDS: u64 = 5;
const CLICKHOUSE_READ_CACHE_MAX_ENTRIES: usize = 256;
const CLICKHOUSE_ROLLUP_BACKFILL_PAUSE_MS: u64 = 100;
const CLICKHOUSE_ROLLUP_DEFAULT_DAYS: u32 = 30;
const CLICKHOUSE_ROLLUP_LIST_DOMAIN_LIMIT: usize = 500;
const CLICKHOUSE_ROLLUP_TOP_COUNTRIES_PER_DOMAIN: usize = 10;
const CLICKHOUSE_ROLLUP_TOP_CONTINENTS_PER_DOMAIN: usize = 8;
const CLICKHOUSE_ROLLUP_TOP_REGIONS_PER_DOMAIN: usize = 10;
const CLICKHOUSE_ROLLUP_TOP_CITIES_PER_DOMAIN: usize = 10;

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
    read_cache: Arc<Mutex<QueryCache>>,
}

#[derive(Debug, Clone)]
struct ClickHouseEndpoint {
    uri: Uri,
    authorization: Option<String>,
}

#[derive(Debug, Default)]
struct QueryCache {
    entries: HashMap<String, QueryCacheEntry>,
    order: VecDeque<String>,
}

#[derive(Debug, Clone)]
struct QueryCacheEntry {
    created_at: Instant,
    rows: Vec<serde_json::Value>,
}

impl QueryCache {
    fn get(&mut self, key: &str) -> Option<Vec<serde_json::Value>> {
        let entry = self.entries.get(key)?;
        if entry.created_at.elapsed() > Duration::from_secs(CLICKHOUSE_READ_CACHE_TTL_SECONDS) {
            self.entries.remove(key);
            return None;
        }
        Some(entry.rows.clone())
    }

    fn insert(&mut self, key: String, rows: Vec<serde_json::Value>) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(
            key,
            QueryCacheEntry {
                created_at: Instant::now(),
                rows,
            },
        );
        while self.entries.len() > CLICKHOUSE_READ_CACHE_MAX_ENTRIES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
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

fn clickhouse_domain_filter(domains: &[String]) -> Option<String> {
    let mut cleaned = domains
        .iter()
        .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
        .collect::<Vec<_>>();
    cleaned.sort();
    cleaned.dedup();
    if cleaned.is_empty() {
        return None;
    }
    Some(format!(
        "domain IN ({})",
        cleaned
            .iter()
            .map(|domain| clickhouse_string_literal(domain))
            .collect::<Vec<_>>()
            .join(",")
    ))
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
        normalize_number_field(object, "unique_ips");
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
        object
            .entry("top_regions")
            .or_insert_with(|| serde_json::json!([]));
        object
            .entry("top_cities")
            .or_insert_with(|| serde_json::json!([]));
    }
}

fn stats_row_domain(row: &serde_json::Value) -> Option<String> {
    row.get("domain")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

fn collect_domain_list(
    lists: &mut HashMap<String, serde_json::Map<String, serde_json::Value>>,
    key: &str,
    rows: Vec<serde_json::Value>,
) {
    for mut row in rows {
        let Some(domain) = stats_row_domain(&row) else {
            continue;
        };
        if let Some(object) = row.as_object_mut() {
            object.remove("domain");
            normalize_number_field(object, "count");
        }
        let domain_lists = lists.entry(domain).or_default();
        let entry = domain_lists
            .entry(key.to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(values) = entry.as_array_mut() {
            values.push(row);
        }
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

fn numeric_field(row: &serde_json::Value, key: &str) -> u64 {
    let Some(value) = row.get(key) else {
        return 0;
    };
    if let Some(number) = value.as_u64() {
        return number;
    }
    value
        .as_str()
        .and_then(|text| text.parse::<u64>().ok())
        .unwrap_or(0)
}

fn date_field(row: &serde_json::Value, key: &str) -> Option<NaiveDate> {
    row.get(key)
        .and_then(|value| value.as_str())
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
}

fn stats_rollup_days() -> u32 {
    std::env::var("PXXL_STATS_ROLLUP_DAYS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|days| *days > 0)
        .unwrap_or(CLICKHOUSE_ROLLUP_DEFAULT_DAYS)
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
        Ok(Self {
            endpoint,
            client,
            read_cache: Arc::new(Mutex::new(QueryCache::default())),
        })
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
            .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD INDEX IF NOT EXISTS idx_request_id request_id TYPE bloom_filter(0.001) GRANULARITY 4")
            .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD INDEX IF NOT EXISTS idx_upstream upstream TYPE bloom_filter(0.01) GRANULARITY 4")
            .await?;
        self.post_sql("ALTER TABLE pxxl_access_logs ADD INDEX IF NOT EXISTS idx_city city TYPE set(4096) GRANULARITY 4")
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
CREATE TABLE IF NOT EXISTS pxxl_access_rollup_backfill_state (
  day Date,
  completed_at DateTime
) ENGINE = ReplacingMergeTree(completed_at)
ORDER BY day
"#,
        )
        .await?;
        self.post_sql("ALTER TABLE pxxl_access_rollup_day ADD INDEX IF NOT EXISTS idx_rollup_day day TYPE minmax GRANULARITY 1")
            .await?;
        self.post_sql("ALTER TABLE pxxl_access_rollup_day ADD INDEX IF NOT EXISTS idx_rollup_domain domain TYPE set(100000) GRANULARITY 4")
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
        self.post_sql(&payload).await?;
        self.clear_read_cache();
        Ok(())
    }

    pub async fn get_domain_stats_snapshot(
        &self,
        domain: &str,
    ) -> Result<Option<serde_json::Value>> {
        let domain_sql = clickhouse_string_literal(domain);
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
WHERE domain = {domain_sql}
GROUP BY domain
"#
        );
        let mut rows = self.query_json_cached(&query).await?;
        let Some(mut stats) = rows.pop() else {
            return Ok(None);
        };
        self.add_domain_stats_lists(&mut stats, domain).await?;
        Ok(Some(stats))
    }

    pub async fn get_domain_stats_snapshots(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        self.get_domain_stats_snapshots_filtered(limit, None).await
    }

    pub async fn get_domain_stats_snapshots_for_domains(
        &self,
        domains: &[String],
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        self.get_domain_stats_snapshots_filtered(limit, Some(domains))
            .await
    }

    async fn get_domain_stats_snapshots_filtered(
        &self,
        limit: usize,
        domains: Option<&[String]>,
    ) -> Result<Vec<serde_json::Value>> {
        let limit = limit.clamp(1, 50_000);
        let domain_filter = domains.and_then(clickhouse_domain_filter);
        let raw_where = domain_filter
            .as_ref()
            .map(|filter| format!("WHERE {filter}"))
            .unwrap_or_default();
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
    uniqExact(remote_ip) AS unique_ips,
    argMax(status, timestamp_unix_ms) AS last_status,
    max(timestamp_unix_ms) AS last_seen_unix_ms
FROM pxxl_access_logs
{raw_where}
GROUP BY domain
ORDER BY last_seen_unix_ms DESC
LIMIT {limit}
"#
        );
        match self
            .get_domain_stats_snapshots_from_rollup(limit, domain_filter.as_deref())
            .await
        {
            Ok(rows) if !rows.is_empty() => return Ok(rows),
            Ok(_) => {}
            Err(error) => {
                warn!(%error, "falling back to raw access logs for domain stats snapshots");
            }
        }

        let mut rows = self.query_json_cached(&query).await?;
        for row in rows.iter_mut() {
            add_empty_stats_lists(row);
        }
        Ok(rows)
    }

    async fn get_domain_stats_snapshots_from_rollup(
        &self,
        limit: usize,
        domain_filter: Option<&str>,
    ) -> Result<Vec<serde_json::Value>> {
        let days = stats_rollup_days();
        let where_clause = match domain_filter {
            Some(filter) => format!("day >= today() - INTERVAL {days} DAY AND {filter}"),
            None => format!("day >= today() - INTERVAL {days} DAY"),
        };
        let query = format!(
            r#"
SELECT
    domain,
    sum(requests) AS requests_total,
    sumIf(requests, status_class = 200) AS responses_2xx,
    sumIf(requests, status_class = 300) AS responses_3xx,
    sumIf(requests, status_class = 400) AS responses_4xx,
    sumIf(requests, status_class = 500) AS responses_5xx,
    if(sum(requests) = 0, 0, sum(latency_ms_sum) / sum(requests)) AS average_latency_ms,
    sum(bytes_sent) AS total_bytes_sent,
    sum(bytes_received) AS total_bytes_received,
    sum(bytes_sent + bytes_received) AS total_bandwidth,
    uniqCombined64Merge(unique_ips) AS unique_ips,
    toUInt16(argMax(status_class, day)) AS last_status,
    toUInt64(toUnixTimestamp(max(day)) * 1000) AS last_seen_unix_ms
FROM pxxl_access_rollup_day
WHERE {where_clause}
GROUP BY domain
ORDER BY requests_total DESC
LIMIT {limit}
"#
        );
        let mut rows = self.query_json_cached(&query).await?;
        if rows.is_empty() {
            return Ok(rows);
        }
        self.add_rollup_stats_lists_bulk(&mut rows, days).await?;
        Ok(rows)
    }

    async fn add_rollup_stats_lists_bulk(
        &self,
        stats_rows: &mut [serde_json::Value],
        days: u32,
    ) -> Result<()> {
        for row in stats_rows.iter_mut() {
            add_empty_stats_lists(row);
        }
        let domains = stats_rows
            .iter()
            .filter_map(stats_row_domain)
            .take(CLICKHOUSE_ROLLUP_LIST_DOMAIN_LIMIT)
            .collect::<Vec<_>>();
        if domains.is_empty() {
            return Ok(());
        }
        let domain_sql = domains
            .iter()
            .map(|domain| clickhouse_string_literal(domain))
            .collect::<Vec<_>>()
            .join(",");
        let top_countries = self
            .query_json_cached(&format!(
                r#"
SELECT domain, code, name, count
FROM (
    SELECT
        domain,
        ifNull(nullIf(country_code, ''), 'XX') AS code,
        ifNull(nullIf(any(country_name), ''), if(code = 'XX', 'Unknown', code)) AS name,
        sum(requests) AS count
    FROM pxxl_access_rollup_day
    WHERE domain IN ({domain_sql}) AND day >= today() - INTERVAL {days} DAY
    GROUP BY domain, code
)
ORDER BY domain ASC, count DESC
LIMIT {CLICKHOUSE_ROLLUP_TOP_COUNTRIES_PER_DOMAIN} BY domain
"#
            ))
            .await?;
        let top_continents = self
            .query_json_cached(&format!(
                r#"
SELECT domain, code, name, count
FROM (
    SELECT
        domain,
        ifNull(nullIf(continent_code, ''), 'XX') AS code,
        ifNull(nullIf(any(continent_name), ''), if(code = 'XX', 'Unknown', code)) AS name,
        sum(requests) AS count
    FROM pxxl_access_rollup_day
    WHERE domain IN ({domain_sql}) AND day >= today() - INTERVAL {days} DAY
    GROUP BY domain, code
)
ORDER BY domain ASC, count DESC
LIMIT {CLICKHOUSE_ROLLUP_TOP_CONTINENTS_PER_DOMAIN} BY domain
"#
            ))
            .await?;
        let top_regions = self
            .query_json_cached(&format!(
                r#"
SELECT domain, name, count
FROM (
    SELECT
        domain,
        ifNull(nullIf(region, ''), 'Unknown') AS name,
        sum(requests) AS count
    FROM pxxl_access_rollup_day
    WHERE domain IN ({domain_sql}) AND day >= today() - INTERVAL {days} DAY
    GROUP BY domain, name
)
ORDER BY domain ASC, count DESC
LIMIT {CLICKHOUSE_ROLLUP_TOP_REGIONS_PER_DOMAIN} BY domain
"#
            ))
            .await?;
        let top_cities = self
            .query_json_cached(&format!(
                r#"
SELECT domain, name, country, count
FROM (
    SELECT
        domain,
        ifNull(nullIf(city, ''), 'Unknown') AS name,
        ifNull(nullIf(country_code, ''), 'XX') AS country,
        sum(requests) AS count
    FROM pxxl_access_rollup_day
    WHERE domain IN ({domain_sql}) AND day >= today() - INTERVAL {days} DAY
    GROUP BY domain, name, country
)
ORDER BY domain ASC, count DESC
LIMIT {CLICKHOUSE_ROLLUP_TOP_CITIES_PER_DOMAIN} BY domain
"#
            ))
            .await?;

        let mut lists: HashMap<String, serde_json::Map<String, serde_json::Value>> = HashMap::new();
        collect_domain_list(&mut lists, "top_countries", top_countries);
        collect_domain_list(&mut lists, "top_continents", top_continents);
        collect_domain_list(&mut lists, "top_regions", top_regions);
        collect_domain_list(&mut lists, "top_cities", top_cities);
        for row in stats_rows {
            let Some(domain) = stats_row_domain(row) else {
                continue;
            };
            let Some(object) = row.as_object_mut() else {
                continue;
            };
            if let Some(domain_lists) = lists.remove(&domain) {
                for (key, value) in domain_lists {
                    object.insert(key, value);
                }
            }
        }
        Ok(())
    }

    async fn add_domain_stats_lists(
        &self,
        stats: &mut serde_json::Value,
        domain: &str,
    ) -> Result<()> {
        add_empty_stats_lists(stats);
        let Some(object) = stats.as_object_mut() else {
            return Ok(());
        };
        let domain_sql = clickhouse_string_literal(domain);
        let top_countries = self.query_json_cached(&format!(
            r#"
SELECT
    ifNull(nullIf(country_code, ''), 'XX') AS code,
    ifNull(nullIf(argMax(country_name, timestamp_unix_ms), ''), if(code = 'XX', 'Unknown', code)) AS name,
    count() AS count
FROM pxxl_access_logs
WHERE domain = {domain_sql}
GROUP BY code
ORDER BY count DESC
LIMIT 80
"#
        )).await?;
        let top_continents = self.query_json_cached(&format!(
            r#"
SELECT
    ifNull(nullIf(continent_code, ''), 'XX') AS code,
    ifNull(nullIf(argMax(continent_name, timestamp_unix_ms), ''), if(code = 'XX', 'Unknown', code)) AS name,
    count() AS count
FROM pxxl_access_logs
WHERE domain = {domain_sql}
GROUP BY code
ORDER BY count DESC
LIMIT 20
"#
        )).await?;
        let top_paths = self
            .query_json_cached(&format!(
                r#"
SELECT path AS value, count() AS count
FROM pxxl_access_logs
WHERE domain = {domain_sql}
GROUP BY path
ORDER BY count DESC
LIMIT 50
"#
            ))
            .await?;
        let top_upstreams = self
            .query_json_cached(&format!(
                r#"
SELECT ifNull(upstream, 'unknown') AS value, count() AS count
FROM pxxl_access_logs
WHERE domain = {domain_sql}
GROUP BY value
ORDER BY count DESC
LIMIT 50
"#
            ))
            .await?;
        object.insert(
            "top_countries".to_string(),
            serde_json::Value::Array(top_countries),
        );
        object.insert(
            "top_continents".to_string(),
            serde_json::Value::Array(top_continents),
        );
        object.insert("top_paths".to_string(), serde_json::Value::Array(top_paths));
        object.insert(
            "top_upstreams".to_string(),
            serde_json::Value::Array(top_upstreams),
        );
        Ok(())
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
        let rows = self.query_json_cached(&query).await?;
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

    pub async fn backfill_access_rollup_days(&self) -> Result<()> {
        let range_rows = self
            .query_json(
                r#"
SELECT
    count() AS raw_rows,
    min(toDate(toDateTime(timestamp_unix_ms / 1000))) AS min_day,
    max(toDate(toDateTime(timestamp_unix_ms / 1000))) AS max_day
FROM pxxl_access_logs
WHERE timestamp_unix_ms < toUnixTimestamp(today()) * 1000
"#,
            )
            .await?;
        let Some(range) = range_rows.first() else {
            return Ok(());
        };
        if numeric_field(range, "raw_rows") == 0 {
            return Ok(());
        }
        let Some(min_day) = date_field(range, "min_day") else {
            return Ok(());
        };
        let Some(max_day) = date_field(range, "max_day") else {
            return Ok(());
        };
        if max_day < min_day {
            return Ok(());
        }

        let mut day = min_day;
        while day <= max_day {
            if self.rollup_day_already_backfilled(day).await? {
                day = day + ChronoDuration::days(1);
                continue;
            }
            if self.rollup_day_has_rows(day).await? {
                self.mark_rollup_day_backfilled(day).await?;
                day = day + ChronoDuration::days(1);
                continue;
            }

            let day_sql = clickhouse_string_literal(&day.to_string());
            self.post_sql(&format!(
                r#"
INSERT INTO pxxl_access_rollup_day
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
WHERE toDate(toDateTime(timestamp_unix_ms / 1000)) = toDate({day_sql})
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
"#
            ))
            .await?;
            self.mark_rollup_day_backfilled(day).await?;
            self.clear_read_cache();
            time::sleep(Duration::from_millis(CLICKHOUSE_ROLLUP_BACKFILL_PAUSE_MS)).await;
            day = day + ChronoDuration::days(1);
        }
        Ok(())
    }

    async fn rollup_day_already_backfilled(&self, day: NaiveDate) -> Result<bool> {
        let day_sql = clickhouse_string_literal(&day.to_string());
        let rows = self
            .query_json(&format!(
                r#"
SELECT count() AS count
FROM pxxl_access_rollup_backfill_state FINAL
WHERE day = toDate({day_sql})
"#
            ))
            .await?;
        Ok(rows
            .first()
            .map(|row| numeric_field(row, "count") > 0)
            .unwrap_or(false))
    }

    async fn rollup_day_has_rows(&self, day: NaiveDate) -> Result<bool> {
        let day_sql = clickhouse_string_literal(&day.to_string());
        let rows = self
            .query_json(&format!(
                r#"
SELECT count() AS count
FROM pxxl_access_rollup_day
WHERE day = toDate({day_sql})
"#
            ))
            .await?;
        Ok(rows
            .first()
            .map(|row| numeric_field(row, "count") > 0)
            .unwrap_or(false))
    }

    async fn mark_rollup_day_backfilled(&self, day: NaiveDate) -> Result<()> {
        let day_sql = clickhouse_string_literal(&day.to_string());
        self.post_sql(&format!(
            r#"
INSERT INTO pxxl_access_rollup_backfill_state (day, completed_at)
VALUES (toDate({day_sql}), now())
"#
        ))
        .await
    }

    fn clear_read_cache(&self) {
        if let Ok(mut cache) = self.read_cache.lock() {
            cache.clear();
        }
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
    let backfill_analytics = analytics.clone();
    tokio::spawn(async move {
        match backfill_analytics.backfill_access_rollup_days().await {
            Ok(()) => info!("ClickHouse access rollup backfill completed"),
            Err(error) => warn!(%error, "ClickHouse access rollup backfill did not complete"),
        }
    });

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
WHERE domain = {} 
  AND timestamp_unix_ms >= {}
  AND timestamp_unix_ms < {}
GROUP BY domain
"#,
            clickhouse_string_literal(domain),
            start_timestamp,
            end_timestamp
        );

        let result = self.query_json_cached(&query).await?;
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

        let result = self.query_json_cached(&query).await?;
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

        let result = self.query_json_cached(&query).await?;
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

    async fn query_json_cached(&self, sql: &str) -> Result<Vec<serde_json::Value>> {
        if let Ok(mut cache) = self.read_cache.lock() {
            if let Some(rows) = cache.get(sql) {
                return Ok(rows);
            }
        }

        let rows = self.query_json(sql).await?;
        if let Ok(mut cache) = self.read_cache.lock() {
            cache.insert(sql.to_string(), rows.clone());
        }
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
