//! Typed client for the Lodestar dashboard API — Foghorn's primary source for
//! roster / QoS / REO / stake. Deserialisation is deliberately tolerant (serde
//! defaults, ignored unknown fields) so Lodestar schema drift degrades to
//! missing signals rather than a hard ingestion failure.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::time::Duration;

#[derive(Clone)]
pub struct LodestarClient {
    base_url: String,
    api_key: Option<String>,
    http: reqwest::Client,
}

/// One indexer from `/api/indexers-enriched`. Only the fields Foghorn consumes.
///
/// Aliases cover both the Vercel-era names and kittiwake's, which also sends GRT figures as strings.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct EnrichedIndexer {
    #[serde(alias = "address")]
    pub id: String,
    #[serde(rename = "ensName")]
    pub ens_name: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<i64>,
    #[serde(rename = "selfStakeGRT", alias = "selfStakeGrt", deserialize_with = "num")]
    pub self_stake_grt: Option<f64>,
    #[serde(rename = "delegatedGRT", alias = "delegatedGrt", deserialize_with = "num")]
    pub delegated_grt: Option<f64>,
    #[serde(rename = "allocationCount")]
    pub allocation_count: Option<i32>,
    #[serde(rename = "queryFeesCollectedGRT", alias = "queryFeesCollectedGrt", deserialize_with = "num")]
    pub query_fees_collected_grt: Option<f64>,
    #[serde(rename = "reoStatus")]
    pub reo_status: Option<String>,
    #[serde(rename = "reoSource")]
    pub reo_source: Option<String>,
    #[serde(deserialize_with = "num")]
    pub score: Option<f64>,
    #[serde(rename = "scoreGrade")]
    pub score_grade: Option<String>,
}

fn num<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Number(n)) => n.as_f64(),
        Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    })
}

/// `{ indexers }` on Vercel, `{ data }` on kittiwake. Neither key defaults: an envelope we do not
/// recognise must fail the cycle, not ingest an empty roster and freeze every profile.
#[derive(Debug, Deserialize)]
struct EnrichedResponse {
    #[serde(alias = "data")]
    indexers: Vec<EnrichedIndexer>,
}

/// One daily QoS data point from `/api/indexer/{address}/qos`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct QosPoint {
    pub date: String,
    #[serde(rename = "queryCount")]
    pub query_count: f64,
    #[serde(rename = "successRate")]
    pub success_rate: f64, // 0..100
    #[serde(rename = "latencyMs")]
    pub latency_ms: f64,
    #[serde(rename = "blocksBehind")]
    pub blocks_behind: f64,
}

#[derive(Debug, Deserialize)]
struct QosInner {
    #[serde(default)]
    qos: Vec<QosPoint>,
}

#[derive(Debug, Deserialize)]
struct QosResponse {
    data: QosInner,
}

/// Aggregated QoS over a trailing window.
#[derive(Debug, Clone, Default)]
pub struct QosAggregate {
    pub query_count: i64,
    pub success_rate: Option<f64>,
    pub latency_ms: Option<f64>,
    pub blocks_behind: Option<f64>,
}

impl LodestarClient {
    pub fn new(base_url: &str, api_key: Option<String>, timeout_secs: u64) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            http,
        })
    }

    fn req(&self, url: &str) -> reqwest::RequestBuilder {
        let b = self.http.get(url);
        match &self.api_key {
            Some(k) => b.bearer_auth(k),
            None => b,
        }
    }

    /// Any route as JSON, for callers that read only a few fields and would rather not own a type.
    pub async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.req(&url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("{path}: HTTP {}", resp.status()));
        }
        Ok(resp.json().await?)
    }

    /// Fetch the full enriched indexer roster.
    pub async fn fetch_enriched(&self) -> Result<Vec<EnrichedIndexer>> {
        let url = format!("{}/api/indexers-enriched", self.base_url);
        let resp = self.req(&url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("enriched: HTTP {}", resp.status()));
        }
        let parsed: EnrichedResponse = resp.json().await?;
        if parsed.indexers.iter().all(|ix| ix.id.is_empty()) {
            return Err(anyhow!("enriched: no indexer carries an address, the schema has moved"));
        }
        Ok(parsed.indexers)
    }

    /// Fetch QoS for one indexer and aggregate over the trailing `window_days`.
    pub async fn fetch_qos(&self, address: &str, window_days: usize) -> Result<QosAggregate> {
        let url = format!(
            "{}/api/indexer/{}/qos?days={window_days}",
            self.base_url,
            address.to_lowercase()
        );
        let resp = self.req(&url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("qos: HTTP {}", resp.status()));
        }
        let parsed: QosResponse = resp.json().await?;
        Ok(aggregate_qos(&parsed.data.qos, window_days))
    }
}

/// Aggregate the trailing `window_days` of daily points. Success/latency/blocks
/// are query-weighted means; query_count is a sum. Days are pre-sorted ascending
/// by the Lodestar API, so we take the tail.
pub fn aggregate_qos(points: &[QosPoint], window_days: usize) -> QosAggregate {
    let tail = if points.len() > window_days {
        &points[points.len() - window_days..]
    } else {
        points
    };
    if tail.is_empty() {
        return QosAggregate::default();
    }
    let mut q_sum = 0.0f64;
    let mut w_sum = 0.0f64;
    let mut succ = 0.0f64;
    let mut lat = 0.0f64;
    let mut beh = 0.0f64;
    for p in tail {
        // weight by query volume, with a floor so zero-query days still register
        let w = p.query_count.max(1.0);
        q_sum += p.query_count;
        w_sum += w;
        succ += p.success_rate * w;
        lat += p.latency_ms * w;
        beh += p.blocks_behind * w;
    }
    QosAggregate {
        query_count: q_sum.round() as i64,
        success_rate: (w_sum > 0.0).then(|| succ / w_sum),
        latency_ms: (w_sum > 0.0).then(|| lat / w_sum),
        blocks_behind: (w_sum > 0.0).then(|| beh / w_sum),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_takes_trailing_window_and_query_weights() {
        let pts = vec![
            QosPoint { date: "d1".into(), query_count: 100.0, success_rate: 50.0, latency_ms: 200.0, blocks_behind: 10.0 },
            QosPoint { date: "d2".into(), query_count: 900.0, success_rate: 100.0, latency_ms: 100.0, blocks_behind: 0.0 },
        ];
        let agg = aggregate_qos(&pts, 30);
        assert_eq!(agg.query_count, 1000);
        // query-weighted success: (50*100 + 100*900)/1000 = 95
        assert!((agg.success_rate.unwrap() - 95.0).abs() < 0.01);
    }

    #[test]
    fn enriched_reads_kittiwake_rows() {
        let body = r#"{"data":[{"address":"0x38f4","ensName":"graphops.eth","selfStakeGrt":"11087938.46",
            "delegatedGrt":"1284594.3","allocationCount":663,"queryFeesCollectedGrt":"72129.4",
            "score":"88","scoreGrade":"A","reoStatus":"eligible"}],"provenance":{}}"#;
        let ix = &serde_json::from_str::<EnrichedResponse>(body).unwrap().indexers[0];
        assert_eq!(ix.id, "0x38f4");
        assert_eq!(ix.allocation_count, Some(663));
        assert_eq!(ix.self_stake_grt, Some(11087938.46));
        assert_eq!(ix.score, Some(88.0));
    }

    #[test]
    fn enriched_still_reads_the_vercel_rows() {
        let body = r#"{"indexers":[{"id":"0x1","selfStakeGRT":5.5,"allocationCount":3,"score":70}]}"#;
        let ix = &serde_json::from_str::<EnrichedResponse>(body).unwrap().indexers[0];
        assert_eq!((ix.id.as_str(), ix.self_stake_grt, ix.score), ("0x1", Some(5.5), Some(70.0)));
    }

    #[test]
    fn unknown_envelope_is_an_error_not_an_empty_roster() {
        assert!(serde_json::from_str::<EnrichedResponse>(r#"{"rows":[]}"#).is_err());
    }

    #[test]
    fn empty_qos_is_default() {
        let agg = aggregate_qos(&[], 30);
        assert_eq!(agg.query_count, 0);
        assert!(agg.success_rate.is_none());
    }
}
