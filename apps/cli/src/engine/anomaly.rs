//! Anomaly Detection Engine — K-Means Clustering of HTTP Responses
//!
//! Standard scanners miss *logical* anomalies: pages that return 200 OK with a
//! zero-byte body only when a specific header is present, or endpoints whose
//! response size is wildly different from every other 200 response on the site.
//!
//! This module addresses that gap using unsupervised machine learning:
//!
//! 1. **Crawl** a set of seed paths on the target and collect HTTP response
//!    feature vectors (status code, body length, header count, response time).
//! 2. **Normalise** the vectors to [0, 1] so no single feature dominates.
//! 3. **Cluster** using K-Means (via the `linfa` + `linfa-clustering` crates).
//! 4. **Flag anomalies**: any response that is the *sole member* of its cluster
//!    ("singleton cluster") or whose distance to its centroid exceeds a
//!    configurable z-score threshold.
//!
//! # Feature Vector
//! | Index | Feature           | Notes                            |
//! |-------|------------------|----------------------------------|
//! | 0     | HTTP status code  | Normalised to [0, 1] over 100–599|
//! | 1     | Body length       | Log-scaled, normalised           |
//! | 2     | Number of headers | Normalised                       |
//! | 3     | Response time ms  | Log-scaled, normalised           |
//!
//! # Dependencies (add to Cargo.toml)
//! ```toml
//! linfa            = "0.7"
//! linfa-clustering = { version = "0.7", features = ["kmeans"] }
//! ndarray          = "0.15"
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use linfa::prelude::*;
use linfa_clustering::KMeans;
use ndarray::{Array2, Axis};
use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Tunable parameters for the anomaly detection engine
pub struct AnomalyConfig {
    /// Maximum number of parallel probes
    pub concurrency: usize,
    /// Per-request timeout
    pub timeout: Duration,
    /// Number of K-Means clusters (default 5)
    pub k: usize,
    /// K-Means max iterations
    pub max_iterations: u64,
    /// Z-score threshold: responses with distance > mean + z*σ are flagged
    pub z_score_threshold: f64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            timeout: Duration::from_secs(10),
            k: 5,
            max_iterations: 300,
            z_score_threshold: 2.5,
        }
    }
}

// ── Response observation ──────────────────────────────────────────────────────

/// Raw measurements from a single HTTP probe
#[derive(Debug, Clone)]
struct ResponseObs {
    url: String,
    status: u16,
    body_len: usize,
    header_count: usize,
    elapsed_ms: f64,
}

impl ResponseObs {
    /// Convert to a 4-dimensional feature vector (raw, un-normalised)
    fn raw_features(&self) -> [f64; 4] {
        [
            self.status as f64,
            (self.body_len as f64 + 1.0).ln(), // log-scale to reduce outlier effect
            self.header_count as f64,
            (self.elapsed_ms + 1.0).ln(),
        ]
    }
}

// ── Seed paths ────────────────────────────────────────────────────────────────

/// A curated list of paths to probe — covers common admin, API, and auth paths
static SEED_PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/robots.txt",
    "/sitemap.xml",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/health",
    "/api/status",
    "/admin",
    "/admin/",
    "/admin/login",
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/dashboard",
    "/profile",
    "/settings",
    "/config",
    "/server-status",
    "/phpinfo.php",
    "/.env",
    "/.git/HEAD",
    "/wp-admin",
    "/wp-login.php",
    "/wp-json/wp/v2/users",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/metrics",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api-docs",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    "/v1/api",
    "/health",
    "/metrics",
    "/debug",
    "/trace",
    "/console",
    "/manager",
    "/status",
    "/info",
    "/version",
    "/backup",
    "/backup.zip",
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Probe the target with seed paths, cluster responses, and flag anomalies.
///
/// Returns findings for singleton clusters and high-distance outliers.
pub async fn run(
    client: Arc<Client>,
    target: &str,
    config: &AnomalyConfig,
) -> Result<Vec<Finding>> {
    info!("Anomaly engine: probing {} seed path(s) on {}", SEED_PATHS.len(), target);

    let observations = collect_observations(Arc::clone(&client), target, config).await;

    if observations.len() < config.k + 1 {
        warn!(
            "Anomaly engine: only {} responses collected — need at least {} for K-Means (k={}). \
             Skipping clustering.",
            observations.len(),
            config.k + 1,
            config.k
        );
        return Ok(vec![]);
    }

    info!("Anomaly engine: {} response(s) collected, running K-Means (k={})", observations.len(), config.k);

    let findings = cluster_and_flag(&observations, config)
        .await
        .unwrap_or_else(|e| {
            warn!("Anomaly engine clustering error: {}", e);
            vec![]
        });

    info!("Anomaly engine: {} anomalous response(s) flagged", findings.len());
    Ok(findings)
}

// ── HTTP Probing ──────────────────────────────────────────────────────────────

async fn collect_observations(
    client: Arc<Client>,
    base: &str,
    config: &AnomalyConfig,
) -> Vec<ResponseObs> {
    let base = base.trim_end_matches('/').to_string();
    let sem = Arc::new(Semaphore::new(config.concurrency));
    let mut handles = Vec::new();

    for path in SEED_PATHS {
        let url = format!("{}{}", base, path);
        let client = Arc::clone(&client);
        let sem = Arc::clone(&sem);
        let timeout = config.timeout;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            probe_url(&client, &url, timeout).await
        }));
    }

    let mut observations = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Some(obs)) => observations.push(obs),
            Ok(None) => {} // connection error or timeout
            Err(e) => debug!("Anomaly probe task panicked: {}", e),
        }
    }

    observations
}

async fn probe_url(client: &Client, url: &str, timeout: Duration) -> Option<ResponseObs> {
    let start = Instant::now();
    let response = client.get(url).timeout(timeout).send().await.ok()?;

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let status = response.status().as_u16();
    let header_count = response.headers().len();
    let body = response.bytes().await.unwrap_or_default();
    let body_len = body.len();

    debug!(
        "Anomaly probe: {} → {} ({} bytes, {} headers, {:.0}ms)",
        url, status, body_len, header_count, elapsed_ms
    );

    Some(ResponseObs {
        url: url.to_string(),
        status,
        body_len,
        header_count,
        elapsed_ms,
    })
}

// ── Clustering & Anomaly Detection ────────────────────────────────────────────

async fn cluster_and_flag(
    observations: &[ResponseObs],
    config: &AnomalyConfig,
) -> Result<Vec<Finding>> {
    // Build raw feature matrix  (n_samples × 4)
    let n = observations.len();
    let raw: Vec<f64> = observations
        .iter()
        .flat_map(|obs| obs.raw_features())
        .collect();

    let mut matrix = Array2::from_shape_vec((n, 4), raw)?;

    // ── Min-max normalise each column ────────────────────────────────────────
    let min = matrix.fold_axis(Axis(0), f64::MAX, |&acc, &v| acc.min(v));
    let max = matrix.fold_axis(Axis(0), f64::MIN, |&acc, &v| acc.max(v));

    for mut row in matrix.rows_mut() {
        for (i, val) in row.iter_mut().enumerate() {
            let range = max[i] - min[i];
            if range > 1e-10 {
                *val = (*val - min[i]) / range;
            } else {
                *val = 0.0; // All values identical — column is constant
            }
        }
    }

    // ── Run K-Means ───────────────────────────────────────────────────────────
    let k = config.k.min(n); // Can't have more clusters than samples
    let dataset = DatasetBase::from(matrix.clone());

    let model = KMeans::params(k)
        .max_n_iterations(config.max_iterations)
        .tolerance(1e-5)
        .fit(&dataset)?;

    let predictions = model.predict(&dataset);
    let assignments: Vec<usize> = predictions.as_targets().iter().cloned().collect();
    let centroids = model.centroids(); // shape: (k, 4)

    // ── Compute per-sample Euclidean distance to its centroid ─────────────────
    let distances: Vec<f64> = (0..n)
        .map(|i| {
            let cluster = assignments[i];
            let row = matrix.row(i);
            let centroid = centroids.row(cluster);
            row.iter()
                .zip(centroid.iter())
                .map(|(a, b)| (a - b).powi(2))
                .sum::<f64>()
                .sqrt()
        })
        .collect();

    // ── Compute cluster sizes ─────────────────────────────────────────────────
    let mut cluster_sizes = vec![0usize; k];
    for &c in &assignments {
        cluster_sizes[c] += 1;
    }

    // ── Z-score threshold on distances ───────────────────────────────────────
    let mean_dist = distances.iter().sum::<f64>() / n as f64;
    let variance = distances
        .iter()
        .map(|&d| (d - mean_dist).powi(2))
        .sum::<f64>()
        / n as f64;
    let std_dist = variance.sqrt();
    let threshold = mean_dist + config.z_score_threshold * std_dist;

    debug!(
        "K-Means: mean distance={:.4}, std={:.4}, threshold={:.4}",
        mean_dist, std_dist, threshold
    );

    // ── Generate findings ────────────────────────────────────────────────────
    let mut findings = Vec::new();

    for (i, obs) in observations.iter().enumerate() {
        let cluster = assignments[i];
        let dist = distances[i];
        let is_singleton = cluster_sizes[cluster] == 1;
        let is_high_distance = dist > threshold;

        if is_singleton || is_high_distance {
            let anomaly_reason = match (is_singleton, is_high_distance) {
                (true, _) => "Singleton cluster — this response pattern is entirely unique among all probed URLs".to_string(),
                (false, true) => format!(
                    "High centroid distance ({:.4} vs threshold {:.4}, z={:.1}×σ) — response features are statistical outliers",
                    dist, threshold, config.z_score_threshold
                ),
                (false, false) => unreachable!("guarded by is_singleton || is_high_distance"),
            };

            let description = format!(
                "The HTTP response from `{}` was flagged as anomalous by K-Means clustering.\n\n\
                 **Anomaly reason:** {}\n\n\
                 **Response features:**\n\
                 - Status: {}\n\
                 - Body length: {} bytes\n\
                 - Headers: {}\n\
                 - Response time: {:.0}ms\n\n\
                 Standard templates did not flag this endpoint. Manual review is recommended \
                 to determine whether this represents a hidden feature, a logic vulnerability, \
                 or a debug/staging artifact.",
                obs.url,
                anomaly_reason,
                obs.status,
                obs.body_len,
                obs.header_count,
                obs.elapsed_ms
            );

            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::SecurityMisconfiguration,
                severity: Severity::Low,
                title: format!("[Anomaly] Unusual Response Pattern at {}", obs.url),
                description,
                evidence: Some(format!(
                    "Cluster #{}: size={}, distance to centroid={:.4}\n\
                     Status={} | Body={}B | Headers={} | Time={:.0}ms",
                    cluster,
                    cluster_sizes[cluster],
                    dist,
                    obs.status,
                    obs.body_len,
                    obs.header_count,
                    obs.elapsed_ms
                )),
                remediation:
                    "Manually inspect the flagged URL. If the endpoint should not be \
                     publicly accessible, restrict it with authentication or firewall rules. \
                     If it is a debug/staging artifact, remove it from production."
                        .to_string(),
                source: FindingSource::AnomalyEngine,
                endpoint: Some(obs.url.clone()),
            });
        }
    }

    Ok(findings)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_features_shape() {
        let obs = ResponseObs {
            url: "http://example.com/".to_string(),
            status: 200,
            body_len: 1024,
            header_count: 8,
            elapsed_ms: 43.5,
        };
        let features = obs.raw_features();
        assert_eq!(features.len(), 4);
        assert_eq!(features[0], 200.0);
        // log-scale body: (1024+1).ln() ≈ 6.93
        assert!((features[1] - (1025f64).ln()).abs() < 1e-6);
        assert_eq!(features[2], 8.0);
    }

    #[test]
    fn test_anomaly_config_defaults() {
        let cfg = AnomalyConfig::default();
        assert_eq!(cfg.k, 5);
        assert_eq!(cfg.z_score_threshold, 2.5);
    }
}
