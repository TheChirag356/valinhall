//! OSV Blackbox Lookup — Technology Fingerprint → CVE Discovery
//!
//! During the DAST recon phase, Valinhall fingerprints the server stack via
//! HTTP response headers (e.g. `Server: nginx/1.18.0`).  This module takes
//! those fingerprints and queries the OSV.dev API for known vulnerabilities,
//! surfacing them as [`Finding`] objects.
//!
//! # How it works
//! 1. [`fingerprint_server`] sends a plain GET request and parses version
//!    strings from `Server`, `X-Powered-By`, and similar headers.
//! 2. Each fingerprint is normalised into an (ecosystem, package, version)
//!    triple using a curated lookup table.
//! 3. The triples are submitted to `https://api.osv.dev/v1/query` (single
//!    query per fingerprint so we get rich per-package responses).
//! 4. Returned CVEs are converted to [`Finding`] objects with severity derived
//!    from the CVSS score.
//!
//! # Rate limiting
//! OSV.dev has a generous public rate limit (~1 k req/min), but we still cap
//! our concurrency to 4 simultaneous requests to be a good citizen.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── Fingerprint ───────────────────────────────────────────────────────────────

/// A technology detected in HTTP response headers
#[derive(Debug, Clone)]
pub struct TechFingerprint {
    /// Human-readable product name, e.g. "nginx"
    pub product: String,
    /// Detected version string, e.g. "1.18.0"
    pub version: String,
    /// The source header, e.g. "Server"
    pub source_header: String,
}

// ── OSV API types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize, Debug)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize, Debug)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Deserialize, Debug)]
struct OsvSeverity {
    r#type: String,
    score: String,
}

#[derive(Deserialize, Debug)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize, Debug)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Deserialize, Debug)]
struct OsvEvent {
    fixed: Option<String>,
}

#[derive(Deserialize, Debug)]
struct OsvReference {
    url: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Fingerprint the target server and look up known CVEs for detected technologies.
///
/// Returns findings with severity derived from CVSS scores.
pub async fn check_fingerprinted_tech(
    client: Arc<Client>,
    target: &str,
) -> Result<Vec<Finding>> {
    let fingerprints = fingerprint_server(Arc::clone(&client), target).await;

    if fingerprints.is_empty() {
        info!("OSV blackbox: no technology fingerprints detected at {}", target);
        return Ok(vec![]);
    }

    info!(
        "OSV blackbox: {} fingerprint(s) detected, querying OSV.dev",
        fingerprints.len()
    );
    for fp in &fingerprints {
        debug!(
            "  Fingerprint — product: {}, version: {}, from: {}",
            fp.product, fp.version, fp.source_header
        );
    }

    let sem = Arc::new(Semaphore::new(4));
    let mut findings = Vec::new();

    // Query each fingerprint individually (gives richer, per-vuln data)
    let mut handles = Vec::new();
    for fp in fingerprints {
        let client = Arc::clone(&client);
        let sem = Arc::clone(&sem);
        let target = target.to_string();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            query_osv_for_fingerprint(&client, &fp, &target).await
        }));
    }

    for handle in handles {
        match handle.await {
            Ok(Ok(f)) => findings.extend(f),
            Ok(Err(e)) => warn!("OSV query error: {}", e),
            Err(e) => warn!("OSV task panicked: {}", e),
        }
    }

    info!("OSV blackbox: {} finding(s)", findings.len());
    Ok(findings)
}

// ── Server Fingerprinting ─────────────────────────────────────────────────────

/// Headers that may reveal technology and version information
static FINGERPRINT_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "via",
    "x-drupal-cache",
    "x-wordpress-cache",
    "x-varnish",
];

/// Regex patterns to extract (product, version) from common header values
/// Format: (pattern, product_group_idx, version_group_idx)
static VERSION_PATTERNS: &[(&str, usize, usize)] = &[
    // "nginx/1.18.0"
    (r"(?i)(nginx)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "Apache/2.4.51 (Unix)"
    (r"(?i)(Apache)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "openresty/1.19.3.1"
    (r"(?i)(openresty)/([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)", 1, 2),
    // "PHP/8.0.12"
    (r"(?i)(PHP)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "Express"  (no version — skip via version_group = 0 sentinel)
    // "ASP.NET/4.0.30319"
    (r"(?i)(ASP\.NET)/([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)", 1, 2),
    // "Node.js/18.12.0"
    (r"(?i)(node\.js)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "Jetty/9.4.43"
    (r"(?i)(Jetty)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "Tomcat/9.0.56"
    (r"(?i)(Tomcat)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "WordPress 6.4"
    (r"(?i)(WordPress)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "Drupal 9"
    (r"(?i)(Drupal)\s+([0-9]+(?:\.[0-9]+)?)", 1, 2),
    // "IIS/10.0"
    (r"(?i)(IIS)/([0-9]+\.[0-9]+)", 1, 2),
];

async fn fingerprint_server(client: Arc<Client>, target: &str) -> Vec<TechFingerprint> {
    let response = match client
        .get(target)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!("Fingerprint request failed: {}", e);
            return vec![];
        }
    };

    let headers = response.headers().clone();
    let mut fingerprints = Vec::new();

    // Collect all header values to inspect
    let mut header_values: Vec<(String, String)> = Vec::new();
    for header_name in FINGERPRINT_HEADERS {
        if let Some(value) = headers.get(*header_name) {
            if let Ok(v) = value.to_str() {
                header_values.push((header_name.to_string(), v.to_string()));
            }
        }
    }

    // Try each version pattern against each header value
    for (header_name, header_value) in &header_values {
        for (pattern, prod_idx, ver_idx) in VERSION_PATTERNS {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(header_value) {
                    let product = caps.get(*prod_idx).map(|m| m.as_str()).unwrap_or("").to_string();
                    let version = caps.get(*ver_idx).map(|m| m.as_str()).unwrap_or("").to_string();
                    if !product.is_empty() && !version.is_empty() {
                        debug!(
                            "Fingerprinted: {} {} (header: {})",
                            product, version, header_name
                        );
                        fingerprints.push(TechFingerprint {
                            product,
                            version,
                            source_header: header_name.clone(),
                        });
                        break; // One fingerprint per header value
                    }
                }
            }
        }
    }

    fingerprints
}

// ── OSV Query ─────────────────────────────────────────────────────────────────

/// Mapping from fingerprinted product name → OSV ecosystem
fn product_to_ecosystem(product: &str) -> Option<(&'static str, &'static str)> {
    // Returns (ecosystem, canonical_package_name)
    let p = product.to_lowercase();
    match p.as_str() {
        "nginx" => Some(("Debian", "nginx")),
        "apache" => Some(("Debian", "apache2")),
        "php" => Some(("Packagist", "php")),
        "asp.net" => Some(("NuGet", "Microsoft.AspNet.Mvc")),
        "node.js" | "nodejs" => Some(("npm", "node")),
        "jetty" => Some(("Maven", "org.eclipse.jetty:jetty-server")),
        "tomcat" => Some(("Maven", "org.apache.tomcat:tomcat")),
        "wordpress" => Some(("Packagist", "wordpress/wordpress")),
        "drupal" => Some(("Packagist", "drupal/core")),
        "openresty" => Some(("Debian", "openresty")),
        "iis" => Some(("NuGet", "Microsoft.Net.Http")),
        _ => None,
    }
}

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

async fn query_osv_for_fingerprint(
    client: &Client,
    fp: &TechFingerprint,
    target: &str,
) -> Result<Vec<Finding>> {
    let (ecosystem, pkg_name) = match product_to_ecosystem(&fp.product) {
        Some(e) => e,
        None => {
            debug!("No OSV ecosystem mapping for '{}'", fp.product);
            return Ok(vec![]);
        }
    };

    let query = OsvQuery {
        package: OsvPackage {
            name: pkg_name.to_string(),
            ecosystem: ecosystem.to_string(),
        },
        version: fp.version.clone(),
    };

    let response = client
        .post(OSV_QUERY_URL)
        .json(&query)
        .timeout(Duration::from_secs(15))
        .send()
        .await?;

    if !response.status().is_success() {
        warn!(
            "OSV API returned {} for {} {}",
            response.status(),
            fp.product,
            fp.version
        );
        return Ok(vec![]);
    }

    let osv_resp: OsvQueryResponse = response.json().await?;
    let vulns = match osv_resp.vulns {
        Some(v) if !v.is_empty() => v,
        _ => {
            debug!("No OSV vulns for {} {}", fp.product, fp.version);
            return Ok(vec![]);
        }
    };

    info!(
        "OSV: {} CVE(s) found for {} {}",
        vulns.len(),
        fp.product,
        fp.version
    );

    let mut findings = Vec::new();

    for vuln in vulns {
        let severity = derive_severity(&vuln.severity);

        // Extract fix version from ranges
        let fix_version = vuln
            .affected
            .iter()
            .flat_map(|a| a.ranges.iter())
            .flat_map(|r| r.events.iter())
            .find_map(|ev| ev.fixed.clone());

        let references: Vec<String> = vuln
            .references
            .iter()
            .filter_map(|r| r.url.clone())
            .collect();

        let description = vuln.details.clone().or_else(|| {
            vuln.summary.clone().map(|s| {
                format!(
                    "{}\n\nDetected: {} {} (via `{}` header at {})",
                    s, fp.product, fp.version, fp.source_header, target
                )
            })
        }).unwrap_or_else(|| {
            format!(
                "{} was detected at version {}. OSV advisory {} applies to this version.",
                fp.product, fp.version, vuln.id
            )
        });

        let remediation = match &fix_version {
            Some(fv) => format!(
                "Upgrade {} to version {} or later. References: {}",
                fp.product,
                fv,
                references.join(", ")
            ),
            None => format!(
                "Patch or mitigate {} {}. References: {}",
                fp.product,
                fp.version,
                references.join(", ")
            ),
        };

        let cve_short = if vuln.id.starts_with("CVE-") {
            vuln.id.clone()
        } else {
            vuln.id.clone()
        };

        findings.push(Finding {
            id: Uuid::new_v4().to_string(),
            category: OwaspCategory::VulnerableComponents,
            severity,
            title: format!(
                "[OSV] {} {} — {}",
                fp.product,
                fp.version,
                vuln.summary.as_deref().unwrap_or(&cve_short)
            ),
            description,
            evidence: Some(format!(
                "Header `{}` revealed {} {}. OSV ID: {}",
                fp.source_header, fp.product, fp.version, vuln.id
            )),
            remediation,
            source: FindingSource::OsvBlackbox,
            endpoint: Some(target.to_string()),
        });
    }

    Ok(findings)
}

/// Derive our internal Severity from an OSV severity array (CVSS-based)
fn derive_severity(severities: &[OsvSeverity]) -> Severity {
    // Prefer CVSS v3 scores; fall back to v2
    let score = severities
        .iter()
        .filter(|s| s.r#type.contains("CVSS"))
        .find_map(|s| {
            // CVSS vectors like "CVSS:3.1/AV:N/.../S:9.8" — score is last token
            s.score.split('/').last().and_then(|n| n.parse::<f32>().ok())
                .or_else(|| s.score.parse::<f32>().ok())
        });

    match score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Medium,
        Some(s) if s > 0.0 => Severity::Low,
        _ => Severity::Medium, // When CVSS is absent default to Medium to avoid under-reporting
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nginx_fingerprint_regex() {
        let header_value = "nginx/1.18.0";
        let (pattern, prod_idx, ver_idx) = VERSION_PATTERNS[0];
        let re = Regex::new(pattern).unwrap();
        let caps = re.captures(header_value).unwrap();
        assert_eq!(caps.get(prod_idx).unwrap().as_str().to_lowercase(), "nginx");
        assert_eq!(caps.get(ver_idx).unwrap().as_str(), "1.18.0");
    }

    #[test]
    fn test_apache_fingerprint_regex() {
        let header_value = "Apache/2.4.51 (Unix)";
        let (pattern, prod_idx, ver_idx) = VERSION_PATTERNS[1];
        let re = Regex::new(pattern).unwrap();
        let caps = re.captures(header_value).unwrap();
        assert_eq!(caps.get(prod_idx).unwrap().as_str().to_lowercase(), "apache");
        assert_eq!(caps.get(ver_idx).unwrap().as_str(), "2.4.51");
    }

    #[test]
    fn test_product_to_ecosystem_nginx() {
        assert_eq!(product_to_ecosystem("nginx"), Some(("Debian", "nginx")));
    }

    #[test]
    fn test_product_to_ecosystem_unknown() {
        assert!(product_to_ecosystem("UnknownProduct").is_none());
    }

    #[test]
    fn test_derive_severity_critical() {
        let sevs = vec![OsvSeverity {
            r#type: "CVSS_V3".into(),
            score: "9.8".into(),
        }];
        assert_eq!(derive_severity(&sevs), Severity::Critical);
    }

    #[test]
    fn test_derive_severity_medium_fallback() {
        assert_eq!(derive_severity(&[]), Severity::Medium);
    }
}
