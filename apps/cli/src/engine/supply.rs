//! Supply Chain Engine — Multi-ecosystem Dependency Vulnerability Auditing
//!
//! Queries the OSV.dev API for known CVEs across:
//! - Node.js  (package-lock.json / yarn.lock)
//! - Rust     (Cargo.lock via cargo_metadata)
//! - Go       (go.sum)

use std::path::Path;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::models::SupplyFinding;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

// ── OSV API Types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

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
struct OsvBatchResponse {
    results: Vec<OsvResult>,
}

#[derive(Deserialize, Debug)]
struct OsvResult {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize, Debug)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Deserialize, Debug)]
struct OsvSeverity {
    r#type: String,
    score: String,
}

#[derive(Deserialize, Debug)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Deserialize, Debug)]
struct OsvRange {
    events: Option<Vec<OsvEvent>>,
}

#[derive(Deserialize, Debug)]
struct OsvEvent {
    fixed: Option<String>,
}

// ── Entry Point ───────────────────────────────────────────────────────────────

/// Audit dependencies in `root_path` for the given ecosystems
pub async fn audit(root_path: &str, ecosystems: &[&str]) -> Result<Vec<SupplyFinding>> {
    let client = Client::new();
    let root = Path::new(root_path);
    let mut all_findings = Vec::new();

    for eco in ecosystems {
        match *eco {
            "node" => {
                let findings = audit_node(root, &client).await.unwrap_or_else(|e| {
                    warn!("Node audit error: {}", e);
                    vec![]
                });
                all_findings.extend(findings);
            }
            "rust" => {
                let findings = audit_rust(root, &client).await.unwrap_or_else(|e| {
                    warn!("Rust audit error: {}", e);
                    vec![]
                });
                all_findings.extend(findings);
            }
            "go" => {
                let findings = audit_go(root, &client).await.unwrap_or_else(|e| {
                    warn!("Go audit error: {}", e);
                    vec![]
                });
                all_findings.extend(findings);
            }
            other => warn!("Unknown ecosystem: {}", other),
        }
    }

    Ok(all_findings)
}

// ── Node.js Audit ─────────────────────────────────────────────────────────────

async fn audit_node(root: &Path, client: &Client) -> Result<Vec<SupplyFinding>> {
    let lock_path = root.join("package-lock.json");
    if !lock_path.exists() {
        debug!("No package-lock.json found at {:?}", root);
        return Ok(vec![]);
    }

    info!("Auditing Node.js deps from {:?}", lock_path);

    let content = std::fs::read_to_string(&lock_path)
        .context("Failed to read package-lock.json")?;
    let lock: serde_json::Value = serde_json::from_str(&content)?;

    let mut packages: Vec<(String, String)> = Vec::new();

    // Support both lockfile v1 (dependencies) and v2/v3 (packages)
    if let Some(deps) = lock.get("packages").and_then(|v| v.as_object()) {
        for (name, meta) in deps {
            if name.is_empty() || name == "." {
                continue; // skip root
            }
            let pkg_name = name.trim_start_matches("node_modules/").to_string();
            if let Some(version) = meta.get("version").and_then(|v| v.as_str()) {
                packages.push((pkg_name, version.to_string()));
            }
        }
    } else if let Some(deps) = lock.get("dependencies").and_then(|v| v.as_object()) {
        for (name, meta) in deps {
            if let Some(version) = meta.get("version").and_then(|v| v.as_str()) {
                packages.push((name.clone(), version.to_string()));
            }
        }
    }

    debug!("Node.js: {} packages found", packages.len());
    query_osv(client, packages, "npm").await
}

// ── Rust Audit ────────────────────────────────────────────────────────────────

async fn audit_rust(root: &Path, client: &Client) -> Result<Vec<SupplyFinding>> {
    let lock_path = root.join("Cargo.lock");
    if !lock_path.exists() {
        debug!("No Cargo.lock found at {:?}", root);
        return Ok(vec![]);
    }

    info!("Auditing Rust deps from {:?}", lock_path);

    let content = std::fs::read_to_string(&lock_path)?;
    let lock: toml::Value = toml::from_str(&content)?;

    let mut packages = Vec::new();
    if let Some(pkgs) = lock.get("package").and_then(|v| v.as_array()) {
        for pkg in pkgs {
            let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !name.is_empty() && !version.is_empty() {
                packages.push((name, version));
            }
        }
    }

    debug!("Rust: {} packages found", packages.len());
    query_osv(client, packages, "crates.io").await
}

// ── Go Audit ─────────────────────────────────────────────────────────────────

async fn audit_go(root: &Path, client: &Client) -> Result<Vec<SupplyFinding>> {
    let sum_path = root.join("go.sum");
    if !sum_path.exists() {
        debug!("No go.sum found at {:?}", root);
        return Ok(vec![]);
    }

    info!("Auditing Go deps from {:?}", sum_path);

    let content = std::fs::read_to_string(&sum_path)?;
    let mut seen = std::collections::HashSet::new();
    let mut packages = Vec::new();

    for line in content.lines() {
        // Format: module@version hash
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let module_ver = parts[0];
        if let Some((module, version)) = module_ver.split_once('@') {
            let version = version.trim_end_matches("/go.mod");
            let key = format!("{}@{}", module, version);
            if seen.insert(key) {
                packages.push((module.to_string(), version.to_string()));
            }
        }
    }

    debug!("Go: {} packages found", packages.len());
    query_osv(client, packages, "Go").await
}

// ── OSV Query ─────────────────────────────────────────────────────────────────

/// Query OSV.dev for vulnerabilities in batches of 100
async fn query_osv(
    client: &Client,
    packages: Vec<(String, String)>,
    ecosystem: &str,
) -> Result<Vec<SupplyFinding>> {
    let mut all_findings = Vec::new();

    // OSV batch API accepts up to 1000 queries, we chunk at 100 for safety
    for chunk in packages.chunks(100) {
        let queries: Vec<OsvQuery> = chunk
            .iter()
            .map(|(name, version)| OsvQuery {
                package: OsvPackage {
                    name: name.clone(),
                    ecosystem: ecosystem.to_string(),
                },
                version: version.clone(),
            })
            .collect();

        let request = OsvBatchRequest { queries };

        let response = client
            .post(OSV_BATCH_URL)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            warn!("OSV API returned {}", response.status());
            continue;
        }

        let batch: OsvBatchResponse = response.json().await?;

        for (idx, result) in batch.results.into_iter().enumerate() {
            let Some(vulns) = result.vulns else { continue };
            if vulns.is_empty() {
                continue;
            }

            let (pkg_name, pkg_version) = &chunk[idx];

            for vuln in vulns {
                let severity = vuln
                    .severity
                    .as_ref()
                    .and_then(|s| s.first())
                    .map(|s| cvss_to_severity(&s.score))
                    .unwrap_or_else(|| "medium".to_string());

                let fix_version = vuln
                    .affected
                    .as_ref()
                    .and_then(|a| a.first())
                    .and_then(|a| a.ranges.as_ref())
                    .and_then(|r| r.first())
                    .and_then(|r| r.events.as_ref())
                    .and_then(|e| e.iter().find_map(|ev| ev.fixed.as_ref()))
                    .cloned();

                let cve = if vuln.id.starts_with("CVE-") {
                    Some(vuln.id.clone())
                } else {
                    None
                };

                all_findings.push(SupplyFinding {
                    package: pkg_name.clone(),
                    version: pkg_version.clone(),
                    ecosystem: ecosystem.to_string(),
                    severity,
                    title: vuln.summary.unwrap_or_else(|| format!("{} vulnerability", vuln.id)),
                    cve,
                    fix_version,
                    osv_id: vuln.id,
                });
            }
        }
    }

    Ok(all_findings)
}

/// Convert CVSS score string to severity label
fn cvss_to_severity(score: &str) -> String {
    // Score may be "CVSS:3.1/AV:N/.../S:9.8" or just "9.8"
    let num: f32 = score
        .split('/')
        .last()
        .and_then(|s| s.parse().ok())
        .or_else(|| score.parse().ok())
        .unwrap_or(0.0);

    match num as u8 {
        0..=3 => "low".into(),
        4..=6 => "medium".into(),
        7..=8 => "high".into(),
        _ => "critical".into(),
    }
}
