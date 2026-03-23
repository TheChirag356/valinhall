//! DAST Engine — Dynamic Application Security Testing
//!
//! Orchestrates all HTTP-based probes concurrently using tokio + reqwest.
//! Fires injection, auth, exception-handling, and supply-chain probes
//! against a live target URL.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use reqwest::{Client, ClientBuilder};
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::models::{Finding, ScanConfig};
use crate::probes;

/// Build a shared reqwest client configured for security testing
pub fn build_client(config: &ScanConfig) -> Result<Client> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(false)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Valinhall Security Scanner/0.1 (+https://github.com/valinhall)")
        .pool_max_idle_per_host(config.concurrency)
        .tcp_keepalive(Duration::from_secs(30))
        .build()?;
    Ok(client)
}

/// Run all DAST probes against the configured target
pub async fn run(config: &ScanConfig) -> Result<Vec<Finding>> {
    info!("DAST engine starting against: {}", config.target);

    let client = Arc::new(build_client(config)?);
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut all_findings = Vec::new();

    // ── Injection Probes ──────────────────────────────────────────────────────
    debug!("Running injection probes");
    let injection_findings = probes::injection::run(
        Arc::clone(&client),
        Arc::clone(&semaphore),
        &config.target,
    )
    .await?;
    all_findings.extend(injection_findings);

    // ── Auth Probes ───────────────────────────────────────────────────────────
    debug!("Running authentication probes");
    let auth_findings = probes::auth::run(
        Arc::clone(&client),
        Arc::clone(&semaphore),
        &config.target,
    )
    .await?;
    all_findings.extend(auth_findings);

    // ── Exception Handling Probes ─────────────────────────────────────────────
    debug!("Running exception-handling probes");
    let exc_findings = probes::exceptions::run(
        Arc::clone(&client),
        Arc::clone(&semaphore),
        &config.target,
    )
    .await?;
    all_findings.extend(exc_findings);

    // ── Security Headers ──────────────────────────────────────────────────────
    debug!("Checking security headers");
    let header_findings = check_security_headers(Arc::clone(&client), &config.target).await?;
    all_findings.extend(header_findings);

    info!("DAST complete — {} finding(s)", all_findings.len());
    Ok(all_findings)
}

/// Check for missing or misconfigured HTTP security headers (A05)
async fn check_security_headers(client: Arc<Client>, target: &str) -> Result<Vec<Finding>> {
    use crate::models::{FindingSource, OwaspCategory, Severity};
    use uuid::Uuid;

    let mut findings = Vec::new();

    let response = match client.get(target).send().await {
        Ok(r) => r,
        Err(e) => {
            debug!("Header check failed to reach target: {}", e);
            return Ok(findings);
        }
    };

    let headers = response.headers().clone();

    let required_headers = [
        (
            "strict-transport-security",
            "Missing Strict-Transport-Security (HSTS)",
            "The HSTS header is absent, allowing downgrade attacks from HTTPS to HTTP.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            Severity::High,
        ),
        (
            "content-security-policy",
            "Missing Content-Security-Policy",
            "Without a CSP header, the application is more vulnerable to XSS attacks.",
            "Define a strict CSP that whitelists only trusted script/style sources.",
            Severity::Medium,
        ),
        (
            "x-frame-options",
            "Missing X-Frame-Options",
            "Without X-Frame-Options or CSP frame-ancestors, the app may be vulnerable to clickjacking.",
            "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors).",
            Severity::Medium,
        ),
        (
            "x-content-type-options",
            "Missing X-Content-Type-Options",
            "Absent nosniff header allows MIME-type sniffing attacks.",
            "Add: X-Content-Type-Options: nosniff",
            Severity::Low,
        ),
        (
            "referrer-policy",
            "Missing Referrer-Policy",
            "Without a Referrer-Policy, sensitive URL fragments may leak to third parties.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin",
            Severity::Low,
        ),
        (
            "permissions-policy",
            "Missing Permissions-Policy",
            "Permissions-Policy is absent; browser features (camera, microphone, geolocation) may be accessible.",
            "Add a restrictive Permissions-Policy header.",
            Severity::Low,
        ),
    ];

    for (header_name, title, description, remediation, severity) in &required_headers {
        if !headers.contains_key(*header_name) {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::SecurityMisconfiguration,
                severity: severity.clone(),
                title: title.to_string(),
                description: description.to_string(),
                evidence: Some(format!("GET {} — header '{}' not present in response", target, header_name)),
                remediation: remediation.to_string(),
                source: FindingSource::Dast,
                endpoint: Some(target.to_string()),
            });
        }
    }

    // Check for information-leaking headers
    let leaky_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"];
    for header_name in &leaky_headers {
        if let Some(value) = headers.get(*header_name) {
            let val_str = value.to_str().unwrap_or("").to_string();
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::SecurityMisconfiguration,
                severity: Severity::Info,
                title: format!("Information-Revealing Header: {}", header_name),
                description: format!(
                    "The '{}' header reveals technology details: '{}'. Fingerprinting aids attackers.",
                    header_name, val_str
                ),
                evidence: Some(format!("{}: {}", header_name, val_str)),
                remediation: format!("Remove or genericize the '{}' header in your server configuration.", header_name),
                source: FindingSource::Dast,
                endpoint: Some(target.to_string()),
            });
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_builds_successfully() {
        let config = ScanConfig {
            target: "http://example.com".into(),
            concurrency: 5,
            timeout_secs: 10,
            llm_probe: false,
        };
        let client = build_client(&config);
        assert!(client.is_ok());
    }
}
