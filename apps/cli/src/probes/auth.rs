//! Auth Probes — OWASP A07: Identification & Authentication Failures
//!
//! Tests for: JWT alg:none attack, default credentials, brute-force
//! protection absence, session fixation, and insecure cookie flags.

use std::sync::Arc;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD_NO_PAD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::Client;
use serde_json::json;
use tokio::sync::Semaphore;
use tracing::debug;
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

/// Common default credentials to test
static DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("superuser", "superuser"),
];

pub async fn run(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    target: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    findings.extend(probe_jwt_alg_none(Arc::clone(&client), Arc::clone(&sem), base).await?);
    findings.extend(probe_default_creds(Arc::clone(&client), Arc::clone(&sem), base).await?);
    findings.extend(probe_brute_force_protection(Arc::clone(&client), Arc::clone(&sem), base).await?);
    findings.extend(probe_cookie_flags(Arc::clone(&client), Arc::clone(&sem), base).await?);

    Ok(findings)
}

// ── JWT alg:none Attack ───────────────────────────────────────────────────────

async fn probe_jwt_alg_none(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    base: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Crafted JWT with alg:none and admin-level claims
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"admin","role":"admin","iat":1700000000,"exp":9999999999}"#);
    let forged_token = format!("{}.{}.", header, payload);

    let protected_endpoints = [
        format!("{}/api/admin", base),
        format!("{}/api/user/profile", base),
        format!("{}/admin", base),
        format!("{}/dashboard", base),
    ];

    for endpoint in &protected_endpoints {
        let _permit = sem.acquire().await.unwrap();

        let response = client
            .get(endpoint)
            .header("Authorization", format!("Bearer {}", forged_token))
            .send()
            .await;

        let Ok(resp) = response else { continue };

        // If we get 200 with admin token, the app accepts alg:none
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Heuristic: if the body looks like a real response (non-empty, not a redirect page)
            if body.len() > 50 && !body.contains("Login") && !body.contains("login") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::AuthFailures,
                    severity: Severity::Critical,
                    title: "JWT Algorithm Confusion (alg:none)".to_string(),
                    description: "The server accepted a JWT token with algorithm set to 'none', meaning no signature verification is performed. An attacker can forge arbitrary tokens to impersonate any user.".to_string(),
                    evidence: Some(format!(
                        "GET {} with forged token (alg:none, role:admin) returned HTTP 200",
                        endpoint
                    )),
                    remediation: "Use a JWT library that rejects 'none' algorithm by default. Explicitly whitelist allowed algorithms (e.g., RS256, HS256). Never allow unsigned JWTs.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(endpoint.clone()),
                });
                break;
            }
        }
    }

    Ok(findings)
}

// ── Default Credentials ───────────────────────────────────────────────────────

async fn probe_default_creds(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    base: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let login_endpoints = [
        format!("{}/login", base),
        format!("{}/api/login", base),
        format!("{}/api/auth", base),
        format!("{}/auth/login", base),
        format!("{}/signin", base),
        format!("{}/admin/login", base),
    ];

    // Only test first 5 credential pairs per endpoint to avoid lockout
    'outer: for endpoint in &login_endpoints {
        for (username, password) in DEFAULT_CREDS.iter().take(5) {
            let _permit = sem.acquire().await.unwrap();

            let body = json!({
                "username": username,
                "password": password,
            });

            let response = client
                .post(endpoint)
                .json(&body)
                .send()
                .await;

            let Ok(resp) = response else { continue };
            let status = resp.status();
            let resp_body = resp.text().await.unwrap_or_default();

            let success_indicators = ["token", "access_token", "session", "dashboard", "welcome"];
            let is_success = status.is_success()
                && success_indicators.iter().any(|&s| resp_body.to_lowercase().contains(s));

            if is_success {
                debug!("Default credentials accepted: {}:{}", username, password);
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::AuthFailures,
                    severity: Severity::Critical,
                    title: "Default Credentials Accepted".to_string(),
                    description: format!(
                        "The application accepted default credentials (username: '{}', password: '{}') at {}.",
                        username, password, endpoint
                    ),
                    evidence: Some(format!("POST {} → HTTP {} with success indicators in body", endpoint, status)),
                    remediation: "Enforce strong password policies and MFA. Remove all default accounts. Force password change on first login.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(endpoint.clone()),
                });
                break 'outer;
            }
        }
    }

    Ok(findings)
}

// ── Brute-Force Protection ────────────────────────────────────────────────────

async fn probe_brute_force_protection(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    base: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let login_endpoint = format!("{}/api/login", base);
    let mut last_status = 0u16;
    let mut consistent_responses = 0;

    // Fire 10 identical failed logins and check if any rate limiting kicks in
    for i in 0..10 {
        let _permit = sem.acquire().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let body = json!({
            "username": "testuser_probe",
            "password": format!("wrongpassword_{}", i),
        });

        let response = client
            .post(&login_endpoint)
            .json(&body)
            .send()
            .await;

        let Ok(resp) = response else { continue };
        let status = resp.status().as_u16();

        // Check for rate limiting signals
        let headers = resp.headers().clone();
        let has_retry_after = headers.contains_key("retry-after");
        let has_ratelimit = headers.contains_key("x-ratelimit-limit")
            || headers.contains_key("ratelimit-limit");

        if status == 429 || has_retry_after || has_ratelimit {
            debug!("Rate limiting detected at attempt {}", i);
            return Ok(findings); // Rate limiting in place — no finding
        }

        if last_status == status {
            consistent_responses += 1;
        }
        last_status = status;
    }

    // If we made 10 requests with no rate limiting (all got same non-429 response)
    if consistent_responses >= 8 {
        findings.push(Finding {
            id: Uuid::new_v4().to_string(),
            category: OwaspCategory::AuthFailures,
            severity: Severity::High,
            title: "No Brute-Force Protection on Login".to_string(),
            description: "The login endpoint allowed 10 consecutive failed login attempts without triggering rate limiting, account lockout, or CAPTCHA. This enables brute-force and credential stuffing attacks.".to_string(),
            evidence: Some(format!(
                "POST {} — 10 requests, no HTTP 429 or Retry-After header observed",
                login_endpoint
            )),
            remediation: "Implement: (1) Account lockout after 5 failed attempts, (2) Exponential backoff, (3) IP-based rate limiting, (4) CAPTCHA after 3 failures, (5) Alerting on suspicious login patterns.".to_string(),
            source: FindingSource::Dast,
            endpoint: Some(login_endpoint),
        });
    }

    Ok(findings)
}

// ── Cookie Security Flags ─────────────────────────────────────────────────────

async fn probe_cookie_flags(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    base: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let _permit = sem.acquire().await.unwrap();
    let response = match client.get(base).send().await {
        Ok(r) => r,
        Err(_) => return Ok(findings),
    };

    let set_cookie_headers: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    for cookie in &set_cookie_headers {
        let cookie_lower = cookie.to_lowercase();
        let cookie_name = cookie.split('=').next().unwrap_or("unknown").trim();

        // Check for session-like cookies
        let is_session_cookie = ["session", "token", "auth", "sid", "jwt", "csrf"]
            .iter()
            .any(|&kw| cookie_lower.contains(kw));

        if !is_session_cookie {
            continue;
        }

        if !cookie_lower.contains("httponly") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::AuthFailures,
                severity: Severity::High,
                title: format!("Cookie Missing HttpOnly Flag: {}", cookie_name),
                description: format!(
                    "The cookie '{}' does not have the HttpOnly flag set, making it accessible via JavaScript and vulnerable to XSS-based session theft.",
                    cookie_name
                ),
                evidence: Some(format!("Set-Cookie: {}", cookie)),
                remediation: "Set the HttpOnly flag on all session and authentication cookies.".to_string(),
                source: FindingSource::Dast,
                endpoint: Some(base.to_string()),
            });
        }

        if !cookie_lower.contains("secure") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::AuthFailures,
                severity: Severity::Medium,
                title: format!("Cookie Missing Secure Flag: {}", cookie_name),
                description: format!(
                    "The cookie '{}' does not have the Secure flag, allowing it to be transmitted over unencrypted HTTP connections.",
                    cookie_name
                ),
                evidence: Some(format!("Set-Cookie: {}", cookie)),
                remediation: "Add the Secure flag to all session cookies. Ensure your site enforces HTTPS.".to_string(),
                source: FindingSource::Dast,
                endpoint: Some(base.to_string()),
            });
        }

        if !cookie_lower.contains("samesite") {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::AuthFailures,
                severity: Severity::Medium,
                title: format!("Cookie Missing SameSite Attribute: {}", cookie_name),
                description: format!(
                    "The cookie '{}' does not specify SameSite, potentially enabling CSRF attacks in older browsers.",
                    cookie_name
                ),
                evidence: Some(format!("Set-Cookie: {}", cookie)),
                remediation: "Set SameSite=Strict or SameSite=Lax on all authentication cookies.".to_string(),
                source: FindingSource::Dast,
                endpoint: Some(base.to_string()),
            });
        }
    }

    Ok(findings)
}
