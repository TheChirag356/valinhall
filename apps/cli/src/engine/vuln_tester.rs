//! Endpoint Vulnerability Tester Engine
//!
//! Runs automated security checks against a list of discovered endpoints:
//! CORS misconfiguration, IDOR, path traversal, open redirect, SSRF, auth bypass,
//! sensitive data exposure, HTTP method enumeration, and JWT/cookie flaws.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use reqwest::{Client, Method};
use tokio::sync::Semaphore;
use tracing::{debug, info};
use uuid::Uuid;

use crate::engine::endpoint_crawler::DiscoveredEndpoint;
use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

pub struct VulnTestConfig {
    pub concurrency: usize,
    pub timeout: Duration,
}

pub async fn test_endpoints(
    client: Arc<Client>,
    endpoints: &[DiscoveredEndpoint],
    cfg: &VulnTestConfig,
) -> Result<Vec<Finding>> {
    info!("Vuln tester: running checks against {} endpoints", endpoints.len());

    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let mut handles = Vec::new();

    for ep in endpoints {
        let client = Arc::clone(&client);
        let sem = Arc::clone(&sem);
        let url = ep.url.clone();
        let timeout = cfg.timeout;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            run_checks(&client, &url, timeout).await
        }));
    }

    let mut all = Vec::new();
    for h in handles {
        if let Ok(findings) = h.await {
            all.extend(findings);
        }
    }

    info!("Vuln tester: {} findings across all endpoints", all.len());
    Ok(all)
}

async fn run_checks(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(check_cors(client, url, tout).await);
    findings.extend(check_sensitive_exposure(url));
    findings.extend(check_http_methods(client, url, tout).await);
    findings.extend(check_open_redirect(client, url, tout).await);
    findings.extend(check_path_traversal(client, url, tout).await);
    findings.extend(check_ssrf_indicators(client, url, tout).await);
    findings.extend(check_auth_bypass(client, url, tout).await);
    findings.extend(check_idor(client, url, tout).await);
    // Active injection checks against every live endpoint
    findings.extend(check_xss_reflection(client, url, tout).await);
    findings.extend(check_sqli_errors(client, url, tout).await);

    findings
}

// ── CORS misconfiguration ────────────────────────────────────────────────────

async fn check_cors(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let evil_origin = "https://evil.attacker.com";
    let resp = match client
        .get(url)
        .header("Origin", evil_origin)
        .timeout(tout)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let acac = resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let mut findings = Vec::new();

    if acao == "*" && acac == "true" {
        findings.push(finding(
            OwaspCategory::BrokenAccessControl,
            Severity::High,
            "[CORS] Wildcard Origin + Allow-Credentials",
            &format!("The endpoint `{}` reflects `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. This combination allows any website to make credentialed cross-origin requests, potentially stealing session data.", url),
            &format!("ACAO: {}, ACAC: {}", acao, acac),
            "Set a strict allowlist of trusted origins. Never combine wildcard ACAO with Allow-Credentials: true.",
            url,
        ));
    } else if acao == evil_origin {
        findings.push(finding(
            OwaspCategory::BrokenAccessControl,
            Severity::High,
            "[CORS] Arbitrary Origin Reflected",
            &format!("The endpoint `{}` reflects back the attacker-supplied `Origin` header verbatim, granting cross-origin access to any domain.", url),
            &format!("Sent Origin: {}, Received ACAO: {}", evil_origin, acao),
            "Validate the Origin header against an explicit allowlist of trusted domains.",
            url,
        ));
    }

    findings
}

// ── Sensitive endpoint exposure ──────────────────────────────────────────────

fn check_sensitive_exposure(url: &str) -> Vec<Finding> {
    let url_lc = url.to_lowercase();
    let sensitive_patterns = [
        (".env",             "Environment File Exposed",      Severity::Critical, "`.env` files contain secrets such as database credentials, API keys, and session secrets."),
        (".git/head",        "Git Repository Exposed",         Severity::High,     "Exposed `.git` directory allows full source code reconstruction."),
        ("phpinfo",          "PHP Info Page Exposed",          Severity::Medium,   "`phpinfo()` reveals server configuration, loaded extensions, and environment variables."),
        ("actuator/env",     "Spring Boot Actuator Env Exposed", Severity::Critical, "The `/actuator/env` endpoint leaks all environment variables including secrets."),
        ("actuator/dump",    "Spring Boot Thread Dump Exposed",  Severity::Medium,   "Thread dumps reveal internal stack traces and class names."),
        ("actuator/shutdown","Spring Boot Shutdown Exposed",    Severity::Critical, "The shutdown actuator can remotely stop the application."),
        ("backup",           "Backup File Accessible",          Severity::High,     "Backup archives may contain source code, database dumps, or credentials."),
        ("graphiql",         "GraphiQL IDE Exposed",            Severity::Medium,   "GraphiQL allows interactive query construction and introspection of the entire schema."),
        ("swagger-ui",       "Swagger UI Exposed",              Severity::Low,      "API documentation exposed. Verify all listed endpoints require authentication."),
        ("openapi.json",     "OpenAPI Spec Exposed",            Severity::Low,      "Full API specification is publicly accessible."),
    ];

    let mut findings = Vec::new();
    for (pattern, title, severity, description) in &sensitive_patterns {
        if url_lc.contains(pattern) {
            findings.push(finding(
                OwaspCategory::SecurityMisconfiguration,
                severity.clone(),
                &format!("[Exposure] {}", title),
                description,
                &format!("URL matched pattern: {}", pattern),
                "Restrict this endpoint to authenticated internal users or remove it from production.",
                url,
            ));
        }
    }
    findings
}

// ── HTTP method enumeration ──────────────────────────────────────────────────

/// Extensions that are always static assets — skip method checks on these
/// entirely (CDNs/proxies routinely return 200 for any method on static files).
fn is_static_asset(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url).to_lowercase();
    matches!(
        path.rsplit('.').next().unwrap_or(""),
        "js" | "css" | "png" | "jpg" | "jpeg" | "gif" | "ico" | "svg" | "woff"
            | "woff2" | "ttf" | "eot" | "otf" | "map" | "webp" | "avif"
            | "mp4" | "mp3" | "pdf" | "zip" | "gz" | "tar"
    )
}

async fn check_http_methods(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    // Static assets are served by CDNs that return 200 for any method —
    // never flag them to avoid massive false-positive noise.
    if is_static_asset(url) {
        return vec![];
    }

    let mut findings = Vec::new();

    // ── TRACE: always dangerous regardless of body content ───────────────────
    if let Ok(resp) = client
        .request(Method::TRACE, url)
        .timeout(tout)
        .send()
        .await
    {
        let status = resp.status().as_u16();
        if status != 405 && status != 501 {
            findings.push(finding(
                OwaspCategory::SecurityMisconfiguration,
                Severity::Medium,
                "[HTTP] TRACE Method Enabled",
                &format!(
                    "`{}` accepts HTTP TRACE requests (status {}). TRACE enables \
                     Cross-Site Tracing (XST) by reflecting request headers — \
                     including session cookies — back to any script that initiates \
                     the request.",
                    url, status
                ),
                &format!("TRACE {} → {}", url, status),
                "Disable TRACE/TRACK in your web server config (e.g. `TraceEnable off` for Apache, `deny_methods TRACE` for Nginx).",
                url,
            ));
        }
    }

    // ── DELETE: only flag if the resource is actually gone after the call ────
    // Strategy:
    //  1. GET the resource to confirm it exists and capture its ETag/body.
    //  2. Send DELETE.
    //  3. If DELETE returned 2xx, GET again — if we now get 404/410 the
    //     deletion was real; otherwise the server just accepted the method
    //     silently (CDN/proxy noise) and we skip the finding.
    let delete_confirmed = async {
        // Step 1 — confirm resource exists
        let before = client.get(url).timeout(tout).send().await.ok()?;
        let before_status = before.status().as_u16();
        if before_status != 200 {
            return None; // Nothing to delete
        }
        let before_body_len = before.bytes().await.ok()?.len();

        // Step 2 — attempt DELETE
        let del_resp = client
            .request(Method::DELETE, url)
            .timeout(tout)
            .send()
            .await
            .ok()?;
        let del_status = del_resp.status().as_u16();
        if del_status >= 400 {
            return None; // Server rejected it
        }

        // Step 3 — verify the resource is actually gone
        let after = client.get(url).timeout(tout).send().await.ok()?;
        let after_status = after.status().as_u16();
        // If the resource is still there with the same size → CDN echoed 200,
        // resource was NOT deleted.  Only flag when it is really gone.
        if after_status == 404 || after_status == 410 {
            Some(format!("DELETE {} → {} (resource confirmed gone: GET now returns {})",
                url, del_status, after_status))
        } else {
            // Body still same length → likely a pass-through 200, not a real delete
            let after_body_len = after.bytes().await.ok()?.len();
            if after_body_len == 0 || (before_body_len > 0 && after_body_len == 0) {
                Some(format!("DELETE {} → {} (resource body is now empty)",
                    url, del_status))
            } else {
                None // Resource still intact — false positive suppressed
            }
        }
    };

    if let Some(evidence) = delete_confirmed.await {
        findings.push(finding(
            OwaspCategory::BrokenAccessControl,
            Severity::High,
            "[HTTP] DELETE Method — Resource Actually Deleted",
            &format!(
                "`{}` accepted an unauthenticated HTTP DELETE request and the resource \
                 was confirmed to be removed in a subsequent GET. This is a real \
                 write-access vulnerability, not a CDN pass-through.",
                url
            ),
            &evidence,
            "Restrict DELETE to authenticated, authorized requests. Return 405 for unauthenticated callers.",
            url,
        ));
    }

    // ── PUT: send a canary body, re-fetch, confirm the new content appears ───
    let canary = "valinhall-canary-test-do-not-flag-false-positive";
    let put_confirmed = async {
        let put_resp = client
            .request(Method::PUT, url)
            .header("Content-Type", "text/plain")
            .body(canary)
            .timeout(tout)
            .send()
            .await
            .ok()?;
        let put_status = put_resp.status().as_u16();
        if put_status >= 400 {
            return None;
        }
        // Re-fetch and look for our canary string in the response
        let after = client.get(url).timeout(tout).send().await.ok()?;
        let body = after.text().await.ok()?;
        if body.contains(canary) {
            Some(format!("PUT {} → {} (canary string reflected in subsequent GET)",
                url, put_status))
        } else {
            None // Server accepted the method but ignored the body — not a real write
        }
    };

    if let Some(evidence) = put_confirmed.await {
        findings.push(finding(
            OwaspCategory::BrokenAccessControl,
            Severity::High,
            "[HTTP] PUT Method — Unauthenticated File Write Confirmed",
            &format!(
                "`{}` accepted an unauthenticated HTTP PUT request and the uploaded \
                 content was confirmed present in a subsequent GET. This allows arbitrary \
                 content replacement or webshell upload.",
                url
            ),
            &evidence,
            "Restrict PUT to authenticated, authorized requests and validate the uploaded content type.",
            url,
        ));
    }

    findings
}

// ── Open redirect ────────────────────────────────────────────────────────────

async fn check_open_redirect(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let payloads = [
        "?redirect=https://evil.attacker.com",
        "?url=https://evil.attacker.com",
        "?next=https://evil.attacker.com",
        "?return=https://evil.attacker.com",
        "?returnUrl=https://evil.attacker.com",
        "?goto=//evil.attacker.com",
    ];

    for payload in &payloads {
        let test_url = format!("{}{}", url, payload);
        if let Ok(resp) = client
            .get(&test_url)
            .timeout(tout)
            // don't follow redirects so we can inspect Location header
            .send()
            .await
        {
            let status = resp.status().as_u16();
            if (300..=399).contains(&status) {
                let location = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if location.contains("evil.attacker.com") {
                    return vec![finding(
                        OwaspCategory::BrokenAccessControl,
                        Severity::Medium,
                        "[Open Redirect] Unvalidated Redirect Parameter",
                        &format!("`{}` redirects to an attacker-controlled URL when a redirect parameter is manipulated. This enables phishing attacks.", url),
                        &format!("Payload: {}\nStatus: {}\nLocation: {}", payload, status, location),
                        "Validate redirect targets against a strict allowlist of trusted domains.",
                        url,
                    )];
                }
            }
        }
    }
    vec![]
}

// ── Path traversal ──────────────────────────────────────────────────────────

async fn check_path_traversal(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let payloads = [
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/....//....//etc/passwd",
    ];

    for payload in &payloads {
        let test_url = format!("{}{}", url.trim_end_matches('/'), payload);
        if let Ok(resp) = client.get(&test_url).timeout(tout).send().await {
            if let Ok(body) = resp.text().await {
                if body.contains("root:x:0:0") || body.contains("/bin/bash") {
                    return vec![finding(
                        OwaspCategory::BrokenAccessControl,
                        Severity::Critical,
                        "[Path Traversal] Directory Traversal — /etc/passwd Read",
                        &format!("`{}` is vulnerable to path traversal. The contents of `/etc/passwd` were returned in the response.", url),
                        &format!("Payload: {}\nResponse snippet: {}", payload, &body[..200.min(body.len())]),
                        "Canonicalize and validate all file paths. Reject any path containing `..` sequences.",
                        url,
                    )];
                }
            }
        }
    }
    vec![]
}

// ── SSRF indicators ─────────────────────────────────────────────────────────

async fn check_ssrf_indicators(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    // Probe for SSRF via AWS/GCP metadata endpoints through URL parameters
    let ssrf_payloads = [
        "?url=http://169.254.169.254/latest/meta-data/",
        "?fetch=http://169.254.169.254/latest/meta-data/",
        "?proxy=http://169.254.169.254/",
        "?target=http://169.254.169.254/",
    ];

    for payload in &ssrf_payloads {
        let test_url = format!("{}{}", url, payload);
        if let Ok(resp) = client.get(&test_url).timeout(tout).send().await {
            let status = resp.status().as_u16();
            if let Ok(body) = resp.text().await {
                // AWS metadata response contains these strings
                if body.contains("ami-id") || body.contains("iam/security-credentials")
                    || body.contains("instance-id")
                {
                    return vec![finding(
                        OwaspCategory::InsecureDesign,
                        Severity::Critical,
                        "[SSRF] Server-Side Request Forgery — Cloud Metadata Accessible",
                        &format!("`{}` is vulnerable to SSRF. The server fetched the AWS EC2 instance metadata endpoint and returned the response, exposing IAM credentials and instance identity.", url),
                        &format!("Payload: {}\nStatus: {}\nBody snippet: {}", payload, status, &body[..200.min(body.len())]),
                        "Validate and whitelist all URLs before making server-side HTTP requests. Block access to 169.254.169.254 at the network level.",
                        url,
                    )];
                }
            }
        }
    }
    vec![]
}

// ── Auth bypass ─────────────────────────────────────────────────────────────

async fn check_auth_bypass(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    // Try common auth bypass headers
    let bypass_headers: &[(&str, &str)] = &[
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
    ];

    // First get baseline status
    let baseline = match client.get(url).timeout(tout).send().await {
        Ok(r) => r.status().as_u16(),
        Err(_) => return vec![],
    };

    // Only interesting if endpoint normally returns 401/403
    if baseline != 401 && baseline != 403 {
        return vec![];
    }

    for (header, value) in bypass_headers {
        if let Ok(resp) = client
            .get(url)
            .header(*header, *value)
            .timeout(tout)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            if status == 200 || status == 302 {
                return vec![finding(
                    OwaspCategory::BrokenAccessControl,
                    Severity::High,
                    "[Auth Bypass] Header-Based Access Control Bypass",
                    &format!("`{}` returns {} normally but responds with {} when the `{}` header is added. This indicates the authorization check is bypassable via HTTP header manipulation.", url, baseline, status, header),
                    &format!("Bypass header: {}: {}\nBaseline: {}, Bypass status: {}", header, value, baseline, status),
                    "Implement server-side authorization based on session tokens, not client-supplied headers. Strip untrusted headers at the load balancer.",
                    url,
                )];
            }
        }
    }
    vec![]
}

// ── IDOR (Insecure Direct Object Reference) ─────────────────────────────────

async fn check_idor(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    // Only probe API-like endpoints with numeric IDs
    let url_lc = url.to_lowercase();
    let is_api = url_lc.contains("/api/") || url_lc.contains("/v1/") || url_lc.contains("/v2/");
    if !is_api {
        return vec![];
    }

    // Try appending common IDOR ID patterns
    let test_ids = ["/1", "/2", "/0", "/999999", "/admin", "/../1"];

    for id in &test_ids {
        let test_url = format!("{}{}", url.trim_end_matches('/'), id);
        if let Ok(resp) = client.get(&test_url).timeout(tout).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                if let Ok(body) = resp.text().await {
                    // Heuristic: response contains user-like data fields
                    let has_user_data = ["email", "password", "token", "secret", "ssn", "credit"]
                        .iter()
                        .any(|kw| body.to_lowercase().contains(kw));
                    if has_user_data {
                        return vec![finding(
                            OwaspCategory::BrokenAccessControl,
                            Severity::High,
                            "[IDOR] Potential Insecure Direct Object Reference",
                            &format!("`{}` returns sensitive user data for an unverified object ID without apparent authorization checks.", &test_url),
                            &format!("Test URL: {}\nStatus: {}\nBody preview: {}", test_url, status, &body[..300.min(body.len())]),
                            "Implement object-level authorization checks. Verify the authenticated user owns the requested resource before returning it.",
                            url,
                        )];
                    }
                }
            }
        }
    }
    vec![]
}

// ── XSS Reflection ──────────────────────────────────────────────────────────
//
// Injects XSS payloads into every query parameter of the URL (and a generic
// ?q= param if none exist), then checks whether the payload is reflected
// unencoded in a text/html response.  Also fires at the root URL with a param.

static XSS_PROBES: &[&str] = &[
    "<script>alert('VH')</script>",
    "<img src=x onerror=alert('VH')>",
    "'><script>alert('VH')</script>",
    "<svg onload=alert('VH')>",
    "javascript:alert('VH')",
    "%3Cscript%3Ealert('VH')%3C/script%3E",
    "<ScRiPt>alert('VH')</ScRiPt>",
];

async fn check_xss_reflection(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    // Build a set of test URLs: replace each existing param value, plus add ?q=
    let mut test_cases: Vec<String> = Vec::new();

    if url.contains('=') {
        // Replace every param value
        if let Some(q_pos) = url.find('?') {
            let base = &url[..q_pos];
            let query = &url[q_pos + 1..];
            for probe in XSS_PROBES {
                let encoded = urlencoding::encode(probe);
                // Naively replace all values after '=' — good enough for reflection check
                let new_query: String = query
                    .split('&')
                    .map(|kv| {
                        if let Some(k) = kv.split('=').next() {
                            format!("{}={}", k, encoded)
                        } else {
                            kv.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                test_cases.push(format!("{}?{}", base, new_query));
            }
        }
    } else {
        // No params — append ?q=<probe>
        for probe in XSS_PROBES {
            let encoded = urlencoding::encode(probe);
            test_cases.push(format!("{}?q={}", url.trim_end_matches('/'), encoded));
        }
    }

    for test_url in &test_cases {
        let resp = match client.get(test_url).timeout(tout).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        // Only flag reflected XSS in HTML responses
        if !ct.contains("text/html") {
            continue;
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Check which probe was used for this URL
        for probe in XSS_PROBES {
            if body.contains(*probe) {
                return vec![finding(
                    OwaspCategory::BrokenAccessControl,
                    Severity::High,
                    "[XSS] Reflected Cross-Site Scripting",
                    &format!(
                        "The endpoint `{}` reflects the XSS payload `{}` unencoded in \
                         the HTML response, confirming a Reflected XSS vulnerability. \
                         An attacker can craft a link that executes arbitrary JavaScript \
                         in the victim's browser.",
                        url, probe
                    ),
                    &format!("Test URL: {}\nPayload reflected: {}", test_url, probe),
                    "HTML-encode all user-supplied output. Implement a strict \
                     Content-Security-Policy. Use a framework that auto-escapes output.",
                    url,
                )];
            }
        }
    }
    vec![]
}

// ── SQLi Error Detection ─────────────────────────────────────────────────────
//
// Injects SQL payloads into every query param (GET) and into common POST body
// fields (email/username/password) for login-like endpoints.  Detects both
// error-based and a simple auth-bypass boolean check.

static SQLI_QUICK: &[&str] = &[
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
    "1; SELECT SLEEP(0)--",
];

static SQL_ERRORS: &[&str] = &[
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "ORA-0",
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark",
    "SQLSTATE",
    "pg_query()",
    "syntax error at or near",
    "SQLite",
    "Incorrect syntax near",
    "mysql_fetch",
    "sql syntax",
    "JDBC",
    "[SQL Server]",
    "unrecognized token:",
];

async fn check_sqli_errors(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let mut test_urls: Vec<String> = Vec::new();

    if url.contains('=') {
        if let Some(q_pos) = url.find('?') {
            let base = &url[..q_pos];
            let query = &url[q_pos + 1..];
            for probe in SQLI_QUICK {
                let encoded = urlencoding::encode(probe);
                let new_query: String = query
                    .split('&')
                    .map(|kv| {
                        if let Some(k) = kv.split('=').next() {
                            format!("{}={}", k, encoded)
                        } else {
                            kv.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                test_urls.push(format!("{}?{}", base, new_query));
            }
        }
    } else {
        for probe in SQLI_QUICK {
            let encoded = urlencoding::encode(probe);
            test_urls.push(format!("{}?id={}", url.trim_end_matches('/'), encoded));
        }
    }

    // GET-based checks
    for test_url in &test_urls {
        if let Ok(resp) = client.get(test_url).timeout(tout).send().await {
            if let Ok(body) = resp.text().await {
                if let Some(err) = SQL_ERRORS.iter().find(|&&e| body.contains(e)) {
                    return vec![finding(
                        OwaspCategory::BrokenAccessControl,
                        Severity::Critical,
                        "[SQLi] SQL Injection — Error-Based (GET)",
                        &format!(
                            "The endpoint `{}` leaks a SQL error in the GET response, \
                             confirming SQL injection. The database error '{}' was triggered.",
                            url, err
                        ),
                        &format!("Test URL: {}\nSQL error: {}", test_url, err),
                        "Use parameterised queries (prepared statements). Never concatenate \
                         user input into SQL strings.",
                        url,
                    )];
                }
            }
        }
    }

    // POST body checks for login-like endpoints
    let url_lc = url.to_lowercase();
    let is_login = ["login", "signin", "auth", "session", "user"]
        .iter()
        .any(|kw| url_lc.contains(kw));

    if is_login {
        // First get a baseline status with dummy creds
        let baseline = {
            client
                .post(url)
                .header("Content-Type", "application/json")
                .body(r#"{"email":"notreal@valinhall.invalid","password":"Dummy!123"}"#)
                .timeout(tout)
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0)
        };

        if baseline != 0 && baseline != 404 && baseline != 405 {
            for (email_probe, pass_probe) in &[
                ("' OR '1'='1'--", "x"),
                ("' OR 1=1--",     "x"),
                ("admin'--",        "x"),
                ("' OR 'x'='x",    "x"),
            ] {
                let json = format!(
                    "{{\"email\":\"{}\",\"password\":\"{}\"}}",
                    email_probe, pass_probe
                );
                let resp = match client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(json)
                    .timeout(tout)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let inject_status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();

                // Error-based
                if let Some(err) = SQL_ERRORS.iter().find(|&&e| body.contains(e)) {
                    return vec![finding(
                        OwaspCategory::BrokenAccessControl,
                        Severity::Critical,
                        "[SQLi] SQL Injection — Error-Based (POST Login)",
                        &format!(
                            "The login endpoint `{}` leaks a SQL error when a crafted \
                             payload is sent in the JSON body. Error: '{}'.",
                            url, err
                        ),
                        &format!("POST {}\nPayload email: {}\nSQL error: {}", url, email_probe, err),
                        "Use parameterised queries. Never concatenate POST body fields into SQL.",
                        url,
                    )];
                }

                // Boolean-blind auth bypass: true payload → 2xx, baseline → 4xx
                if inject_status < 400
                    && (baseline == 401 || baseline == 403 || baseline == 422)
                {
                    // Verify false condition still fails
                    let false_body = r#"{"email":"' AND '1'='2'--","password":"x"}"#;
                    let false_status = client
                        .post(url)
                        .header("Content-Type", "application/json")
                        .body(false_body)
                        .timeout(tout)
                        .send()
                        .await
                        .map(|r| r.status().as_u16())
                        .unwrap_or(0);

                    if false_status >= 400 {
                        return vec![finding(
                            OwaspCategory::BrokenAccessControl,
                            Severity::Critical,
                            "[SQLi] SQL Injection — Boolean-Blind Auth Bypass (POST Login)",
                            &format!(
                                "The login endpoint `{}` is vulnerable to SQL injection. \
                                 The true-condition payload `{}` returns HTTP {} (auth succeeds), \
                                 while the false-condition payload returns HTTP {} (auth fails). \
                                 This confirms boolean-blind SQLi allowing full authentication bypass.",
                                url, email_probe, inject_status, false_status
                            ),
                            &format!(
                                "POST {}\nTrue payload: {} → HTTP {}\nFalse payload → HTTP {}",
                                url, email_probe, inject_status, false_status
                            ),
                            "Use parameterised queries (prepared statements). Never build \
                             SQL from login form input.",
                            url,
                        )];
                    }
                }
            }
        }
    }

    vec![]
}

// ── Helper ───────────────────────────────────────────────────────────────────

fn finding(
    category: OwaspCategory,
    severity: Severity,
    title: &str,
    description: &str,
    evidence: &str,
    remediation: &str,
    endpoint: &str,
) -> Finding {
    Finding {
        id: Uuid::new_v4().to_string(),
        category,
        severity,
        title: title.to_string(),
        description: description.to_string(),
        evidence: Some(evidence.to_string()),
        remediation: remediation.to_string(),
        source: FindingSource::VulnTester,
        endpoint: Some(endpoint.to_string()),
    }
}
