//! Exception Handling Probes — OWASP A10: Mishandling of Exceptional Conditions

use std::sync::Arc;
use anyhow::Result;
use reqwest::Client;
use tokio::sync::Semaphore;
use uuid::Uuid;
use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

static STACK_TRACE_PATTERNS: &[&str] = &[
    "at Object.", "at Function.", "stack trace:", "Traceback (most recent call last)",
    "java.lang.", "NullPointerException", "in /var/www", "C:\\inetpub\\",
    "fatal error:", "panic: runtime error", "goroutine",
];

static TECH_DISCLOSURE_PATTERNS: &[&str] = &[
    "Django", "Rails", "Laravel", "Spring Boot", "Express.js", "ASP.NET",
    "PHP/", "Apache/", "nginx/", "Python/", "Ruby/", "Node.js/",
];

pub async fn run(client: Arc<Client>, sem: Arc<Semaphore>, target: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    let api_endpoints = [
        format!("{}/api/login", base),
        format!("{}/api/chat", base),
        format!("{}/api/user", base),
    ];

    let malformed_bodies: &[&str] = &[
        "{not valid json",
        "null",
        "<xml>not json</xml>",
        "undefined",
    ];

    // Malformed JSON probe
    for endpoint in &api_endpoints {
        for body in malformed_bodies {
            let _permit = sem.acquire().await.unwrap();
            let response = client
                .post(endpoint)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .await;

            let Ok(resp) = response else { continue };
            let status = resp.status().as_u16();
            if status < 400 { continue; }

            let resp_text = resp.text().await.unwrap_or_default();

            if let Some(pattern) = STACK_TRACE_PATTERNS.iter().find(|&&p| resp_text.contains(p)) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::ExceptionalConditions,
                    severity: Severity::High,
                    title: "Stack Trace Disclosure on Malformed Input".to_string(),
                    description: format!("Server returned a stack trace on malformed input. Pattern: '{}'.", pattern),
                    evidence: Some(format!("POST {} body={:.60} → HTTP {}", endpoint, body, status)),
                    remediation: "Use a global exception handler that returns generic errors. Disable debug mode in production.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(endpoint.clone()),
                });
                break;
            }

            if let Some(tech) = TECH_DISCLOSURE_PATTERNS.iter().find(|&&p| resp_text.contains(p)) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::SecurityMisconfiguration,
                    severity: Severity::Low,
                    title: "Technology Disclosure in Error Response".to_string(),
                    description: format!("Error response revealed tech stack: '{}'.", tech),
                    evidence: Some(format!("POST {} → HTTP {}: '{}' found in body", endpoint, status, tech)),
                    remediation: "Configure all error pages to return generic messages.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(endpoint.clone()),
                });
                break;
            }
        }
    }

    // TRACE method probe
    let base_url = format!("{}/", base);
    let _permit = sem.acquire().await.unwrap();
    let trace_resp = client
        .request(reqwest::Method::from_bytes(b"TRACE").unwrap(), &base_url)
        .send()
        .await;

    if let Ok(resp) = trace_resp {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("TRACE") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::SecurityMisconfiguration,
                    severity: Severity::Medium,
                    title: "HTTP TRACE Method Enabled (XST Risk)".to_string(),
                    description: "TRACE is enabled, enabling Cross-Site Tracing attacks that bypass HttpOnly cookies.".to_string(),
                    evidence: Some(format!("TRACE {} → HTTP 200", base_url)),
                    remediation: "Disable the TRACE method in your web server configuration.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(base_url),
                });
            }
        }
    }

    // Null fields probe
    let null_bodies = [
        serde_json::json!({"username": null, "password": null}),
        serde_json::json!({}),
    ];
    let login_ep = format!("{}/api/login", base);
    for body in &null_bodies {
        let _permit = sem.acquire().await.unwrap();
        let response = client.post(&login_ep).json(body).send().await;
        let Ok(resp) = response else { continue };
        let status = resp.status().as_u16();
        let resp_body = resp.text().await.unwrap_or_default();
        if status == 500 {
            if let Some(pattern) = STACK_TRACE_PATTERNS.iter().find(|&&p| resp_body.contains(p)) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::ExceptionalConditions,
                    severity: Severity::Medium,
                    title: "Unhandled Exception on Null/Empty Input".to_string(),
                    description: format!("Null fields caused HTTP 500. Pattern '{}' detected.", pattern),
                    evidence: Some(format!("POST {} body={} → HTTP 500", login_ep, body)),
                    remediation: "Validate all inputs. Return HTTP 400 for invalid input.".to_string(),
                    source: FindingSource::Dast,
                    endpoint: Some(login_ep.clone()),
                });
                break;
            }
        }
    }

    Ok(findings)
}
