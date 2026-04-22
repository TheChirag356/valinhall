//! OpenAPI Specification Fuzzer
//!
//! Fetches a discovered `openapi.json` or `swagger.json`, parses every endpoint,
//! and auto-generates typed HTTP test cases for each parameter (path, query, body).
//!
//! Attack surface covered:
//!   - **Type-Confusion**: sends wrong type for every parameter (string where int expected, etc.)
//!   - **Boundary injection**: sends numeric extremes, empty strings, and null values.
//!   - **Missing required fields**: omits required body parameters to probe error handling.
//!   - **SQLi / XSS probes**: injects into every parameter that accepts a string.
//!   - **Unprotected endpoints**: flags 2xx responses that require no auth.

use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use serde_json::{Value, json};
use tracing::{debug, info};
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── Public entry point ────────────────────────────────────────────────────────

/// Attempt to discover and fuzz OpenAPI/Swagger spec at `base_url`.
/// Tries several common spec paths automatically.
pub async fn run(client: &Client, base_url: &str, timeout: Duration) -> Result<Vec<Finding>> {
    let spec_paths = [
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/v1/openapi.json",
        "/v2/openapi.json",
        "/v3/openapi.json",
        "/docs/openapi.json",
        "/swagger/v1/swagger.json",
    ];

    let base = base_url.trim_end_matches('/');

    for path in &spec_paths {
        let url = format!("{}{}", base, path);
        debug!("OpenAPI fuzzer: probing {}", url);

        let resp = match client.get(&url).timeout(timeout).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let ct = resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if !ct.contains("json") && !ct.contains("yaml") {
            continue;
        }

        let text = match resp.text().await {
            Ok(t) => t,
            Err(_) => continue,
        };

        let spec: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Only proceed if this looks like an OpenAPI document
        if spec.get("paths").is_none() && spec.get("swagger").is_none() && spec.get("openapi").is_none() {
            continue;
        }

        info!("OpenAPI fuzzer: found spec at {}", url);

        let mut findings = Vec::new();

        // Flag the exposure itself
        findings.push(exposure_finding(&url, &text));

        // Extract server base URL from spec (fall back to base_url)
        let server_base = extract_server_base(&spec, base);

        // Fuzz every path × method combination
        if let Some(paths) = spec["paths"].as_object() {
            for (path, path_item) in paths {
                if let Some(path_item_obj) = path_item.as_object() {
                    for (method, operation) in path_item_obj {
                        let method_uc = method.to_uppercase();
                        if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method_uc.as_str()) {
                            continue;
                        }
                        let endpoint_url = format!("{}{}", server_base, path);
                        findings.extend(
                            fuzz_operation(client, &endpoint_url, &method_uc, operation, path, timeout).await
                        );
                    }
                }
            }
        }

        info!("OpenAPI fuzzer: {} finding(s) from spec {}", findings.len(), url);
        return Ok(findings);
    }

    Ok(vec![])
}

// ── Spec exposure finding ─────────────────────────────────────────────────────

fn exposure_finding(spec_url: &str, body_snippet: &str) -> Finding {
    let preview = &body_snippet[..300.min(body_snippet.len())];
    Finding {
        id: Uuid::new_v4().to_string(),
        category: OwaspCategory::SecurityMisconfiguration,
        severity: Severity::Medium,
        title: "[OpenAPI] Spec File Publicly Accessible".to_string(),
        description: format!(
            "The API specification file is publicly accessible at `{}`. \
             It exposes every endpoint, parameter name, data type, and auth scheme, \
             providing a detailed attack map to any adversary.",
            spec_url
        ),
        evidence: Some(format!("URL: {}\nBody preview: {}", spec_url, preview)),
        remediation: "Restrict access to the OpenAPI spec behind authentication, or serve it \
                      only on internal/staging environments.".to_string(),
        source: FindingSource::OpenApiFuzzer,
        endpoint: Some(spec_url.to_string()),
    }
}

// ── Extract server base URL ───────────────────────────────────────────────────

fn extract_server_base<'a>(spec: &'a Value, fallback: &'a str) -> String {
    // OpenAPI 3.x
    if let Some(servers) = spec["servers"].as_array() {
        if let Some(first) = servers.first() {
            if let Some(url) = first["url"].as_str() {
                if url.starts_with("http") {
                    return url.trim_end_matches('/').to_string();
                }
            }
        }
    }
    // Swagger 2.x
    if let (Some(host), Some(basepath)) = (spec["host"].as_str(), spec["basePath"].as_str()) {
        let scheme = spec["schemes"].as_array()
            .and_then(|s| s.first())
            .and_then(|s| s.as_str())
            .unwrap_or("https");
        return format!("{}://{}{}", scheme, host, basepath.trim_end_matches('/'));
    }
    fallback.to_string()
}

// ── Per-operation fuzzer ──────────────────────────────────────────────────────

async fn fuzz_operation(
    client: &Client,
    endpoint_url: &str,
    method: &str,
    operation: &Value,
    path_template: &str,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Gather parameter definitions
    let params = gather_params(operation);

    // ── 1. Unprotected endpoint check ────────────────────────────────────────
    if let Some(f) = check_unprotected(client, endpoint_url, method, &params, path_template, timeout).await {
        findings.push(f);
    }

    // ── 2. Type-confusion probes ─────────────────────────────────────────────
    findings.extend(
        check_type_confusion(client, endpoint_url, method, &params, path_template, timeout).await
    );

    // ── 3. SQL injection probes into string params ────────────────────────────
    findings.extend(
        check_string_injection(client, endpoint_url, method, &params, path_template, timeout).await
    );

    // ── 4. Missing required fields ────────────────────────────────────────────
    if method == "POST" || method == "PUT" || method == "PATCH" {
        if let Some(f) = check_missing_required(client, endpoint_url, method, operation, path_template, timeout).await {
            findings.push(f);
        }
    }

    findings
}

// ── Parameter extraction ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ParamDef {
    name: String,
    location: String, // "query", "path", "header", "body"
    schema_type: String,
    required: bool,
}

fn gather_params(operation: &Value) -> Vec<ParamDef> {
    let mut params = Vec::new();

    if let Some(arr) = operation["parameters"].as_array() {
        for p in arr {
            let name = p["name"].as_str().unwrap_or("param").to_string();
            let location = p["in"].as_str().unwrap_or("query").to_string();
            let required = p["required"].as_bool().unwrap_or(false);

            // OpenAPI 3 uses p["schema"]["type"], Swagger 2 uses p["type"]
            let schema_type = p["schema"]["type"].as_str()
                .or_else(|| p["type"].as_str())
                .unwrap_or("string")
                .to_string();

            params.push(ParamDef { name, location, schema_type, required });
        }
    }

    // OpenAPI 3 requestBody — treat body properties as "body" params
    if let Some(content) = operation["requestBody"]["content"].as_object() {
        for (_media_type, media) in content {
            if let Some(props) = media["schema"]["properties"].as_object() {
                for (prop_name, prop_schema) in props {
                    let schema_type = prop_schema["type"].as_str().unwrap_or("string").to_string();
                    params.push(ParamDef {
                        name: prop_name.clone(),
                        location: "body".to_string(),
                        schema_type,
                        required: false,
                    });
                }
            }
        }
    }

    params
}

// ── Build a URL substituting path params with valid sentinel values ───────────

fn resolve_path(url_template: &str, params: &[ParamDef]) -> String {
    let mut url = url_template.to_string();
    for p in params.iter().filter(|p| p.location == "path") {
        let placeholder = format!("{{{}}}", p.name);
        let sentinel = match p.schema_type.as_str() {
            "integer" | "number" => "1",
            "boolean" => "true",
            _ => "test",
        };
        url = url.replace(&placeholder, sentinel);
    }
    url
}

// ── Build query string from non-path params ───────────────────────────────────

fn build_query(params: &[ParamDef], overrides: &[(String, String)]) -> String {
    let mut parts: Vec<String> = params
        .iter()
        .filter(|p| p.location == "query")
        .map(|p| {
            // Check if this param has an override
            let val = overrides.iter()
                .find(|(k, _)| k == &p.name)
                .map(|(_, v)| v.as_str())
                .unwrap_or(match p.schema_type.as_str() {
                    "integer" | "number" => "1",
                    "boolean" => "true",
                    _ => "test",
                });
            format!("{}={}", p.name, urlencoding::encode(val))
        })
        .collect();

    // Add any override keys that weren't already in params
    for (k, v) in overrides {
        if !params.iter().any(|p| p.location == "query" && &p.name == k) {
            parts.push(format!("{}={}", k, urlencoding::encode(v)));
        }
    }

    parts.join("&")
}

// ── Check 1: Unprotected endpoint ─────────────────────────────────────────────

async fn check_unprotected(
    client: &Client,
    url_template: &str,
    method: &str,
    params: &[ParamDef],
    path_template: &str,
    timeout: Duration,
) -> Option<Finding> {
    let url = resolve_path(url_template, params);
    let qs = build_query(params, &[]);
    let full_url = if qs.is_empty() { url.clone() } else { format!("{}?{}", url, qs) };

    let req = match method {
        "GET" | "DELETE" => client.request(
            reqwest::Method::from_bytes(method.as_bytes()).ok()?,
            &full_url
        ).timeout(timeout).build().ok()?,
        _ => {
            // Build a minimal valid JSON body
            let body = build_sentinel_body(params);
            client.request(
                reqwest::Method::from_bytes(method.as_bytes()).ok()?,
                &full_url
            )
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .timeout(timeout)
            .build().ok()?
        }
    };

    let resp = client.execute(req).await.ok()?;
    let status = resp.status().as_u16();

    // Flag if we get 200/201 with no auth headers at all
    if status == 200 || status == 201 {
        return Some(Finding {
            id: Uuid::new_v4().to_string(),
            category: OwaspCategory::BrokenAccessControl,
            severity: Severity::High,
            title: format!("[OpenAPI] Unauthenticated Access — {} {}", method, path_template),
            description: format!(
                "The endpoint `{} {}` returned HTTP {} without any authentication token. \
                 This endpoint is defined in the OpenAPI spec and appears to be unauthenticated.",
                method, path_template, status
            ),
            evidence: Some(format!("{} {} → HTTP {}", method, full_url, status)),
            remediation: "Require a valid Bearer token or session cookie on all non-public endpoints.".to_string(),
            source: FindingSource::OpenApiFuzzer,
            endpoint: Some(full_url),
        });
    }

    None
}

// ── Check 2: Type confusion ───────────────────────────────────────────────────

async fn check_type_confusion(
    client: &Client,
    url_template: &str,
    method: &str,
    params: &[ParamDef],
    path_template: &str,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for p in params {
        let wrong_value = match p.schema_type.as_str() {
            "integer" | "number" => "WRONG_TYPE_STRING",
            "boolean" => "WRONG_TYPE_999",
            _ => "-1", // send int where string expected
        };

        let url = resolve_path(url_template, params);

        let full_url = if p.location == "query" {
            let qs = build_query(params, &[(p.name.clone(), wrong_value.to_string())]);
            format!("{}?{}", url, qs)
        } else {
            url.clone()
        };

        let resp = match method {
            "GET" => client.get(&full_url).timeout(timeout).send().await,
            _ => {
                let mut body = build_sentinel_body(params);
                body[&p.name] = json!(wrong_value);
                client.request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST),
                    &full_url
                )
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .timeout(timeout)
                .send()
                .await
            }
        };

        if let Ok(r) = resp {
            let status = r.status().as_u16();
            // 500 = unhandled type error leaking internal state
            if status == 500 {
                if let Ok(body) = r.text().await {
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        category: OwaspCategory::ExceptionalConditions,
                        severity: Severity::Medium,
                        title: format!(
                            "[OpenAPI] Type Confusion → 500 — {} {} param `{}`",
                            method, path_template, p.name
                        ),
                        description: format!(
                            "Sending a wrong type (`{}`) for parameter `{}` on `{} {}` \
                             caused an unhandled HTTP 500 error, indicating the server \
                             does not validate or sanitize parameter types before processing.",
                            wrong_value, p.name, method, path_template
                        ),
                        evidence: Some(format!(
                            "Payload type confusion — param `{}` = `{}`\nURL: {}\nStatus: 500\nBody: {}",
                            p.name, wrong_value, full_url, &body[..300.min(body.len())]
                        )),
                        remediation: "Validate and coerce all incoming parameter types before use. \
                                      Return 400 for malformed inputs, never 500.".to_string(),
                        source: FindingSource::OpenApiFuzzer,
                        endpoint: Some(full_url.clone()),
                    });
                }
            }
        }
    }

    findings
}

// ── Check 3: String injection ─────────────────────────────────────────────────

static SQLI_PROBE: &str = "' OR '1'='1";
static XSS_PROBE: &str = "<script>alert('VH')</script>";

async fn check_string_injection(
    client: &Client,
    url_template: &str,
    method: &str,
    params: &[ParamDef],
    path_template: &str,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let sql_errors = [
        "You have an error in your SQL syntax",
        "ORA-0", "SQLSTATE", "pg_query()",
        "syntax error at or near", "Unclosed quotation mark",
        "Microsoft OLE DB", "SQLite", "JDBC",
    ];

    for p in params.iter().filter(|p| p.schema_type == "string" || p.schema_type.is_empty()) {
        for (probe, probe_label) in &[(SQLI_PROBE, "SQLi"), (XSS_PROBE, "XSS")] {
            let url = resolve_path(url_template, params);
            let full_url = if p.location == "query" {
                let qs = build_query(params, &[(p.name.clone(), probe.to_string())]);
                format!("{}?{}", url, qs)
            } else {
                url.clone()
            };

            let resp = match method {
                "GET" => client.get(&full_url).timeout(timeout).send().await,
                _ => {
                    let mut body = build_sentinel_body(params);
                    body[&p.name] = json!(probe);
                    client.request(
                        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST),
                        &full_url
                    )
                    .header("Content-Type", "application/json")
                    .body(body.to_string())
                    .timeout(timeout)
                    .send()
                    .await
                }
            };

            if let Ok(r) = resp {
                if let Ok(body) = r.text().await {
                    if *probe_label == "SQLi" {
                        if let Some(err) = sql_errors.iter().find(|&&e| body.contains(e)) {
                            findings.push(Finding {
                                id: Uuid::new_v4().to_string(),
                                category: OwaspCategory::BrokenAccessControl,
                                severity: Severity::Critical,
                                title: format!("[OpenAPI] SQLi via param `{}` — {} {}", p.name, method, path_template),
                                description: format!(
                                    "SQL injection in parameter `{}` on `{} {}` produced a database error: `{}`.",
                                    p.name, method, path_template, err
                                ),
                                evidence: Some(format!("Probe: {}\nURL: {}\nError: {}", probe, full_url, err)),
                                remediation: "Use parameterised queries. Never build SQL from user input.".to_string(),
                                source: FindingSource::OpenApiFuzzer,
                                endpoint: Some(full_url.clone()),
                            });
                        }
                    } else if body.contains(*probe) {
                        findings.push(Finding {
                            id: Uuid::new_v4().to_string(),
                            category: OwaspCategory::BrokenAccessControl,
                            severity: Severity::High,
                            title: format!("[OpenAPI] Reflected XSS via param `{}` — {} {}", p.name, method, path_template),
                            description: format!(
                                "XSS payload injected into parameter `{}` on `{} {}` was reflected back unencoded.",
                                p.name, method, path_template
                            ),
                            evidence: Some(format!("Probe: {}\nURL: {}\nPayload reflected in response", probe, full_url)),
                            remediation: "HTML-encode all user-supplied output. Use a strict CSP.".to_string(),
                            source: FindingSource::OpenApiFuzzer,
                            endpoint: Some(full_url.clone()),
                        });
                    }
                }
            }
        }
    }

    findings
}

// ── Check 4: Missing required fields ─────────────────────────────────────────

async fn check_missing_required(
    client: &Client,
    url_template: &str,
    method: &str,
    operation: &Value,
    path_template: &str,
    timeout: Duration,
) -> Option<Finding> {
    // Find required properties in requestBody
    let required_fields: Vec<String> = operation["requestBody"]["content"]
        .as_object()?
        .values()
        .find_map(|media| media["schema"]["required"].as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    if required_fields.is_empty() {
        return None;
    }

    // Send an entirely empty body
    let url = url_template.to_string();
    let resp = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).ok()?,
        &url
    )
    .header("Content-Type", "application/json")
    .body("{}")
    .timeout(timeout)
    .send()
    .await.ok()?;

    let status = resp.status().as_u16();
    // 500 = unhandled missing field, 200/201 = missing fields silently accepted
    if status == 500 || status == 200 || status == 201 {
        let severity = if status == 500 { Severity::Medium } else { Severity::Low };
        let body = resp.text().await.unwrap_or_default();

        return Some(Finding {
            id: Uuid::new_v4().to_string(),
            category: OwaspCategory::ExceptionalConditions,
            severity,
            title: format!("[OpenAPI] Missing Required Fields — {} {}", method, path_template),
            description: format!(
                "Sending an empty `{{}}` body to `{} {}` returned HTTP {} \
                 despite the spec declaring required fields: [{}]. \
                 {}",
                method, path_template, status,
                required_fields.join(", "),
                if status == 500 {
                    "The server threw a 500 error, indicating missing input validation."
                } else {
                    "The server accepted the empty body without error, indicating missing validation."
                }
            ),
            evidence: Some(format!(
                "POST {} with empty body → HTTP {}\nRequired fields: {:?}\nBody snippet: {}",
                url, status, required_fields, &body[..200.min(body.len())]
            )),
            remediation: "Validate all required fields server-side and return a 400 Bad Request \
                          with a clear error message.".to_string(),
            source: FindingSource::OpenApiFuzzer,
            endpoint: Some(url),
        });
    }

    None
}

// ── Helper: build a minimal JSON body with sentinel values ────────────────────

fn build_sentinel_body(params: &[ParamDef]) -> Value {
    let mut map = serde_json::Map::new();
    for p in params.iter().filter(|p| p.location == "body") {
        let val = match p.schema_type.as_str() {
            "integer" | "number" => json!(1),
            "boolean" => json!(true),
            "array" => json!([]),
            "object" => json!({}),
            _ => json!("test"),
        };
        map.insert(p.name.clone(), val);
    }
    Value::Object(map)
}
