//! Nuclei Template Engine
//!
//! Parses a directory of Nuclei-compatible YAML templates and executes the
//! corresponding HTTP requests against the target.  Supports:
//!
//!   - Multiple `requests` blocks per template
//!   - `matchers` (word, status, regex) combined with `matcher-condition`
//!   - `extractors` (word, regex) — captured groups emitted as evidence
//!   - `severity` / `tags` / `cve` metadata
//!
//! Templates are loaded lazily: the runner only parses files whose `tags`
//! contain at least one of the user-supplied tag filters (or all templates
//! when no filter is given).
//!
//! # Template directory
//! By default the runner looks for templates in `~/.valinhall/nuclei-templates/`.
//! Pass `--nuclei-templates <path>` on the CLI to override.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;
use reqwest::{Client, Method, RequestBuilder};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── Nuclei YAML schema ────────────────────────────────────────────────────────

/// Top-level Nuclei template
#[derive(Debug, Deserialize)]
pub struct NucleiTemplate {
    pub id: String,
    pub info: NucleiInfo,
    #[serde(default)]
    pub requests: Vec<NucleiRequest>,
    /// Nuclei v2 uses `http:` as an alias for `requests:`
    #[serde(default)]
    pub http: Vec<NucleiRequest>,
}

impl NucleiTemplate {
    /// Unified view of HTTP request blocks regardless of key name
    pub fn http_requests(&self) -> &[NucleiRequest] {
        if !self.requests.is_empty() {
            &self.requests
        } else {
            &self.http
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NucleiInfo {
    pub name: String,
    #[serde(default)]
    pub author: Vec<String>,
    #[serde(default)]
    pub severity: NucleiSeverity,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub reference: Vec<String>,
    /// CVE identifier (e.g. "CVE-2021-44228")
    #[serde(default)]
    pub classification: Option<NucleiClassification>,
}

#[derive(Debug, Deserialize, Default)]
pub struct NucleiClassification {
    #[serde(rename = "cve-id", default)]
    pub cve_id: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NucleiSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    #[default]
    Unknown,
}

impl NucleiSeverity {
    fn to_model_severity(&self) -> Severity {
        match self {
            Self::Critical => Severity::Critical,
            Self::High => Severity::High,
            Self::Medium => Severity::Medium,
            Self::Low => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NucleiRequest {
    #[serde(default = "default_method")]
    pub method: String,
    /// Paths relative to the base URL; may contain `{{BaseURL}}` markers
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub matchers: Vec<NucleiMatcher>,
    /// "and" or "or" (default "or")
    #[serde(rename = "matcher-condition", default = "default_condition")]
    pub matcher_condition: String,
    #[serde(default)]
    pub extractors: Vec<NucleiExtractor>,
    /// Follow redirects
    #[serde(default = "default_true")]
    pub redirects: bool,
    /// Maximum redirects
    #[serde(rename = "max-redirects", default = "default_redirects")]
    pub max_redirects: u32,
}

fn default_method() -> String {
    "GET".to_string()
}
fn default_condition() -> String {
    "or".to_string()
}
fn default_true() -> bool {
    true
}
fn default_redirects() -> u32 {
    10
}

#[derive(Debug, Deserialize)]
pub struct NucleiMatcher {
    #[serde(rename = "type")]
    pub matcher_type: String,
    /// For `word` matchers: list of strings to find in response
    #[serde(default)]
    pub words: Vec<String>,
    /// For `regex` matchers
    #[serde(default)]
    pub regex: Vec<String>,
    /// For `status` matchers
    #[serde(default)]
    pub status: Vec<u16>,
    /// Where to apply the match: "body" | "header" | "all" (default "body")
    #[serde(default = "default_part")]
    pub part: String,
    /// If true all words/regexes must match (AND within matcher)
    #[serde(default)]
    pub condition: Option<String>,
    /// Negate: match when pattern does NOT appear
    #[serde(default)]
    pub negative: bool,
}

fn default_part() -> String {
    "body".to_string()
}

#[derive(Debug, Deserialize)]
pub struct NucleiExtractor {
    #[serde(rename = "type")]
    pub extractor_type: String,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default = "default_part")]
    pub part: String,
    #[serde(default)]
    pub group: usize,
    #[serde(default)]
    pub name: Option<String>,
}

// ── Runner Configuration ──────────────────────────────────────────────────────

/// Configuration for the Nuclei template runner
pub struct NucleiRunnerConfig {
    /// Base URL to scan, e.g. `https://example.com`
    pub target: String,
    /// Directory containing `*.yaml` / `*.yml` template files
    pub templates_dir: PathBuf,
    /// Only run templates whose `tags` overlap with this set (empty = run all)
    pub tag_filter: Vec<String>,
    /// Max concurrent HTTP requests
    pub concurrency: usize,
    /// Per-request timeout
    pub timeout: Duration,
}

impl NucleiRunnerConfig {
    /// Resolve the default template directory: `~/.valinhall/nuclei-templates`
    pub fn default_templates_dir() -> PathBuf {
        dirs_home()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".valinhall")
            .join("nuclei-templates")
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Load all templates from `config.templates_dir`, filter by tags, and execute
/// each request block against `config.target`.
pub async fn run(config: &NucleiRunnerConfig) -> Result<Vec<Finding>> {
    let templates = load_templates(&config.templates_dir, &config.tag_filter)?;
    info!(
        "Nuclei engine: loaded {} template(s) from {:?}",
        templates.len(),
        config.templates_dir
    );

    if templates.is_empty() {
        warn!(
            "No Nuclei templates found in {:?}. \
             Download community templates with: \
             git clone https://github.com/projectdiscovery/nuclei-templates ~/.valinhall/nuclei-templates",
            config.templates_dir
        );
        return Ok(vec![]);
    }

    let client = Arc::new(
        Client::builder()
            .timeout(config.timeout)
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent("Valinhall/Nuclei-Runner 0.1")
            .build()
            .context("Failed to build HTTP client for Nuclei runner")?,
    );

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut findings = Vec::new();

    for template in &templates {
        let template_findings = execute_template(
            Arc::clone(&client),
            Arc::clone(&semaphore),
            template,
            &config.target,
        )
        .await;

        match template_findings {
            Ok(f) => findings.extend(f),
            Err(e) => warn!("Template '{}' execution error: {}", template.id, e),
        }
    }

    info!("Nuclei engine: {} finding(s)", findings.len());
    Ok(findings)
}

// ── Template Loading ──────────────────────────────────────────────────────────

fn load_templates(dir: &Path, tag_filter: &[String]) -> Result<Vec<NucleiTemplate>> {
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut templates = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }

        match load_template(path) {
            Ok(tpl) => {
                if should_include(&tpl, tag_filter) {
                    templates.push(tpl);
                }
            }
            Err(e) => debug!("Skipping {:?}: {}", path, e),
        }
    }

    Ok(templates)
}

fn load_template(path: &Path) -> Result<NucleiTemplate> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read template {:?}", path))?;
    let tpl: NucleiTemplate = serde_yaml::from_str(&content)
        .with_context(|| format!("Cannot parse template {:?}", path))?;
    Ok(tpl)
}

fn should_include(tpl: &NucleiTemplate, tag_filter: &[String]) -> bool {
    if tag_filter.is_empty() {
        return true;
    }
    tpl.info
        .tags
        .iter()
        .any(|t| tag_filter.iter().any(|f| f.eq_ignore_ascii_case(t)))
}

// ── Template Execution ────────────────────────────────────────────────────────

async fn execute_template(
    client: Arc<Client>,
    semaphore: Arc<Semaphore>,
    template: &NucleiTemplate,
    base_url: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let base = base_url.trim_end_matches('/');

    for request_block in template.http_requests() {
        for raw_path in &request_block.path {
            let url = interpolate_url(base, raw_path);
            let _permit = semaphore.acquire().await.unwrap();

            // Build the request
            let method = Method::from_bytes(request_block.method.to_uppercase().as_bytes())
                .unwrap_or(Method::GET);

            let mut rb: RequestBuilder = client.request(method, &url);

            // Attach custom headers
            for (k, v) in &request_block.headers {
                rb = rb.header(k.as_str(), v.as_str());
            }

            // Attach body
            if let Some(body) = &request_block.body {
                rb = rb.body(body.clone());
            }

            // Execute
            let response = match rb.send().await {
                Ok(r) => r,
                Err(e) => {
                    debug!("Template '{}' → {} failed: {}", template.id, url, e);
                    continue;
                }
            };

            let status = response.status().as_u16();
            let resp_headers = response.headers().clone();
            let body_bytes = response.bytes().await.unwrap_or_default();
            let body_text = String::from_utf8_lossy(&body_bytes).to_string();

            // Build the search corpus for parts
            let header_text: String = resp_headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");

            let all_text = format!("{}\n\n{}", header_text, body_text);

            // Evaluate matchers
            let matched = evaluate_matchers(
                &request_block.matchers,
                &request_block.matcher_condition,
                status,
                &body_text,
                &header_text,
                &all_text,
            );

            if matched {
                // Run extractors to capture evidence snippets
                let extracted = run_extractors(&request_block.extractors, &body_text, &header_text, &all_text);

                let cve = template
                    .info
                    .classification
                    .as_ref()
                    .and_then(|c| c.cve_id.first())
                    .cloned();

                let evidence_parts: Vec<String> = extracted
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();

                let evidence = if evidence_parts.is_empty() {
                    Some(format!(
                        "{} {} → HTTP {}\nMatched template: {}",
                        request_block.method, url, status, template.id
                    ))
                } else {
                    Some(format!(
                        "{} {} → HTTP {}\nTemplate: {}\nExtracted: {}",
                        request_block.method,
                        url,
                        status,
                        template.id,
                        evidence_parts.join(", ")
                    ))
                };

                let description = template
                    .info
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Matched Nuclei template: {}", template.id));

                let references = template.info.reference.join(", ");
                let remediation = if references.is_empty() {
                    "Review the referenced Nuclei template for remediation guidance.".to_string()
                } else {
                    format!("References: {}", references)
                };

                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: cve_to_owasp(cve.as_deref()),
                    severity: template.info.severity.to_model_severity(),
                    title: format!("[Nuclei] {}", template.info.name),
                    description,
                    evidence,
                    remediation,
                    source: FindingSource::Nuclei,
                    endpoint: Some(url),
                });
            }
        }
    }

    Ok(findings)
}

// ── URL Interpolation ─────────────────────────────────────────────────────────

fn interpolate_url(base: &str, path: &str) -> String {
    // Replace common Nuclei variables
    let p = path
        .replace("{{BaseURL}}", base)
        .replace("{{RootURL}}", base);

    if p.starts_with("http://") || p.starts_with("https://") {
        p
    } else {
        format!("{}/{}", base, p.trim_start_matches('/'))
    }
}

// ── Matcher Evaluation ────────────────────────────────────────────────────────

fn evaluate_matchers(
    matchers: &[NucleiMatcher],
    condition: &str,
    status: u16,
    body: &str,
    headers: &str,
    all: &str,
) -> bool {
    if matchers.is_empty() {
        return false;
    }

    let results: Vec<bool> = matchers
        .iter()
        .map(|m| eval_single_matcher(m, status, body, headers, all))
        .collect();

    let matched = if condition.eq_ignore_ascii_case("and") {
        results.iter().all(|&b| b)
    } else {
        // default "or"
        results.iter().any(|&b| b)
    };

    matched
}

fn eval_single_matcher(
    m: &NucleiMatcher,
    status: u16,
    body: &str,
    headers: &str,
    all: &str,
) -> bool {
    // Choose the corpus based on `part`
    let corpus = match m.part.as_str() {
        "header" | "headers" => headers,
        "all" => all,
        _ => body,
    };

    let raw_result = match m.matcher_type.as_str() {
        "status" => m.status.contains(&status),
        "word" => {
            let inner_cond = m.condition.as_deref().unwrap_or("or");
            if inner_cond.eq_ignore_ascii_case("and") {
                m.words.iter().all(|w| corpus.contains(w.as_str()))
            } else {
                m.words.iter().any(|w| corpus.contains(w.as_str()))
            }
        }
        "regex" => {
            let inner_cond = m.condition.as_deref().unwrap_or("or");
            let matches: Vec<bool> = m
                .regex
                .iter()
                .map(|pat| {
                    Regex::new(pat)
                        .map(|re| re.is_match(corpus))
                        .unwrap_or(false)
                })
                .collect();
            if inner_cond.eq_ignore_ascii_case("and") {
                matches.iter().all(|&b| b)
            } else {
                matches.iter().any(|&b| b)
            }
        }
        other => {
            debug!("Unsupported matcher type '{}', treating as false", other);
            false
        }
    };

    // Apply negation
    if m.negative {
        !raw_result
    } else {
        raw_result
    }
}

// ── Extractor ────────────────────────────────────────────────────────────────

fn run_extractors(
    extractors: &[NucleiExtractor],
    body: &str,
    headers: &str,
    all: &str,
) -> Vec<(String, String)> {
    let mut results = Vec::new();

    for ext in extractors {
        let corpus = match ext.part.as_str() {
            "header" | "headers" => headers,
            "all" => all,
            _ => body,
        };

        let key = ext
            .name
            .clone()
            .unwrap_or_else(|| ext.extractor_type.clone());

        match ext.extractor_type.as_str() {
            "regex" => {
                for pat in &ext.regex {
                    if let Ok(re) = Regex::new(pat) {
                        if let Some(captures) = re.captures(corpus) {
                            let value = captures
                                .get(ext.group)
                                .map(|m| m.as_str())
                                .unwrap_or_else(|| captures.get(0).map(|m| m.as_str()).unwrap_or(""))
                                .to_string();
                            if !value.is_empty() {
                                results.push((key.clone(), value));
                            }
                        }
                    }
                }
            }
            "word" => {
                for word in &ext.words {
                    if corpus.contains(word.as_str()) {
                        results.push((key.clone(), word.clone()));
                    }
                }
            }
            _ => {}
        }
    }

    results
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn cve_to_owasp(cve: Option<&str>) -> OwaspCategory {
    // Without deeper analysis we map all CVE-linked findings to VulnerableComponents
    match cve {
        Some(_) => OwaspCategory::VulnerableComponents,
        None => OwaspCategory::SecurityMisconfiguration,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TEMPLATE: &str = r#"
id: test-xss-probe
info:
  name: "Reflected XSS Probe"
  author:
    - valinhall-tests
  severity: high
  description: "Checks for reflected XSS in the query string."
  tags:
    - xss
    - test
requests:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
        part: body
      - type: status
        status:
          - 200
    matcher-condition: and
"#;

    #[test]
    fn test_parse_sample_template() {
        let tpl: NucleiTemplate = serde_yaml::from_str(SAMPLE_TEMPLATE).unwrap();
        assert_eq!(tpl.id, "test-xss-probe");
        assert_eq!(tpl.info.severity, NucleiSeverity::High);
        assert_eq!(tpl.http_requests().len(), 1);
        assert_eq!(tpl.http_requests()[0].matchers.len(), 2);
    }

    #[test]
    fn test_url_interpolation() {
        let base = "https://example.com";
        let url = interpolate_url(base, "{{BaseURL}}/admin");
        assert_eq!(url, "https://example.com/admin");
    }

    #[test]
    fn test_word_matcher() {
        let matcher = NucleiMatcher {
            matcher_type: "word".into(),
            words: vec!["secret".into()],
            regex: vec![],
            status: vec![],
            part: "body".into(),
            condition: None,
            negative: false,
        };
        assert!(eval_single_matcher(&matcher, 200, "here is a secret value", "", ""));
        assert!(!eval_single_matcher(&matcher, 200, "nothing here", "", ""));
    }

    #[test]
    fn test_status_matcher() {
        let matcher = NucleiMatcher {
            matcher_type: "status".into(),
            words: vec![],
            regex: vec![],
            status: vec![200, 201],
            part: "body".into(),
            condition: None,
            negative: false,
        };
        assert!(eval_single_matcher(&matcher, 200, "", "", ""));
        assert!(!eval_single_matcher(&matcher, 404, "", "", ""));
    }

    #[test]
    fn test_negated_matcher() {
        let matcher = NucleiMatcher {
            matcher_type: "word".into(),
            words: vec!["WAF".into()],
            regex: vec![],
            status: vec![],
            part: "body".into(),
            condition: None,
            negative: true, // We want the word to NOT be present
        };
        // Word absent → raw=false → !false = true
        assert!(eval_single_matcher(&matcher, 200, "Normal response body", "", ""));
        // Word present → raw=true → !true = false
        assert!(!eval_single_matcher(&matcher, 403, "Blocked by WAF", "", ""));
    }
}
