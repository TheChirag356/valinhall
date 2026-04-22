//! WAF Mutator — LLM-Powered Payload Bypass via OpenRouter
//!
//! When a security payload is blocked (e.g. WAF returns 403/406), this module
//! sends the original payload *and* the server's response to an LLM on
//! OpenRouter, asking it to suggest bypass variants.  Valinhall then
//! automatically retries with each suggested mutation.
//!
//! # Pipeline
//! ```text
//! 1. Fire original payload  →  Server: 403 WAF Block
//! 2. Send {payload, response} to OpenRouter  →  LLM: ["bypass_1", "bypass_2", ...]
//! 3. Fire each bypass  →  If 200 OK  →  Finding (WAF Bypass Confirmed)
//! 4. If all bypasses fail  →  Finding (WAF Active, Bypass Attempted)
//! ```
//!
//! # Rate limiting
//! A token-bucket rate limiter caps calls to `MAX_LLM_CALLS_PER_MIN` per
//! minute.  Within that budget each call is retried up to `MAX_RETRIES` times
//! on transient errors (429, 500, 502, 503, 504) using exponential back-off
//! with jitter.
//!
//! # Configuration
//! Set `OPENROUTER_API_KEY` environment variable (or pass via [`WafMutatorConfig`]).
//! The default model is `google/gemma-4-31b-it:free` (free tier).  Override
//! with `OPENROUTER_MODEL` env var or the `model` field on [`WafMutatorConfig`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum LLM API calls per minute (token-bucket refill rate)
const MAX_LLM_CALLS_PER_MIN: u32 = 10;
/// Maximum retry attempts for transient API errors
const MAX_RETRIES: u32 = 4;
/// Base delay for exponential back-off (milliseconds)
const BASE_BACKOFF_MS: u64 = 500;
/// Maximum jitter added to back-off (milliseconds)
const MAX_JITTER_MS: u64 = 300;
/// Maximum mutations to request per payload from the LLM
const MAX_MUTATIONS: usize = 5;
/// Status codes that indicate a WAF block
const WAF_BLOCK_STATUSES: &[u16] = &[403, 406, 429, 503];
/// Status codes that indicate a successful bypass
const BYPASS_SUCCESS_STATUSES: &[u16] = &[200, 201, 202, 204, 301, 302, 307];

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the WAF mutator engine
#[derive(Debug, Clone)]
pub struct WafMutatorConfig {
    /// OpenRouter API key.  Defaults to `$OPENROUTER_API_KEY`.
    pub api_key: String,
    /// OpenRouter model identifier.  Default: `google/gemma-4-31b-it:free`.
    /// Override with the `OPENROUTER_MODEL` env var.
    pub model: String,
    /// Maximum mutations to request per blocked payload
    pub max_mutations: usize,
    /// Whether to automatically retry bypass candidates against the target
    pub auto_retry: bool,
}

impl WafMutatorConfig {
    /// Build from environment variables with fallback defaults
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("OPENROUTER_API_KEY")
            .context("OPENROUTER_API_KEY not set — set it to enable WAF bypass mutations")?;
        let model = std::env::var("OPENROUTER_MODEL")
            .unwrap_or_else(|_| "google/gemma-4-31b-it:free".to_string());
        Ok(Self {
            api_key,
            model,
            max_mutations: MAX_MUTATIONS,
            auto_retry: true,
        })
    }
}

// ── Rate Limiter (token bucket) ───────────────────────────────────────────────

/// A simple token-bucket rate limiter for the OpenRouter API
struct RateLimiter {
    tokens: u32,
    max_tokens: u32,
    last_refill: Instant,
    refill_interval: Duration,
}

impl RateLimiter {
    fn new(calls_per_minute: u32) -> Self {
        Self {
            tokens: calls_per_minute,
            max_tokens: calls_per_minute,
            last_refill: Instant::now(),
            refill_interval: Duration::from_secs(60),
        }
    }

    /// Wait until a token is available, then consume it
    async fn acquire(&mut self) {
        loop {
            // Refill if enough time has passed
            let elapsed = self.last_refill.elapsed();
            if elapsed >= self.refill_interval {
                let periods = (elapsed.as_secs_f64() / self.refill_interval.as_secs_f64()) as u32;
                self.tokens = (self.tokens + self.max_tokens * periods).min(self.max_tokens);
                self.last_refill = Instant::now();
            }

            if self.tokens > 0 {
                self.tokens -= 1;
                return;
            }

            // Wait until next refill
            let wait = self.refill_interval - self.last_refill.elapsed();
            debug!(
                "WafMutator rate limiter: out of tokens, waiting {:.1}s",
                wait.as_secs_f64()
            );
            sleep(wait).await;
        }
    }
}

// ── OpenRouter API types ──────────────────────────────────────────────────────

#[derive(Serialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    temperature: f32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize, Debug)]
struct OpenRouterResponse {
    choices: Vec<OpenRouterChoice>,
}

#[derive(Deserialize, Debug)]
struct OpenRouterChoice {
    message: ChatMessage,
}

// ── Blocked Request descriptor ────────────────────────────────────────────────

/// A payload attempt that was blocked by the target
#[derive(Debug, Clone)]
pub struct BlockedAttempt {
    /// The endpoint the payload was sent to
    pub endpoint: String,
    /// HTTP method used ("GET", "POST", etc.)
    pub method: String,
    /// The original payload that was blocked
    pub original_payload: String,
    /// The HTTP status code returned by the server (e.g. 403)
    pub block_status: u16,
    /// The response body from the server (first 2 KB)
    pub response_snippet: String,
    /// The parameter / injection point where the payload was placed
    pub injection_point: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Shared WAF mutator that throttles LLM calls and manages retries.
/// Create one instance and reuse it across probes.
pub struct WafMutator {
    client: Arc<Client>,
    config: WafMutatorConfig,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    concurrency: Arc<Semaphore>,
}

impl WafMutator {
    /// Create a new mutator with a shared HTTP client
    pub fn new(client: Arc<Client>, config: WafMutatorConfig) -> Self {
        Self {
            client,
            config: config.clone(),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(MAX_LLM_CALLS_PER_MIN))),
            // At most 2 concurrent LLM calls (avoids overwhelming the API budget)
            concurrency: Arc::new(Semaphore::new(2)),
        }
    }

    /// Attempt to mutate a blocked payload using the LLM, then retry.
    ///
    /// Returns findings:
    /// - **WAF Bypass Confirmed** if a mutation succeeds
    /// - **WAF Active (Bypass Failed)** if the WAF held for all mutations
    pub async fn mutate_and_retry(&self, attempt: &BlockedAttempt) -> Result<Vec<Finding>> {
        let _permit = self.concurrency.acquire().await.unwrap();

        info!(
            "WafMutator: requesting bypass mutations for payload blocked at {}",
            attempt.endpoint
        );

        // 1. Ask the LLM for bypass suggestions
        let mutations = self
            .get_mutations(attempt)
            .await
            .unwrap_or_else(|e| {
                warn!("WafMutator: LLM call failed: {}", e);
                vec![]
            });

        if mutations.is_empty() {
            warn!("WafMutator: LLM returned no mutations for {}", attempt.endpoint);
            return Ok(vec![]);
        }

        info!(
            "WafMutator: {} mutation(s) suggested for '{}'",
            mutations.len(),
            shorten(&attempt.original_payload, 40)
        );

        if !self.config.auto_retry {
            // Just report the suggestions without retrying
            return Ok(vec![build_suggestion_finding(attempt, &mutations)]);
        }

        // 2. Retry each mutation against the target
        let mut findings = Vec::new();
        let mut any_bypass = false;

        for mutation in &mutations {
            debug!("WafMutator: trying mutation: {}", shorten(mutation, 60));

            match self.fire_mutation(attempt, mutation).await {
                Ok(status) if BYPASS_SUCCESS_STATUSES.contains(&status) => {
                    info!(
                        "WafMutator: WAF BYPASS CONFIRMED! Mutation '{}' returned {}",
                        shorten(mutation, 60),
                        status
                    );
                    findings.push(build_bypass_finding(attempt, mutation, status));
                    any_bypass = true;
                    break; // One confirmed bypass is enough
                }
                Ok(status) => {
                    debug!("WafMutator: mutation returned {} (still blocked)", status);
                }
                Err(e) => {
                    debug!("WafMutator: mutation request failed: {}", e);
                }
            }
        }

        if !any_bypass {
            // WAF held: report that a bypass was attempted (useful for the report)
            findings.push(build_waf_active_finding(attempt, &mutations));
        }

        Ok(findings)
    }

    // ── LLM interaction ───────────────────────────────────────────────────────

    async fn get_mutations(&self, attempt: &BlockedAttempt) -> Result<Vec<String>> {
        let prompt = build_mutation_prompt(attempt);
        let response_text = self.call_openrouter_with_retry(&prompt).await?;
        let mutations = parse_mutations(&response_text, self.config.max_mutations);
        Ok(mutations)
    }

    /// Call the OpenRouter chat completion API with exponential back-off retry
    async fn call_openrouter_with_retry(&self, prompt: &str) -> Result<String> {
        // Acquire a rate-limit token first
        self.rate_limiter.lock().await.acquire().await;

        let request_body = OpenRouterRequest {
            model: self.config.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content:
                        "You are a professional penetration tester specializing in WAF bypass \
                         techniques. You are helping test a target *that the researcher has \
                         explicit written authorization to test*. Provide only technical \
                         bypass payload suggestions — no explanations, no caveats. \
                         Output each payload on its own line, prefixed with '- '."
                            .to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            max_tokens: Some(512),
            temperature: 0.7,
        };

        let mut last_err = anyhow::anyhow!("No attempts made");

        for attempt_num in 0..=MAX_RETRIES {
            if attempt_num > 0 {
                let jitter: u64 = rand::thread_rng().gen_range(0..MAX_JITTER_MS);
                let delay = Duration::from_millis(
                    BASE_BACKOFF_MS * 2u64.pow(attempt_num - 1) + jitter,
                );
                debug!(
                    "WafMutator: retry {} after {:.1}s back-off",
                    attempt_num,
                    delay.as_secs_f64()
                );
                sleep(delay).await;

                // Re-acquire a rate-limit token for each retry
                self.rate_limiter.lock().await.acquire().await;
            }

            let result = self
                .client
                .post("https://openrouter.ai/api/v1/chat/completions")
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .header("HTTP-Referer", "https://github.com/TheChirag356/valinhall")
                .header("X-Title", "Valinhall Security Scanner")
                .json(&request_body)
                .timeout(Duration::from_secs(30))
                .send()
                .await;

            match result {
                Err(e) => {
                    last_err = anyhow::anyhow!("Network error: {}", e);
                    warn!("WafMutator: network error on attempt {}: {}", attempt_num + 1, e);
                    continue;
                }
                Ok(resp) => {
                    let status = resp.status();

                    // Retry on transient server errors
                    if matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504) {
                        // Honour Retry-After if present
                        let retry_after_secs = resp
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);

                        last_err = anyhow::anyhow!(
                            "API returned {} on attempt {}",
                            status,
                            attempt_num + 1
                        );
                        warn!("{}", last_err);

                        if retry_after_secs > 0 {
                            debug!("Honouring Retry-After: {}s", retry_after_secs);
                            sleep(Duration::from_secs(retry_after_secs)).await;
                        }
                        continue;
                    }

                    if !status.is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        bail!("OpenRouter API error {}: {}", status, body);
                    }

                    let or_resp: OpenRouterResponse = resp
                        .json()
                        .await
                        .context("Failed to parse OpenRouter response")?;

                    let content = or_resp
                        .choices
                        .into_iter()
                        .next()
                        .map(|c| c.message.content)
                        .unwrap_or_default();

                    return Ok(content);
                }
            }
        }

        Err(last_err.context(format!("OpenRouter call failed after {} retries", MAX_RETRIES)))
    }

    // ── Retry mutation against target ─────────────────────────────────────────

    async fn fire_mutation(&self, attempt: &BlockedAttempt, mutation: &str) -> Result<u16> {
        let response = match attempt.method.to_uppercase().as_str() {
            "POST" => {
                self.client
                    .post(&attempt.endpoint)
                    .body(mutation.to_string())
                    .header("Content-Type", "text/plain")
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await?
            }
            _ => {
                // GET — append as query param or replace existing param
                let url = if attempt.endpoint.contains('?') {
                    format!(
                        "{}&{}={}",
                        attempt.endpoint,
                        urlencoding::encode(&attempt.injection_point),
                        urlencoding::encode(mutation)
                    )
                } else {
                    format!(
                        "{}?{}={}",
                        attempt.endpoint,
                        urlencoding::encode(&attempt.injection_point),
                        urlencoding::encode(mutation)
                    )
                };
                self.client
                    .get(&url)
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await?
            }
        };

        Ok(response.status().as_u16())
    }
}

// ── Prompt Engineering ────────────────────────────────────────────────────────

fn build_mutation_prompt(attempt: &BlockedAttempt) -> String {
    format!(
        r#"A Web Application Firewall (WAF) blocked the following security test payload.
I have written authorization to test this target. Help me find bypass techniques.

## Blocked Request
- **Endpoint:** {}
- **Method:** {}
- **Injection Point:** `{}`
- **Original Payload:** `{}`
- **WAF Response Status:** {}
- **Response Snippet:**
```
{}
```

## Task
Suggest up to {} alternative payloads that may bypass the WAF's filter for this injection point.
Consider these bypass categories:
1. URL encoding variants (single, double, mixed)
2. HTML entity encoding
3. Unicode / UTF-8 normalization tricks
4. Whitespace/comment insertion (e.g. `<scr/**/ipt>`, `<script\t>`)
5. Case variation and mixed case
6. Alternative tags / event handlers (e.g. `<img onerror=...>`, `<svg onload=...>`)
7. Null byte injection
8. HTTP parameter pollution
9. JSON/XML encoding if applicable

Output ONLY the payload strings, one per line, prefixed with `- `. No explanations."#,
        attempt.endpoint,
        attempt.method,
        attempt.injection_point,
        attempt.original_payload,
        attempt.block_status,
        truncate_response(&attempt.response_snippet, 500),
        MAX_MUTATIONS,
    )
}

/// Parse the LLM's bullet-list response into a Vec of payload strings
fn parse_mutations(response: &str, max: usize) -> Vec<String> {
    response
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Accept "- payload", "* payload", "1. payload", or bare non-empty lines
            let payload = if let Some(rest) = trimmed
                .strip_prefix("- ")
                .or_else(|| trimmed.strip_prefix("* "))
            {
                rest.trim()
            } else if trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                trimmed
                    .splitn(2, ". ")
                    .nth(1)
                    .map(|s| s.trim())
                    .unwrap_or("")
            } else {
                trimmed
            };

            if payload.is_empty() || payload.starts_with('#') || payload.starts_with("```") {
                None
            } else {
                Some(payload.to_string())
            }
        })
        .take(max)
        .collect()
}

// ── Finding Builders ──────────────────────────────────────────────────────────

fn build_bypass_finding(attempt: &BlockedAttempt, mutation: &str, bypass_status: u16) -> Finding {
    Finding {
        id: Uuid::new_v4().to_string(),
        category: OwaspCategory::BrokenAccessControl,
        severity: Severity::High,
        title: format!(
            "[WAF Bypass] Injection Succeeded After Mutation at {}",
            attempt.endpoint
        ),
        description: format!(
            "A WAF bypass was confirmed at `{}`.\n\n\
             The original payload `{}` was blocked (HTTP {}).\n\
             After LLM-suggested mutation, the payload `{}` was accepted (HTTP {}).\n\n\
             This indicates the WAF's ruleset has a gap that can be exploited.",
            attempt.endpoint,
            attempt.original_payload,
            attempt.block_status,
            mutation,
            bypass_status
        ),
        evidence: Some(format!(
            "Original payload: {}\nOriginal status: {}\nBypass payload: {}\nBypass status: {}",
            attempt.original_payload, attempt.block_status, mutation, bypass_status
        )),
        remediation: format!(
            "Update WAF rules to block the mutation `{}`. \
             Consider using a semantics-aware WAF, not just pattern-matching. \
             Validate and sanitize input server-side regardless of WAF status.",
            mutation
        ),
        source: FindingSource::WafMutator,
        endpoint: Some(attempt.endpoint.clone()),
    }
}

fn build_waf_active_finding(attempt: &BlockedAttempt, mutations: &[String]) -> Finding {
    let mutation_list = mutations
        .iter()
        .enumerate()
        .map(|(i, m)| format!("  {}. {}", i + 1, m))
        .collect::<Vec<_>>()
        .join("\n");

    Finding {
        id: Uuid::new_v4().to_string(),
        category: OwaspCategory::SecurityMisconfiguration,
        severity: Severity::Info,
        title: format!("[WAF] Active Protection Confirmed at {}", attempt.endpoint),
        description: format!(
            "A WAF successfully blocked all {} LLM-suggested mutation(s) for the payload \
             `{}` at `{}`.\n\n\
             **Attempted mutations:**\n{}\n\n\
             The WAF appears robust against common bypass techniques for this payload type.",
            mutations.len(),
            attempt.original_payload,
            attempt.endpoint,
            mutation_list
        ),
        evidence: Some(format!(
            "Original payload: {}\nBlock status: {}\nMutations tried: {}",
            attempt.original_payload,
            attempt.block_status,
            mutations.len()
        )),
        remediation:
            "WAF appears effective. Continue monitoring for novel bypass techniques. \
             Ensure server-side validation is also in place as a defence-in-depth measure."
                .to_string(),
        source: FindingSource::WafMutator,
        endpoint: Some(attempt.endpoint.clone()),
    }
}

fn build_suggestion_finding(attempt: &BlockedAttempt, mutations: &[String]) -> Finding {
    let mutation_list = mutations
        .iter()
        .enumerate()
        .map(|(i, m)| format!("  {}. {}", i + 1, m))
        .collect::<Vec<_>>()
        .join("\n");

    Finding {
        id: Uuid::new_v4().to_string(),
        category: OwaspCategory::SecurityMisconfiguration,
        severity: Severity::Medium,
        title: format!(
            "[WAF] Bypass Suggestions Generated for {}",
            attempt.endpoint
        ),
        description: format!(
            "The payload `{}` was blocked at `{}` (HTTP {}). \
             The LLM suggested the following bypass candidates \
             (auto-retry was disabled — test manually):\n\n{}",
            attempt.original_payload, attempt.endpoint, attempt.block_status, mutation_list
        ),
        evidence: Some(format!(
            "Original payload blocked with status {}. {} mutations suggested.",
            attempt.block_status,
            mutations.len()
        )),
        remediation:
            "Test each suggested mutation manually. If any succeeds, the WAF ruleset is \
             incomplete and must be updated."
                .to_string(),
        source: FindingSource::WafMutator,
        endpoint: Some(attempt.endpoint.clone()),
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

fn shorten(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

fn truncate_response(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mutations_bullet_list() {
        let llm_output = r#"
Here are some bypass suggestions:
- <ScRiPt>alert(1)</ScRiPt>
- <img src=x onerror=alert(1)>
- %3Cscript%3Ealert(1)%3C%2Fscript%3E
- <svg onload=alert(1)>
- <script\u0009>alert(1)</script>
"#;
        let mutations = parse_mutations(llm_output, 10);
        assert_eq!(mutations.len(), 5);
        assert!(mutations[0].contains("ScRiPt"));
        assert!(mutations[1].contains("onerror"));
    }

    #[test]
    fn test_parse_mutations_numbered() {
        let llm_output = "1. payload_one\n2. payload_two\n3. payload_three";
        let mutations = parse_mutations(llm_output, 10);
        assert_eq!(mutations.len(), 3);
        assert_eq!(mutations[0], "payload_one");
    }

    #[test]
    fn test_parse_mutations_max_limit() {
        let llm_output = (1..=20)
            .map(|i| format!("- mutation_{}", i))
            .collect::<Vec<_>>()
            .join("\n");
        let mutations = parse_mutations(&llm_output, 5);
        assert_eq!(mutations.len(), 5);
    }

    #[test]
    fn test_rate_limiter_refills() {
        // Just verify the struct initialises without panicking
        let rl = RateLimiter::new(10);
        assert_eq!(rl.tokens, 10);
        assert_eq!(rl.max_tokens, 10);
    }
}
