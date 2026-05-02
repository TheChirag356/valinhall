use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::time::Duration;
use tracing::warn;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct ResponseFormat {
    #[serde(rename = "type")]
    pub format_type: String,
}

#[derive(Serialize)]
struct LlmPayload {
    model: String,
    /// OpenAI-compatible chat completions API (Groq, OpenAI, etc.) uses 'messages'
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
    temperature: f32,
}

#[derive(Clone)]
pub struct LlmClient {
    client: Client,
    api_key: String,
    model: String,
}

impl LlmClient {
    pub fn new() -> Result<Self> {
        let api_key = env::var("LLM_API_KEY")
            .context("LLM_API_KEY not set - needed for LLM functionality")?;

        let model = env::var("LLM_MODEL").unwrap_or_else(|_| "llama-3.3-70b-versatile".to_string());

        Ok(Self {
            client: Client::new(),
            api_key,
            model,
        })
    }

    /// Issue a chat completion using the xAI responses API.
    /// Includes robust exponential backoff retry logic.
    pub async fn chat_completion(
        &self,
        messages: &[ChatMessage],
        json_mode: bool,
    ) -> Result<String> {
        let request_body = LlmPayload {
            model: self.model.clone(),
            messages: messages.to_vec(),
            response_format: if json_mode {
                Some(ResponseFormat {
                    format_type: "json_object".to_string(),
                })
            } else {
                None
            },
            temperature: 0.7,
        };

        let mut attempt = 0;
        let max_retries = 5;
        let mut last_error = String::new();

        loop {
            let resp_result = self
                .client
                .post("https://api.groq.com/openai/v1/chat/completions")
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .header("X-Title", "Valinhall Security Scanner")
                .json(&request_body)
                .timeout(Duration::from_secs(30))
                .send()
                .await;

            match resp_result {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let text = resp.text().await?;
                        let v: Value =
                            serde_json::from_str(&text).context("error decoding response body")?;

                        // Try to extract from x.ai's /v1/responses output
                        // x.ai /v1/responses generally returns "output_text" or "choices[0].message.content"
                        // Let's support both formats to be safe
                        if let Some(output) = v.get("output_text").and_then(|s| s.as_str()) {
                            return Ok(output.to_string());
                        } else if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
                            if let Some(first_choice) = choices.get(0) {
                                if let Some(message) = first_choice.get("message") {
                                    if let Some(content) =
                                        message.get("content").and_then(|c| c.as_str())
                                    {
                                        return Ok(content.to_string());
                                    }
                                }
                            }
                        }

                        bail!(
                            "Failed to parse content from LLM response. Raw response: {}",
                            text
                        );
                    } else if resp.status() == 429 || resp.status().is_server_error() {
                        last_error = resp.text().await.unwrap_or_default();
                    } else {
                        let error_text = resp.text().await.unwrap_or_default();
                        bail!("LLM API error (fatal): {}", error_text);
                    }
                }
                Err(e) => {
                    last_error = e.to_string();
                }
            }

            attempt += 1;
            if attempt > max_retries {
                bail!(
                    "LLM API failed after {} retries. Last error: {}",
                    max_retries,
                    last_error
                );
            }

            let backoff = Duration::from_secs(2u64.pow(attempt));
            warn!(
                "LlmClient: API rate limited or failed. Retrying {}/{} in {}s...",
                attempt,
                max_retries,
                backoff.as_secs()
            );
            tokio::time::sleep(backoff).await;
        }
    }
}
