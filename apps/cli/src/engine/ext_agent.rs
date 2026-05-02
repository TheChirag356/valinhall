use anyhow::Result;
use serde_json::Value;

use crate::engine::llm::{LlmClient, ChatMessage};

pub struct ExtAgent {
    llm_client: LlmClient,
    pub conversation_history: Vec<ChatMessage>,
}

impl ExtAgent {
    /// Create a new ExtAgent.
    /// `instructions` is optional user-supplied guidance that is appended to the system prompt.
    pub fn new(instructions: Option<&str>) -> Result<Self> {
        let instructions_block = if let Some(instr) = instructions.filter(|s| !s.trim().is_empty()) {
            format!("\n\n## User instructions\n{}", instr)
        } else {
            String::new()
        };

        let system_prompt = format!(
            r#"You are an automated security testing agent operating a browser extension.
Your goal is to test the target application for vulnerabilities, including traditional web exploits and AI prompt fuzzing/guardrail testing.
You will receive context about the DOM (forms, text snippets, elements) and the results of previously executed actions.

You must respond with a JSON object that contains an **array** of actions to execute in sequence.
Batching multiple actions in a single response greatly reduces the number of round-trips and is strongly preferred.
Plan ahead: if you know a flow requires fill → submit → inspect, put all of those in one batch.

Available actions:
1. FILL_FORM
   Payload: {{ "value": "<payload_string>" }}
   Fills all visible text/textarea/input fields with the given value.

2. SUBMIT_FORM
   Payload: {{}}
   Submits the currently active form.

3. INJECT_PAYLOAD
   Payload: {{ "selector": "<css_selector>", "value": "<payload_string>" }}
   Sets the value of a specific DOM element.

4. CLICK_ELEMENT
   Payload: {{ "selector": "<css_selector>" }}
   Clicks a specific DOM element.

5. GET_PAGE_TEXT
   Payload: {{}}
   Returns the full visible text of the current page so you can read responses, passwords, etc.

6. NAVIGATE
   Payload: {{ "url": "<url>" }}
   Navigates the browser to the given URL.

7. DONE
   Payload: {{ "summary": "<findings_summary>" }}
   Signals that all testing is complete. Include a full summary of what was found.

Your response MUST be a valid JSON object matching this schema exactly:
{{
  "actions": [
    {{ "action": "<ACTION_NAME>", "payload": {{ ... }} }},
    ...
  ]
}}

Rules:
- Always return at least one action.
- End every complete testing sequence with a DONE action.
- Do NOT include markdown fences or any text outside the JSON object.
- After receiving GET_PAGE_TEXT results, use that information to decide the next steps.{instructions_block}
"#
        );

        let conversation_history = vec![ChatMessage {
            role: "system".to_string(),
            content: system_prompt,
        }];

        Ok(Self {
            llm_client: LlmClient::new()?,
            conversation_history,
        })
    }

    /// Ask the LLM for the next batch of actions given a user-provided context prompt.
    /// Returns a `Vec<Value>` where each element is `{"action": "...", "payload": {...}}`.
    pub async fn get_next_actions(&mut self, user_prompt: String) -> Result<Vec<Value>> {
        self.conversation_history.push(ChatMessage {
            role: "user".to_string(),
            content: user_prompt,
        });

        let content = self
            .llm_client
            .chat_completion(&self.conversation_history, true)
            .await?;

        self.conversation_history.push(ChatMessage {
            role: "assistant".to_string(),
            content: content.clone(),
        });

        // Strip optional markdown fences
        let mut json_str = content.as_str();
        if let Some(start) = json_str.find("```json") {
            if let Some(end) = json_str[start + 7..].find("```") {
                json_str = &json_str[start + 7..start + 7 + end];
            }
        } else if let Some(start) = json_str.find("```") {
            if let Some(end) = json_str[start + 3..].find("```") {
                json_str = &json_str[start + 3..start + 3 + end];
            }
        }

        let parsed: Value = match serde_json::from_str(json_str.trim()) {
            Ok(v) => v,
            Err(e) => anyhow::bail!(
                "Failed to parse LLM response as JSON. Error: {}. Response: {}",
                e,
                content
            ),
        };

        // Support both {"actions":[...]} and legacy {"action":..., "payload":...}
        let actions = if let Some(arr) = parsed.get("actions").and_then(|v| v.as_array()) {
            arr.clone()
        } else if parsed.get("action").is_some() {
            // Graceful fallback: wrap single-action response
            vec![parsed]
        } else {
            anyhow::bail!("LLM response missing 'actions' array. Response: {}", content)
        };

        Ok(actions)
    }
}
