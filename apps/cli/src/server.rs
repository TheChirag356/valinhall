//! Embedded HTTP server for live dashboard integration (--serve mode)
//!
//! Provides:
//!   GET /api/status  — current scan state
//!   GET /api/events  — SSE stream of live scan findings
//!   GET /api/results — completed ScanResult JSON

use anyhow::Result;
use axum::{
    extract::{State, ws::{WebSocketUpgrade, WebSocket, Message}},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response, Sse},
    routing::get,
    Json, Router,
};
use futures::stream::{self, Stream};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use colored::Colorize;

use crate::models::ScanResult;

#[derive(Clone)]
struct AppState {
    result: Arc<RwLock<Option<ScanResult>>>,
    status: Arc<RwLock<ServerStatus>>,
    /// Optional user-supplied task instructions forwarded to the agent.
    instructions: Arc<String>,
}

#[derive(Clone, serde::Serialize)]
pub struct ServerStatus {
    pub state: String, // "idle" | "scanning" | "complete" | "error"
    pub progress: u8,
    pub target: Option<String>,
}

/// Start the embedded HTTP + WebSocket server.
///
/// * `port`         — TCP port to listen on.
/// * `target`       — If `Some`, begin a DAST scan immediately.
/// * `instructions` — Optional natural-language task description forwarded to the
///                    browser-extension agent (from `--explain`).
pub async fn start(port: u16, target: Option<String>, instructions: String) -> Result<()> {
    let state = AppState {
        result: Arc::new(RwLock::new(None)),
        status: Arc::new(RwLock::new(ServerStatus {
            state: "idle".into(),
            progress: 0,
            target: target.clone(),
        })),
        instructions: Arc::new(instructions),
    };

    if let Some(t) = target.clone() {
        let state_clone = state.clone();
        tokio::spawn(async move {
            {
                let mut status = state_clone.status.write().await;
                status.state = "scanning".into();
                status.progress = 10;
            }

            let mut all_findings = Vec::new();
            let is_url = t.starts_with("http://") || t.starts_with("https://");

            if !is_url {
                if let Ok(findings) = crate::engine::sast::run(&t) {
                    all_findings.extend(findings);
                }
            } else {
                let config = crate::models::ScanConfig {
                    target: t.clone(),
                    concurrency: 20,
                    timeout_secs: 10,
                    llm_probe: false,
                    nuclei: false,
                    nuclei_templates_dir: None,
                    nuclei_tags: vec![],
                    osv_blackbox: false,
                    anomaly: false,
                    waf_mutator: false,
                    port_scan: false,
                    blackbox: false,
                };
                if let Ok(findings) = crate::engine::dast::run(&config).await {
                    all_findings.extend(findings);
                }
            }

            {
                let mut status = state_clone.status.write().await;
                status.progress = 80;
            }

            let result = ScanResult {
                id: uuid::Uuid::new_v4().to_string(),
                target: t.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                findings: all_findings,
            };

            {
                let mut res_guard = state_clone.result.write().await;
                *res_guard = Some(result);
            }

            {
                let mut status = state_clone.status.write().await;
                status.progress = 100;
                status.state = "complete".into();
            }
        });
    }

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/results", get(get_results))
        .route("/api/events", get(sse_handler))
        .route("/extension", get(ws_extension_handler))
        .route("/health", get(|| async { "OK" }))
        .layer(cors)
        .with_state(state.clone());

    let addr = format!("0.0.0.0:{}", port);
    info!("Valinhall server listening on http://{}", addr);
    println!("  🌐 Dashboard server: http://localhost:{}", port);
    println!("  📡 SSE events:       http://localhost:{}/api/events", port);
    println!("  📊 Results JSON:     http://localhost:{}/api/results", port);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let status = state.status.read().await.clone();
    Json(status)
}

async fn get_results(State(state): State<AppState>) -> Response {
    let result = state.result.read().await;
    match &*result {
        Some(r) => Json(r.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No scan results available yet"})),
        )
            .into_response(),
    }
}

async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<axum::response::sse::Event, Infallible>>> {
    let stream = stream::unfold(state, |state| async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let status = state.status.read().await.clone();
        let data = serde_json::to_string(&status).unwrap_or_default();
        let event = axum::response::sse::Event::default().data(data);
        Some((Ok(event), state))
    });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

async fn ws_extension_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let instructions = Arc::clone(&state.instructions);
    ws.on_upgrade(move |socket| handle_socket(socket, instructions))
}

/// Handle a connected browser-extension WebSocket.
///
/// ## Protocol
///
/// **CLI → Extension messages:**
/// - `LLM_REQUEST`    — ask the extension to gather DOM context.
/// - `EXECUTE_BATCH`  — a list of actions for the extension to run in order.
///
/// **Extension → CLI messages:**
/// - `EXTENSION_READY`  — extension just connected.
/// - `CONTEXT_GATHERED` — DOM context (triggers first LLM call).
/// - `BATCH_RESULT`     — results of a previously dispatched batch (triggers next LLM call).
///
/// The key improvement over the old protocol is that the LLM now returns an **array** of
/// actions per call, which are all dispatched to the extension in a single `EXECUTE_BATCH`
/// message.  The extension executes them in sequence and sends back one `BATCH_RESULT`.
/// This way we use O(phases) LLM calls instead of O(actions) calls.
async fn handle_socket(mut socket: WebSocket, instructions: Arc<String>) {
    tracing::info!("Browser extension connected via WebSocket");

    let instructions_ref: Option<&str> = if instructions.trim().is_empty() {
        None
    } else {
        Some(instructions.as_str())
    };

    let mut agent = match crate::engine::ext_agent::ExtAgent::new(instructions_ref) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to initialize ExtAgent: {}. Disconnecting.", e);
            return;
        }
    };

    while let Some(msg) = socket.recv().await {
        let msg = match msg {
            Ok(m) => m,
            Err(_) => {
                tracing::warn!("Extension connection abruptly disconnected");
                break;
            }
        };

        match msg {
            Message::Text(t) => {
                tracing::info!("Received from extension: {}", t);

                let json_msg = match serde_json::from_str::<serde_json::Value>(&t) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Could not parse message as JSON: {}", e);
                        continue;
                    }
                };

                let msg_type = json_msg
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // ── EXTENSION_READY: ask for initial DOM snapshot ──────────────
                if msg_type == "EXTENSION_READY" {
                    println!("{} Extension connected. Requesting initial DOM context...", "🔌".blue());
                    let cmd = serde_json::json!({
                        "type": "LLM_REQUEST",
                        "taskId": uuid::Uuid::new_v4().to_string()
                    });
                    if let Err(e) = socket.send(Message::Text(cmd.to_string().into())).await {
                        tracing::error!("Failed to request context: {}", e);
                    }
                    continue;
                }

                // ── Build the prompt depending on message type ─────────────────
                let prompt = if msg_type == "CONTEXT_GATHERED" {
                    let context = json_msg
                        .get("context")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    println!(
                        "{} Received DOM context from browser. Agent is analyzing...",
                        "👁️".green()
                    );
                    format!(
                        "Current page context:\n{}",
                        serde_json::to_string_pretty(&context).unwrap_or_default()
                    )
                } else if msg_type == "BATCH_RESULT" {
                    let results = json_msg
                        .get("results")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([]));
                    println!(
                        "{} Batch complete. {} action(s) executed. Agent is planning next steps...",
                        "✅".green(),
                        results
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0)
                    );
                    format!(
                        "Batch results:\n{}",
                        serde_json::to_string_pretty(&results).unwrap_or_default()
                    )
                } else {
                    // Unknown message type — skip
                    continue;
                };

                // ── Ask the LLM for a batch of actions ────────────────────────
                tracing::info!("Asking LLM for next action batch...");
                match agent.get_next_actions(prompt).await {
                    Ok(actions) => {
                        let done = actions.iter().any(|a| {
                            a.get("action").and_then(|v| v.as_str()) == Some("DONE")
                        });

                        // Log the planned batch
                        println!(
                            "{} Agent planned {} action(s):",
                            "⚡".yellow(),
                            actions.len()
                        );
                        for (i, a) in actions.iter().enumerate() {
                            let name = a
                                .get("action")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            let payload = a
                                .get("payload")
                                .map(|p| serde_json::to_string(p).unwrap_or_default())
                                .unwrap_or_default();
                            println!("   {}. {} → {}", i + 1, name.cyan(), payload.dimmed());
                        }

                        // Send the whole batch to the extension in one message
                        let batch_cmd = serde_json::json!({
                            "type": "EXECUTE_BATCH",
                            "taskId": uuid::Uuid::new_v4().to_string(),
                            "actions": actions
                        });
                        if let Err(e) = socket
                            .send(Message::Text(batch_cmd.to_string().into()))
                            .await
                        {
                            tracing::error!("Failed to send batch to extension: {}", e);
                        }

                        if done {
                            // Find the DONE action's summary if present
                            let summary = actions
                                .iter()
                                .find(|a| {
                                    a.get("action").and_then(|v| v.as_str()) == Some("DONE")
                                })
                                .and_then(|a| a.get("payload"))
                                .and_then(|p| p.get("summary"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("(no summary provided)");
                            println!(
                                "\n{} Agent finished. Summary:\n  {}",
                                "🏁".blue(),
                                summary
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to get next action batch from LLM: {}", e);
                    }
                }
            }

            Message::Close(c) => {
                tracing::info!("Extension disconnected: {:?}", c);
                break;
            }

            _ => {}
        }
    }
}
