//! Embedded HTTP server for live dashboard integration (--serve mode)
//!
//! Provides:
//!   GET /api/status  — current scan state
//!   GET /api/events  — SSE stream of live scan findings
//!   GET /api/results — completed ScanResult JSON

use anyhow::Result;
use axum::{
    extract::State,
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

use crate::models::ScanResult;

#[derive(Clone)]
struct AppState {
    result: Arc<RwLock<Option<ScanResult>>>,
    status: Arc<RwLock<ServerStatus>>,
}

#[derive(Clone, serde::Serialize)]
pub struct ServerStatus {
    pub state: String, // "idle" | "scanning" | "complete" | "error"
    pub progress: u8,
    pub target: Option<String>,
}

pub async fn start(port: u16, target: Option<String>) -> Result<()> {
    let state = AppState {
        result: Arc::new(RwLock::new(None)),
        status: Arc::new(RwLock::new(ServerStatus {
            state: "idle".into(),
            progress: 0,
            target: target.clone(),
        })),
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
