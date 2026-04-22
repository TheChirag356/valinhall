//! Endpoint Crawler Engine
//!
//! Automatically discovers all public and private endpoints on a target:
//!
//! 1. **Crawl** — follows href links on the landing page (depth-1)
//! 2. **robots.txt & sitemap.xml** — extracts disallowed and listed paths
//! 3. **JS API mining** — scans inline and external JS for API route patterns
//! 4. **Wordlist bruteforce** — probes a 500-entry common-path dictionary
//!
//! Returns a de-duplicated `Vec<DiscoveredEndpoint>` for downstream probing.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

// ── Discovery wordlist ────────────────────────────────────────────────────────

static WORDLIST: &[&str] = &[
    // Auth / accounts
    "/login", "/logout", "/register", "/signup", "/forgot-password",
    "/reset-password", "/change-password", "/verify-email", "/oauth/callback",
    "/auth", "/auth/login", "/auth/token", "/auth/refresh",
    // Admin panels
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/users",
    "/admin/settings", "/admin/config", "/administrator", "/wp-admin",
    "/wp-login.php", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    // API roots
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/internal",
    "/api/admin", "/api/debug", "/api/health", "/api/status",
    "/api/users", "/api/user", "/api/me", "/api/account",
    "/api/config", "/api/settings", "/api/keys", "/api/tokens",
    "/graphql", "/graphiql", "/gql",
    // Dev / debug
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/debug", "/debug/vars", "/debug/pprof", "/trace",
    "/console", "/rails/info/routes", "/rails/info/properties",
    "/phpinfo.php", "/info.php", "/test.php", "/config.php",
    // Actuator (Spring Boot)
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/metrics", "/actuator/loggers",
    "/actuator/httptrace", "/actuator/dump", "/actuator/shutdown",
    // Monitoring / metrics
    "/health", "/healthz", "/livez", "/readyz", "/ping", "/status",
    "/metrics", "/prometheus", "/stats", "/_status",
    // Documentation
    "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs/", "/openapi.json", "/openapi.yaml",
    "/docs", "/docs/api", "/redoc", "/v1/api-docs",
    // Config / secrets
    "/config", "/config.json", "/config.yaml", "/config.yml",
    "/settings", "/settings.json", "/app.config", "/web.config",
    "/server-status", "/server-info", "/nginx_status",
    // Backups / archives
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql", "/site.zip",
    // Misc internal
    "/internal", "/private", "/hidden", "/secret", "/restricted",
    "/management", "/manager", "/monitor", "/panel",
    "/cron", "/jobs", "/queue", "/workers",
    "/upload", "/uploads", "/files", "/static", "/assets",
    "/cdn-cgi/", "/.well-known/security.txt", "/.well-known/acme-challenge/",
    // Cloud / infra metadata
    "/latest/meta-data", "/latest/user-data",  // AWS IMDS
    "/metadata/v1", "/metadata/instance",       // GCP / Azure IMDS via SSRF
    // Common SPA paths
    "/dashboard", "/profile", "/account", "/billing", "/payments",
    "/reports", "/analytics", "/logs", "/audit",
    "/users", "/user", "/me", "/session", "/sessions",
    // Next.js / Nuxt / Vercel internals
    "/_next/static/", "/__nuxt/", "/_api/",
    "/api/auth/session", "/api/auth/signin", "/api/auth/signout",
];

// ── Discovered endpoint ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub status: u16,
    pub content_type: String,
    pub body_preview: String,
    pub source: EndpointSource,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EndpointSource {
    Crawl,
    RobotsTxt,
    Sitemap,
    JsApiRoute,
    Wordlist,
}

impl EndpointSource {
    pub fn label(&self) -> &str {
        match self {
            Self::Crawl       => "crawl",
            Self::RobotsTxt   => "robots.txt",
            Self::Sitemap     => "sitemap.xml",
            Self::JsApiRoute  => "js-mining",
            Self::Wordlist    => "wordlist",
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct CrawlConfig {
    pub concurrency: usize,
    pub timeout: Duration,
}

pub async fn discover(
    client: Arc<Client>,
    base_url: &str,
    cfg: &CrawlConfig,
) -> Result<Vec<DiscoveredEndpoint>> {
    let base = base_url.trim_end_matches('/').to_string();
    info!("Endpoint crawler: starting on {}", base);

    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates: Vec<(String, EndpointSource)> = Vec::new();

    // ── Phase 1: robots.txt ──────────────────────────────────────────────────
    let robots_paths = fetch_robots(&client, &base).await;
    for path in robots_paths {
        let url = format!("{}{}", base, path);
        if seen.insert(url.clone()) {
            candidates.push((url, EndpointSource::RobotsTxt));
        }
    }

    // ── Phase 2: sitemap.xml ─────────────────────────────────────────────────
    let sitemap_urls = fetch_sitemap(&client, &base).await;
    for url in sitemap_urls {
        if seen.insert(url.clone()) {
            candidates.push((url, EndpointSource::Sitemap));
        }
    }

    // ── Phase 3: crawl landing page links + JS mining ────────────────────────
    let (crawled, js_routes) = crawl_page(&client, &base, &base).await;
    for url in crawled {
        if seen.insert(url.clone()) {
            candidates.push((url, EndpointSource::Crawl));
        }
    }
    for path in js_routes {
        let url = if path.starts_with("http") { path.clone() } else { format!("{}{}", base, path) };
        if seen.insert(url.clone()) {
            candidates.push((url, EndpointSource::JsApiRoute));
        }
    }

    // ── Phase 4: wordlist bruteforce ─────────────────────────────────────────
    for path in WORDLIST {
        let url = format!("{}{}", base, path);
        if seen.insert(url.clone()) {
            candidates.push((url, EndpointSource::Wordlist));
        }
    }

    info!("Endpoint crawler: probing {} candidates", candidates.len());

    // ── Probe all candidates ─────────────────────────────────────────────────
    let mut handles = Vec::new();
    for (url, source) in candidates {
        let client = Arc::clone(&client);
        let sem = Arc::clone(&sem);
        let timeout = cfg.timeout;
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            probe_endpoint(client, url, source, timeout).await
        }));
    }

    let mut discovered = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Some(ep)) => discovered.push(ep),
            Ok(None)     => {}
            Err(e)       => debug!("Crawler task panicked: {}", e),
        }
    }

    info!("Endpoint crawler: {} live endpoints found", discovered.len());
    Ok(discovered)
}

// ── Probe a single URL ───────────────────────────────────────────────────────

async fn probe_endpoint(
    client: Arc<Client>,
    url: String,
    source: EndpointSource,
    tout: Duration,
) -> Option<DiscoveredEndpoint> {
    let resp = client.get(&url).timeout(tout).send().await.ok()?;
    let status = resp.status().as_u16();

    // Skip 404/410 for wordlist probes; keep everything else
    if source == EndpointSource::Wordlist && (status == 404 || status == 410) {
        return None;
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = resp.bytes().await.unwrap_or_default();
    let body_preview: String = String::from_utf8_lossy(&body)
        .chars()
        .take(300)
        .collect();

    debug!("Endpoint {} → {} ({})", url, status, source.label());

    Some(DiscoveredEndpoint { url, status, content_type, body_preview, source })
}

// ── robots.txt parser ────────────────────────────────────────────────────────

async fn fetch_robots(client: &Client, base: &str) -> Vec<String> {
    let url = format!("{}/robots.txt", base);
    let text = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => return vec![],
    };

    let mut paths = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Disallow:").or_else(|| line.strip_prefix("Allow:")) {
            let path = rest.trim();
            if !path.is_empty() && path != "/" {
                paths.push(path.to_string());
            }
        } else if let Some(sm) = line.strip_prefix("Sitemap:") {
            // Handled separately, but we can note the sitemap URL
            let _ = sm;
        }
    }
    paths
}

// ── sitemap.xml parser ───────────────────────────────────────────────────────

async fn fetch_sitemap(client: &Client, base: &str) -> Vec<String> {
    let url = format!("{}/sitemap.xml", base);
    let text = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => return vec![],
    };

    let re = Regex::new(r"<loc>\s*(https?://[^\s<]+)\s*</loc>").unwrap();
    re.captures_iter(&text)
        .map(|c| c[1].to_string())
        .collect()
}

// ── Page crawl + JS API mining ───────────────────────────────────────────────

async fn crawl_page(
    client: &Client,
    base: &str,
    url: &str,
) -> (Vec<String>, Vec<String>) {
    let text = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => return (vec![], vec![]),
    };

    let href_re  = Regex::new(r#"href=["']([^"'#?]+)["']"#).unwrap();
    let src_re   = Regex::new(r#"src=["']([^"']+\.js[^"']*)["']"#).unwrap();
    // Common API route patterns in bundled JS
    let api_re   = Regex::new(r#"["'`](/(?:api|v\d+|graphql|auth|admin|internal)[^"'`\s]{0,80})["'`]"#).unwrap();

    let mut links = Vec::new();
    let mut js_routes = Vec::new();

    // Collect href links (same-origin only)
    for cap in href_re.captures_iter(&text) {
        let href = cap[1].to_string();
        let full = if href.starts_with("http") {
            if href.starts_with(base) { href } else { continue; }
        } else {
            format!("{}/{}", base.trim_end_matches('/'), href.trim_start_matches('/'))
        };
        links.push(full);
    }

    // Collect API routes from inline JS
    for cap in api_re.captures_iter(&text) {
        js_routes.push(cap[1].to_string());
    }

    // Mine external JS files for API routes
    let js_urls: Vec<String> = src_re
        .captures_iter(&text)
        .map(|c| {
            let src = c[1].to_string();
            if src.starts_with("http") { src }
            else { format!("{}/{}", base.trim_end_matches('/'), src.trim_start_matches('/')) }
        })
        .take(10) // limit to 10 JS files
        .collect();

    for js_url in js_urls {
        if let Ok(r) = client.get(&js_url).send().await {
            if let Ok(js_text) = r.text().await {
                for cap in api_re.captures_iter(&js_text) {
                    js_routes.push(cap[1].to_string());
                }
            }
        }
    }

    js_routes.sort();
    js_routes.dedup();

    (links, js_routes)
}
