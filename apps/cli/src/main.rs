use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing::info;

mod engine;
mod models;
mod probes;
mod report;
mod server;

use engine::{anomaly, dast, endpoint_crawler, nuclei, openapi_fuzzer, osv_blackbox, port_scanner, sast, supply, vuln_tester, waf_mutator};

#[derive(Parser)]
#[command(
    name = "valinhall",
    version,
    about = "AI-Assisted Automated Security Testing Tool",
    long_about = "A high-performance security scanner covering OWASP Top 10 (2026),\nLLM red-teaming, and multi-ecosystem dependency auditing."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (repeat for more: -v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full security scan against a target URL or local directory
    Scan {
        /// Target URL (e.g. https://example.com) or local path
        #[arg(short, long)]
        target: String,

        /// Output directory or file path for JSON results.
        /// If a directory (e.g. "./" or "C:\reports\"), filenames are auto-generated.
        /// If omitted, writes to the current directory.
        #[arg(short, long)]
        output: Option<String>,

        /// Generate an HTML report alongside JSON output
        #[arg(long, default_value = "true")]
        report: bool,

        /// Run only SAST (static analysis) — skip DAST
        #[arg(long)]
        sast_only: bool,

        /// Run only DAST (dynamic attacks) — skip SAST
        #[arg(long)]
        dast_only: bool,

        /// Include LLM red-team probes
        #[arg(long)]
        llm: bool,

        /// Run Nuclei YAML template engine (requires templates directory)
        #[arg(long)]
        nuclei: bool,

        /// Path to Nuclei templates directory (default: ~/.valinhall/nuclei-templates)
        #[arg(long)]
        nuclei_templates: Option<String>,

        /// Only run Nuclei templates matching these tags (comma-separated, e.g. "xss,sqli")
        #[arg(long, default_value = "")]
        nuclei_tags: String,

        /// Query OSV.dev for CVEs in fingerprinted server technologies
        #[arg(long)]
        osv_blackbox: bool,

        /// Run K-Means anomaly detection on HTTP responses
        #[arg(long)]
        anomaly: bool,

        /// Use OpenRouter LLM to mutate blocked payloads (requires OPENROUTER_API_KEY)
        #[arg(long)]
        waf_mutator: bool,

        /// Max concurrent HTTP requests for DAST
        #[arg(long, default_value = "20")]
        concurrency: usize,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Scan all TCP ports 1-10000 + common high-numbered hidden ports
        #[arg(long)]
        port_scan: bool,

        /// Auto-discover all public & private endpoints (crawl+wordlist+JS), then test each for CORS, IDOR, SSRF, path traversal, open redirect, auth bypass
        #[arg(long)]
        blackbox: bool,

        /// Parse discovered OpenAPI/Swagger specs and fuzz every defined endpoint
        #[arg(long)]
        openapi: bool,
    },

    /// Audit project dependencies for known vulnerabilities (OSV.dev)
    Audit {
        /// Path to the project root (will auto-detect lock files)
        #[arg(short, long, default_value = ".")]
        path: String,

        /// Ecosystems to audit: node, rust, go (comma-separated, default: all)
        #[arg(long, default_value = "node,rust,go")]
        ecosystems: String,

        /// Fail with exit code 1 if any vulnerabilities found
        #[arg(long)]
        fail_on_vuln: bool,
    },

    /// Generate a standalone HTML report from a scan result JSON file
    Report {
        /// Path to scan-result JSON file
        #[arg(short, long)]
        input: String,

        /// Output HTML file path (default: valinhall-report-<timestamp>.html)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Start embedded HTTP server for live dashboard integration
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "7474")]
        port: u16,

        /// Target to scan (starts scan immediately on server start)
        #[arg(short, long)]
        target: Option<String>,
    },

    /// Launch Chromium with the Valinhall testing extension loaded
    ExtTest {
        /// Target URL to test with the extension
        #[arg(short, long)]
        target: String,

        /// Extension directory path (default: apps/extension)
        #[arg(short, long, default_value = "apps/extension")]
        ext_dir: String,
        
        /// Websocket server port
        #[arg(short, long, default_value = "7474")]
        port: u16,

        /// Natural-language instructions for the agent (e.g. "try prompt injection on every level")
        #[arg(long, default_value = "")]
        explain: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // ── Load .env from CWD or any parent directory ────────────────────────────
    // Walks up from the current working directory so the key is found whether
    // the user runs `valinhall` from `apps/cli/`, the project root, or anywhere
    // else in the repository tree.
    load_dotenv_from_ancestors();

    let cli = Cli::parse();

    // Initialize tracing
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    print_banner();

    match cli.command {
        Commands::Scan {
            target,
            output,
            report,
            sast_only,
            dast_only,
            llm,
            nuclei,
            nuclei_templates,
            nuclei_tags,
            osv_blackbox,
            anomaly,
            waf_mutator,
            concurrency,
            timeout,
            port_scan,
            blackbox,
            openapi,
        } => {
            cmd_scan(
                target, output, report, sast_only, dast_only,
                llm, nuclei, nuclei_templates, nuclei_tags,
                osv_blackbox, anomaly, waf_mutator,
                concurrency, timeout, port_scan, blackbox, openapi,
            )
            .await?;
        }

        Commands::Audit {
            path,
            ecosystems,
            fail_on_vuln,
        } => {
            cmd_audit(path, ecosystems, fail_on_vuln).await?;
        }

        Commands::Report { input, output } => {
            cmd_report(input, output)?;
        }

        Commands::Serve { port, target } => {
            tokio::select! {
                res = server::start(port, target, String::new()) => {
                    if let Err(e) = res {
                        tracing::error!("Server ended with error: {}", e);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\n{} Shutting down server...", "🛑".red());
                    std::process::exit(0);
                }
            }
        }

        Commands::ExtTest { target, ext_dir, port, explain } => {
            println!("{} Starting WebSocket server for extension on port {}...", "▶".cyan(), port);
            if !explain.trim().is_empty() {
                println!("{} Agent instructions: {}", "📋".cyan(), explain.dimmed());
            }
            
            // Start the server in the background, forwarding user instructions to the agent
            let server_task = tokio::spawn(async move {
                server::start(port, None, explain).await
            });
            
            println!("{} Launching Chromium with extension...", "▶".cyan());
            
            let ext_path = if std::path::Path::new(&ext_dir).is_absolute() {
                std::path::PathBuf::from(&ext_dir)
            } else {
                let direct_path = std::env::current_dir()?.join(&ext_dir);
                if direct_path.exists() {
                    direct_path
                } else if std::path::Path::new("Cargo.toml").exists() && std::env::current_dir()?.parent().unwrap().join("extension").exists() {
                    std::env::current_dir()?.parent().unwrap().join("extension")
                } else {
                    direct_path
                }
            };
            
            let ext_path_str = ext_path.to_string_lossy();
            let temp_dir = std::env::temp_dir().join(format!("valinhall-chrome-{}", uuid::Uuid::new_v4()));
            let temp_dir_str = temp_dir.to_string_lossy();
            
            let mut cmd = std::process::Command::new("chrome"); // fallback name
            if cfg!(target_os = "windows") {
                cmd = std::process::Command::new("cmd");
                cmd.args(["/C", "start", "chrome"]);
            } else if cfg!(target_os = "macos") {
                cmd = std::process::Command::new("open");
                cmd.args(["-a", "Google Chrome", "-n", "--args"]);
            } else {
                cmd = std::process::Command::new("google-chrome");
            }
            
            // Adding Chrome flags
            if cfg!(target_os = "windows") {
                cmd.args([
                    &format!("--user-data-dir={}", temp_dir_str),
                    &format!("--load-extension={}", ext_path_str),
                    &target
                ]);
            } else if cfg!(target_os = "macos") {
                cmd.args([
                    &format!("--user-data-dir={}", temp_dir_str),
                    &format!("--load-extension={}", ext_path_str),
                    &target
                ]);
            } else {
                cmd.args([
                    &format!("--user-data-dir={}", temp_dir_str),
                    &format!("--load-extension={}", ext_path_str),
                    &target
                ]);
            }
            
            match cmd.spawn() {
                Ok(_) => {
                    println!("{} Browser launched successfully.", "✓".green());
                    println!("{} Waiting for extension to connect and run tests (Press Ctrl+C to exit)...", "ℹ".blue());
                }
                Err(e) => {
                    println!("{} Failed to launch browser: {}", "✗".red(), e);
                    println!("Please run Chrome manually with: --load-extension={}", ext_path_str);
                }
            }
            
            // Keep the process alive for the server, but handle Ctrl+C gracefully
            tokio::select! {
                res = server_task => {
                    match res {
                        Ok(Err(e)) => {
                            tracing::error!("Server task ended with error: {}", e);
                            println!("{} Server failed to start: {}", "✗".red(), e);
                        }
                        Err(e) => {
                            tracing::error!("Server task panicked: {}", e);
                        }
                        Ok(Ok(())) => {
                            tracing::info!("Server shut down cleanly.");
                        }
                    }
                    std::process::exit(1);
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\n{} Shutting down Valinhall...", "🛑".red());
                    // Cleanup temporary profile on exit
                    let _ = std::fs::remove_dir_all(&temp_dir);
                    std::process::exit(0);
                }
            }
        }
    }

    Ok(())
}

/// Walk from the current working directory up to the filesystem root looking
/// for a `.env` file and load the first one found.  This means the key works
/// whether the user runs `valinhall` from `apps/cli/`, the project root, or
/// anywhere else in the repository tree.  Already-set env vars are NOT
/// overridden (dotenvy's default `from_path` behaviour).
fn load_dotenv_from_ancestors() {
    let mut dir = std::env::current_dir().unwrap_or_default();
    loop {
        let candidate = dir.join(".env");
        if candidate.exists() {
            // `from_path` silently skips keys that are already in the env.
            if let Err(e) = dotenvy::from_path(&candidate) {
                // Only warn — never abort startup because of a missing/malformed .env
                eprintln!("warning: failed to load {:?}: {}", candidate, e);
            } else {
                // Let the user know which .env was loaded (visible at -v or higher)
                tracing::debug!("Loaded env from {:?}", candidate);
            }
            return; // stop at the first .env found
        }
        // Go up one level; break if we've reached the root
        if !dir.pop() {
            break;
        }
    }
}

/// Resolve an output path argument into a concrete file path.
/// If `arg` is a directory (ends with `/`, `\`, or exists as a dir), append `filename`.
/// If `arg` is a file path (has a recognizable extension), use it directly.
/// If `arg` is None, use `filename` in the current directory.
fn resolve_output_path(arg: Option<&str>, filename: &str) -> std::path::PathBuf {
    use std::path::Path;
    match arg {
        None => Path::new(filename).to_path_buf(),
        Some(p) => {
            let path = Path::new(p);
            // Treat as directory if: ends with sep, is existing dir, or has no extension
            let is_dir = p.ends_with('/') || p.ends_with('\\') || path.is_dir()
                || path.extension().is_none();
            if is_dir {
                path.join(filename)
            } else {
                path.to_path_buf()
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    target: String,
    output: Option<String>,
    generate_report: bool,
    sast_only: bool,
    dast_only: bool,
    llm: bool,
    run_nuclei: bool,
    nuclei_templates: Option<String>,
    nuclei_tags: String,
    run_osv_blackbox: bool,
    run_anomaly: bool,
    run_waf_mutator: bool,
    concurrency: usize,
    timeout: u64,
    run_port_scan: bool,
    run_blackbox: bool,
    run_openapi: bool,
) -> Result<()> {
    use crate::models::{ScanConfig, ScanResult};
    use chrono::Utc;
    use indicatif::{ProgressBar, ProgressStyle};
    use uuid::Uuid;

    let scan_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now();

    println!(
        "{} {} {}",
        "▶".cyan().bold(),
        "Scanning:".bold(),
        target.yellow()
    );
    println!("  {} {}", "Scan ID:".dimmed(), scan_id.dimmed());
    println!("  {} {}", "Started: ".dimmed(), timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string().dimmed());
    println!();

    let tags: Vec<String> = nuclei_tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let config = ScanConfig {
        target: target.clone(),
        concurrency,
        timeout_secs: timeout,
        llm_probe: llm,
        nuclei: run_nuclei,
        nuclei_templates_dir: nuclei_templates,
        nuclei_tags: tags,
        osv_blackbox: run_osv_blackbox,
        anomaly: run_anomaly,
        waf_mutator: run_waf_mutator,
        port_scan: run_port_scan,
        blackbox: run_blackbox,
    };

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );

    let mut all_findings = Vec::new();

    // SAST phase
    if !dast_only {
        pb.set_message("Running static analysis (SAST)…");
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        info!("Starting SAST engine");

        // Only run SAST if target looks like a local path
        if !target.starts_with("http://") && !target.starts_with("https://") {
            let sast_findings = sast::run(&target)?;
            println!(
                "  {} SAST: {} findings",
                "✓".green(),
                sast_findings.len().to_string().bold()
            );
            all_findings.extend(sast_findings);
        } else {
            println!("  {} SAST: skipped (URL target — use a local path for SAST)", "ℹ".blue());
        }
    }

    // DAST phase
    if !sast_only {
        pb.set_message("Running dynamic analysis (DAST)…");
        let dast_findings = dast::run(&config).await?;
        println!(
            "  {} DAST: {} findings",
            "✓".green(),
            dast_findings.len().to_string().bold()
        );
        all_findings.extend(dast_findings);
    }

    // LLM red-team phase
    if llm {
        pb.set_message("Running LLM red-team probes…");
        let llm_findings = probes::llm::run(&config).await?;
        println!(
            "  {} LLM:  {} findings",
            "✓".green(),
            llm_findings.len().to_string().bold()
        );
        all_findings.extend(llm_findings);
    }

    // ── Nuclei template engine ───────────────────────────────────────────────
    if run_nuclei {
        pb.set_message("Running Nuclei template engine…");
        let templates_dir = config
            .nuclei_templates_dir
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(nuclei::NucleiRunnerConfig::default_templates_dir);

        let nuclei_cfg = nuclei::NucleiRunnerConfig {
            target: config.target.clone(),
            templates_dir,
            tag_filter: config.nuclei_tags.clone(),
            concurrency: config.concurrency,
            timeout: std::time::Duration::from_secs(config.timeout_secs),
        };

        match nuclei::run(&nuclei_cfg).await {
            Ok(f) => {
                println!(
                    "  {} Nuclei: {} finding(s)",
                    "✓".green(),
                    f.len().to_string().bold()
                );
                all_findings.extend(f);
            }
            Err(e) => println!("  {} Nuclei engine error: {}", "✗".red(), e),
        }
    }

    // ── OSV blackbox fingerprint lookup ──────────────────────────────────────
    if run_osv_blackbox && (target.starts_with("http://") || target.starts_with("https://")) {
        pb.set_message("Querying OSV.dev for fingerprinted technologies…");
        let shared_client = std::sync::Arc::new(dast::build_client(&config)?);
        match osv_blackbox::check_fingerprinted_tech(shared_client, &config.target).await {
            Ok(f) => {
                println!(
                    "  {} OSV Blackbox: {} finding(s)",
                    "✓".green(),
                    f.len().to_string().bold()
                );
                all_findings.extend(f);
            }
            Err(e) => println!("  {} OSV blackbox error: {}", "✗".red(), e),
        }
    }

    // ── Anomaly detection engine (K-Means) ───────────────────────────────────
    if run_anomaly && (target.starts_with("http://") || target.starts_with("https://")) {
        pb.set_message("Running K-Means anomaly detection…");
        let shared_client = std::sync::Arc::new(dast::build_client(&config)?);
        let anomaly_cfg = anomaly::AnomalyConfig {
            concurrency: config.concurrency,
            timeout: std::time::Duration::from_secs(config.timeout_secs),
            ..anomaly::AnomalyConfig::default()
        };
        match anomaly::run(shared_client, &config.target, &anomaly_cfg).await {
            Ok(f) => {
                println!(
                    "  {} Anomaly: {} finding(s)",
                    "✓".green(),
                    f.len().to_string().bold()
                );
                all_findings.extend(f);
            }
            Err(e) => println!("  {} Anomaly engine error: {}", "✗".red(), e),
        }
    }

    // ── Port Scanner ──────────────────────────────────────────────────────────
    if run_port_scan && (target.starts_with("http://") || target.starts_with("https://")) {
        pb.set_message("Scanning TCP ports (1–10000 + hidden high ports)…");
        match port_scanner::host_from_url(&config.target) {
            Ok(host) => {
                let ps_cfg = port_scanner::PortScanConfig {
                    concurrency: 500.max(config.concurrency * 10),
                    connect_timeout: std::time::Duration::from_millis(800),
                    banner_timeout: std::time::Duration::from_millis(1000),
                    port_range_max: 10_000,
                };
                match port_scanner::run(&host, &ps_cfg).await {
                    Ok(f) => {
                        println!(
                            "  {} Port Scan: {} finding(s)",
                            "✓".green(),
                            f.len().to_string().bold()
                        );
                        all_findings.extend(f);
                    }
                    Err(e) => println!("  {} Port scanner error: {}", "✗".red(), e),
                }
            }
            Err(e) => println!("  {} Port scanner: could not parse host — {}", "✗".red(), e),
        }
    }

    // ── Blackbox: Endpoint Crawler + Vuln Tester ──────────────────────────────
    if run_blackbox && (target.starts_with("http://") || target.starts_with("https://")) {
        let shared_client = std::sync::Arc::new(dast::build_client(&config)?);

        pb.set_message("Discovering endpoints (crawl + wordlist + JS mining)…");
        let crawl_cfg = endpoint_crawler::CrawlConfig {
            concurrency: config.concurrency,
            timeout: std::time::Duration::from_secs(config.timeout_secs),
        };
        let endpoints = match endpoint_crawler::discover(
            std::sync::Arc::clone(&shared_client),
            &config.target,
            &crawl_cfg,
        )
        .await
        {
            Ok(eps) => {
                println!(
                    "  {} Endpoint Crawler: {} endpoint(s) discovered",
                    "✓".green(),
                    eps.len().to_string().bold()
                );
                eps
            }
            Err(e) => {
                println!("  {} Endpoint crawler error: {}", "✗".red(), e);
                vec![]
            }
        };

        pb.set_message("Testing discovered endpoints for vulnerabilities…");
        let vt_cfg = vuln_tester::VulnTestConfig {
            concurrency: config.concurrency,
            timeout: std::time::Duration::from_secs(config.timeout_secs),
        };
        match vuln_tester::test_endpoints(
            std::sync::Arc::clone(&shared_client),
            &endpoints,
            &vt_cfg,
        )
        .await
        {
            Ok(f) => {
                println!(
                    "  {} Vuln Tester: {} finding(s) across {} endpoint(s)",
                    "✓".green(),
                    f.len().to_string().bold(),
                    endpoints.len()
                );
                all_findings.extend(f);
            }
            Err(e) => println!("  {} Vuln tester error: {}", "✗".red(), e),
        }
    }

    // ── OpenAPI / Swagger Spec Fuzzer ─────────────────────────────────────────
    if run_openapi && (target.starts_with("http://") || target.starts_with("https://")) {
        pb.set_message("Fetching & fuzzing OpenAPI/Swagger spec…");
        let shared_client = std::sync::Arc::new(dast::build_client(&config)?);
        match openapi_fuzzer::run(
            &shared_client,
            &config.target,
            std::time::Duration::from_secs(config.timeout_secs),
        )
        .await
        {
            Ok(f) => {
                println!(
                    "  {} OpenAPI Fuzzer: {} finding(s)",
                    "✓".green(),
                    f.len().to_string().bold()
                );
                all_findings.extend(f);
            }
            Err(e) => println!("  {} OpenAPI fuzzer error: {}", "✗".red(), e),
        }
    }

    // ── WAF Mutator (LLM bypass) ─────────────────────────────────────────────
    if run_waf_mutator {
        match waf_mutator::WafMutatorConfig::from_env() {
            Ok(waf_cfg) => {
                pb.set_message("WAF mutator: analysing blocked payloads with LLM…");
                let shared_client = std::sync::Arc::new(dast::build_client(&config)?);
                let mutator = waf_mutator::WafMutator::new(shared_client, waf_cfg);

                // Collect blocked findings from prior phases to attempt bypass
                let blocked: Vec<waf_mutator::BlockedAttempt> = all_findings
                    .iter()
                    .filter(|f| {
                        f.evidence
                            .as_deref()
                            .map(|e| e.contains("406") || e.contains("403"))
                            .unwrap_or(false)
                    })
                    .filter_map(|f| {
                        Some(waf_mutator::BlockedAttempt {
                            endpoint: f.endpoint.clone()?,
                            method: "GET".to_string(),
                            original_payload: f
                                .evidence
                                .as_deref()
                                .unwrap_or("")
                                .lines()
                                .find(|l| l.to_lowercase().contains("payload"))
                                .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
                                .unwrap_or_else(|| f.title.clone()),
                            block_status: if f
                                .evidence
                                .as_deref()
                                .unwrap_or("")
                                .contains("406")
                            {
                                406
                            } else {
                                403
                            },
                            response_snippet: f
                                .evidence
                                .clone()
                                .unwrap_or_default(),
                            injection_point: "q".to_string(),
                        })
                    })
                    .take(5) // limit mutation budget
                    .collect();

                let mut waf_findings = Vec::new();
                for attempt in &blocked {
                    match mutator.mutate_and_retry(attempt).await {
                        Ok(f) => waf_findings.extend(f),
                        Err(e) => tracing::warn!("WAF mutator error: {}", e),
                    }
                }
                println!(
                    "  {} WAF Mutator: {} finding(s) ({} attempt(s))",
                    "✓".green(),
                    waf_findings.len().to_string().bold(),
                    blocked.len()
                );
                all_findings.extend(waf_findings);
            }
            Err(e) => {
                println!("  {} WAF Mutator skipped: {}", "ℹ".blue(), e);
            }
        }
    }

    pb.finish_and_clear();

    let result = ScanResult {
        id: scan_id,
        target,
        timestamp: timestamp.to_rfc3339(),
        findings: all_findings,
    };

    // Write JSON
    let json_filename = format!("scan-result-{}.json", timestamp.format("%Y%m%d-%H%M%S"));
    let json_path = resolve_output_path(output.as_deref(), &json_filename);
    // Ensure parent directory exists
    if let Some(parent) = json_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(&result)?;
    std::fs::write(&json_path, &json)?;
    println!("\n  {} JSON:   {}", "💾".dimmed(), json_path.display().to_string().green());

    // Generate HTML report
    if generate_report {
        let html_filename = format!("valinhall-report-{}.html", timestamp.format("%Y%m%d-%H%M%S"));
        // HTML goes in the same directory as the JSON
        let html_path = if let Some(parent) = json_path.parent() {
            parent.join(&html_filename)
        } else {
            std::path::PathBuf::from(&html_filename)
        };
        let html = report::html::render(&result)?;
        std::fs::write(&html_path, html)?;
        println!("  {} Report: {}", "📄".dimmed(), html_path.display().to_string().green());
        
        if let Err(e) = open::that(&html_path) {
            tracing::warn!("Failed to open HTML report: {}", e);
        } else {
            println!("  {} Opened report in browser", "🌐".dimmed());
        }
    }

    // Print summary
    print_summary(&result.findings);

    Ok(())
}

async fn cmd_audit(path: String, ecosystems: String, fail_on_vuln: bool) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};

    println!("{} {}", "▶ Auditing dependencies in:".bold(), path.yellow());

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let eco_list: Vec<&str> = ecosystems.split(',').map(|s| s.trim()).collect();
    let findings = supply::audit(&path, &eco_list).await?;

    pb.finish_and_clear();

    if findings.is_empty() {
        println!("  {} No known vulnerabilities found!", "✓".green().bold());
    } else {
        for f in &findings {
            println!(
                "  {} [{}] {} — {}",
                "⚠".yellow(),
                f.severity.to_uppercase().red(),
                f.package.bold(),
                f.title
            );
        }
        println!("\n  {} {} vulnerability(s) found", "⚠".yellow(), findings.len());

        if fail_on_vuln {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_report(input: String, output: Option<String>) -> Result<()> {
    use crate::models::ScanResult;
    use chrono::Utc;

    let json = std::fs::read_to_string(&input)?;
    let result: ScanResult = serde_json::from_str(&json)?;

    let html_path = output.unwrap_or_else(|| {
        format!(
            "valinhall-report-{}.html",
            Utc::now().format("%Y%m%d-%H%M%S")
        )
    });

    let html = report::html::render(&result)?;
    std::fs::write(&html_path, html)?;

    println!("{} Report written to: {}", "✓".green().bold(), html_path.yellow());

    if let Err(e) = open::that(&html_path) {
        tracing::warn!("Failed to open HTML report: {}", e);
    } else {
        println!("{} Opened report in browser", "✓".green());
    }

    Ok(())
}

fn print_banner() {
    println!("{}", r#"
  ██╗   ██╗ █████╗ ██╗     ██╗███╗   ██╗██╗  ██╗ █████╗ ██╗     ██╗
  ██║   ██║██╔══██╗██║     ██║████╗  ██║██║  ██║██╔══██╗██║     ██║
  ██║   ██║███████║██║     ██║██╔██╗ ██║███████║███████║██║     ██║
  ╚██╗ ██╔╝██╔══██║██║     ██║██║╚██╗██║██╔══██║██╔══██║██║     ██║
   ╚████╔╝ ██║  ██║███████╗██║██║ ╚████║██║  ██║██║  ██║███████╗███████╗
    ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
  "#.cyan().bold());
    println!("  {} AI-Assisted Automated Security Testing Tool\n", "🛡".dimmed());
}

fn print_summary(findings: &[crate::models::Finding]) {
    use crate::models::Severity;

    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
    let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

    println!("\n  ┌─────────────────────────────┐");
    println!("  │       SCAN SUMMARY          │");
    println!("  ├─────────────────────────────┤");
    println!("  │  {} Critical: {:>3}              │", "●".red().bold(), critical);
    println!("  │  {} High:     {:>3}              │", "●".truecolor(255, 120, 0).bold(), high);
    println!("  │  {} Medium:   {:>3}              │", "●".yellow().bold(), medium);
    println!("  │  {} Low:      {:>3}              │", "●".cyan().bold(), low);
    println!("  │  {} Info:     {:>3}              │", "●".white().dimmed(), info);
    println!("  ├─────────────────────────────┤");
    println!("  │  Total:      {:>3}              │", findings.len());
    println!("  └─────────────────────────────┘");
}
