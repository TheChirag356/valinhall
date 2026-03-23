use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing::info;

mod engine;
mod models;
mod probes;
mod report;
mod server;

use engine::{dast, sast, supply};

/// Valinhall — AI-Assisted Automated Security Testing Tool
#[derive(Parser)]
#[command(
    name = "valinhall",
    version,
    author,
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

        /// Max concurrent HTTP requests for DAST
        #[arg(long, default_value = "20")]
        concurrency: usize,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
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
}

#[tokio::main]
async fn main() -> Result<()> {
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
            concurrency,
            timeout,
        } => {
            cmd_scan(
                target, output, report, sast_only, dast_only, llm, concurrency, timeout,
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
            server::start(port, target).await?;
        }
    }

    Ok(())
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

async fn cmd_scan(
    target: String,
    output: Option<String>,
    generate_report: bool,
    sast_only: bool,
    dast_only: bool,
    llm: bool,
    concurrency: usize,
    timeout: u64,
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

    let config = ScanConfig {
        target: target.clone(),
        concurrency,
        timeout_secs: timeout,
        llm_probe: llm,
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
