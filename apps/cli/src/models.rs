use serde::{Deserialize, Serialize};

/// Top-level scan result — serialized to JSON and rendered in HTML report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub target: String,
    pub timestamp: String,
    pub findings: Vec<Finding>,
}

/// A single security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: OwaspCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: String,
    pub source: FindingSource,
    pub endpoint: Option<String>,
}

/// OWASP Top 10 (2026 draft) + LLM category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OwaspCategory {
    /// A01: Broken Access Control
    BrokenAccessControl,
    /// A02: Cryptographic Failures
    CryptographicFailures,
    /// A03: Software Supply Chain Failures
    SupplyChainFailures,
    /// A04: Insecure Design
    InsecureDesign,
    /// A05: Security Misconfiguration
    SecurityMisconfiguration,
    /// A06: Vulnerable & Outdated Components
    VulnerableComponents,
    /// A07: Identification & Authentication Failures
    AuthFailures,
    /// A08: Software & Data Integrity Failures
    IntegrityFailures,
    /// A09: Security Logging & Monitoring Failures
    LoggingFailures,
    /// A10: Mishandling of Exceptional Conditions
    ExceptionalConditions,
    /// LLM: AI/LLM-specific vulnerabilities
    LlmVulnerability,
}

impl OwaspCategory {
    pub fn label(&self) -> &str {
        match self {
            Self::BrokenAccessControl => "A01: Broken Access Control",
            Self::CryptographicFailures => "A02: Cryptographic Failures",
            Self::SupplyChainFailures => "A03: Supply Chain Failures",
            Self::InsecureDesign => "A04: Insecure Design",
            Self::SecurityMisconfiguration => "A05: Security Misconfiguration",
            Self::VulnerableComponents => "A06: Vulnerable Components",
            Self::AuthFailures => "A07: Auth Failures",
            Self::IntegrityFailures => "A08: Integrity Failures",
            Self::LoggingFailures => "A09: Logging Failures",
            Self::ExceptionalConditions => "A10: Exceptional Conditions",
            Self::LlmVulnerability => "LLM: AI/LLM Vulnerability",
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::BrokenAccessControl => "A01",
            Self::CryptographicFailures => "A02",
            Self::SupplyChainFailures => "A03",
            Self::InsecureDesign => "A04",
            Self::SecurityMisconfiguration => "A05",
            Self::VulnerableComponents => "A06",
            Self::AuthFailures => "A07",
            Self::IntegrityFailures => "A08",
            Self::LoggingFailures => "A09",
            Self::ExceptionalConditions => "A10",
            Self::LlmVulnerability => "LLM",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        }
    }

    /// Tailwind CSS color class for badge
    pub fn color_class(&self) -> &str {
        match self {
            Self::Critical => "bg-red-600 text-white",
            Self::High => "bg-orange-500 text-white",
            Self::Medium => "bg-yellow-400 text-black",
            Self::Low => "bg-blue-400 text-white",
            Self::Info => "bg-gray-400 text-white",
        }
    }

    pub fn hex_color(&self) -> &str {
        match self {
            Self::Critical => "#dc2626",
            Self::High => "#f97316",
            Self::Medium => "#facc15",
            Self::Low => "#60a5fa",
            Self::Info => "#9ca3af",
        }
    }
}

/// Which engine produced this finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingSource {
    Sast,
    Dast,
    SupplyChain,
    LlmProbe,
    /// Nuclei YAML template runner
    Nuclei,
    /// OSV.dev blackbox fingerprint lookup
    OsvBlackbox,
    /// K-Means anomaly detection engine
    AnomalyEngine,
    /// LLM-powered WAF bypass mutator
    WafMutator,
    /// TCP port scanner with banner grabbing
    PortScanner,
    /// Endpoint crawler (crawl + wordlist + JS mining)
    EndpointCrawler,
    /// Automated endpoint vulnerability tester
    VulnTester,
    /// GraphQL Introspection and Fuzzer
    GraphqlFuzzer,
    /// OpenAPI/Swagger spec parser and endpoint fuzzer
    OpenApiFuzzer,
    /// XML External Entity (XXE) injection scanner
    XxeScanner,
}

impl FindingSource {
    pub fn label(&self) -> &str {
        match self {
            Self::Sast => "SAST",
            Self::Dast => "DAST",
            Self::SupplyChain => "Supply Chain",
            Self::LlmProbe => "LLM Probe",
            Self::Nuclei => "Nuclei Templates",
            Self::OsvBlackbox => "OSV Blackbox",
            Self::AnomalyEngine => "Anomaly Engine",
            Self::WafMutator => "WAF Mutator",
            Self::PortScanner => "Port Scanner",
            Self::EndpointCrawler => "Endpoint Crawler",
            Self::VulnTester => "Vuln Tester",
            Self::GraphqlFuzzer => "GraphQL Fuzzer",
            Self::OpenApiFuzzer => "OpenAPI Fuzzer",
            Self::XxeScanner => "XXE Scanner",
        }
    }
}

/// Configuration passed to scan engines
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub llm_probe: bool,
    /// Run Nuclei template engine
    pub nuclei: bool,
    /// Path to Nuclei templates directory (None = use default)
    pub nuclei_templates_dir: Option<String>,
    /// Comma-separated Nuclei tag filter (empty = all templates)
    pub nuclei_tags: Vec<String>,
    /// Run OSV blackbox fingerprint lookup
    pub osv_blackbox: bool,
    /// Run K-Means anomaly detection engine
    pub anomaly: bool,
    /// Run WAF mutator with OpenRouter (requires OPENROUTER_API_KEY)
    pub waf_mutator: bool,
    /// Run TCP port scanner (all 1-10000 + hidden high ports)
    pub port_scan: bool,
    /// Auto-discover endpoints (crawl + wordlist + JS) then test them
    pub blackbox: bool,
}

/// A supply-chain vulnerability finding (dependency audit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyFinding {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub severity: String,
    pub title: String,
    pub cve: Option<String>,
    pub fix_version: Option<String>,
    pub osv_id: String,
}
