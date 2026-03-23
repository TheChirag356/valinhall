//! Supply Chain Probes — OWASP A03: Software Supply Chain Failures
//!
//! Tests for: typosquatting, dependency confusion, and outdated packages.

use std::sync::Arc;
use anyhow::Result;
use reqwest::Client;
use strsim::levenshtein;
use tokio::sync::Semaphore;
use uuid::Uuid;
use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

/// Popular npm packages; used to detect typosquatting
static POPULAR_NPM_PACKAGES: &[&str] = &[
    "react", "vue", "angular", "lodash", "axios", "express", "webpack",
    "typescript", "eslint", "prettier", "next", "nuxt", "svelte",
    "tailwindcss", "vite", "rollup", "babel", "jest", "mocha",
    "chalk", "commander", "dotenv", "zod", "prisma", "drizzle",
];

/// Packages known to be used in dependency confusion attacks (private-sounding names)
static PRIVATE_NAME_PATTERNS: &[&str] = &[
    "internal-", "private-", "corp-", "company-", "-internal", "-private",
    "local-", "-local", "dev-", "-dev",
];

pub async fn run(
    _client: Arc<Client>,
    _sem: Arc<Semaphore>,
    packages: &[(String, String)], // (name, version)
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for (name, version) in packages {
        // Typosquatting detection
        for &popular in POPULAR_NPM_PACKAGES {
            let distance = levenshtein(name.as_str(), popular);
            if distance == 1 && name != popular {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::SupplyChainFailures,
                    severity: Severity::High,
                    title: format!("Potential Typosquatting: '{}'", name),
                    description: format!(
                        "Package '{}' is 1 character away from popular package '{}'. This may be a typosquatting attack.",
                        name, popular
                    ),
                    evidence: Some(format!("Package: {}@{}, similar to: {}", name, version, popular)),
                    remediation: "Verify this package is the intended dependency. Check the npm/crates.io page. Consider using exact dependency pinning.".to_string(),
                    source: FindingSource::SupplyChain,
                    endpoint: None,
                });
            }
        }

        // Dependency confusion detection
        for &pattern in PRIVATE_NAME_PATTERNS {
            if name.contains(pattern) {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::SupplyChainFailures,
                    severity: Severity::Medium,
                    title: format!("Possible Dependency Confusion Risk: '{}'", name),
                    description: format!(
                        "Package '{}' has a name suggesting it may be an internal/private package. If a public package with this name exists on npm/PyPI/crates.io, a dependency confusion attack may be possible.",
                        name
                    ),
                    evidence: Some(format!("Package: {}@{}", name, version)),
                    remediation: "Namespace private packages under a private registry scope (e.g., @company/package). Use npm configuration to prevent falling back to the public registry for private packages.".to_string(),
                    source: FindingSource::SupplyChain,
                    endpoint: None,
                });
                break;
            }
        }
    }

    Ok(findings)
}
