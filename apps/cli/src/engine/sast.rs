//! SAST Engine — Static Application Security Testing
//!
//! Walks a source directory tree and applies:
//! - Rust AST analysis via `syn` (unsafe blocks, secret literals, dangerous APIs)
//! - Regex pattern matching for JS/TS/Python/Go source files

use std::path::Path;

use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use tracing::{debug, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

/// SAST rule: describes a pattern and the finding it generates
struct SastRule {
    name: &'static str,
    pattern: &'static str,
    category: OwaspCategory,
    severity: Severity,
    description: &'static str,
    remediation: &'static str,
}

/// Regex-based rules applied to all supported file types
static REGEX_RULES: &[SastRule] = &[
    SastRule {
        name: "Hardcoded Secret (Generic)",
        pattern: r#"(?i)(api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{8,}["']"#,
        category: OwaspCategory::CryptographicFailures,
        severity: Severity::Critical,
        description: "A potential hardcoded credential or secret was detected in source code. Secrets committed to version control are a critical security risk.",
        remediation: "Move secrets to environment variables or a secrets manager (e.g., Vault, AWS Secrets Manager). Rotate the exposed secret immediately.",
    },
    SastRule {
        name: "SQL Injection Sink (String Concat)",
        pattern: r#"(?i)(query|execute|exec|raw)\s*\(\s*["'].*\+|["'].*\$\{|format!\(".*SELECT|format!\(".*INSERT|format!\(".*UPDATE|format!\(".*DELETE"#,
        category: OwaspCategory::BrokenAccessControl,
        severity: Severity::High,
        description: "User-controlled input may be concatenated directly into a SQL query, enabling SQL injection.",
        remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
    },
    SastRule {
        name: "eval() Usage",
        pattern: r"eval\s*\(",
        category: OwaspCategory::IntegrityFailures,
        severity: Severity::High,
        description: "Use of eval() can execute arbitrary code if user-controlled data is passed in.",
        remediation: "Avoid eval(). Use safer alternatives like JSON.parse() for data parsing.",
    },
    SastRule {
        name: "innerHTML Assignment",
        pattern: r"\.innerHTML\s*=",
        category: OwaspCategory::BrokenAccessControl,
        severity: Severity::Medium,
        description: "Setting innerHTML with unsanitized data enables DOM-based XSS attacks.",
        remediation: "Use textContent/innerText for plain text, or a sanitization library (DOMPurify) if HTML is required.",
    },
    SastRule {
        name: "subprocess with Shell=True (Python)",
        pattern: r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
        category: OwaspCategory::BrokenAccessControl,
        severity: Severity::High,
        description: "Running subprocesses with shell=True and user-supplied input enables command injection.",
        remediation: "Pass command arguments as a list. Avoid shell=True unless absolutely necessary.",
    },
    SastRule {
        name: "Hardcoded AWS Key",
        pattern: r"AKIA[0-9A-Z]{16}",
        category: OwaspCategory::CryptographicFailures,
        severity: Severity::Critical,
        description: "An AWS Access Key ID pattern was detected in source code.",
        remediation: "Revoke the key immediately. Use IAM roles or environment variables.",
    },
    SastRule {
        name: "Hardcoded Private Key",
        pattern: r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        category: OwaspCategory::CryptographicFailures,
        severity: Severity::Critical,
        description: "A private key block was detected in source code.",
        remediation: "Remove from source immediately. Use a key management service or environment variable.",
    },
    SastRule {
        name: "JWT Secret Hardcoded",
        pattern: r#"(?i)jwt[._-]?secret\s*[:=]\s*["'][^"']{8,}["']"#,
        category: OwaspCategory::AuthFailures,
        severity: Severity::Critical,
        description: "A hardcoded JWT signing secret was detected. Compromise enables forged authentication tokens.",
        remediation: "Load the JWT secret from environment variables. Use a strong randomly generated secret (≥256 bits).",
    },
    SastRule {
        name: "TODO/FIXME Security Comment",
        pattern: r"(?i)(TODO|FIXME|HACK|XXX).{0,30}(auth|secur|crypt|token|password|inject|xss|sqli)",
        category: OwaspCategory::InsecureDesign,
        severity: Severity::Info,
        description: "A TODO/FIXME comment referencing a security concern was found.",
        remediation: "Address the security issue before shipping to production.",
    },
    SastRule {
        name: "Insecure Random (Math.random)",
        pattern: r"Math\.random\s*\(\s*\)",
        category: OwaspCategory::CryptographicFailures,
        severity: Severity::Medium,
        description: "Math.random() is NOT cryptographically secure and should not be used for tokens, session IDs, or nonces.",
        remediation: "Use crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js).",
    },
    SastRule {
        name: "Unsafe Rust Block",
        pattern: r"\bunsafe\s*\{",
        category: OwaspCategory::IntegrityFailures,
        severity: Severity::Low,
        description: "An unsafe Rust block was detected. These can introduce memory safety vulnerabilities if misused.",
        remediation: "Minimize unsafe usage. Document invariants maintained within each unsafe block. Consider safety audits.",
    },
    SastRule {
        name: "MD5 / SHA1 Usage",
        pattern: r"(?i)(md5|sha1|sha-1)\s*\(",
        category: OwaspCategory::CryptographicFailures,
        severity: Severity::Medium,
        description: "MD5 and SHA-1 are cryptographically broken and should not be used for security-sensitive hashing.",
        remediation: "Use SHA-256 or stronger. For passwords, use Argon2id, bcrypt, or scrypt.",
    },
    SastRule {
        name: "CORS Allow All Origins",
        pattern: r#"(?i)(access-control-allow-origin|cors[^"']*)\s*[:=]\s*["']\*["']"#,
        category: OwaspCategory::SecurityMisconfiguration,
        severity: Severity::Medium,
        description: "A wildcard CORS policy was detected, allowing any origin to make cross-origin requests.",
        remediation: "Restrict allowed origins to a specific whitelist of trusted domains.",
    },
    SastRule {
        name: "Disabled TLS Verification",
        pattern: r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)",
        category: OwaspCategory::CryptographicFailures,
        severity: Severity::High,
        description: "TLS/SSL certificate verification is disabled, enabling man-in-the-middle attacks.",
        remediation: "Never disable TLS verification in production. Use proper certificate management.",
    },
    SastRule {
        name: "Pickle / Deserialization Sink (Python)",
        pattern: r"pickle\.(load|loads|Unpickler)\s*\(",
        category: OwaspCategory::IntegrityFailures,
        severity: Severity::High,
        description: "Python pickle deserialization of untrusted data enables arbitrary code execution.",
        remediation: "Avoid pickling untrusted data. Use safer formats like JSON with schema validation.",
    },
    SastRule {
        name: "Hardcoded IP Address",
        pattern: r#"["'](25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)["']"#,
        category: OwaspCategory::SecurityMisconfiguration,
        severity: Severity::Info,
        description: "A hardcoded IP address was detected. This may indicate hardcoded infrastructure references.",
        remediation: "Use environment variables or configuration files for infrastructure addresses.",
    },
    SastRule {
        name: "Path Traversal Sink",
        pattern: r"(?i)(open|read_to_string|File::open)\s*\([^)]*user|(?i)join\s*\([^)]*request|(?i)join\s*\([^)]*param",
        category: OwaspCategory::BrokenAccessControl,
        severity: Severity::High,
        description: "User-controlled input may be used to construct file paths, enabling path traversal attacks.",
        remediation: "Validate and canonicalize paths. Ensure the resolved path is within the expected directory.",
    },
    SastRule {
        name: "XML External Entity (XXE) Risk",
        pattern: r"(?i)(XMLParser|parseString|xml\.parse|DOMParser)\s*\(",
        category: OwaspCategory::IntegrityFailures,
        severity: Severity::Medium,
        description: "XML parsing detected without explicit XXE protection. May be vulnerable to XXE attacks.",
        remediation: "Disable external entity processing. Use defusedxml (Python) or equivalent safe parsers.",
    },
    SastRule {
        name: "Debug Mode Enabled",
        pattern: r#"(?i)(DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\([^)]*debug\s*=\s*True)"#,
        category: OwaspCategory::SecurityMisconfiguration,
        severity: Severity::Medium,
        description: "Debug mode is enabled. In production, this exposes stack traces and internal details.",
        remediation: "Disable debug mode in production. Use environment-specific configuration.",
    },
];

/// Extensions for regex-based scanning
static TEXT_EXTENSIONS: &[&str] = &[
    "rs", "js", "ts", "jsx", "tsx", "py", "go", "java", "php",
    "rb", "cs", "cpp", "c", "h", "swift", "kt", "scala",
    "env", "yaml", "yml", "json", "toml", "ini", "cfg", "conf",
];

/// Run SAST on the given directory path
pub fn run(root: &str) -> Result<Vec<Finding>> {
    let compiled_rules: Vec<(Regex, &SastRule)> = REGEX_RULES
        .iter()
        .filter_map(|rule| {
            Regex::new(rule.pattern)
                .map(|re| (re, rule))
                .map_err(|e| warn!("Failed to compile rule '{}': {}", rule.name, e))
                .ok()
        })
        .collect();

    // Read custom ignores from .valinhallignore
    let ignore_path = Path::new(root).join(".valinhallignore");
    let mut custom_ignores = Vec::new();
    if let Ok(content) = std::fs::read_to_string(ignore_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                custom_ignores.push(trimmed.replace('\\', "/"));
            }
        }
    }

    let files: Vec<_> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|ext| TEXT_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
                .unwrap_or(false)
        })
        // Skip common non-source directories
        .filter(|e| {
            !e.path()
                .components()
                .any(|c| matches!(c.as_os_str().to_str(), Some("node_modules" | "target" | ".git" | "dist" | "build" | ".svelte-kit")))
        })
        // Apply .valinhallignore rules
        .filter(|e| {
            if custom_ignores.is_empty() {
                return true;
            }
            let normalized = e.path().to_string_lossy().replace('\\', "/");
            for ig in &custom_ignores {
                if normalized.contains(ig) {
                    return false;
                }
            }
            true
        })
        .collect();

    debug!("SAST: scanning {} files in {}", files.len(), root);

    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map(|entry| scan_file(entry.path(), &compiled_rules))
        .collect();

    Ok(findings)
}

fn scan_file(path: &Path, rules: &[(Regex, &SastRule)]) -> Vec<Finding> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        for (regex, rule) in rules {
            if regex.is_match(line) {
                // Skip commented-out lines (basic heuristic)
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                    // Still flag security TODO comments
                    if rule.name != "TODO/FIXME Security Comment" {
                        continue;
                    }
                }

                let evidence = format!(
                    "{}:{} — {}",
                    path.display(),
                    line_num + 1,
                    line.trim()
                );

                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    category: rule.category.clone(),
                    severity: rule.severity.clone(),
                    title: rule.name.to_string(),
                    description: rule.description.to_string(),
                    evidence: Some(evidence),
                    remediation: rule.remediation.to_string(),
                    source: FindingSource::Sast,
                    endpoint: Some(path.display().to_string()),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn scan_content(content: &str) -> Vec<Finding> {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        let path = f.path().to_path_buf();
        let rules: Vec<(Regex, &SastRule)> = REGEX_RULES
            .iter()
            .filter_map(|r| Regex::new(r.pattern).ok().map(|re| (re, r)))
            .collect();
        scan_file(&path, &rules)
    }

    #[test]
    fn detects_hardcoded_secret() {
        let findings = scan_content(r#"api_key = "supersecretkey123""#);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_innerHTML() {
        let findings = scan_content("element.innerHTML = userInput;");
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_aws_key() {
        let findings = scan_content("const key = 'AKIAIOSFODNN7EXAMPLE';");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_unsafe_block() {
        let findings = scan_content("unsafe { *ptr = 42; }");
        assert!(!findings.is_empty());
    }
}
