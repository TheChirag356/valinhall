# Valinhall 🛡️

> AI-Assisted Automated Security Testing Tool

A high-performance security scanner built with a Rust CLI engine and a SvelteKit web dashboard, covering OWASP Top 10 (2026 draft), LLM red-teaming, and multi-ecosystem dependency auditing.

Test site: https://pentest-ground.com/

## Table of Contents

- [Valinhall 🛡️](#valinhall-️)
  - [Table of Contents](#table-of-contents)
  - [Monorepo Structure](#monorepo-structure)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
  - [CLI Usage](#cli-usage)
    - [`scan` — Web or Local Codebase](#scan--web-or-local-codebase)
    - [`audit` — Dependency Vulnerabilities](#audit--dependency-vulnerabilities)
    - [`report` — Generate HTML Report](#report--generate-html-report)
    - [`serve` — Live Dashboard Server](#serve--live-dashboard-server)
  - [Scanning a Local Codebase](#scanning-a-local-codebase)
    - [What SAST scans](#what-sast-scans)
    - [Common workflows](#common-workflows)
    - [Example output](#example-output)
  - [Output Files](#output-files)
  - [OWASP 2026 Coverage](#owasp-2026-coverage)
  - [SAST Rules Reference](#sast-rules-reference)
  - [Development](#development)
    - [CI Integration](#ci-integration)

---

## Monorepo Structure

```
valinhall/
├── apps/
│   ├── cli/          # Rust CLI scanner engine
│   └── dashboard/    # SvelteKit web dashboard
├── packages/
│   └── shared-types/ # Shared TypeScript types
├── pnpm-workspace.yaml
└── package.json
```

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| [Rust](https://rustup.rs/) | stable | MSVC toolchain required on Windows |
| [Node.js](https://nodejs.org/) | ≥ 20.0 | |
| [pnpm](https://pnpm.io/) | ≥ 9.0 | `npm i -g pnpm` |

---

## Quick Start

```bash
# 1. Install Node dependencies
pnpm install

# 2. Build the Rust CLI (release mode)
pnpm cli:build

# 3a. Scan a remote web target
./apps/cli/target/release/valinhall scan --target https://example.com

# 3b. Scan a local codebase (SAST only)
./apps/cli/target/release/valinhall scan --target ./my-project --sast-only

# 4. Start the dashboard
pnpm dev
```

> **Windows users:** Use `.\apps\cli\target\release\valinhall.exe` or add the binary to your `PATH`.

---

## CLI Usage

```
valinhall <COMMAND> [OPTIONS]

Commands:
  scan    Run a security scan against a URL or local directory
  audit   Audit dependencies for known CVEs (via OSV.dev)
  report  Generate a standalone HTML report from a JSON scan result
  serve   Start an embedded HTTP server for live dashboard integration

Global Options:
  -v, --verbose   Increase log verbosity (repeat for more: -v, -vv, -vvv)
  -h, --help      Print help
  -V, --version   Print version
```

---

### `scan` — Web or Local Codebase

Runs a full security scan. Automatically selects SAST, DAST, or both depending on whether the target is a URL or a local path.

```
valinhall scan --target <TARGET> [OPTIONS]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-t, --target` | string | **required** | URL (`https://…`) or local directory path |
| `-o, --output` | string | current dir | Output path for JSON results. Can be a file or directory. |
| `--report` | bool | `true` | Generate an HTML report alongside the JSON output |
| `--sast-only` | flag | false | Run only static analysis — skip DAST (network attacks) |
| `--dast-only` | flag | false | Run only dynamic analysis — skip SAST |
| `--llm` | flag | false | Include LLM red-team probes |
| `--concurrency` | number | `20` | Max concurrent HTTP requests (DAST only) |
| `--timeout` | number | `10` | Request timeout in seconds (DAST only) |

**Examples:**

```bash
# Scan a live web application (DAST + dependency probes)
valinhall scan --target https://my-app.example.com

# Scan with LLM red-team probes enabled
valinhall scan --target https://my-app.example.com --llm

# Scan a local directory for source code vulnerabilities (SAST only)
valinhall scan --target ./src --sast-only

# Scan entire codebase, save results to a specific directory
valinhall scan --target . --sast-only --output ./reports/

# Scan both local + remote (run SAST on local, then DAST on a URL)
valinhall scan --target . --sast-only --output scan-local.json
valinhall scan --target https://staging.example.com --dast-only --output scan-remote.json

# Scan with higher concurrency for faster DAST
valinhall scan --target https://example.com --concurrency 50 --timeout 15

# Verbose output (useful for debugging)
valinhall -vv scan --target https://example.com
```

If it had found an issue, it would parse the CVSS (Common Vulnerability Scoring System) score to give you a severity rating (Low, Medium, High, Critical), tell you which package is vulnerable, and print the title/CVE ID so you can investigate.

---

### `audit` — Dependency Vulnerabilities

Audits project dependencies against the [OSV.dev](https://osv.dev) vulnerability database. Auto-detects lock files for Node.js (`package-lock.json`), Rust (`Cargo.lock`), and Go (`go.sum`).

```
valinhall audit [OPTIONS]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-p, --path` | string | `.` (current dir) | Root of the project to audit |
| `--ecosystems` | string | `node,rust,go` | Comma-separated list of ecosystems to check |
| `--fail-on-vuln` | flag | false | Exit with code `1` if any vulnerabilities are found (useful in CI) |

**Examples:**

```bash
# Audit all ecosystems in the current directory
valinhall audit

# Audit a specific project directory
valinhall audit --path ./my-rust-app

# Audit only Node.js dependencies
valinhall audit --ecosystems node

# Audit Node + Rust, fail the pipeline if any CVEs are found
valinhall audit --ecosystems node,rust --fail-on-vuln

# Audit a Go project
valinhall audit --path ./my-go-service --ecosystems go
```

---

### `report` — Generate HTML Report

Converts a previously saved JSON scan result into a self-contained HTML report.

```
valinhall report --input <JSON_FILE> [--output <HTML_FILE>]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-i, --input` | string | **required** | Path to a `scan-result-*.json` file |
| `-o, --output` | string | auto-generated | Output HTML file path |

**Examples:**

```bash
# Generate an HTML report from a saved JSON result
valinhall report --input scan-result-20260101-120000.json

# Specify a custom output filename
valinhall report --input scan-result-20260101-120000.json --output my-report.html
```

---

### `serve` — Live Dashboard Server

Starts an embedded HTTP server that the SvelteKit dashboard connects to for real-time scan results.

```
valinhall serve [OPTIONS]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-p, --port` | number | `7474` | Port to listen on |
| `-t, --target` | string | none | Immediately start a scan against this target on server start |

**Examples:**

```bash
# Start the server (dashboard connects to http://localhost:7474)
valinhall serve

# Start on a custom port
valinhall serve --port 8080

# Start and immediately kick off a scan
valinhall serve --target https://my-app.example.com

# Then open the dashboard in a separate terminal
pnpm dev
```

---

## Scanning a Local Codebase

When `--target` is a **local directory path** (not starting with `http://` or `https://`), Valinhall automatically runs the **SAST (Static Analysis)** engine instead of DAST.

### What SAST scans

The SAST engine recursively walks your source tree and checks all supported file types for security issues using regex-based rules. It skips `node_modules/`, `target/`, `.git/`, `dist/`, `build/`, and `.svelte-kit/` directories automatically.

**Supported file types:** `.rs`, `.js`, `.ts`, `.jsx`, `.tsx`, `.py`, `.go`, `.java`, `.php`, `.rb`, `.cs`, `.cpp`, `.c`, `.h`, `.swift`, `.kt`, `.scala`, `.env`, `.yaml`, `.yml`, `.json`, `.toml`, `.ini`, `.cfg`, `.conf`

### Common workflows

```bash
# Scan your entire monorepo root
valinhall scan --target . --sast-only

# Scan only the backend service
valinhall scan --target ./apps/api --sast-only

# Scan and write results to a reports directory
valinhall scan --target . --sast-only --output ./reports/

# Run SAST and also audit dependencies in one step
valinhall scan --target . --sast-only
valinhall audit --path .

# CI: fail if any critical/high findings
# (check the JSON exit code or filter the report)
valinhall scan --target . --sast-only --output ci-results.json
```

### Example output

```
▶ Scanning: ./my-project
  Scan ID: a3f1d2e4-...
  Started:  2026-01-01T12:00:00Z

  ✓ SAST: 7 findings

  💾 JSON:   scan-result-20260101-120000.json
  📄 Report: valinhall-report-20260101-120000.html

  ┌─────────────────────────────┐
  │       SCAN SUMMARY          │
  ├─────────────────────────────┤
  │  ● Critical:   2            │
  │  ● High:       3            │
  │  ● Medium:     1            │
  │  ● Low:        1            │
  │  ● Info:       0            │
  ├─────────────────────────────┤
  │  Total:        7            │
  └─────────────────────────────┘
```

---

## Output Files

Every `scan` run produces two files in the output directory (current directory by default):

| File | Description |
|---|---|
| `scan-result-<YYYYMMDD-HHmmss>.json` | Machine-readable findings in JSON format |
| `valinhall-report-<YYYYMMDD-HHmmss>.html` | Self-contained HTML report (generated when `--report` is true, which is the default) |

Pass `--output <dir>` to redirect both files to a specific directory, or `--output <file>.json` to write to an exact path.

```bash
# Write to a custom directory
valinhall scan --target https://example.com --output ./reports/

# Write to an exact filename
valinhall scan --target ./src --sast-only --output ./ci/scan-output.json
```

---

## OWASP 2026 Coverage

| # | Category | Engine / Probe |
|---|---|---|
| A01 | Broken Access Control | `probes/auth` |
| A02 | Cryptographic Failures | `engine/sast` |
| A03 | Software Supply Chain Failures | `engine/supply` |
| A04 | Insecure Design | `probes/auth` |
| A05 | Security Misconfiguration | `engine/dast` |
| A06 | Vulnerable Components | `engine/supply` |
| A07 | Identification & Auth Failures | `probes/auth` |
| A08 | Software & Data Integrity Failures | `probes/injection` |
| A09 | Security Logging Failures | `probes/exceptions` |
| A10 | Mishandling Exceptional Conditions | `probes/exceptions` |
| LLM | AI/LLM Red-Teaming | `probes/llm` |

---

## SAST Rules Reference

These rules are applied during every local codebase scan:

| Rule | Severity | Languages | Description |
|---|---|---|---|
| Hardcoded Secret (Generic) | 🔴 Critical | All | API keys, tokens, passwords assigned as string literals |
| Hardcoded AWS Key | 🔴 Critical | All | AWS Access Key ID pattern (`AKIA…`) |
| Hardcoded Private Key | 🔴 Critical | All | `BEGIN PRIVATE KEY` blocks in source |
| JWT Secret Hardcoded | 🔴 Critical | All | Hardcoded JWT signing secrets |
| SQL Injection Sink | 🟠 High | All | String-concatenated SQL queries |
| eval() Usage | 🟠 High | JS/TS/Python | Dynamic code execution via `eval()` |
| subprocess shell=True | 🟠 High | Python | Shell injection risk in subprocess calls |
| Disabled TLS Verification | 🟠 High | All | `verify=False`, `rejectUnauthorized: false` |
| Path Traversal Sink | 🟠 High | RS/JS/PY | User input in file path construction |
| Pickle Deserialization | 🟠 High | Python | `pickle.load()` on untrusted data |
| innerHTML Assignment | 🟡 Medium | JS/TS | XSS risk via unescaped HTML assignment |
| Insecure Random | 🟡 Medium | JS/TS | `Math.random()` for security-sensitive values |
| MD5 / SHA1 Usage | 🟡 Medium | All | Broken cryptographic hash functions |
| CORS Allow All Origins | 🟡 Medium | All | Wildcard `Access-Control-Allow-Origin: *` |
| XML External Entity Risk | 🟡 Medium | All | XML parsers without explicit XXE protection |
| Debug Mode Enabled | 🟡 Medium | Py/JS | `DEBUG=True` / `debug: true` in production configs |
| Potential ReDoS | 🟡 Medium | All | Nested regex quantifiers `(a+)+` inside patterns |
| Unsafe Rust Block | 🔵 Low | Rust | `unsafe {}` blocks — flagged for review |
| Hardcoded IP Address | ⚪ Info | All | Hardcoded infrastructure IP references |
| TODO/FIXME Security Comment | ⚪ Info | All | Unresolved security `TODO` or `FIXME` notes |

---

## Development

```bash
# Run CLI tests (Rust)
pnpm cli:test

# Build CLI in debug mode (faster compile)
cargo build --manifest-path apps/cli/Cargo.toml

# Build CLI in release mode
pnpm cli:build

# Type-check dashboard
pnpm type-check

# Development server (dashboard + hot reload)
pnpm dev

# Run with verbose logging during development
RUST_LOG=debug ./apps/cli/target/debug/valinhall scan --target .
```

### CI Integration

```yaml
# Example GitHub Actions step
- name: Security scan
  run: |
    cargo build --release --manifest-path apps/cli/Cargo.toml
    ./target/release/valinhall scan --target . --sast-only --output reports/
    ./target/release/valinhall audit --fail-on-vuln
```
