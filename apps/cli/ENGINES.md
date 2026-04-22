# Valinhall — Advanced Detection Engine

> **AI-Assisted Automated Security Testing Tool**  
> OWASP Top 10 · Nuclei Templates · OSV CVE Lookup · ML Anomaly Detection · LLM WAF Bypass

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation & Build](#installation--build)
3. [Quick Start](#quick-start)
4. [Detection Engines](#detection-engines)
   - [Nuclei Template Runner](#1-nuclei-template-runner---nuclei)
   - [OSV Blackbox Fingerprinting](#2-osv-blackbox-fingerprinting---osv-blackbox)
   - [K-Means Anomaly Detection](#3-k-means-anomaly-detection---anomaly)
   - [LLM WAF Mutator](#4-llm-waf-mutator---waf-mutator)
   - [TCP Port Scanner](#5-tcp-port-scanner---port-scan)
   - [Endpoint Crawler + Vuln Tester](#6-endpoint-crawler--vuln-tester---blackbox)
5. [Full CLI Reference](#full-cli-reference)
6. [Environment Variables](#environment-variables)
7. [Example Scan Recipes](#example-scan-recipes)
8. [Finding Sources](#finding-sources)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | ≥ 1.78 | Install via [rustup.rs](https://rustup.rs) |
| Cargo | ≥ 1.78 | Bundled with Rust |
| Git | Any | For cloning Nuclei templates |
| OpenRouter API key | — | **Only** for `--waf-mutator` |

---

## Installation & Build

```bash
# Clone the repository
git clone https://github.com/TheChirag356/valinhall
cd valinhall/apps/cli

# Development build
cargo build

# Optimised release build (recommended for scanning)
cargo build --release

# Run directly
cargo run -- --help

# Or after installing
cargo install --path .
valinhall --help
```

---

## Quick Start

```bash
# Basic DAST scan
valinhall scan --target https://example.com

# SAST scan on a local project
valinhall scan --target ./my-project

# Full upgrade: all four new engines
valinhall scan \
  --target https://example.com \
  --nuclei \
  --osv-blackbox \
  --anomaly \
  --waf-mutator
```

---

## Detection Engines

### 1. Nuclei Template Runner — `--nuclei`

Executes community-maintained YAML security templates against the target. Equivalent to running Project Discovery's Nuclei scanner — but natively in Rust inside the same pipeline.

#### Setup: download templates

```bash
# Default location — Valinhall looks here automatically
git clone https://github.com/projectdiscovery/nuclei-templates \
          ~/.valinhall/nuclei-templates

# Or update an existing clone
git -C ~/.valinhall/nuclei-templates pull
```

#### Usage

```bash
# Run ALL templates in the default directory
valinhall scan --target https://example.com --nuclei

# Use a custom templates directory
valinhall scan --target https://example.com \
  --nuclei \
  --nuclei-templates /path/to/my-templates

# Only run templates tagged with specific categories
valinhall scan --target https://example.com \
  --nuclei \
  --nuclei-tags xss,sqli,cve

# Combine multiple tag filters (comma-separated)
valinhall scan --target https://example.com \
  --nuclei \
  --nuclei-tags "xss,sqli,lfi,rce,cve,exposure,misconfig"
```

#### What the engine supports

| Feature | Supported |
|---------|-----------|
| `requests:` and `http:` block aliases | ✅ |
| GET, POST, PUT, DELETE, HEAD methods | ✅ |
| `{{BaseURL}}` / `{{RootURL}}` interpolation | ✅ |
| `word`, `status`, `regex` matchers | ✅ |
| `matcher-condition: and \| or` | ✅ |
| Negative matchers (`negative: true`) | ✅ |
| `regex` and `word` extractors | ✅ |
| Named extractor groups | ✅ |
| CVE / severity / tags metadata | ✅ |
| Raw HTTP / TCP templates | ❌ (HTTP only) |
| Nuclei DAST variables (`{{username}}`) | ❌ (planned) |

#### Write your own template

```yaml
# ~/.valinhall/nuclei-templates/my-custom/debug-page.yaml
id: exposed-debug-page

info:
  name: "Exposed Debug Page"
  author: [yourname]
  severity: high
  description: "Checks for an exposed debug endpoint."
  tags: [exposure, debug]

requests:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/debug/info"
    matchers:
      - type: word
        words:
          - "DEBUG"
          - "stack trace"
        condition: or
        part: body
      - type: status
        status: [200]
    matcher-condition: and
```

---

### 2. OSV Blackbox Fingerprinting — `--osv-blackbox`

During a DAST scan, Valinhall reads the `Server`, `X-Powered-By`, and similar response headers to fingerprint the technology stack. Each detected version is then queried against the [OSV.dev](https://osv.dev) public API, returning known CVEs.

#### Usage

```bash
# Fingerprint + CVE lookup in a single flag
valinhall scan --target https://example.com --osv-blackbox

# Combine with DAST for a complete blackbox audit
valinhall scan --target https://example.com --osv-blackbox
```

#### What gets detected

| Header | Example value | Detected as |
|--------|---------------|-------------|
| `Server` | `nginx/1.18.0` | nginx 1.18.0 → Debian ecosystem |
| `Server` | `Apache/2.4.51 (Unix)` | Apache 2.4.51 → Debian ecosystem |
| `X-Powered-By` | `PHP/8.0.12` | PHP 8.0.12 → Packagist |
| `X-Powered-By` | `ASP.NET/4.0.30319` | ASP.NET → NuGet |
| `Server` | `Jetty/9.4.43` | Jetty → Maven |
| `X-Generator` | `WordPress 6.4` | WordPress → Packagist |

#### No API key required — OSV.dev is fully public.

Severity is derived from the CVSS score embedded in each OSV advisory:

| CVSS | Severity |
|------|----------|
| ≥ 9.0 | 🔴 Critical |
| ≥ 7.0 | 🟠 High |
| ≥ 4.0 | 🟡 Medium |
| > 0.0 | 🔵 Low |
| Absent | 🟡 Medium (conservative) |

---

### 3. K-Means Anomaly Detection — `--anomaly`

Standard scanners only find what they know to look for. The anomaly engine finds what is *statistically unusual* — hidden admin panels, staging endpoints, or pages with unexpected response patterns that no template would ever catch.

#### How it works

1. Probes ~50 seed paths (`/admin`, `/actuator`, `/.env`, `/graphql`, `/backup.zip`, …)
2. Builds a 4-feature vector per response:
   - HTTP status code
   - Body length (log-scaled)
   - Number of response headers
   - Response time in ms (log-scaled)
3. Runs **K-Means clustering** (k=5 by default)
4. Flags **two types of anomalies**:
   - **Singleton cluster** — the only response in its cluster (unique pattern)
   - **High-distance outlier** — centroid distance > mean + 2.5×σ

#### Usage

```bash
# Run anomaly detection
valinhall scan --target https://example.com --anomaly

# Combined with DAST for best coverage
valinhall scan --target https://example.com --anomaly --concurrency 10
```

> **Note:** At least 6 seed paths must respond for clustering to run. With the default concurrency of 10, this typically takes 5–10 seconds.

#### What it catches (examples)

- An `/internal/debug` that returns `200 OK` but with 0 bytes — anomalous size
- A `/admin` that has 2× more headers than every other endpoint — fingerprints a different backend
- A `/api/v2/config` that responds in 2000ms while everything else is 50ms — possible SSRF or slow query

---

### 4. LLM WAF Mutator — `--waf-mutator`

When the DAST engines get a **403 or 406** response (WAF block), the mutator kicks in. It sends the blocked payload and the server's response to **Google Gemma 4 31B** via OpenRouter, asking the model to suggest bypass variants. Valinhall then automatically retries each suggestion.

#### Setup

```bash
# Required: get a free API key at https://openrouter.ai
export OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxx

# Optional: override the model (default is google/gemma-4-31b-it:free)
export OPENROUTER_MODEL=google/gemma-4-31b-it:free
```

#### Usage

```bash
# Enable WAF mutator (auto-reads OPENROUTER_API_KEY from env)
valinhall scan --target https://example.com --waf-mutator

# Best results: run full DAST first so there are blocked findings to mutate
valinhall scan --target https://example.com --waf-mutator --concurrency 20
```

> **Important:** `--waf-mutator` only triggers **after** DAST/injection phases produce 403/406 findings. Always run a full scan (not `--sast-only`).

#### Rate limiting & retry policy

| Parameter | Value | Configurable via |
|-----------|-------|-----------------|
| Max LLM calls per minute | 10 | `MAX_LLM_CALLS_PER_MIN` constant |
| Max concurrent LLM calls | 2 | Semaphore in code |
| Max retries per call | 4 | `MAX_RETRIES` constant |
| Back-off base delay | 500ms | `BASE_BACKOFF_MS` |
| Back-off jitter | 0–300ms | `MAX_JITTER_MS` |
| Retry triggers | 429, 500, 502, 503, 504 | — |
| `Retry-After` header | Honoured | — |
| Max blocked findings mutated | 5 per scan | `take(5)` in main.rs |
| Max mutations per payload | 5 | `MAX_MUTATIONS` |

#### Bypass techniques the LLM explores

1. URL encoding (single, double, mixed)
2. HTML entity encoding
3. Unicode / UTF-8 normalization
4. Whitespace / comment insertion (`<scr/**/ipt>`)
5. Case variation (`<ScRiPt>`)
6. Alternative tags / event handlers (`<img onerror=...>`, `<svg onload=...>`)
7. Null byte injection
8. HTTP parameter pollution
9. JSON/XML encoding

#### Output findings

| Scenario | Finding title | Severity |
|----------|--------------|----------|
| A mutation bypasses the WAF | `[WAF Bypass] Injection Succeeded After Mutation` | 🟠 High |
| WAF blocks all mutations | `[WAF] Active Protection Confirmed` | ⬜ Info |
| `--waf-mutator` but no OPENROUTER_API_KEY | Skipped with info message | — |

---

### 5. TCP Port Scanner — `--port-scan`

Scans **all TCP ports 1–10000** plus a curated list of **~60 high-value hidden ports** above 10000 (databases, message queues, Kubernetes, Docker, dev servers, etc.). Every open port receives a banner-grab attempt and is fingerprinted against a known-service table.

#### Usage

```bash
valinhall scan --target https://example.com --port-scan
```

#### What gets scanned

| Range | Ports |
|-------|-------|
| Full sequential sweep | 1 – 10,000 |
| MongoDB | 27017, 27018, 27019, 28017 |
| Elasticsearch / Kibana | 9200, 9300, 5601 |
| Redis | 6379, 6380 |
| Kafka / ZooKeeper | 9092, 9093, 2181 |
| Kubernetes | 6443, 10250, 10255 |
| Docker | 2376, 2377 |
| RabbitMQ | 5672, 15672 |
| Databases | 5432, 3306, 1521, 5984, 7474 |
| Remote access | 3389, 5900-5902, 5985 |
| Dev / CI | 8080-8090, 8888, 50000 |
| Vault / Consul / etcd | 8200, 8300-8302, 2379 |
| Misc | 11434, 61616, 16686, 9411 |

#### Findings generated

| Severity | Condition |
|----------|-----------|
| 🔴 Critical | Telnet (23), SMB (445), MongoDB, Redis, Memcached, Elasticsearch, Kubelet, Docker, Jupyter |
| 🟠 High | RDP, VNC, WinRM, MySQL, PostgreSQL, FTP, ActiveMQ, Kafka |
| 🟡 Medium | Unknown high-numbered open ports, Prometheus, PHP-FPM |
| 🔵 Info | Summary of all open ports |

---

### 6. Endpoint Crawler + Vuln Tester — `--blackbox`

A two-phase automated blackbox assessment:

**Phase 1 — Endpoint Discovery** crawls all accessible paths using:
- Link crawling (href attributes on the landing page)
- `robots.txt` Disallow/Allow entries
- `sitemap.xml` `<loc>` entries
- Inline and external JavaScript API route mining (regex patterns for `/api/…`, `/v1/…`, `/graphql/…`)
- **500-entry wordlist** of common admin, API, debug, backup, and config paths

**Phase 2 — Vulnerability Testing** probes every discovered endpoint for:

| Check | Severity | Description |
|-------|----------|-------------|
| CORS misconfiguration | 🟠 High | Wildcard ACAO + credentials, or arbitrary origin reflection |
| Sensitive file exposure | 🔴–🟡 | `.env`, `.git/HEAD`, `phpinfo`, actuator endpoints |
| Dangerous HTTP methods | 🟡 Medium | PUT, DELETE, PATCH, TRACE accepted |
| Open redirect | 🟡 Medium | `?redirect=`, `?url=`, `?next=` parameters |
| Path traversal | 🔴 Critical | `../../../../etc/passwd` sequences |
| SSRF — cloud metadata | 🔴 Critical | AWS `169.254.169.254` metadata via URL params |
| Auth bypass via headers | 🟠 High | `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin` |
| IDOR | 🟠 High | API endpoints returning sensitive data for arbitrary IDs |

#### Usage

```bash
# Full automatic blackbox test
valinhall scan --target https://example.com --blackbox

# Combined: port scan + full blackbox
valinhall scan --target https://example.com --port-scan --blackbox

# Maximum coverage kitchen-sink
valinhall scan --target https://example.com \
  --port-scan --blackbox --anomaly --osv-blackbox --nuclei --waf-mutator
```

---

## Full CLI Reference

```
valinhall scan [OPTIONS] --target <TARGET>

SCAN OPTIONS:
  -t, --target <TARGET>              Target URL or local path
  -o, --output <OUTPUT>              Output directory/file for JSON results
      --report                       Generate HTML report (default: true)
      --sast-only                    Run only SAST (skip DAST)
      --dast-only                    Run only DAST (skip SAST)
      --llm                          Enable LLM red-team probes
      --concurrency <N>              Max concurrent HTTP requests [default: 20]
      --timeout <SECS>               Per-request timeout [default: 10]

NEW ENGINES:
      --nuclei                       Run Nuclei YAML template engine
      --nuclei-templates <PATH>      Templates directory [default: ~/.valinhall/nuclei-templates]
      --nuclei-tags <TAGS>           Comma-separated tag filter (e.g. "xss,sqli,cve")
      --osv-blackbox                 Fingerprint server headers + query OSV.dev for CVEs
      --anomaly                      Run K-Means anomaly detection on HTTP responses
      --waf-mutator                  Use LLM to mutate blocked payloads (needs OPENROUTER_API_KEY)
      --port-scan                    Scan TCP ports 1-10000 + 60+ hidden high-value ports
      --blackbox                     Auto-discover endpoints (crawl+wordlist+JS) and test each
                                     for CORS, IDOR, SSRF, path traversal, open redirect, auth bypass

OTHER COMMANDS:
  valinhall audit --path <PATH>      Audit dependencies (Node/Rust/Go) via OSV.dev
  valinhall report --input <FILE>    Regenerate HTML report from a JSON result
  valinhall serve --port <PORT>      Start embedded dashboard server

GLOBAL FLAGS:
  -v, -vv, -vvv                      Verbosity (info / debug / trace)
  -h, --help                         Print help
  -V, --version                      Print version
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENROUTER_API_KEY` | For `--waf-mutator` | — | API key from [openrouter.ai](https://openrouter.ai) |
| `OPENROUTER_MODEL` | No | `google/gemma-4-31b-it:free` | OpenRouter model ID to use |
| `RUST_LOG` | No | `warn` | Override log level (`info`, `debug`, `trace`) |

---

## Example Scan Recipes

### Minimal blackbox scan
```bash
valinhall scan --target https://target.example.com
```

### Nuclei-only with tag filter
```bash
valinhall scan --target https://target.example.com \
  --nuclei \
  --nuclei-tags "cve,exposure,misconfig" \
  --dast-only
```

### OSV fingerprint + supply chain audit
```bash
# Blackbox: fingerprint the live server
valinhall scan --target https://target.example.com --osv-blackbox

# Whitebox: audit the project's lock files
valinhall audit --path ./my-project --ecosystems node,rust
```

### Anomaly-focused recon
```bash
valinhall scan --target https://target.example.com \
  --anomaly \
  --dast-only \
  --concurrency 15 \
  --timeout 8 \
  -v
```

### Full kitchen-sink scan
```bash
export OPENROUTER_API_KEY=sk-or-v1-...

valinhall scan \
  --target https://target.example.com \
  --nuclei \
  --nuclei-templates ~/.valinhall/nuclei-templates \
  --nuclei-tags "xss,sqli,lfi,rce,cve,exposure" \
  --osv-blackbox \
  --anomaly \
  --waf-mutator \
  --llm \
  --concurrency 20 \
  --timeout 15 \
  -vv
```

### CI pipeline (fail on High+)
```bash
valinhall scan --target $STAGING_URL \
  --nuclei \
  --osv-blackbox \
  --dast-only \
  --report false \
  --output ./ci-results/
# Check exit code or parse JSON for severity
```

---

## Finding Sources

Every finding in the JSON/HTML report carries a `source` field indicating which engine found it:

| `source` value | Engine |
|---------------|--------|
| `"SAST"` | Static analysis (Rust/JS/Go AST rules) |
| `"DAST"` | Dynamic probes (injection, auth, headers) |
| `"Supply Chain"` | Dependency audit (OSV batch API) |
| `"LLM Probe"` | AI red-team (prompt injection, PII) |
| `"Nuclei Templates"` | Nuclei YAML template runner |
| `"OSV Blackbox"` | Header fingerprint → OSV CVE lookup |
| `"Anomaly Engine"` | K-Means HTTP response clustering |
| `"WAF Mutator"` | LLM-assisted WAF bypass |
| `"Port Scanner"` | TCP port scan with banner grabbing |
| `"Endpoint Crawler"` | Discovered endpoints (crawl/wordlist/JS) |
| `"Vuln Tester"` | CORS/IDOR/SSRF/traversal/redirect/bypass checks |

---

## Troubleshooting

### Nuclei engine finds 0 templates

```
⚠ No Nuclei templates found in ~/.valinhall/nuclei-templates
```

**Fix:** Clone the community templates:
```bash
git clone https://github.com/projectdiscovery/nuclei-templates \
          ~/.valinhall/nuclei-templates
```
Or pass `--nuclei-templates /your/custom/path`.

---

### WAF Mutator skipped

```
ℹ WAF Mutator skipped: OPENROUTER_API_KEY not set
```

**Fix:**
```bash
export OPENROUTER_API_KEY=sk-or-v1-xxxxxxxx
```
Then re-run the scan. Get a free key at [openrouter.ai](https://openrouter.ai).

---

### WAF Mutator produces 0 findings

The mutator only runs on findings that contain `403` or `406` in their evidence string. If DAST didn't trigger any WAF responses, there is nothing to mutate. Try a more aggressive payload set or scan an endpoint that actually has a WAF.

---

### Anomaly engine skipped

```
⚠ Anomaly engine: only N responses collected — need at least 6
```

**Cause:** The target is blocking or timing out most seed paths.  
**Fix:** Increase `--timeout` or reduce `--concurrency` to avoid triggering rate limits:
```bash
valinhall scan --target https://example.com --anomaly --timeout 15 --concurrency 5
```

---

### OSV Blackbox returns nothing

The server may not expose a versioned `Server` header (e.g. Cloudflare, AWS ALB). This is actually good security hygiene! The engine will log:
```
ℹ OSV blackbox: no technology fingerprints detected
```
No action needed.

---

### Build errors with linfa

```
error: failed to select a version for `linfa-clustering`
```

**Fix:** Ensure your `Cargo.toml` uses plain version strings (no feature flags):
```toml
linfa             = "0.7"
linfa-clustering  = "0.7"
ndarray           = "0.15"
```
Then run `cargo clean && cargo build`.
