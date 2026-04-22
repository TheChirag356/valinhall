//! Port Scanner Engine
//!
//! Performs asynchronous TCP port scanning against the target host:
//!
//! 1. **Full-range sweep** — tests ports 1–10000 plus a curated list of
//!    high-value "hidden" ports above 10000 (e.g. 27017, 5432, 6379, 8443, …)
//! 2. **Banner grabbing** — reads the first 512 bytes from every open TCP port
//!    within a short deadline (1 s) to identify the running service.
//! 3. **Service fingerprinting** — maps port numbers and banner content to
//!    known service labels and OWASP findings.
//! 4. **Dangerous service detection** — flags services that should never be
//!    internet-facing (MongoDB, Redis, Elasticsearch, MySQL, Memcached, RDP, …)
//!
//! The scanner is fully async: all ports are probed concurrently behind a
//! semaphore so we never exceed `concurrency` simultaneous TCP connections.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

// ── Configuration ─────────────────────────────────────────────────────────────

pub struct PortScanConfig {
    /// Timeout for each TCP connection attempt
    pub connect_timeout: Duration,
    /// Timeout for reading the service banner after connecting
    pub banner_timeout: Duration,
    /// Maximum concurrent TCP connections
    pub concurrency: usize,
    /// Upper bound of sequential scan range (1..=port_range_max)
    pub port_range_max: u16,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(800),
            banner_timeout: Duration::from_millis(1000),
            concurrency: 500,
            port_range_max: 10_000,
        }
    }
}

// ── "Hidden" high-value ports above 10000 ────────────────────────────────────

/// Ports above 10000 that are common targets but easily missed by basic scanners.
static EXTENDED_PORTS: &[u16] = &[
    // Databases
    27017, 27018, 27019, // MongoDB replica set
    28017,               // MongoDB HTTP status
    5432,                // PostgreSQL (sometimes on non-default high port)
    3306, 3307,          // MySQL / MariaDB
    1521, 1830,          // Oracle DB
    5984, 6984,          // CouchDB
    9200, 9300,          // Elasticsearch HTTP / transport
    5601,                // Kibana
    6379, 6380,          // Redis
    11211,               // Memcached
    7474, 7687,          // Neo4j HTTP / Bolt
    8086, 8088,          // InfluxDB
    // Message queues
    5672, 15672,         // RabbitMQ AMQP / management
    9092, 9093,          // Apache Kafka broker / TLS
    2181,                // ZooKeeper
    // Remote access / management
    3389,                // RDP
    5900, 5901, 5902,    // VNC
    5985, 5986,          // WinRM HTTP / HTTPS
    22222,               // Alt SSH
    10022,               // Alt SSH
    // Dev / CI servers
    8080, 8081, 8082, 8083, 8443, 8888, 9090, 9091,
    // Kubernetes / container
    10250, 10255, // Kubelet API
    6443,         // Kubernetes API server
    2376, 2377,   // Docker daemon / Swarm
    4149, 4243,   // cAdvisor / Docker alt
    // Consul / etcd / Vault
    8300, 8301, 8302, // Consul RPC
    4001, 2379, 2380, // etcd
    8200,             // Vault
    // Misc internal services
    11434,       // Ollama (local LLM)
    50000,       // SAP Message Server / Jenkins alt
    61616,       // Apache ActiveMQ
    18080,       // Alt HTTP
    16686,       // Jaeger UI
    14268,       // Jaeger collector
    9411,        // Zipkin
    3000, 3001,  // Grafana / Node apps
    4000, 4001,  // GraphQL / dev servers
    7000, 7001,  // Cassandra gossip / JMX
];

// ── Service fingerprinting table ──────────────────────────────────────────────

/// Map a port number to a (label, is_dangerous) tuple.
/// `is_dangerous = true` means this service should NOT be internet-facing.
fn fingerprint_port(port: u16, banner: &str) -> (&'static str, bool) {
    let banner_lc = banner.to_lowercase();

    // Banner-based override first
    if banner_lc.contains("mongodb") || banner_lc.contains("ismaster") {
        return ("MongoDB", true);
    }
    if banner_lc.contains("redis") || banner_lc.starts_with("+pong") {
        return ("Redis", true);
    }
    if banner_lc.contains("elasticsearch") {
        return ("Elasticsearch", true);
    }
    if banner_lc.starts_with("ssh-") {
        return ("SSH", false);
    }
    if banner_lc.contains("http/1") || banner_lc.contains("html") {
        return ("HTTP", false);
    }
    if banner_lc.contains("ftp") || banner_lc.starts_with("220") {
        return ("FTP", true);
    }
    if banner_lc.contains("smtp") || banner_lc.starts_with("220 ") && banner_lc.contains("mail") {
        return ("SMTP", false);
    }
    if banner_lc.contains("memcache") || banner_lc.starts_with("stat") {
        return ("Memcached", true);
    }
    if banner_lc.contains("kafka") {
        return ("Kafka", true);
    }

    // Port-number lookup
    match port {
        21          => ("FTP", true),
        22          => ("SSH", false),
        23          => ("Telnet", true),
        25          => ("SMTP", false),
        53          => ("DNS", false),
        80          => ("HTTP", false),
        110         => ("POP3", false),
        143         => ("IMAP", false),
        443         => ("HTTPS", false),
        445         => ("SMB", true),
        587         => ("SMTP/TLS", false),
        993         => ("IMAPS", false),
        995         => ("POP3S", false),
        1433        => ("MSSQL", true),
        1521        => ("Oracle DB", true),
        1830        => ("Oracle DB Alt", true),
        2181        => ("ZooKeeper", true),
        2376 | 2377 => ("Docker", true),
        2379 | 2380 | 4001 => ("etcd", true),
        3000..=3010 => ("Dev HTTP", false),
        3306 | 3307 => ("MySQL/MariaDB", true),
        3389        => ("RDP", true),
        4000        => ("Dev GraphQL", false),
        4149 | 4243 => ("Docker cAdvisor", true),
        5432        => ("PostgreSQL", true),
        5601        => ("Kibana", true),
        5672        => ("RabbitMQ AMQP", true),
        5900..=5902 => ("VNC", true),
        5984 | 6984 => ("CouchDB", true),
        5985 | 5986 => ("WinRM", true),
        6379 | 6380 => ("Redis", true),
        6443        => ("Kubernetes API", true),
        7000 | 7001 => ("Cassandra", true),
        7474 | 7687 => ("Neo4j", true),
        8080..=8090 => ("Alt HTTP", false),
        8200        => ("HashiCorp Vault", true),
        8300..=8302 => ("Consul", true),
        8443        => ("Alt HTTPS", false),
        8888        => ("Jupyter / Dev", true),
        9000        => ("PHP-FPM / SonarQube", true),
        9090 | 9091 => ("Prometheus / Pushgateway", true),
        9092 | 9093 => ("Kafka", true),
        9200 | 9300 => ("Elasticsearch", true),
        9411        => ("Zipkin", true),
        10250       => ("Kubelet API", true),
        10255       => ("Kubelet Read-Only", true),
        11211       => ("Memcached", true),
        11434       => ("Ollama LLM", true),
        15672       => ("RabbitMQ Mgmt", true),
        16686       => ("Jaeger UI", true),
        27017..=27019 => ("MongoDB", true),
        28017       => ("MongoDB HTTP", true),
        50000       => ("Jenkins / SAP", true),
        61616       => ("ActiveMQ", true),
        _           => ("Unknown", false),
    }
}

// ── Open port result ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OpenPort {
    pub port: u16,
    pub service: &'static str,
    pub banner: String,
    pub is_dangerous: bool,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Run a full port scan against `host`.
///
/// `host` should be a bare hostname or IP (no scheme / path).
pub async fn run(host: &str, config: &PortScanConfig) -> Result<Vec<Finding>> {
    info!("Port scanner: scanning {} (1–{} + {} extended ports)",
        host, config.port_range_max, EXTENDED_PORTS.len());

    // Build the full list of ports to probe
    let mut ports: Vec<u16> = (1..=config.port_range_max).collect();
    for &p in EXTENDED_PORTS {
        if p > config.port_range_max {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();

    let total = ports.len();
    let sem = Arc::new(Semaphore::new(config.concurrency));
    let mut handles = Vec::with_capacity(total);

    for port in ports {
        let host = host.to_string();
        let sem = Arc::clone(&sem);
        let connect_timeout = config.connect_timeout;
        let banner_timeout = config.banner_timeout;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            probe_port(&host, port, connect_timeout, banner_timeout).await
        }));
    }

    let mut open_ports = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Some(op)) => open_ports.push(op),
            Ok(None) => {}
            Err(e) => debug!("Port scan task panicked: {}", e),
        }
    }

    info!("Port scanner: {}/{} ports open", open_ports.len(), total);

    Ok(findings_from_open_ports(host, &open_ports))
}

// ── TCP probe ─────────────────────────────────────────────────────────────────

async fn probe_port(
    host: &str,
    port: u16,
    connect_timeout: Duration,
    banner_timeout: Duration,
) -> Option<OpenPort> {
    let addr_str = format!("{}:{}", host, port);

    // Resolve + connect with timeout
    let stream = timeout(connect_timeout, TcpStream::connect(&addr_str))
        .await
        .ok()? // timeout elapsed
        .ok()?; // connection refused / error

    debug!("Port {port} open on {host}");

    // Read banner
    let banner = grab_banner(stream, banner_timeout).await;
    let (service, is_dangerous) = fingerprint_port(port, &banner);

    Some(OpenPort { port, service, banner, is_dangerous })
}

async fn grab_banner(mut stream: TcpStream, banner_timeout: Duration) -> String {
    let mut buf = vec![0u8; 512];
    match timeout(banner_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let raw = &buf[..n];
            // Convert to printable string
            String::from_utf8_lossy(raw)
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '\n' || *c == '\r')
                .take(256)
                .collect()
        }
        _ => String::new(),
    }
}

// ── Convert open ports → Findings ────────────────────────────────────────────

fn findings_from_open_ports(host: &str, open_ports: &[OpenPort]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Summary finding for all open ports
    if !open_ports.is_empty() {
        let port_list: Vec<String> = open_ports
            .iter()
            .map(|p| format!("{} ({})", p.port, p.service))
            .collect();

        findings.push(Finding {
            id: Uuid::new_v4().to_string(),
            category: OwaspCategory::SecurityMisconfiguration,
            severity: Severity::Info,
            title: format!("[Port Scan] {} open port(s) found on {}", open_ports.len(), host),
            description: format!(
                "The following TCP ports are open on `{}`:\n\n{}",
                host,
                port_list.iter().map(|p| format!("- {}", p)).collect::<Vec<_>>().join("\n")
            ),
            evidence: Some(format!("Open ports: {}", port_list.join(", "))),
            remediation: "Review all open ports and close any that are not required for normal operation. Use firewalls to restrict access to sensitive services.".to_string(),
            source: FindingSource::PortScanner,
            endpoint: Some(format!("tcp://{}", host)),
        });
    }

    // 2. Individual findings for dangerous/unexpected services
    for op in open_ports {
        if op.is_dangerous {
            let (severity, description) = dangerous_service_finding(host, op);
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::SecurityMisconfiguration,
                severity,
                title: format!("[Exposed Service] {} on port {}", op.service, op.port),
                description,
                evidence: Some(if op.banner.is_empty() {
                    format!("TCP port {} ({}) is open", op.port, op.service)
                } else {
                    format!("TCP port {} ({}) is open\nBanner: {}", op.port, op.service, op.banner)
                }),
                remediation: format!(
                    "Restrict access to port {} ({}) using a firewall. This service should \
                     only be reachable from trusted internal networks, never from the internet. \
                     If not needed, disable the service entirely.",
                    op.port, op.service
                ),
                source: FindingSource::PortScanner,
                endpoint: Some(format!("{}:{}", host, op.port)),
            });
        }

        // Flag Telnet regardless of is_dangerous classification
        if op.port == 23 {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::CryptographicFailures,
                severity: Severity::Critical,
                title: "[Critical] Telnet (Port 23) — Cleartext Remote Access".to_string(),
                description: format!(
                    "Telnet is running on `{}:23`. Telnet transmits all data—including \
                     credentials—in cleartext. Any network eavesdropper can trivially \
                     capture login sessions.",
                    host
                ),
                evidence: Some(format!("Port 23 open. Banner: {}", op.banner)),
                remediation: "Disable Telnet immediately. Replace with SSH (port 22) which encrypts all traffic.".to_string(),
                source: FindingSource::PortScanner,
                endpoint: Some(format!("{}:23", host)),
            });
        }

        // Flag SMB (445) as Critical on internet-facing hosts
        if op.port == 445 {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::SecurityMisconfiguration,
                severity: Severity::Critical,
                title: "[Critical] SMB (Port 445) — Exposed File Sharing Protocol".to_string(),
                description: format!(
                    "SMB is exposed on `{}:445`. Internet-facing SMB is associated with \
                     critical vulnerabilities including EternalBlue (MS17-010/CVE-2017-0144), \
                     WannaCry, NotPetya, and many others. This is an extremely high-risk \
                     configuration.",
                    host
                ),
                evidence: Some("Port 445 (SMB) is open to the internet".to_string()),
                remediation: "Block port 445 at the firewall immediately. SMB must never be exposed to the internet.".to_string(),
                source: FindingSource::PortScanner,
                endpoint: Some(format!("{}:445", host)),
            });
        }
    }

    // 3. Flag unknown high-numbered open ports (potential hidden backdoors or tunnels)
    let unknown_high: Vec<_> = open_ports
        .iter()
        .filter(|p| p.service == "Unknown" && p.port > 1024)
        .collect();

    if !unknown_high.is_empty() {
        for op in &unknown_high {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                category: OwaspCategory::SecurityMisconfiguration,
                severity: Severity::Medium,
                title: format!("[Hidden Port] Unidentified service on port {}", op.port),
                description: format!(
                    "Port {} on `{}` is open but the service could not be fingerprinted. \
                     Unidentified high-numbered ports may indicate non-standard services, \
                     development servers, backdoors, or misconfigured daemons.\n\n\
                     Banner (if any): {}",
                    op.port,
                    host,
                    if op.banner.is_empty() { "<empty>" } else { &op.banner }
                ),
                evidence: Some(format!("Port {} open, service unknown, banner: {:?}", op.port, op.banner)),
                remediation: "Investigate what is running on this port. Close it if not intentional.".to_string(),
                source: FindingSource::PortScanner,
                endpoint: Some(format!("{}:{}", host, op.port)),
            });
        }
    }

    findings
}

fn dangerous_service_finding(host: &str, op: &OpenPort) -> (Severity, String) {
    let (severity, risk_context) = match op.service {
        "MongoDB"      => (Severity::Critical, "MongoDB has shipped with no authentication enabled by default in older versions. An exposed instance allows unauthenticated read/write of all databases."),
        "Redis"        => (Severity::Critical, "Exposed Redis instances have been used to write SSH authorized_keys and achieve RCE without any credentials."),
        "Memcached"    => (Severity::Critical, "Memcached has no authentication. Exposed instances leak cached application data and have been abused for DDoS amplification attacks."),
        "Elasticsearch" => (Severity::Critical, "Elasticsearch (pre-8.0) shipped with no authentication. Internet-facing instances routinely expose all indexed data to the public."),
        "Kibana"       => (Severity::High, "Kibana exposes the Elasticsearch management UI. Access to Kibana typically grants full control of all indexed data."),
        "Kubernetes API" => (Severity::Critical, "An exposed Kubernetes API server can lead to full cluster compromise, container escape, and lateral movement to all workloads."),
        "Kubelet API"  => (Severity::Critical, "The Kubelet API (port 10250) allows unauthenticated command execution in containers when the `--anonymous-auth` flag is enabled."),
        "Docker"       => (Severity::Critical, "An exposed Docker daemon grants full control of the host through container escape. This is equivalent to root access on the host."),
        "etcd"         => (Severity::Critical, "etcd stores all Kubernetes cluster state including secrets. An exposed etcd instance exposes every secret in the cluster."),
        "RDP"          => (Severity::High, "Internet-facing RDP (port 3389) is one of the most common attack vectors for ransomware deployment via brute-force and credential stuffing."),
        "VNC"          => (Severity::High, "Exposed VNC provides graphical remote desktop access. Many VNC servers use weak or no authentication."),
        "WinRM"        => (Severity::High, "WinRM (Windows Remote Management) exposed to the internet enables remote PowerShell execution. Common lateral movement target."),
        "MySQL/MariaDB" => (Severity::High, "Direct internet exposure of MySQL/MariaDB allows brute-force attacks against database credentials."),
        "PostgreSQL"   => (Severity::High, "Internet-facing PostgreSQL is at risk of credential brute-force and, if misconfigured, unauthenticated access."),
        "Oracle DB"    | "Oracle DB Alt" => (Severity::High, "Internet-facing Oracle Database exposure is a serious misconfiguration enabling credential attacks and potential data exfiltration."),
        "MSSQL"        => (Severity::High, "Internet-facing SQL Server (port 1433) is a common brute-force target and may enable xp_cmdshell RCE."),
        "FTP"          => (Severity::High, "FTP transmits credentials in cleartext. Anonymous access is common and allows data exfiltration or upload."),
        "Telnet"       => (Severity::Critical, "Telnet transmits all data in cleartext including passwords."),
        "SMB"          => (Severity::Critical, "Internet-facing SMB is associated with critical worm-able vulnerabilities (EternalBlue, MS17-010)."),
        "CouchDB"      => (Severity::High, "CouchDB has been exploited via its admin interface to execute OS commands when exposed."),
        "Neo4j"        => (Severity::High, "Exposed Neo4j may allow unauthenticated Cypher query execution in older versions."),
        "Cassandra"    => (Severity::High, "Internet-facing Cassandra may allow unauthenticated CQL access to all data in older configurations."),
        "RabbitMQ AMQP" | "RabbitMQ Mgmt" => (Severity::High, "Exposed RabbitMQ can allow message injection, eavesdropping, or management UI access."),
        "Kafka"        => (Severity::High, "Exposed Kafka brokers may allow unauthenticated topic enumeration, data consumption, and message injection."),
        "ZooKeeper"    => (Severity::High, "ZooKeeper has no authentication by default and exposes coordination state of all connected services."),
        "Consul"       => (Severity::High, "Consul service mesh configuration may be fully readable and writable without authentication when exposed."),
        "HashiCorp Vault" => (Severity::High, "While Vault requires auth, an exposed UI and API surface increases the attack surface against secrets management."),
        "Jupyter / Dev" => (Severity::Critical, "Jupyter Notebook/Lab (port 8888) often runs without authentication and allows arbitrary code execution on the server."),
        "Prometheus / Pushgateway" => (Severity::Medium, "Prometheus metrics endpoints can expose internal system details, service topology, and sensitive operational data."),
        "PHP-FPM / SonarQube" => (Severity::Medium, "PHP-FPM exposed directly to the internet may allow code execution. SonarQube exposes source code analysis."),
        "Ollama LLM"   => (Severity::Medium, "Ollama's API (port 11434) is typically unauthenticated and allows prompt injection and model enumeration."),
        "ActiveMQ"     => (Severity::High, "Apache ActiveMQ has multiple critical RCE CVEs (CVE-2023-46604). Internet exposure is extremely dangerous."),
        "Jenkins / SAP" => (Severity::High, "Exposed Jenkins (port 50000 / JNLP) allows agent connection and may lead to RCE through pipeline execution."),
        _              => (Severity::Medium, "This service should not be directly exposed to the internet without proper authentication and access controls."),
    };

    let description = format!(
        "`{}` is running on `{}:{}` and appears to be internet-accessible.\n\n\
         **Risk:** {}\n\n\
         **Banner:** {}",
        op.service,
        host,
        op.port,
        risk_context,
        if op.banner.is_empty() { "<no banner received>" } else { &op.banner }
    );

    (severity, description)
}

// ── Utility: extract host from URL ───────────────────────────────────────────

/// Strip scheme and path from a URL to get just the host (for socket connections).
pub fn host_from_url(url: &str) -> Result<String> {
    let url = url::Url::parse(url).context("Invalid target URL")?;
    url.host_str()
        .map(|h| h.to_string())
        .context("URL has no host")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_port_by_number() {
        let (svc, dangerous) = fingerprint_port(6379, "");
        assert_eq!(svc, "Redis");
        assert!(dangerous);
    }

    #[test]
    fn test_fingerprint_port_by_banner() {
        let (svc, dangerous) = fingerprint_port(12345, "+PONG\r\n");
        assert_eq!(svc, "Redis");
        assert!(dangerous);
    }

    #[test]
    fn test_fingerprint_ssh_banner() {
        let (svc, dangerous) = fingerprint_port(22, "SSH-2.0-OpenSSH_8.9p1");
        assert_eq!(svc, "SSH");
        assert!(!dangerous);
    }

    #[test]
    fn test_host_from_url() {
        assert_eq!(host_from_url("https://example.com/path").unwrap(), "example.com");
        assert_eq!(host_from_url("http://192.168.1.1:8080").unwrap(), "192.168.1.1");
    }
}
