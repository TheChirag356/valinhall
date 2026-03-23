export interface Finding {
	id: string;
	category: OwaspCategory;
	severity: Severity;
	title: string;
	description: string;
	evidence?: string;
	remediation: string;
	source: FindingSource;
	endpoint?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingSource = 'SAST' | 'DAST' | 'Supply Chain' | 'LLM Probe';
export type OwaspCategory =
	| 'BrokenAccessControl'
	| 'CryptographicFailures'
	| 'SupplyChainFailures'
	| 'InsecureDesign'
	| 'SecurityMisconfiguration'
	| 'VulnerableComponents'
	| 'AuthFailures'
	| 'IntegrityFailures'
	| 'LoggingFailures'
	| 'ExceptionalConditions'
	| 'LlmVulnerability';

export interface ScanResult {
	id: string;
	target: string;
	timestamp: string;
	findings: Finding[];
}

export interface SupplyFinding {
	package: string;
	version: string;
	ecosystem: string;
	severity: string;
	title: string;
	cve?: string;
	fix_version?: string;
	osv_id: string;
}

export interface ServerStatus {
	state: 'idle' | 'scanning' | 'complete' | 'error';
	progress: number;
	target?: string;
}

export interface ScanHistoryEntry {
	id: string;
	target: string;
	timestamp: string;
	critical: number;
	high: number;
	medium: number;
	low: number;
	total: number;
}

export const OWASP_LABELS: Record<OwaspCategory, string> = {
	BrokenAccessControl: 'A01: Broken Access Control',
	CryptographicFailures: 'A02: Cryptographic Failures',
	SupplyChainFailures: 'A03: Supply Chain Failures',
	InsecureDesign: 'A04: Insecure Design',
	SecurityMisconfiguration: 'A05: Misconfiguration',
	VulnerableComponents: 'A06: Vulnerable Components',
	AuthFailures: 'A07: Auth Failures',
	IntegrityFailures: 'A08: Integrity Failures',
	LoggingFailures: 'A09: Logging Failures',
	ExceptionalConditions: 'A10: Exceptional Conditions',
	LlmVulnerability: 'LLM: AI/LLM Vulnerability',
};

export const SEVERITY_COLORS: Record<Severity, string> = {
	critical: '#dc2626',
	high: '#f97316',
	medium: '#facc15',
	low: '#60a5fa',
	info: '#6b7280',
};

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
	return findings.reduce(
		(acc, f) => { acc[f.severity]++; return acc; },
		{ critical: 0, high: 0, medium: 0, low: 0, info: 0 }
	);
}

export function countByCategory(findings: Finding[]): Partial<Record<OwaspCategory, number>> {
	return findings.reduce((acc, f) => {
		acc[f.category] = (acc[f.category] ?? 0) + 1;
		return acc;
	}, {} as Partial<Record<OwaspCategory, number>>);
}

/** Generate DEMO scan result data for the dashboard */
export function generateDemoResult(): ScanResult {
	return {
		id: 'demo-scan-001',
		target: 'http://demo.testfire.net',
		timestamp: new Date().toISOString(),
		findings: [
			{
				id: '1', category: 'BrokenAccessControl', severity: 'critical',
				title: 'SQL Injection', source: 'DAST', endpoint: 'http://demo.testfire.net/login',
				description: "SQL injection confirmed via ' OR '1'='1 payload triggering database error.",
				evidence: "GET /login?id=' OR '1'='1\nYou have an error in your SQL syntax near '1'='1'",
				remediation: 'Use parameterized queries. Never concatenate user input into SQL strings.',
			},
			{
				id: '2', category: 'CryptographicFailures', severity: 'critical',
				title: 'Hardcoded AWS Key', source: 'SAST', endpoint: 'src/config.js:42',
				description: 'An AWS Access Key ID (AKIA...) was found hardcoded in source code.',
				evidence: 'src/config.js:42 — const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
				remediation: 'Revoke the key immediately. Store secrets in environment variables.',
			},
			{
				id: '3', category: 'AuthFailures', severity: 'high',
				title: 'JWT alg:none Accepted', source: 'DAST', endpoint: 'http://demo.testfire.net/api/admin',
				description: 'The server accepted a forged JWT with algorithm set to none.',
				evidence: 'GET /api/admin with forged token (alg:none, role:admin) → HTTP 200',
				remediation: "Whitelist specific algorithms (RS256/HS256). Never allow 'none'.",
			},
			{
				id: '4', category: 'SecurityMisconfiguration', severity: 'high',
				title: 'Missing HSTS Header', source: 'DAST', endpoint: 'http://demo.testfire.net',
				description: 'Strict-Transport-Security header is absent, allowing HTTP downgrade attacks.',
				evidence: "GET / — 'strict-transport-security' not present in response headers",
				remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
			},
			{
				id: '5', category: 'LlmVulnerability', severity: 'high',
				title: 'Direct Prompt Injection', source: 'LLM Probe', endpoint: 'http://demo.testfire.net/api/chat',
				description: "The LLM endpoint revealed system context when prompted with 'Ignore previous instructions'.",
				evidence: 'POST /api/chat — response contained "your instructions are" keyword',
				remediation: 'Apply system prompt isolation. Sanitize user inputs before injecting into LLM context.',
			},
			{
				id: '6', category: 'SupplyChainFailures', severity: 'high',
				title: 'Typosquatting: lodahs', source: 'Supply Chain',
				description: "Package 'lodahs' is 1 character away from popular 'lodash'. Potential typosquatting.",
				evidence: 'Package: lodahs@4.17.19, similar to: lodash',
				remediation: 'Verify the intended package. Use lockfiles and exact version pinning.',
			},
			{
				id: '7', category: 'BrokenAccessControl', severity: 'medium',
				title: 'Reflected XSS', source: 'DAST', endpoint: 'http://demo.testfire.net/search',
				description: 'XSS payload reflected unencoded in search results HTML response.',
				evidence: "GET /search?q=<script>alert('XSS')</script> — payload reflected in body",
				remediation: 'HTML-encode all user-supplied output. Implement Content-Security-Policy.',
			},
			{
				id: '8', category: 'CryptographicFailures', severity: 'medium',
				title: 'MD5 Usage Detected', source: 'SAST', endpoint: 'src/auth/hash.js:18',
				description: 'MD5 is cryptographically broken and must not be used for security-sensitive hashing.',
				evidence: 'src/auth/hash.js:18 — const hash = md5(password);',
				remediation: 'Replace with Argon2id, bcrypt, or scrypt for password hashing.',
			},
			{
				id: '9', category: 'AuthFailures', severity: 'medium',
				title: 'Cookie Missing SameSite', source: 'DAST', endpoint: 'http://demo.testfire.net',
				description: "Session cookie 'session' lacks SameSite attribute, enabling CSRF attacks.",
				evidence: 'Set-Cookie: session=abc123; Path=/; HttpOnly',
				remediation: 'Add SameSite=Strict or SameSite=Lax to all authentication cookies.',
			},
			{
				id: '10', category: 'ExceptionalConditions', severity: 'medium',
				title: 'Stack Trace Disclosure', source: 'DAST', endpoint: 'http://demo.testfire.net/api/user',
				description: 'Malformed JSON body triggered a Python Traceback in the response body.',
				evidence: "POST /api/user body={not json} → HTTP 500\nTraceback (most recent call last):\n  File '/app/server.py', line 42",
				remediation: 'Implement global exception handler. Return generic error messages to clients.',
			},
			{
				id: '11', category: 'VulnerableComponents', severity: 'high',
				title: 'CVE-2024-29180: webpack-dev-server SSRF', source: 'Supply Chain',
				description: 'webpack-dev-server 4.15.1 is vulnerable to SSRF via malicious hosts.',
				evidence: 'Package: webpack-dev-server@4.15.1 — OSV: GHSA-xxxx-yyyy',
				remediation: 'Upgrade to webpack-dev-server ≥ 5.0.4.',
			},
			{
				id: '12', category: 'SecurityMisconfiguration', severity: 'low',
				title: 'Server Header Disclosure', source: 'DAST', endpoint: 'http://demo.testfire.net',
				description: "The 'Server: nginx/1.18.0' header reveals the web server version.",
				evidence: 'Server: nginx/1.18.0',
				remediation: "Configure nginx to suppress or genericize the 'Server' header.",
			},
			{
				id: '13', category: 'InsecureDesign', severity: 'info',
				title: 'TODO Security Comment', source: 'SAST', endpoint: 'src/api/auth.ts:77',
				description: 'A TODO comment references an unresolved security concern.',
				evidence: 'src/api/auth.ts:77 — // TODO: fix auth bypass before production',
				remediation: 'Address security TODOs before shipping to production.',
			},
		],
	};
}
