/** Shared TypeScript types — mirrors Rust CLI structs */

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

export const OWASP_LABELS: Record<OwaspCategory, string> = {
  BrokenAccessControl: 'A01: Broken Access Control',
  CryptographicFailures: 'A02: Cryptographic Failures',
  SupplyChainFailures: 'A03: Supply Chain Failures',
  InsecureDesign: 'A04: Insecure Design',
  SecurityMisconfiguration: 'A05: Security Misconfiguration',
  VulnerableComponents: 'A06: Vulnerable Components',
  AuthFailures: 'A07: Auth Failures',
  IntegrityFailures: 'A08: Integrity Failures',
  LoggingFailures: 'A09: Logging Failures',
  ExceptionalConditions: 'A10: Exceptional Conditions',
  LlmVulnerability: 'LLM: AI/LLM Vulnerability',
};

export const OWASP_CODES: Record<OwaspCategory, string> = {
  BrokenAccessControl: 'A01',
  CryptographicFailures: 'A02',
  SupplyChainFailures: 'A03',
  InsecureDesign: 'A04',
  SecurityMisconfiguration: 'A05',
  VulnerableComponents: 'A06',
  AuthFailures: 'A07',
  IntegrityFailures: 'A08',
  LoggingFailures: 'A09',
  ExceptionalConditions: 'A10',
  LlmVulnerability: 'LLM',
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#facc15',
  low: '#60a5fa',
  info: '#6b7280',
};

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

/** Count findings by severity */
export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** Count findings by OWASP category */
export function countByCategory(findings: Finding[]): Partial<Record<OwaspCategory, number>> {
  const counts: Partial<Record<OwaspCategory, number>> = {};
  for (const f of findings) {
    counts[f.category] = (counts[f.category] ?? 0) + 1;
  }
  return counts;
}
