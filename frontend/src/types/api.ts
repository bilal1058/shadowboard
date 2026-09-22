export interface Target {
  id: number;
  name: string;
  base_url: string;
  model_name?: string;
  target_type: string;
  target_mode?: string;
  capabilities?: TargetCapabilities | Record<string, unknown>;
}

export interface TargetCapabilities {
  chat: boolean;
  rag: boolean;
  tools: boolean;
  data_access: boolean;
  tool_names: string[];
}

export interface ScanRun {
  id: number;
  target_id: number;
  target_name: string;
  status: string;
  scan_mode: string;
  mitigation_enabled: boolean;
  started_at: string;
  completed_at: string;
  overall_score: number;
  risk_grade: string;
  objectives_tested: number;
  confirmed_count: number;
  policy_coverage: number;
}

export interface Finding {
  id: number;
  finding_id: string;
  owasp_category: string;
  severity: string;
  status: string;
  remediation: string;
  evidence_hash: string;
  confidence: number;
}

export interface ScanRequest {
  target_id: number;
  scan_mode: string;
  mitigation_enabled: boolean;
}

export interface SSEEvent {
  type: string;
  scan_id: number;
  data: Record<string, unknown>;
}

export interface Policy {
  target_id: number;
  policy: Record<string, unknown>;
}

export interface EvidencePackage {
  scan_id: number;
  finding_id: string;
  target_name: string;
  severity: string;
  evidence: Record<string, unknown>;
  evidence_hash: string;
  remediation: string;
  verified: boolean;
}
