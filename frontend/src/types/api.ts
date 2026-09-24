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

export interface Attempt {
  id: number;
  turn: number;
  strategy: string;
  prompt: string;
  response: string;
  stance: string;
  reason: string;
  confidence: number;
  next_strategy?: string;
  observation?: Record<string, unknown>;
  events?: Array<{ event_type: string; event_data: Record<string, unknown>; source: string }>;
}

export interface Objective {
  id: number;
  family: string;
  rule_id: string;
  objective: string;
  status: string;
  verdict: string;
  attack_outcome: string;
  evidence_status: string;
  severity: string;
  owasp_category: string;
  taxonomy_version?: string;
  application_security_class?: string;
  attempts: Attempt[];
}

export interface ScanDetails extends ScanRun {
  findings: Finding[];
  objectives: Objective[];
  attempts: Attempt[];
  target_info?: Record<string, any>;
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
