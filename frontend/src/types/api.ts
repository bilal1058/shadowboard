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

export interface CausalNode {
  node_id: string;
  label: string;
  type: string;
  timestamp: number;
  trust_level: string;
  evidence_snippet: string;
  details: Record<string, any>;
}

export interface CausalEdge {
  source: string;
  target: string;
  relationship: string;
  link_type: string;
  uncertainty_score: number;
  correlation_method: string;
}

export interface CausalGraphData {
  finding_id: string;
  rule_id: string;
  severity: string;
  nodes: CausalNode[];
  edges: CausalEdge[];
  developer_summary: Record<string, string>;
  non_expert_explanation: string;
  remediation_guidance: string;
  mermaid_diagram: string;
}

export interface DifferentialAuthCaseResult {
  case_id: string;
  description: string;
  invariant_category: string;
  caller: string;
  role: string;
  target_owner: string;
  action_type: string;
  tool_name: string;
  expected_outcome: string;
  actual_outcome: string;
  passed: boolean;
  discrepancy_details: string;
  response_snippet: string;
}

export interface DifferentialAuthResponse {
  total_cases: number;
  passed_cases: number;
  violations_detected: number;
  enforce_mitigation: boolean;
  results: DifferentialAuthCaseResult[];
}

export interface TargetContractInfo {
  target_mode: string;
  schema_version: string;
  supported_event_types: string[];
  trace_format: string;
}
