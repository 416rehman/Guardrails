import type { Mode, SetupStep, Verdict } from "./types";

export interface WhyExplanation {
  reference: string;
  receipt_id: string;
  attempt_id: string;
  heading: string;
  verdict: Verdict;
  status_code: string;
  component: string;
  action_class: string;
  rule_id: string;
  rule_title: string;
  pack_id: string;
  agent_name: string;
  device_id: string;
  device_name: string;
  session_id: string;
  target_quoted: string;
  reason: string;
  agent_told: string;
  timestamp: string;
  key_id: string | null;
  signature_status: string;
  primary_action_label: string;
  primary_action_route: string;
  approval_id: string | null;
  approver_label: string | null;
}

export type ReviewBucket = "worth_a_look" | "routine" | "noise";
export type ReviewStatus = "open" | "promoted" | "suppressed" | "dismissed" | "escalated";

export interface ReviewCluster {
  id: string;
  bucket: ReviewBucket;
  score: number;
  rule_id: string;
  rule_title: string;
  observable_digest: string;
  agent_name: string;
  device_id: string;
  device_name: string;
  session_id: string;
  receipt_ref: string;
  occurrence_count: number;
  latest_timestamp: string;
  target_preview: string;
  current_mode: Mode;
  suggested_mode: Mode;
  risk_label: string;
  status: ReviewStatus;
  reason: string;
  note: string;
}

export interface ReviewQueueResponse {
  clusters: ReviewCluster[];
  worth_a_look_count: number;
  routine_count: number;
  noise_count: number;
}

export interface FrameworkCoverageSummary {
  framework_id: string;
  display_title: string;
  total_controls: number;
  addressed_controls: number;
  coverage_percent: number;
}

export interface ComplianceEvidenceEntry {
  id: string;
  capability: string;
  statement: string;
  result: string;
  responsibility: string;
  control_refs: string[];
  sample_ids: string[];
  period_end: string;
  signature_status: string;
}

export interface RetentionStateSummary {
  organisation: string;
  privacy_profile: "standard" | "works-council";
  presets: string[];
  content_days: number;
  activity_days: number;
  decision_days: number;
  audit_days: number;
  hot_days: number;
  backup_days_max: number;
  legal_basis: string[];
  conflict_note: string;
}

export interface LegalHoldEntry {
  hold_id: string;
  matter_ref: string;
  reason: string;
  lifecycle: string;
  created_by: string;
  approvers: string[];
  created_at: string;
  review_by: string;
  notice_mode: string;
  scope_summary: string;
}

export interface SubjectRequestEntry {
  request_id: string;
  kind: string;
  subject_ref: string;
  status: "executed" | "pending_held";
  hold_ids: string[];
  requested_at: string;
  detail: string;
}

export interface ComplianceConnectorEntry {
  id: string;
  name: string;
  kind: string;
  stability: string;
  circuit_state: string;
  queued_items: number;
  delivered_items: number;
  capture_ceiling: string;
  assurance_label: string;
  last_delivery_at: string | null;
  summary: string;
}

export interface ReidentificationRequestEntry {
  request_id: string;
  pseudonym_id: string;
  requester: string;
  reason: string;
  legal_basis: string;
  status: "pending_quorum" | "approved" | "denied";
  approvers: string[];
  required_approvals: number;
  resolved_identity: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface DisclosureLedgerEntry {
  id: string;
  kind: string;
  actor: string;
  target_ref: string;
  legal_basis: string;
  timestamp: string;
  quarter: string;
  summary: string;
}

export interface DisclosureMetrics {
  quarter: string;
  total_reidentifications: number;
  total_holds: number;
  total_erasures: number;
  total_exports: number;
}

export interface FirstRunState {
  selected_profile: "protected" | "user";
  confirmed: boolean;
  step_up_enabled: boolean;
  steps: SetupStep[];
}

export interface ComplianceWorkspaceResponse {
  frameworks: FrameworkCoverageSummary[];
  evidence_items: ComplianceEvidenceEntry[];
  retention: RetentionStateSummary;
  legal_holds: LegalHoldEntry[];
  subject_requests: SubjectRequestEntry[];
  connectors: ComplianceConnectorEntry[];
  reid_requests: ReidentificationRequestEntry[];
  disclosures: DisclosureLedgerEntry[];
  disclosure_metrics: DisclosureMetrics;
  first_run: FirstRunState;
}

export interface ComplianceExportArtifact {
  format: string;
  filename: string;
  content_type: string;
  payload: string;
  oscal_version: string;
  digest: string;
}

export interface GrcPushResult {
  target: string;
  envelope_id: string;
  outbox_state: string;
  circuit_state: string;
  summary: string;
  payload_preview: string;
}

export interface ProviderOrgEntry {
  org_id: string;
  name: string;
  org_set: string;
  ring: string;
  devices_count: number;
  open_findings: number;
  pending_approvals: number;
  coverage_pct: number;
  floor_version: string;
  delegated_overrides: number;
  status: "healthy" | "attention" | "offline";
}

export interface ProviderRingSummary {
  ring: string;
  org_count: number;
  target_version: string;
  health_state: string;
  soak_hours: number;
}

export interface ProviderWorkspaceResponse {
  acting_as_org_id: string | null;
  acting_as_org_name: string | null;
  acting_as_reason: string | null;
  orgs: ProviderOrgEntry[];
  rings: ProviderRingSummary[];
}

export interface OperatorRuntimeConfig {
  revision_id: string;
  version: number;
  capture_level: string;
  privacy_profile: string;
  retention_preset: string;
  hot_days: number;
  activity_days: number;
  decision_days: number;
  audit_days: number;
  otlp_enabled: boolean;
  release_channel: string;
  summary: string;
}

export interface ConfigDiffEntry {
  field: string;
  previous: string;
  next: string;
}

export type ConfigRevisionState =
  | "draft"
  | "validated"
  | "applying"
  | "applied"
  | "rolled_back"
  | "superseded"
  | "discarded";

export interface ConfigRevisionEntry {
  revision_id: string;
  version: number;
  state: ConfigRevisionState;
  author: string;
  summary: string;
  created_at: string;
  applied_at: string | null;
  diff_lines: ConfigDiffEntry[];
  config: OperatorRuntimeConfig;
}

export interface CompatCheckEntry {
  component: string;
  current_version: string;
  target_version: string;
  supported_range: string;
  status: "compatible" | "compatible_with_warnings" | "incompatible";
  agreed_capabilities: string[];
  warnings: string[];
  remediation: string;
}

export interface TargetHealthEntry {
  id: string;
  name: string;
  tier: number;
  kind: string;
  status: "healthy" | "degraded" | "open_circuit";
  circuit_state: string;
  failure_count: number;
  latency_ms: number;
  detail: string;
  last_checked_at: string;
}

export interface BackupDrillRecord {
  drill_id: string;
  kind: string;
  status: "passed" | "running" | "failed";
  snapshot_digest: string;
  record_count: number;
  verified_tables: number;
  duration_ms: number;
  executed_at: string;
  actor: string;
  note: string;
}

export interface OperatorStateResponse {
  runtime_config: OperatorRuntimeConfig;
  revisions: ConfigRevisionEntry[];
  preflight_matrix: CompatCheckEntry[];
  target_version: string;
  overall_compatible: boolean;
  targets: TargetHealthEntry[];
  drills: BackupDrillRecord[];
}
