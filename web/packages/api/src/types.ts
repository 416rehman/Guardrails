export type Mode = "off" | "watch" | "ask" | "block";
export type Verdict = "allow" | "modify" | "step_up" | "defer" | "deny";
export type InstallProfile = "user" | "protected";
export type AssuranceLevel = "AL0" | "AL1" | "AL2" | "AL3" | "AL4";
export type GrantScope = "once" | "session" | "one_hour";
export type FindingLifecycle = "open" | "acknowledged" | "contained" | "resolved";
export type SessionLabel =
  | "credential_accessed"
  | "untrusted_web_fetched"
  | "repeated_denials"
  | "tainted_exfil_risk";
export type KillScope = "session" | "device" | "organisation";
export type KillAction = "freeze" | "kill" | "release";
export type IdentityMode = "named" | "pseudonymous";
export type RiskTier = "low" | "elevated" | "high" | "critical";
export type ArtifactKind = "skill" | "rule" | "plugin" | "command" | "subagent";
export type ArtifactScope = "user" | "workspace" | "managed";
export type ArtifactRiskFlag =
  | "has-scripts"
  | "requests-broad-tools"
  | "bidi-obfuscation"
  | "unpinned-digest";
export type SpanKind =
  | "invoke_agent"
  | "chat"
  | "execute_tool"
  | "mcp_call"
  | "os_effect"
  | "subagent_spawn"
  | "compaction";
export type ProvenanceSource = "claimed" | "observed" | "mediated" | "reconciled";

export type ActionClass =
  | "exec"
  | "file.read"
  | "file.write"
  | "file.delete"
  | "net.connect"
  | "net.request"
  | "llm.request"
  | "mcp.connect"
  | "mcp.call"
  | "cred.use"
  | "agent.spawn"
  | "config.change"
  | "elevate"
  | "ui.act"
  | "data.flow";

export type NavRoute =
  | "home"
  | "users"
  | "inventory"
  | "sessions"
  | "protect"
  | "respond"
  | "coverage"
  | "tester";

export interface AssuranceRecord {
  visibility: string;
  control: string;
  on_failure: string;
  tamper: string;
}

export interface DiscoveredAgent {
  id: string;
  name: string;
  kind: string;
  config_path: string;
  hook_installed: boolean;
  mcp_count: number;
  assurance: AssuranceRecord;
  assurance_level: AssuranceLevel;
  sponsor: string | null;
  detected_at: string;
}

export interface McpServerEntry {
  name: string;
  transport: string;
  command: string;
  source_agent: string;
  config_path: string;
  pinned: boolean;
}

export interface ArtifactEntry {
  id: string;
  name: string;
  kind: ArtifactKind;
  scope: ArtifactScope;
  source_agent: string;
  path: string;
  content_digest: string;
  file_count: number;
  total_bytes: number;
  usage_count: number;
  pinned: boolean;
  risk_flags: ArtifactRiskFlag[];
  device_id: string;
  device_name: string;
  user_id?: string | null;
  detected_at: string;
}

export interface Device {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  install_profile: InstallProfile;
  daemon_version: string;
  online: boolean;
  hook_effective: boolean;
  agents: DiscoveredAgent[];
  mcp_servers: McpServerEntry[];
  artifacts?: ArtifactEntry[];
  user_id?: string | null;
  user_display?: string | null;
  last_seen: string;
}

export interface TurnSummary {
  turn_index: number;
  trace_id: string;
  span_count: number;
  duration_ms: number;
  blocked_count: number;
  asked_count: number;
  has_compaction: boolean;
  has_subagent_handoff: boolean;
  started_at: string;
}

export interface SessionSummary {
  id: string;
  device_id: string;
  device_name: string;
  agent_name: string;
  user_id?: string | null;
  user_display?: string | null;
  turn_count?: number;
  parent_session_id?: string | null;
  started_at: string;
  last_activity: string;
  total_actions: number;
  blocked_count: number;
  step_up_count: number;
  watch_hits: number;
  assurance_level: AssuranceLevel;
  labels?: SessionLabel[];
}

export interface SecondaryAction {
  command: string;
  action_class: ActionClass;
  target: string;
}

export interface ActionAttempt {
  id: string;
  session_id: string;
  device_id: string;
  device_name: string;
  agent_name: string;
  action_class: ActionClass;
  control_point: string;
  target: string;
  summary: string;
  timestamp: string;
  user_id?: string | null;
  user_display?: string | null;
  turn_index?: number;
  span_id?: string | null;
  parent_span_id?: string | null;
  span_kind?: SpanKind;
  duration_ms?: number;
  provenance?: ProvenanceSource;
  secondary_actions?: SecondaryAction[];
  skill_used?: string | null;
  compaction?: boolean;
}

export interface OrgPrivacyConfig {
  identity_mode: IdentityMode;
  user_risk_scoring: boolean;
}

export interface UserRiskFactor {
  code: string;
  label: string;
  points: number;
  count: number;
}

export interface UserProfile {
  id: string;
  display_name: string;
  email: string;
  department: string;
  idp_source: string;
  pseudonym_id: string;
  device_ids: string[];
  agent_names: string[];
  artifact_count: number;
  session_count: number;
  blocked_count: number;
  asked_count: number;
  watch_count: number;
  finding_count: number;
  risk_score: number;
  risk_tier: RiskTier;
  risk_factors: UserRiskFactor[];
  last_active: string;
}

export interface DecisionReceipt {
  receipt_id: string;
  attempt_id: string;
  session_id: string;
  device_id: string;
  agent_name: string;
  action_class: ActionClass;
  control_point: string;
  target: string;
  verdict: Verdict;
  would_be: Verdict | null;
  rule_id: string | null;
  pack_id: string | null;
  mode_applied: Mode | null;
  grant_id: string | null;
  reason: string;
  next_step: string;
  receipt_digest: string;
  decided_at: string;
  key_id?: string | null;
  signature?: string | null;
  signature_verified?: boolean | null;
}

export interface SessionDetailResponse {
  session: SessionSummary;
  attempts: ActionAttempt[];
  receipts: DecisionReceipt[];
  turns?: TurnSummary[];
  user?: UserProfile | null;
}

export interface UserDetailResponse {
  user: UserProfile;
  devices: Device[];
  sessions: SessionSummary[];
  recent_attempts: ActionAttempt[];
  receipts: DecisionReceipt[];
  findings: Finding[];
  artifacts: ArtifactEntry[];
  identity_mode: IdentityMode;
}

export interface RuleMatch {
  action_classes: ActionClass[];
  target_prefixes: string[];
  target_contains: string[];
  agents: string[];
}

export interface PolicyRule {
  id: string;
  title: string;
  description: string;
  mode: Mode;
  min_grade: string;
  enabled: boolean;
  locked: boolean;
  matcher: RuleMatch;
  hits: number;
  would_ask_hits: number;
  would_block_hits: number;
  reason_template: string;
}

export interface PolicyPack {
  id: string;
  name: string;
  description: string;
  version: string;
  channel: string;
  rules: PolicyRule[];
}

export type ApprovalState =
  | { status: "pending"; expires_at: string }
  | { status: "approved"; grant_id: string; scope: GrantScope; decided_at: string; note: string }
  | { status: "denied"; decided_at: string; note: string }
  | { status: "expired"; expired_at: string };

export interface ApprovalRequest {
  id: string;
  receipt_id: string;
  session_id: string;
  device_id: string;
  device_name: string;
  agent_name: string;
  action_class: ActionClass;
  target: string;
  rule_id: string;
  rule_title: string;
  required_grade: string;
  reason: string;
  requested_at: string;
  state: ApprovalState;
}

export interface Finding {
  id: string;
  session_id: string;
  device_id: string;
  device_name: string;
  agent_name: string;
  class: string;
  severity: string;
  lifecycle: FindingLifecycle;
  rule_id: string | null;
  title: string;
  summary: string;
  target: string;
  detected_at: string;
}

export interface Incident {
  id: string;
  session_id: string;
  device_id: string;
  device_name: string;
  agent_name: string;
  title: string;
  summary: string;
  severity: string;
  lifecycle: FindingLifecycle;
  finding_ids: string[];
  finding_count: number;
  labels: SessionLabel[];
  first_seen: string;
  last_seen: string;
}

export type KillSwitchState =
  | { state: "inactive" }
  | { state: "frozen"; scope: KillScope; target_id: string; reason: string; issued_at: string; expires_at: string }
  | { state: "killed"; scope: KillScope; target_id: string; reason: string; issued_at: string };

export interface ReplaySample {
  attempt_id: string;
  session_id: string;
  agent_name: string;
  action_class: ActionClass;
  target: string;
  current_verdict: Verdict;
  candidate_verdict: Verdict;
  timestamp: string;
}

export interface ReplaySummary {
  rule_id: string;
  candidate_mode: Mode;
  window_label: string;
  total_scanned: number;
  matched: number;
  would_ask: number;
  would_block: number;
  not_matched: number;
  samples: ReplaySample[];
}

export interface InsightTile {
  id: string;
  headline: string;
  metric: string;
  comparison: string;
  action_label: string;
  route: NavRoute;
  tone: string;
}

export interface SetupStep {
  id: string;
  label: string;
  done: boolean;
  detail: string;
}

export interface OverviewResponse {
  server_status: string;
  total_devices: number;
  online_devices: number;
  total_agents: number;
  total_mcp_servers: number;
  active_sessions: number;
  pending_approvals: number;
  open_findings: number;
  open_incidents?: number;
  kill_switch: KillSwitchState;
  tiles: InsightTile[];
  setup_steps: SetupStep[];
}

export interface LiveEvent {
  id: string;
  topic: string;
  summary: string;
  verdict: Verdict | null;
  timestamp: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  kind: string;
  actor: string;
  summary: string;
  target: string;
}

export interface TrustedKeyInfo {
  key_id: string;
  public_key_b64: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  storage_mode: string;
  timestamp: string;
}

export type ConfirmationClass = "none" | "consequence" | "typed" | "propose" | "quorum";

export type DeploymentKeyStatus = "active" | "exhausted" | "expired" | "revoked";

export interface DeploymentKey {
  id: string;
  label: string;
  token_preview: string;
  install_profile: string;
  wave: string;
  max_uses: number;
  used_count: number;
  status: DeploymentKeyStatus;
  created_at: string;
  expires_at: string;
  created_by: string;
}

export interface CreateDeploymentKeyResponse {
  key: DeploymentKey;
  plaintext_token: string;
}

export type MdmFormat =
  | "intune_win32"
  | "jamf_mobileconfig"
  | "hexnode"
  | "tanium"
  | "chrome_enterprise"
  | "firefox_gpo"
  | "linux_repo";

export interface InstallerSpec {
  platform: string;
  label: string;
  version: string;
  command: string;
  sha256: string;
  doctor_command: string;
  notes: string;
}

export interface MdmRenderResponse {
  format: MdmFormat;
  filename: string;
  content_type: string;
  payload: string;
  deployment_notes: string[];
}

export type IntegrationCategory = "directory_sync" | "saas_connector" | "export_sink";
export type IntegrationHealthState = "connected" | "at_risk" | "degraded" | "not_configured";

export interface ReadinessCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface IntegrationEntry {
  id: string;
  name: string;
  provider: string;
  category: IntegrationCategory;
  state: IntegrationHealthState;
  synced_users: number;
  last_sync_at: string | null;
  credential_expires_in_days: number | null;
  detail: string;
  readiness_checks: ReadinessCheck[];
}

export interface OtlpFanoutConfig {
  enabled: boolean;
  grpc_port: number;
  http_port: number;
  bind_address: string;
  downstream_targets: string[];
  loopback_only: boolean;
  accepted_spans_24h: number;
}

export interface ConnectConfigResponse {
  server_origin: string;
  installers: InstallerSpec[];
  deployment_keys: DeploymentKey[];
  otlp: OtlpFanoutConfig;
  integrations: IntegrationEntry[];
}

export type BrowserDlpClass = "file_upload" | "paste_secret" | "source_code" | "customer_pii";

export interface BrowserAppPolicy {
  id: string;
  name: string;
  domains: string[];
  mode: Mode;
  block_file_uploads: boolean;
  block_secret_paste: boolean;
  managed_extension_only: boolean;
  events_24h: number;
  blocked_24h: number;
}

export interface BrowserEvaluateResponse {
  app_id: string;
  app_name: string;
  verdict: Verdict;
  rule_id: string | null;
  reason: string;
  dlp_class: BrowserDlpClass;
}
