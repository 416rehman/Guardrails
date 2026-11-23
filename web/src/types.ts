export type Mode = "off" | "watch" | "ask" | "block";
export type Verdict = "allow" | "modify" | "step_up" | "defer" | "deny";
export type InstallProfile = "user" | "protected";
export type AssuranceLevel = "AL0" | "AL1" | "AL2" | "AL3" | "AL4";
export type GrantScope = "once" | "session" | "one_hour";
export type FindingLifecycle = "open" | "acknowledged" | "contained" | "resolved";
export type KillScope = "session" | "device" | "organisation";
export type KillAction = "freeze" | "kill" | "release";

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
  last_seen: string;
}

export interface SessionSummary {
  id: string;
  device_id: string;
  device_name: string;
  agent_name: string;
  started_at: string;
  last_activity: string;
  total_actions: number;
  blocked_count: number;
  step_up_count: number;
  watch_hits: number;
  assurance_level: AssuranceLevel;
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
}

export interface SessionDetailResponse {
  session: SessionSummary;
  attempts: ActionAttempt[];
  receipts: DecisionReceipt[];
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
  kill_switch: KillSwitchState;
  tiles: InsightTile[];
  setup_steps: SetupStep[];
}

export type NavRoute = "home" | "inventory" | "sessions" | "protect" | "respond" | "tester";

export interface LiveEvent {
  id: string;
  topic: string;
  summary: string;
  verdict: Verdict | null;
  timestamp: string;
}
