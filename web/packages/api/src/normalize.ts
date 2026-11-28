// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type {
  ActionAttempt,
  ActionClass,
  ArtifactEntry,
  ArtifactKind,
  ArtifactRiskFlag,
  ArtifactScope,
  AssuranceLevel,
  DecisionReceipt,
  Device,
  DiscoveredAgent,
  InstallProfile,
  McpServerEntry,
  Mode,
  PageInfo,
  ProvenanceSource,
  RiskTier,
  SessionDetailResponse,
  SessionLabel,
  SessionSummary,
  SpanKind,
  TrustedKeyInfo,
  TurnSummary,
  UserProfile,
  UserRiskFactor,
  Verdict,
} from "./types";

export type RawRecord = Record<string, unknown>;

export function rec(v: unknown): RawRecord {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as RawRecord) : {};
}

export function recArr(v: unknown): RawRecord[] {
  return Array.isArray(v) ? v.map(rec) : [];
}

export function str(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

export function optStr(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

export function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

export function num(v: unknown, fallback = 0): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}

export function boolOpt(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

export function stripEnum(raw: unknown, prefix: string, fallback: string): string {
  if (typeof raw !== "string" || !raw) return fallback;
  const upper = raw.toUpperCase();
  if (upper.startsWith(prefix)) {
    return upper.slice(prefix.length).toLowerCase();
  }
  return raw.toLowerCase();
}

export function normMode(v: unknown): Mode {
  const s = stripEnum(v, "MODE_", "watch");
  if (s === "off" || s === "watch" || s === "ask" || s === "block") return s;
  return "watch";
}

export function normVerdict(v: unknown): Verdict {
  const s = stripEnum(v, "VERDICT_", "allow");
  if (s === "allow" || s === "modify" || s === "step_up" || s === "defer" || s === "deny") return s;
  return "allow";
}

export function normActionClass(v: unknown): ActionClass {
  const map: Record<string, ActionClass> = {
    exec: "exec",
    file_read: "file.read",
    "file.read": "file.read",
    file_write: "file.write",
    "file.write": "file.write",
    file_delete: "file.delete",
    "file.delete": "file.delete",
    net_connect: "net.connect",
    "net.connect": "net.connect",
    net_request: "net.request",
    "net.request": "net.request",
    llm_request: "llm.request",
    "llm.request": "llm.request",
    mcp_connect: "mcp.connect",
    "mcp.connect": "mcp.connect",
    mcp_call: "mcp.call",
    "mcp.call": "mcp.call",
    cred_use: "cred.use",
    "cred.use": "cred.use",
    agent_spawn: "agent.spawn",
    "agent.spawn": "agent.spawn",
    config_change: "config.change",
    "config.change": "config.change",
    elevate: "elevate",
    ui_act: "ui.act",
    "ui.act": "ui.act",
    data_flow: "data.flow",
    "data.flow": "data.flow",
  };
  const s = stripEnum(v, "ACTION_CLASS_", "exec");
  return map[s] ?? "exec";
}

export function normAssurance(v: unknown): AssuranceLevel {
  const s = stripEnum(v, "ASSURANCE_LEVEL_", "al0").toUpperCase();
  if (s === "AL0" || s === "AL1" || s === "AL2" || s === "AL3" || s === "AL4") return s;
  return "AL0";
}

export function normPageInfo(raw: unknown): PageInfo {
  const r = rec(raw);
  return {
    next_page_token: str(r.nextPageToken ?? r.next_page_token),
    prev_page_token: str(r.prevPageToken ?? r.prev_page_token),
    total_size_estimate: num(r.totalSizeEstimate ?? r.total_size_estimate),
    has_more: Boolean(r.hasMore ?? r.has_more ?? false),
  };
}

export function normTrustedKey(raw: RawRecord): TrustedKeyInfo {
  return {
    key_id: str(raw.keyId ?? raw.key_id),
    public_key_b64: str(raw.publicKeyB64 ?? raw.public_key_b64),
  };
}

export function normAgent(raw: RawRecord): DiscoveredAgent {
  const a = rec(raw.assurance);
  const vendor = optStr(raw.vendor);
  const iconKey = optStr(raw.iconKey ?? raw.icon_key);
  return {
    id: str(raw.id),
    name: str(raw.name),
    ...(vendor ? { vendor } : {}),
    kind: str(raw.kind),
    ...(iconKey ? { icon_key: iconKey } : {}),
    config_path: str(raw.configPath ?? raw.config_path),
    hook_installed: Boolean(raw.hookInstalled ?? raw.hook_installed),
    mcp_count: num(raw.mcpCount ?? raw.mcp_count),
    assurance: {
      visibility: stripEnum(a.visibility, "VISIBILITY_", "none"),
      control: stripEnum(a.control, "CONTROL_STRENGTH_", "none").replace(/_/g, "-"),
      on_failure: stripEnum(a.onFailure ?? a.on_failure, "ON_FAILURE_", "open"),
      tamper: stripEnum(a.tamper, "TAMPER_GRADE_", "user"),
    },
    assurance_level: normAssurance(raw.assuranceLevel ?? raw.assurance_level),
    sponsor: optStr(raw.sponsor),
    detected_at: str(raw.detectedAt ?? raw.detected_at),
  };
}

export function normMcpServer(raw: RawRecord): McpServerEntry {
  return {
    name: str(raw.name),
    transport: str(raw.transport),
    command: str(raw.command),
    source_agent: str(raw.sourceAgent ?? raw.source_agent),
    config_path: str(raw.configPath ?? raw.config_path),
    pinned: Boolean(raw.pinned),
  };
}

export function normArtifact(raw: RawRecord): ArtifactEntry {
  const kind = stripEnum(raw.kind, "ARTIFACT_KIND_", "skill") as ArtifactKind;
  const scope = stripEnum(raw.scope, "ARTIFACT_SCOPE_", "user") as ArtifactScope;
  const rawFlags = raw.riskFlags ?? raw.risk_flags;
  const flags = (Array.isArray(rawFlags) ? rawFlags : []).map((f: unknown) =>
    stripEnum(f, "ARTIFACT_RISK_FLAG_", "unpinned-digest").replace(/_/g, "-"),
  ) as ArtifactRiskFlag[];
  return {
    id: str(raw.id),
    name: str(raw.name),
    kind,
    scope,
    source_agent: str(raw.sourceAgent ?? raw.source_agent),
    path: str(raw.path),
    content_digest: str(raw.contentDigest ?? raw.content_digest),
    file_count: num(raw.fileCount ?? raw.file_count),
    total_bytes: num(raw.totalBytes ?? raw.total_bytes),
    usage_count: num(raw.usageCount ?? raw.usage_count),
    pinned: Boolean(raw.pinned),
    risk_flags: flags,
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    user_id: optStr(raw.userId ?? raw.user_id),
    detected_at: str(raw.detectedAt ?? raw.detected_at),
  };
}

export function normDevice(raw: RawRecord): Device {
  return {
    id: str(raw.id),
    hostname: str(raw.hostname),
    os: str(raw.os),
    arch: str(raw.arch),
    install_profile: stripEnum(raw.installProfile ?? raw.install_profile, "INSTALL_PROFILE_", "user") as InstallProfile,
    daemon_version: str(raw.daemonVersion ?? raw.daemon_version),
    online: Boolean(raw.online),
    hook_effective: Boolean(raw.hookEffective ?? raw.hook_effective),
    agents: recArr(raw.agents).map(normAgent),
    mcp_servers: recArr(raw.mcpServers ?? raw.mcp_servers).map(normMcpServer),
    artifacts: recArr(raw.artifacts).map(normArtifact),
    user_id: optStr(raw.userId ?? raw.user_id),
    user_display: optStr(raw.userDisplay ?? raw.user_display),
    last_seen: str(raw.lastSeen ?? raw.last_seen),
  };
}

export function normSession(raw: RawRecord): SessionSummary {
  const rawLabels = raw.labels;
  return {
    id: str(raw.id),
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    agent_name: str(raw.agentName ?? raw.agent_name),
    user_id: optStr(raw.userId ?? raw.user_id),
    user_display: optStr(raw.userDisplay ?? raw.user_display),
    turn_count: num(raw.turnCount ?? raw.turn_count, 1),
    parent_session_id: optStr(raw.parentSessionId ?? raw.parent_session_id),
    started_at: str(raw.startedAt ?? raw.started_at),
    last_activity: str(raw.lastActivity ?? raw.last_activity),
    total_actions: num(raw.totalActions ?? raw.total_actions),
    blocked_count: num(raw.blockedCount ?? raw.blocked_count),
    step_up_count: num(raw.stepUpCount ?? raw.step_up_count),
    watch_hits: num(raw.watchHits ?? raw.watch_hits),
    assurance_level: normAssurance(raw.assuranceLevel ?? raw.assurance_level),
    labels: (Array.isArray(rawLabels) ? rawLabels : []).map(
      (l: unknown) => stripEnum(l, "SESSION_LABEL_", "credential_accessed") as SessionLabel,
    ),
  };
}

export function normAttempt(raw: RawRecord): ActionAttempt {
  return {
    id: str(raw.id),
    session_id: str(raw.sessionId ?? raw.session_id),
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    agent_name: str(raw.agentName ?? raw.agent_name),
    action_class: normActionClass(raw.actionClass ?? raw.action_class),
    control_point: stripEnum(raw.controlPoint ?? raw.control_point, "CONTROL_POINT_", "hook").replace(/_/g, "-"),
    target: str(raw.target),
    summary: str(raw.summary),
    timestamp: str(raw.timestamp),
    user_id: optStr(raw.userId ?? raw.user_id),
    user_display: optStr(raw.userDisplay ?? raw.user_display),
    turn_index: num(raw.turnIndex ?? raw.turn_index, 1),
    span_id: optStr(raw.spanId ?? raw.span_id),
    parent_span_id: optStr(raw.parentSpanId ?? raw.parent_span_id),
    span_kind: stripEnum(raw.spanKind ?? raw.span_kind, "SPAN_KIND_", "execute_tool") as SpanKind,
    duration_ms: num(raw.durationMs ?? raw.duration_ms),
    provenance: stripEnum(raw.provenance, "PROVENANCE_SOURCE_", "observed") as ProvenanceSource,
    secondary_actions: recArr(raw.secondaryActions ?? raw.secondary_actions).map((s) => ({
      command: str(s.command),
      action_class: normActionClass(s.actionClass ?? s.action_class),
      target: str(s.target),
    })),
    skill_used: optStr(raw.skillUsed ?? raw.skill_used),
    compaction: Boolean(raw.compaction),
  };
}

export function normReceipt(raw: RawRecord): DecisionReceipt {
  const wb = raw.wouldBe ?? raw.would_be;
  const ma = raw.modeApplied ?? raw.mode_applied;
  return {
    receipt_id: str(raw.receiptId ?? raw.receipt_id),
    attempt_id: str(raw.attemptId ?? raw.attempt_id),
    session_id: str(raw.sessionId ?? raw.session_id),
    device_id: str(raw.deviceId ?? raw.device_id),
    agent_name: str(raw.agentName ?? raw.agent_name),
    action_class: normActionClass(raw.actionClass ?? raw.action_class),
    control_point: stripEnum(raw.controlPoint ?? raw.control_point, "CONTROL_POINT_", "hook").replace(/_/g, "-"),
    target: str(raw.target),
    verdict: normVerdict(raw.verdict),
    would_be: wb ? normVerdict(wb) : null,
    rule_id: optStr(raw.ruleId ?? raw.rule_id),
    pack_id: optStr(raw.packId ?? raw.pack_id),
    mode_applied: ma ? normMode(ma) : null,
    grant_id: optStr(raw.grantId ?? raw.grant_id),
    reason: str(raw.reason),
    next_step: str(raw.nextStep ?? raw.next_step),
    receipt_digest: str(raw.receiptDigest ?? raw.receipt_digest),
    decided_at: str(raw.decidedAt ?? raw.decided_at),
    key_id: optStr(raw.keyId ?? raw.key_id),
    signature: optStr(raw.signature),
    signature_verified: boolOpt(raw.signatureVerified ?? raw.signature_verified),
  };
}

export function normTurn(raw: RawRecord): TurnSummary {
  return {
    turn_index: num(raw.turnIndex ?? raw.turn_index, 1),
    trace_id: str(raw.traceId ?? raw.trace_id),
    span_count: num(raw.spanCount ?? raw.span_count),
    duration_ms: num(raw.durationMs ?? raw.duration_ms),
    blocked_count: num(raw.blockedCount ?? raw.blocked_count),
    asked_count: num(raw.askedCount ?? raw.asked_count),
    has_compaction: Boolean(raw.hasCompaction ?? raw.has_compaction),
    has_subagent_handoff: Boolean(raw.hasSubagentHandoff ?? raw.has_subagent_handoff),
    started_at: str(raw.startedAt ?? raw.started_at),
  };
}

export function normUser(raw: RawRecord): UserProfile {
  return {
    id: str(raw.id),
    display_name: str(raw.displayName ?? raw.display_name),
    email: str(raw.email),
    department: str(raw.department),
    idp_source: str(raw.idpSource ?? raw.idp_source),
    pseudonym_id: str(raw.pseudonymId ?? raw.pseudonym_id),
    device_ids: strArr(raw.deviceIds ?? raw.device_ids),
    agent_names: strArr(raw.agentNames ?? raw.agent_names),
    artifact_count: num(raw.artifactCount ?? raw.artifact_count),
    session_count: num(raw.sessionCount ?? raw.session_count),
    blocked_count: num(raw.blockedCount ?? raw.blocked_count),
    asked_count: num(raw.askedCount ?? raw.asked_count),
    watch_count: num(raw.watchCount ?? raw.watch_count),
    finding_count: num(raw.findingCount ?? raw.finding_count),
    risk_score: num(raw.riskScore ?? raw.risk_score),
    risk_tier: stripEnum(raw.riskTier ?? raw.risk_tier, "RISK_TIER_", "low") as RiskTier,
    risk_factors: recArr(raw.riskFactors ?? raw.risk_factors).map(
      (f): UserRiskFactor => ({
        code: str(f.code),
        label: str(f.label),
        points: num(f.points),
        count: num(f.count),
      }),
    ),
    last_active: str(raw.lastActive ?? raw.last_active),
  };
}

export function normSessionDetail(raw: RawRecord): SessionDetailResponse {
  return {
    session: normSession(rec(raw.session)),
    attempts: recArr(raw.attempts).map(normAttempt),
    receipts: recArr(raw.receipts).map(normReceipt),
    turns: recArr(raw.turns).map(normTurn),
    user: raw.user ? normUser(rec(raw.user)) : null,
  };
}

export * from "./normalize-ops";
