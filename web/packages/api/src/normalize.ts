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
  SessionDetailResponse,
  SessionLabel,
  SessionSummary,
  SpanKind,
  TrustedKeyInfo,
  TurnSummary,
  UserProfile,
  RiskTier,
  Verdict,
} from "./types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type RawRecord = Record<string, any>;

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

export function normPageInfo(raw: RawRecord | undefined): PageInfo {
  return {
    next_page_token: raw?.nextPageToken ?? raw?.next_page_token ?? "",
    prev_page_token: raw?.prevPageToken ?? raw?.prev_page_token ?? "",
    total_size_estimate: Number(raw?.totalSizeEstimate ?? raw?.total_size_estimate ?? 0),
    has_more: Boolean(raw?.hasMore ?? raw?.has_more ?? false),
  };
}

export function normTrustedKey(raw: RawRecord): TrustedKeyInfo {
  return {
    key_id: raw.keyId ?? raw.key_id ?? "",
    public_key_b64: raw.publicKeyB64 ?? raw.public_key_b64 ?? "",
  };
}

export function normAgent(raw: RawRecord): DiscoveredAgent {
  const a = raw.assurance ?? {};
  return {
    id: raw.id ?? "",
    name: raw.name ?? "",
    kind: raw.kind ?? "",
    config_path: raw.configPath ?? raw.config_path ?? "",
    hook_installed: Boolean(raw.hookInstalled ?? raw.hook_installed),
    mcp_count: Number(raw.mcpCount ?? raw.mcp_count ?? 0),
    assurance: {
      visibility: stripEnum(a.visibility, "VISIBILITY_", "none"),
      control: stripEnum(a.control, "CONTROL_STRENGTH_", "none").replace(/_/g, "-"),
      on_failure: stripEnum(a.onFailure ?? a.on_failure, "ON_FAILURE_", "open"),
      tamper: stripEnum(a.tamper, "TAMPER_GRADE_", "user"),
    },
    assurance_level: normAssurance(raw.assuranceLevel ?? raw.assurance_level),
    sponsor: raw.sponsor ?? null,
    detected_at: raw.detectedAt ?? raw.detected_at ?? "",
  };
}

export function normMcpServer(raw: RawRecord): McpServerEntry {
  return {
    name: raw.name ?? "",
    transport: raw.transport ?? "",
    command: raw.command ?? "",
    source_agent: raw.sourceAgent ?? raw.source_agent ?? "",
    config_path: raw.configPath ?? raw.config_path ?? "",
    pinned: Boolean(raw.pinned),
  };
}

export function normArtifact(raw: RawRecord): ArtifactEntry {
  const kind = stripEnum(raw.kind, "ARTIFACT_KIND_", "skill") as ArtifactKind;
  const scope = stripEnum(raw.scope, "ARTIFACT_SCOPE_", "user") as ArtifactScope;
  const flags = (raw.riskFlags ?? raw.risk_flags ?? []).map((f: unknown) =>
    stripEnum(f, "ARTIFACT_RISK_FLAG_", "unpinned-digest").replace(/_/g, "-"),
  ) as ArtifactRiskFlag[];
  return {
    id: raw.id ?? "",
    name: raw.name ?? "",
    kind,
    scope,
    source_agent: raw.sourceAgent ?? raw.source_agent ?? "",
    path: raw.path ?? "",
    content_digest: raw.contentDigest ?? raw.content_digest ?? "",
    file_count: Number(raw.fileCount ?? raw.file_count ?? 0),
    total_bytes: Number(raw.totalBytes ?? raw.total_bytes ?? 0),
    usage_count: Number(raw.usageCount ?? raw.usage_count ?? 0),
    pinned: Boolean(raw.pinned),
    risk_flags: flags,
    device_id: raw.deviceId ?? raw.device_id ?? "",
    device_name: raw.deviceName ?? raw.device_name ?? "",
    user_id: raw.userId ?? raw.user_id ?? null,
    detected_at: raw.detectedAt ?? raw.detected_at ?? "",
  };
}

export function normDevice(raw: RawRecord): Device {
  return {
    id: raw.id ?? "",
    hostname: raw.hostname ?? "",
    os: raw.os ?? "",
    arch: raw.arch ?? "",
    install_profile: stripEnum(raw.installProfile ?? raw.install_profile, "INSTALL_PROFILE_", "user") as InstallProfile,
    daemon_version: raw.daemonVersion ?? raw.daemon_version ?? "",
    online: Boolean(raw.online),
    hook_effective: Boolean(raw.hookEffective ?? raw.hook_effective),
    agents: (raw.agents ?? []).map(normAgent),
    mcp_servers: (raw.mcpServers ?? raw.mcp_servers ?? []).map(normMcpServer),
    artifacts: (raw.artifacts ?? []).map(normArtifact),
    user_id: raw.userId ?? raw.user_id ?? null,
    user_display: raw.userDisplay ?? raw.user_display ?? null,
    last_seen: raw.lastSeen ?? raw.last_seen ?? "",
  };
}

export function normSession(raw: RawRecord): SessionSummary {
  return {
    id: raw.id ?? "",
    device_id: raw.deviceId ?? raw.device_id ?? "",
    device_name: raw.deviceName ?? raw.device_name ?? "",
    agent_name: raw.agentName ?? raw.agent_name ?? "",
    user_id: raw.userId ?? raw.user_id ?? null,
    user_display: raw.userDisplay ?? raw.user_display ?? null,
    turn_count: Number(raw.turnCount ?? raw.turn_count ?? 1),
    parent_session_id: raw.parentSessionId ?? raw.parent_session_id ?? null,
    started_at: raw.startedAt ?? raw.started_at ?? "",
    last_activity: raw.lastActivity ?? raw.last_activity ?? "",
    total_actions: Number(raw.totalActions ?? raw.total_actions ?? 0),
    blocked_count: Number(raw.blockedCount ?? raw.blocked_count ?? 0),
    step_up_count: Number(raw.stepUpCount ?? raw.step_up_count ?? 0),
    watch_hits: Number(raw.watchHits ?? raw.watch_hits ?? 0),
    assurance_level: normAssurance(raw.assuranceLevel ?? raw.assurance_level),
    labels: (raw.labels ?? []).map((l: unknown) => stripEnum(l, "SESSION_LABEL_", "credential_accessed") as SessionLabel),
  };
}

export function normAttempt(raw: RawRecord): ActionAttempt {
  return {
    id: raw.id ?? "",
    session_id: raw.sessionId ?? raw.session_id ?? "",
    device_id: raw.deviceId ?? raw.device_id ?? "",
    device_name: raw.deviceName ?? raw.device_name ?? "",
    agent_name: raw.agentName ?? raw.agent_name ?? "",
    action_class: normActionClass(raw.actionClass ?? raw.action_class),
    control_point: stripEnum(raw.controlPoint ?? raw.control_point, "CONTROL_POINT_", "hook").replace(/_/g, "-"),
    target: raw.target ?? "",
    summary: raw.summary ?? "",
    timestamp: raw.timestamp ?? "",
    user_id: raw.userId ?? raw.user_id ?? null,
    user_display: raw.userDisplay ?? raw.user_display ?? null,
    turn_index: Number(raw.turnIndex ?? raw.turn_index ?? 1),
    span_id: raw.spanId ?? raw.span_id ?? null,
    parent_span_id: raw.parentSpanId ?? raw.parent_span_id ?? null,
    span_kind: stripEnum(raw.spanKind ?? raw.span_kind, "SPAN_KIND_", "execute_tool") as SpanKind,
    duration_ms: Number(raw.durationMs ?? raw.duration_ms ?? 0),
    provenance: stripEnum(raw.provenance, "PROVENANCE_SOURCE_", "observed") as ProvenanceSource,
    secondary_actions: (raw.secondaryActions ?? raw.secondary_actions ?? []).map((s: RawRecord) => ({
      command: s.command ?? "",
      action_class: normActionClass(s.actionClass ?? s.action_class),
      target: s.target ?? "",
    })),
    skill_used: raw.skillUsed ?? raw.skill_used ?? null,
    compaction: Boolean(raw.compaction),
  };
}

export function normReceipt(raw: RawRecord): DecisionReceipt {
  const wb = raw.wouldBe ?? raw.would_be;
  const ma = raw.modeApplied ?? raw.mode_applied;
  return {
    receipt_id: raw.receiptId ?? raw.receipt_id ?? "",
    attempt_id: raw.attemptId ?? raw.attempt_id ?? "",
    session_id: raw.sessionId ?? raw.session_id ?? "",
    device_id: raw.deviceId ?? raw.device_id ?? "",
    agent_name: raw.agentName ?? raw.agent_name ?? "",
    action_class: normActionClass(raw.actionClass ?? raw.action_class),
    control_point: stripEnum(raw.controlPoint ?? raw.control_point, "CONTROL_POINT_", "hook").replace(/_/g, "-"),
    target: raw.target ?? "",
    verdict: normVerdict(raw.verdict),
    would_be: wb ? normVerdict(wb) : null,
    rule_id: raw.ruleId ?? raw.rule_id ?? null,
    pack_id: raw.packId ?? raw.pack_id ?? null,
    mode_applied: ma ? normMode(ma) : null,
    grant_id: raw.grantId ?? raw.grant_id ?? null,
    reason: raw.reason ?? "",
    next_step: raw.nextStep ?? raw.next_step ?? "",
    receipt_digest: raw.receiptDigest ?? raw.receipt_digest ?? "",
    decided_at: raw.decidedAt ?? raw.decided_at ?? "",
    key_id: raw.keyId ?? raw.key_id ?? null,
    signature: raw.signature ?? null,
    signature_verified: raw.signatureVerified ?? raw.signature_verified ?? null,
  };
}

export function normTurn(raw: RawRecord): TurnSummary {
  return {
    turn_index: Number(raw.turnIndex ?? raw.turn_index ?? 1),
    trace_id: raw.traceId ?? raw.trace_id ?? "",
    span_count: Number(raw.spanCount ?? raw.span_count ?? 0),
    duration_ms: Number(raw.durationMs ?? raw.duration_ms ?? 0),
    blocked_count: Number(raw.blockedCount ?? raw.blocked_count ?? 0),
    asked_count: Number(raw.askedCount ?? raw.asked_count ?? 0),
    has_compaction: Boolean(raw.hasCompaction ?? raw.has_compaction),
    has_subagent_handoff: Boolean(raw.hasSubagentHandoff ?? raw.has_subagent_handoff),
    started_at: raw.startedAt ?? raw.started_at ?? "",
  };
}

export function normUser(raw: RawRecord): UserProfile {
  return {
    id: raw.id ?? "",
    display_name: raw.displayName ?? raw.display_name ?? "",
    email: raw.email ?? "",
    department: raw.department ?? "",
    idp_source: raw.idpSource ?? raw.idp_source ?? "",
    pseudonym_id: raw.pseudonymId ?? raw.pseudonym_id ?? "",
    device_ids: raw.deviceIds ?? raw.device_ids ?? [],
    agent_names: raw.agentNames ?? raw.agent_names ?? [],
    artifact_count: Number(raw.artifactCount ?? raw.artifact_count ?? 0),
    session_count: Number(raw.sessionCount ?? raw.session_count ?? 0),
    blocked_count: Number(raw.blockedCount ?? raw.blocked_count ?? 0),
    asked_count: Number(raw.askedCount ?? raw.asked_count ?? 0),
    watch_count: Number(raw.watchCount ?? raw.watch_count ?? 0),
    finding_count: Number(raw.findingCount ?? raw.finding_count ?? 0),
    risk_score: Number(raw.riskScore ?? raw.risk_score ?? 0),
    risk_tier: stripEnum(raw.riskTier ?? raw.risk_tier, "RISK_TIER_", "low") as RiskTier,
    risk_factors: raw.riskFactors ?? raw.risk_factors ?? [],
    last_active: raw.lastActive ?? raw.last_active ?? "",
  };
}

export function normSessionDetail(raw: RawRecord): SessionDetailResponse {
  return {
    session: normSession(raw.session ?? {}),
    attempts: (raw.attempts ?? []).map(normAttempt),
    receipts: (raw.receipts ?? []).map(normReceipt),
    turns: (raw.turns ?? []).map(normTurn),
    user: raw.user ? normUser(raw.user) : null,
  };
}

export * from "./normalize-ops";
