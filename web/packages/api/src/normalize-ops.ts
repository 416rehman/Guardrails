import {
  normActionClass,
  normArtifact,
  normAttempt,
  normDevice,
  normMode,
  normReceipt,
  normSession,
  normUser,
  normVerdict,
  stripEnum,
  type RawRecord,
} from "./normalize";
import type {
  ApprovalRequest,
  ApprovalState,
  AuditEntry,
  Finding,
  FindingLifecycle,
  GrantScope,
  HealthResponse,
  IdentityMode,
  Incident,
  KillScope,
  KillSwitchState,
  OrgPrivacyConfig,
  OverviewResponse,
  PolicyPack,
  PolicyRule,
  ReplaySummary,
  ServerHealth,
  SessionLabel,
  StorageMode,
  UserDetailResponse,
} from "./types";
import type {
  BrowserAppPolicy,
  BrowserDlpClass,
  BrowserEvaluateResponse,
  ConnectConfigResponse,
  CreateDeploymentKeyResponse,
  DeploymentKey,
  DeploymentKeyStatus,
  IntegrationCategory,
  IntegrationEntry,
  IntegrationHealthState,
  MdmFormat,
  MdmRenderResponse,
} from "./types-connect";

function normGrade(v: unknown): string {
  const s = stripEnum(v, "APPROVAL_GRADE_", "g1").toUpperCase();
  return s === "UNSPECIFIED" ? "G1" : s;
}

function normGrantScope(v: unknown): GrantScope {
  const s = stripEnum(v, "GRANT_SCOPE_", "once");
  if (s === "once" || s === "session" || s === "one_hour") return s;
  return "once";
}

export function normPrivacyConfig(raw: RawRecord): OrgPrivacyConfig {
  return {
    identity_mode: stripEnum(raw.identityMode ?? raw.identity_mode, "IDENTITY_MODE_", "named") as IdentityMode,
    user_risk_scoring: Boolean(raw.userRiskScoring ?? raw.user_risk_scoring),
  };
}

export function normRule(raw: RawRecord): PolicyRule {
  const m = raw.matcher ?? {};
  return {
    id: raw.id ?? "",
    title: raw.title ?? "",
    description: raw.description ?? "",
    mode: normMode(raw.mode),
    min_grade: normGrade(raw.minGrade ?? raw.min_grade),
    enabled: Boolean(raw.enabled),
    locked: Boolean(raw.locked),
    matcher: {
      action_classes: (m.actionClasses ?? m.action_classes ?? []).map(normActionClass),
      target_prefixes: m.targetPrefixes ?? m.target_prefixes ?? [],
      target_contains: m.targetContains ?? m.target_contains ?? [],
      agents: m.agents ?? [],
    },
    hits: Number(raw.hits ?? 0),
    would_ask_hits: Number(raw.wouldAskHits ?? raw.would_ask_hits ?? 0),
    would_block_hits: Number(raw.wouldBlockHits ?? raw.would_block_hits ?? 0),
    reason_template: raw.reasonTemplate ?? raw.reason_template ?? "",
  };
}

export function normPack(raw: RawRecord): PolicyPack {
  return {
    id: raw.id ?? "",
    name: raw.name ?? "",
    description: raw.description ?? "",
    version: raw.version ?? "",
    channel: raw.channel ?? "",
    rules: (raw.rules ?? []).map(normRule),
  };
}

export function normApproval(raw: RawRecord): ApprovalRequest {
  let state: ApprovalState;
  if (raw.state && typeof raw.state === "object" && "status" in raw.state) {
    state = raw.state as ApprovalState;
  } else {
    const status = stripEnum(raw.status, "APPROVAL_STATUS_", "pending");
    if (status === "approved") {
      state = {
        status: "approved",
        grant_id: raw.grantId ?? raw.grant_id ?? "",
        scope: normGrantScope(raw.scope),
        decided_at: raw.decidedAt ?? raw.decided_at ?? "",
        note: raw.note ?? "",
      };
    } else if (status === "denied") {
      state = {
        status: "denied",
        decided_at: raw.decidedAt ?? raw.decided_at ?? "",
        note: raw.note ?? "",
      };
    } else if (status === "expired") {
      state = { status: "expired", expired_at: raw.expiresAt ?? raw.expires_at ?? "" };
    } else {
      state = { status: "pending", expires_at: raw.expiresAt ?? raw.expires_at ?? "" };
    }
  }
  return {
    id: raw.id ?? "",
    receipt_id: raw.receiptId ?? raw.receipt_id ?? "",
    session_id: raw.sessionId ?? raw.session_id ?? "",
    device_id: raw.deviceId ?? raw.device_id ?? "",
    device_name: raw.deviceName ?? raw.device_name ?? "",
    agent_name: raw.agentName ?? raw.agent_name ?? "",
    action_class: normActionClass(raw.actionClass ?? raw.action_class),
    target: raw.target ?? "",
    rule_id: raw.ruleId ?? raw.rule_id ?? "",
    rule_title: raw.ruleTitle ?? raw.rule_title ?? "",
    required_grade: normGrade(raw.requiredGrade ?? raw.required_grade),
    reason: raw.reason ?? "",
    requested_at: raw.requestedAt ?? raw.requested_at ?? "",
    state,
  };
}

export function normFinding(raw: RawRecord): Finding {
  return {
    id: raw.id ?? "",
    session_id: raw.sessionId ?? raw.session_id ?? "",
    device_id: raw.deviceId ?? raw.device_id ?? "",
    device_name: raw.deviceName ?? raw.device_name ?? "",
    agent_name: raw.agentName ?? raw.agent_name ?? "",
    class: stripEnum(raw.findingClass ?? raw.finding_class ?? raw.class, "FINDING_CLASS_", "policy_violation"),
    severity: stripEnum(raw.severity, "FINDING_SEVERITY_", "medium"),
    lifecycle: stripEnum(raw.lifecycle, "FINDING_LIFECYCLE_", "open") as FindingLifecycle,
    rule_id: raw.ruleId ?? raw.rule_id ?? null,
    title: raw.title ?? "",
    summary: raw.summary ?? "",
    target: raw.target ?? "",
    detected_at: raw.detectedAt ?? raw.detected_at ?? "",
  };
}

export function normIncident(raw: RawRecord): Incident {
  return {
    id: raw.id ?? "",
    session_id: raw.sessionId ?? raw.session_id ?? "",
    device_id: raw.deviceId ?? raw.device_id ?? "",
    device_name: raw.deviceName ?? raw.device_name ?? "",
    agent_name: raw.agentName ?? raw.agent_name ?? "",
    title: raw.title ?? "",
    summary: raw.summary ?? "",
    severity: stripEnum(raw.severity, "FINDING_SEVERITY_", "high"),
    lifecycle: stripEnum(raw.lifecycle, "FINDING_LIFECYCLE_", "open") as FindingLifecycle,
    finding_ids: raw.findingIds ?? raw.finding_ids ?? [],
    finding_count: Number(raw.findingCount ?? raw.finding_count ?? 0),
    labels: (raw.labels ?? []).map((l: unknown) => stripEnum(l, "SESSION_LABEL_", "credential_accessed") as SessionLabel),
    first_seen: raw.firstSeen ?? raw.first_seen ?? "",
    last_seen: raw.lastSeen ?? raw.last_seen ?? "",
  };
}

export function normKillSwitch(raw: RawRecord | undefined): KillSwitchState {
  if (!raw) return { state: "inactive" };
  const s = stripEnum(raw.state, "KILL_STATE_", "inactive");
  const scope = stripEnum(raw.scope, "KILL_SCOPE_", "organisation") as KillScope;
  if (s === "frozen") {
    return {
      state: "frozen",
      scope,
      target_id: raw.targetId ?? raw.target_id ?? "*",
      reason: raw.reason ?? "",
      issued_at: raw.issuedAt ?? raw.issued_at ?? "",
      expires_at: raw.expiresAt ?? raw.expires_at ?? "",
    };
  }
  if (s === "killed") {
    return {
      state: "killed",
      scope,
      target_id: raw.targetId ?? raw.target_id ?? "*",
      reason: raw.reason ?? "",
      issued_at: raw.issuedAt ?? raw.issued_at ?? "",
    };
  }
  return { state: "inactive" };
}

export function normOverview(raw: RawRecord): OverviewResponse {
  return {
    server_status: stripEnum(raw.serverStatus ?? raw.server_status, "SERVER_HEALTH_", "healthy") as ServerHealth,
    total_devices: Number(raw.totalDevices ?? raw.total_devices ?? 0),
    online_devices: Number(raw.onlineDevices ?? raw.online_devices ?? 0),
    total_agents: Number(raw.totalAgents ?? raw.total_agents ?? 0),
    total_mcp_servers: Number(raw.totalMcpServers ?? raw.total_mcp_servers ?? 0),
    active_sessions: Number(raw.activeSessions ?? raw.active_sessions ?? 0),
    pending_approvals: Number(raw.pendingApprovals ?? raw.pending_approvals ?? 0),
    open_findings: Number(raw.openFindings ?? raw.open_findings ?? 0),
    open_incidents: Number(raw.openIncidents ?? raw.open_incidents ?? 0),
    kill_switch: normKillSwitch(raw.killSwitch ?? raw.kill_switch),
    tiles: (raw.tiles ?? []).map((t: RawRecord) => ({
      id: t.id ?? "",
      headline: t.headline ?? "",
      metric: t.metric ?? "",
      comparison: t.comparison ?? "",
      action_label: t.actionLabel ?? t.action_label ?? "",
      route: t.route ?? "home",
      tone: t.tone ?? "neutral",
    })),
    setup_steps: (raw.setupSteps ?? raw.setup_steps ?? []).map((s: RawRecord) => ({
      id: s.id ?? "",
      label: s.label ?? "",
      done: Boolean(s.done),
      detail: s.detail ?? "",
    })),
  };
}

export function normHealth(raw: RawRecord): HealthResponse {
  const sm = raw.storageMode ?? raw.storage_mode ?? {};
  const kind = stripEnum(sm.kind, "STORAGE_KIND_", "memory");
  const storage_mode: StorageMode =
    kind === "sqlite" ? { kind: "sqlite", path: sm.path ?? "" } : { kind: "memory" };
  return {
    status: stripEnum(raw.status, "SERVER_HEALTH_", "healthy") as ServerHealth,
    version: raw.version ?? "",
    storage_mode,
    timestamp: raw.timestamp ?? "",
  };
}

export function normAudit(raw: RawRecord): AuditEntry {
  return {
    id: raw.id ?? "",
    timestamp: raw.timestamp ?? "",
    kind: raw.kind ?? "",
    actor: raw.actor ?? "",
    summary: raw.summary ?? "",
    target: raw.target ?? "",
  };
}

export function normReplay(raw: RawRecord): ReplaySummary {
  return {
    rule_id: raw.ruleId ?? raw.rule_id ?? "",
    candidate_mode: normMode(raw.candidateMode ?? raw.candidate_mode),
    window_label: raw.windowLabel ?? raw.window_label ?? "",
    total_scanned: Number(raw.totalScanned ?? raw.total_scanned ?? 0),
    matched: Number(raw.matched ?? 0),
    would_ask: Number(raw.wouldAsk ?? raw.would_ask ?? 0),
    would_block: Number(raw.wouldBlock ?? raw.would_block ?? 0),
    not_matched: Number(raw.notMatched ?? raw.not_matched ?? 0),
    samples: (raw.samples ?? []).map((s: RawRecord) => ({
      attempt_id: s.attemptId ?? s.attempt_id ?? "",
      session_id: s.sessionId ?? s.session_id ?? "",
      agent_name: s.agentName ?? s.agent_name ?? "",
      action_class: normActionClass(s.actionClass ?? s.action_class),
      target: s.target ?? "",
      current_verdict: normVerdict(s.currentVerdict ?? s.current_verdict),
      candidate_verdict: normVerdict(s.candidateVerdict ?? s.candidate_verdict),
      timestamp: s.timestamp ?? "",
    })),
  };
}

export function normDeploymentKey(raw: RawRecord): DeploymentKey {
  return {
    id: raw.id ?? "",
    label: raw.label ?? "",
    token_preview: raw.tokenPreview ?? raw.token_preview ?? "",
    install_profile: raw.installProfile ?? raw.install_profile ?? "",
    wave: raw.wave ?? "",
    max_uses: Number(raw.maxUses ?? raw.max_uses ?? 0),
    used_count: Number(raw.usedCount ?? raw.used_count ?? 0),
    status: stripEnum(raw.status, "DEPLOYMENT_KEY_STATUS_", "active") as DeploymentKeyStatus,
    created_at: raw.createdAt ?? raw.created_at ?? "",
    expires_at: raw.expiresAt ?? raw.expires_at ?? "",
    created_by: raw.createdBy ?? raw.created_by ?? "",
  };
}

export function normIntegration(raw: RawRecord): IntegrationEntry {
  return {
    id: raw.id ?? "",
    name: raw.name ?? "",
    provider: raw.provider ?? "",
    category: stripEnum(raw.category, "INTEGRATION_CATEGORY_", "directory_sync") as IntegrationCategory,
    state: stripEnum(raw.state, "INTEGRATION_HEALTH_STATE_", "not_configured") as IntegrationHealthState,
    synced_users: Number(raw.syncedUsers ?? raw.synced_users ?? 0),
    last_sync_at: raw.lastSyncAt ?? raw.last_sync_at ?? null,
    credential_expires_in_days: raw.credentialExpiresInDays ?? raw.credential_expires_in_days ?? null,
    detail: raw.detail ?? "",
    readiness_checks: raw.readinessChecks ?? raw.readiness_checks ?? [],
  };
}

export function normConnectConfig(raw: RawRecord): ConnectConfigResponse {
  const otlp = raw.otlp ?? {};
  return {
    server_origin: raw.serverOrigin ?? raw.server_origin ?? "",
    installers: (raw.installers ?? []).map((i: RawRecord) => ({
      platform: i.platform ?? "",
      label: i.label ?? "",
      version: i.version ?? "",
      command: i.command ?? "",
      sha256: i.sha256 ?? "",
      doctor_command: i.doctorCommand ?? i.doctor_command ?? "",
      notes: i.notes ?? "",
    })),
    deployment_keys: (raw.deploymentKeys ?? raw.deployment_keys ?? []).map(normDeploymentKey),
    otlp: {
      enabled: Boolean(otlp.enabled),
      grpc_port: Number(otlp.grpcPort ?? otlp.grpc_port ?? 4317),
      http_port: Number(otlp.httpPort ?? otlp.http_port ?? 4318),
      bind_address: otlp.bindAddress ?? otlp.bind_address ?? "127.0.0.1",
      downstream_targets: otlp.downstreamTargets ?? otlp.downstream_targets ?? [],
      loopback_only: Boolean(otlp.loopbackOnly ?? otlp.loopback_only ?? true),
      accepted_spans_24h: Number(otlp.acceptedSpans24h ?? otlp.accepted_spans_24h ?? 0),
    },
    integrations: (raw.integrations ?? []).map(normIntegration),
  };
}

export function normCreateDeploymentKey(raw: RawRecord): CreateDeploymentKeyResponse {
  return {
    key: normDeploymentKey(raw.key ?? {}),
    plaintext_token: raw.plaintextToken ?? raw.plaintext_token ?? "",
  };
}

export function normMdmRender(raw: RawRecord): MdmRenderResponse {
  return {
    format: stripEnum(raw.format, "MDM_FORMAT_", "intune_win32") as MdmFormat,
    filename: raw.filename ?? "",
    content_type: raw.contentType ?? raw.content_type ?? "",
    payload: raw.payload ?? "",
    deployment_notes: raw.deploymentNotes ?? raw.deployment_notes ?? [],
  };
}

export function normBrowserPolicy(raw: RawRecord): BrowserAppPolicy {
  return {
    id: raw.id ?? "",
    name: raw.name ?? "",
    domains: raw.domains ?? [],
    mode: normMode(raw.mode),
    block_file_uploads: Boolean(raw.blockFileUploads ?? raw.block_file_uploads),
    block_secret_paste: Boolean(raw.blockSecretPaste ?? raw.block_secret_paste),
    managed_extension_only: Boolean(raw.managedExtensionOnly ?? raw.managed_extension_only),
    events_24h: Number(raw.events24h ?? raw.events_24h ?? 0),
    blocked_24h: Number(raw.blocked24h ?? raw.blocked_24h ?? 0),
  };
}

export function normBrowserEvaluate(raw: RawRecord): BrowserEvaluateResponse {
  return {
    app_id: raw.appId ?? raw.app_id ?? "",
    app_name: raw.appName ?? raw.app_name ?? "",
    verdict: normVerdict(raw.verdict),
    rule_id: raw.ruleId ?? raw.rule_id ?? null,
    reason: raw.reason ?? "",
    dlp_class: stripEnum(raw.dlpClass ?? raw.dlp_class, "BROWSER_DLP_CLASS_", "file_upload") as BrowserDlpClass,
  };
}

export function normUserDetail(raw: RawRecord): UserDetailResponse {
  return {
    user: normUser(raw.user ?? {}),
    devices: (raw.devices ?? []).map(normDevice),
    sessions: (raw.sessions ?? []).map(normSession),
    recent_attempts: (raw.recentAttempts ?? raw.recent_attempts ?? []).map(normAttempt),
    receipts: (raw.receipts ?? []).map(normReceipt),
    findings: (raw.findings ?? []).map(normFinding),
    artifacts: (raw.artifacts ?? []).map(normArtifact),
    identity_mode: stripEnum(raw.identityMode ?? raw.identity_mode, "IDENTITY_MODE_", "named") as IdentityMode,
  };
}
