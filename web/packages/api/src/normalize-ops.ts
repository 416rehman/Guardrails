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
  num,
  optStr,
  rec,
  recArr,
  str,
  strArr,
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
  NavRoute,
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
  ReadinessCheck,
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
  const m = rec(raw.matcher);
  return {
    id: str(raw.id),
    title: str(raw.title),
    description: str(raw.description),
    mode: normMode(raw.mode),
    min_grade: normGrade(raw.minGrade ?? raw.min_grade),
    enabled: Boolean(raw.enabled),
    locked: Boolean(raw.locked),
    matcher: {
      action_classes: (Array.isArray(m.actionClasses ?? m.action_classes)
        ? ((m.actionClasses ?? m.action_classes) as unknown[])
        : []
      ).map(normActionClass),
      target_prefixes: strArr(m.targetPrefixes ?? m.target_prefixes),
      target_contains: strArr(m.targetContains ?? m.target_contains),
      agents: strArr(m.agents),
    },
    hits: num(raw.hits),
    would_ask_hits: num(raw.wouldAskHits ?? raw.would_ask_hits),
    would_block_hits: num(raw.wouldBlockHits ?? raw.would_block_hits),
    reason_template: str(raw.reasonTemplate ?? raw.reason_template),
  };
}

export function normPack(raw: RawRecord): PolicyPack {
  return {
    id: str(raw.id),
    name: str(raw.name),
    description: str(raw.description),
    version: str(raw.version),
    channel: str(raw.channel),
    rules: recArr(raw.rules).map(normRule),
  };
}

export function normApproval(raw: RawRecord): ApprovalRequest {
  let state: ApprovalState;
  const rawState = rec(raw.state);
  if (typeof rawState.status === "string") {
    state = rawState as unknown as ApprovalState;
  } else {
    const status = stripEnum(raw.status, "APPROVAL_STATUS_", "pending");
    if (status === "approved") {
      state = {
        status: "approved",
        grant_id: str(raw.grantId ?? raw.grant_id),
        scope: normGrantScope(raw.scope),
        decided_at: str(raw.decidedAt ?? raw.decided_at),
        note: str(raw.note),
      };
    } else if (status === "denied") {
      state = {
        status: "denied",
        decided_at: str(raw.decidedAt ?? raw.decided_at),
        note: str(raw.note),
      };
    } else if (status === "expired") {
      state = { status: "expired", expired_at: str(raw.expiresAt ?? raw.expires_at) };
    } else {
      state = { status: "pending", expires_at: str(raw.expiresAt ?? raw.expires_at) };
    }
  }
  return {
    id: str(raw.id),
    receipt_id: str(raw.receiptId ?? raw.receipt_id),
    session_id: str(raw.sessionId ?? raw.session_id),
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    agent_name: str(raw.agentName ?? raw.agent_name),
    action_class: normActionClass(raw.actionClass ?? raw.action_class),
    target: str(raw.target),
    rule_id: str(raw.ruleId ?? raw.rule_id),
    rule_title: str(raw.ruleTitle ?? raw.rule_title),
    required_grade: normGrade(raw.requiredGrade ?? raw.required_grade),
    reason: str(raw.reason),
    requested_at: str(raw.requestedAt ?? raw.requested_at),
    state,
  };
}

export function normFinding(raw: RawRecord): Finding {
  return {
    id: str(raw.id),
    session_id: str(raw.sessionId ?? raw.session_id),
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    agent_name: str(raw.agentName ?? raw.agent_name),
    class: stripEnum(raw.findingClass ?? raw.finding_class ?? raw.class, "FINDING_CLASS_", "policy_violation"),
    severity: stripEnum(raw.severity, "FINDING_SEVERITY_", "medium"),
    lifecycle: stripEnum(raw.lifecycle, "FINDING_LIFECYCLE_", "open") as FindingLifecycle,
    rule_id: optStr(raw.ruleId ?? raw.rule_id),
    title: str(raw.title),
    summary: str(raw.summary),
    target: str(raw.target),
    detected_at: str(raw.detectedAt ?? raw.detected_at),
  };
}

export function normIncident(raw: RawRecord): Incident {
  const rawLabels = raw.labels;
  return {
    id: str(raw.id),
    session_id: str(raw.sessionId ?? raw.session_id),
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    agent_name: str(raw.agentName ?? raw.agent_name),
    title: str(raw.title),
    summary: str(raw.summary),
    severity: stripEnum(raw.severity, "FINDING_SEVERITY_", "high"),
    lifecycle: stripEnum(raw.lifecycle, "FINDING_LIFECYCLE_", "open") as FindingLifecycle,
    finding_ids: strArr(raw.findingIds ?? raw.finding_ids),
    finding_count: num(raw.findingCount ?? raw.finding_count),
    labels: (Array.isArray(rawLabels) ? rawLabels : []).map(
      (l: unknown) => stripEnum(l, "SESSION_LABEL_", "credential_accessed") as SessionLabel,
    ),
    first_seen: str(raw.firstSeen ?? raw.first_seen),
    last_seen: str(raw.lastSeen ?? raw.last_seen),
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
      target_id: str(raw.targetId ?? raw.target_id, "*"),
      reason: str(raw.reason),
      issued_at: str(raw.issuedAt ?? raw.issued_at),
      expires_at: str(raw.expiresAt ?? raw.expires_at),
    };
  }
  if (s === "killed") {
    return {
      state: "killed",
      scope,
      target_id: str(raw.targetId ?? raw.target_id, "*"),
      reason: str(raw.reason),
      issued_at: str(raw.issuedAt ?? raw.issued_at),
    };
  }
  return { state: "inactive" };
}

export function normOverview(raw: RawRecord): OverviewResponse {
  return {
    server_status: stripEnum(raw.serverStatus ?? raw.server_status, "SERVER_HEALTH_", "healthy") as ServerHealth,
    total_devices: num(raw.totalDevices ?? raw.total_devices),
    online_devices: num(raw.onlineDevices ?? raw.online_devices),
    total_agents: num(raw.totalAgents ?? raw.total_agents),
    total_mcp_servers: num(raw.totalMcpServers ?? raw.total_mcp_servers),
    active_sessions: num(raw.activeSessions ?? raw.active_sessions),
    pending_approvals: num(raw.pendingApprovals ?? raw.pending_approvals),
    open_findings: num(raw.openFindings ?? raw.open_findings),
    open_incidents: num(raw.openIncidents ?? raw.open_incidents),
    kill_switch: normKillSwitch(rec(raw.killSwitch ?? raw.kill_switch)),
    tiles: recArr(raw.tiles).map((t) => ({
      id: str(t.id),
      headline: str(t.headline),
      metric: str(t.metric),
      comparison: str(t.comparison),
      action_label: str(t.actionLabel ?? t.action_label),
      route: (str(t.route, "home") as NavRoute),
      tone: str(t.tone, "neutral"),
    })),
    setup_steps: recArr(raw.setupSteps ?? raw.setup_steps).map((s) => ({
      id: str(s.id),
      label: str(s.label),
      done: Boolean(s.done),
      detail: str(s.detail),
    })),
  };
}

export function normHealth(raw: RawRecord): HealthResponse {
  const sm = rec(raw.storageMode ?? raw.storage_mode);
  const kind = stripEnum(sm.kind, "STORAGE_KIND_", "memory");
  const storage_mode: StorageMode =
    kind === "sqlite" ? { kind: "sqlite", path: str(sm.path) } : { kind: "memory" };
  return {
    status: stripEnum(raw.status, "SERVER_HEALTH_", "healthy") as ServerHealth,
    version: str(raw.version),
    storage_mode,
    timestamp: str(raw.timestamp),
  };
}

export function normAudit(raw: RawRecord): AuditEntry {
  return {
    id: str(raw.id),
    timestamp: str(raw.timestamp),
    kind: str(raw.kind),
    actor: str(raw.actor),
    summary: str(raw.summary),
    target: str(raw.target),
  };
}

export function normReplay(raw: RawRecord): ReplaySummary {
  return {
    rule_id: str(raw.ruleId ?? raw.rule_id),
    candidate_mode: normMode(raw.candidateMode ?? raw.candidate_mode),
    window_label: str(raw.windowLabel ?? raw.window_label),
    total_scanned: num(raw.totalScanned ?? raw.total_scanned),
    matched: num(raw.matched),
    would_ask: num(raw.wouldAsk ?? raw.would_ask),
    would_block: num(raw.wouldBlock ?? raw.would_block),
    not_matched: num(raw.notMatched ?? raw.not_matched),
    samples: recArr(raw.samples).map((s) => ({
      attempt_id: str(s.attemptId ?? s.attempt_id),
      session_id: str(s.sessionId ?? s.session_id),
      agent_name: str(s.agentName ?? s.agent_name),
      action_class: normActionClass(s.actionClass ?? s.action_class),
      target: str(s.target),
      current_verdict: normVerdict(s.currentVerdict ?? s.current_verdict),
      candidate_verdict: normVerdict(s.candidateVerdict ?? s.candidate_verdict),
      timestamp: str(s.timestamp),
    })),
  };
}

export function normDeploymentKey(raw: RawRecord): DeploymentKey {
  return {
    id: str(raw.id),
    label: str(raw.label),
    token_preview: str(raw.tokenPreview ?? raw.token_preview),
    install_profile: str(raw.installProfile ?? raw.install_profile),
    wave: str(raw.wave),
    max_uses: num(raw.maxUses ?? raw.max_uses),
    used_count: num(raw.usedCount ?? raw.used_count),
    status: stripEnum(raw.status, "DEPLOYMENT_KEY_STATUS_", "active") as DeploymentKeyStatus,
    created_at: str(raw.createdAt ?? raw.created_at),
    expires_at: str(raw.expiresAt ?? raw.expires_at),
    created_by: str(raw.createdBy ?? raw.created_by),
  };
}

export function normIntegration(raw: RawRecord): IntegrationEntry {
  return {
    id: str(raw.id),
    name: str(raw.name),
    provider: str(raw.provider),
    category: stripEnum(raw.category, "INTEGRATION_CATEGORY_", "directory_sync") as IntegrationCategory,
    state: stripEnum(raw.state, "INTEGRATION_HEALTH_STATE_", "not_configured") as IntegrationHealthState,
    synced_users: num(raw.syncedUsers ?? raw.synced_users),
    last_sync_at: optStr(raw.lastSyncAt ?? raw.last_sync_at),
    credential_expires_in_days:
      typeof (raw.credentialExpiresInDays ?? raw.credential_expires_in_days) === "number"
        ? (raw.credentialExpiresInDays ?? raw.credential_expires_in_days) as number
        : null,
    detail: str(raw.detail),
    readiness_checks: recArr(raw.readinessChecks ?? raw.readiness_checks).map(
      (c): ReadinessCheck => ({
        name: str(c.name),
        passed: Boolean(c.passed),
        detail: str(c.detail),
      }),
    ),
  };
}

export function normConnectConfig(raw: RawRecord): ConnectConfigResponse {
  const otlp = rec(raw.otlp);
  return {
    server_origin: str(raw.serverOrigin ?? raw.server_origin),
    installers: recArr(raw.installers).map((i) => ({
      platform: str(i.platform),
      label: str(i.label),
      version: str(i.version),
      command: str(i.command),
      sha256: str(i.sha256),
      doctor_command: str(i.doctorCommand ?? i.doctor_command),
      notes: str(i.notes),
    })),
    deployment_keys: recArr(raw.deploymentKeys ?? raw.deployment_keys).map(normDeploymentKey),
    otlp: {
      enabled: Boolean(otlp.enabled),
      grpc_port: num(otlp.grpcPort ?? otlp.grpc_port, 4317),
      http_port: num(otlp.httpPort ?? otlp.http_port, 4318),
      bind_address: str(otlp.bindAddress ?? otlp.bind_address, "127.0.0.1"),
      downstream_targets: strArr(otlp.downstreamTargets ?? otlp.downstream_targets),
      loopback_only: Boolean(otlp.loopbackOnly ?? otlp.loopback_only ?? true),
      accepted_spans_24h: num(otlp.acceptedSpans24h ?? otlp.accepted_spans_24h),
    },
    integrations: recArr(raw.integrations).map(normIntegration),
  };
}

export function normCreateDeploymentKey(raw: RawRecord): CreateDeploymentKeyResponse {
  return {
    key: normDeploymentKey(rec(raw.key)),
    plaintext_token: str(raw.plaintextToken ?? raw.plaintext_token),
  };
}

export function normMdmRender(raw: RawRecord): MdmRenderResponse {
  return {
    format: stripEnum(raw.format, "MDM_FORMAT_", "intune_win32") as MdmFormat,
    filename: str(raw.filename),
    content_type: str(raw.contentType ?? raw.content_type),
    payload: str(raw.payload),
    deployment_notes: strArr(raw.deploymentNotes ?? raw.deployment_notes),
  };
}

export function normBrowserPolicy(raw: RawRecord): BrowserAppPolicy {
  return {
    id: str(raw.id),
    name: str(raw.name),
    domains: strArr(raw.domains),
    mode: normMode(raw.mode),
    block_file_uploads: Boolean(raw.blockFileUploads ?? raw.block_file_uploads),
    block_secret_paste: Boolean(raw.blockSecretPaste ?? raw.block_secret_paste),
    managed_extension_only: Boolean(raw.managedExtensionOnly ?? raw.managed_extension_only),
    events_24h: num(raw.events24h ?? raw.events_24h),
    blocked_24h: num(raw.blocked24h ?? raw.blocked_24h),
  };
}

export function normBrowserEvaluate(raw: RawRecord): BrowserEvaluateResponse {
  return {
    app_id: str(raw.appId ?? raw.app_id),
    app_name: str(raw.appName ?? raw.app_name),
    verdict: normVerdict(raw.verdict),
    rule_id: optStr(raw.ruleId ?? raw.rule_id),
    reason: str(raw.reason),
    dlp_class: stripEnum(raw.dlpClass ?? raw.dlp_class, "BROWSER_DLP_CLASS_", "file_upload") as BrowserDlpClass,
  };
}

export function normUserDetail(raw: RawRecord): UserDetailResponse {
  return {
    user: normUser(rec(raw.user)),
    devices: recArr(raw.devices).map(normDevice),
    sessions: recArr(raw.sessions).map(normSession),
    recent_attempts: recArr(raw.recentAttempts ?? raw.recent_attempts).map(normAttempt),
    receipts: recArr(raw.receipts).map(normReceipt),
    findings: recArr(raw.findings).map(normFinding),
    artifacts: recArr(raw.artifacts).map(normArtifact),
    identity_mode: stripEnum(raw.identityMode ?? raw.identity_mode, "IDENTITY_MODE_", "named") as IdentityMode,
  };
}
