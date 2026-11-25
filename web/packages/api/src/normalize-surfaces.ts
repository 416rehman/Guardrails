import {
  normMode,
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
  BackupDrillRecord,
  CompatCheckEntry,
  ComplianceConnectorEntry,
  ComplianceEvidenceEntry,
  ComplianceExportArtifact,
  ComplianceWorkspaceResponse,
  ConfigDiffEntry,
  ConfigRevisionEntry,
  ConfigRevisionState,
  DisclosureLedgerEntry,
  DisclosureMetrics,
  FirstRunState,
  FrameworkCoverageSummary,
  GrcPushResult,
  LegalHoldEntry,
  OperatorRuntimeConfig,
  OperatorStateResponse,
  ProviderOrgEntry,
  ProviderRingSummary,
  ProviderWorkspaceResponse,
  ReidentificationRequestEntry,
  RetentionStateSummary,
  ReviewBucket,
  ReviewCluster,
  ReviewQueueResponse,
  ReviewStatus,
  SubjectRequestEntry,
  TargetHealthEntry,
  WhyExplanation,
} from "./types-surfaces";

export function normWhyExplanation(raw: RawRecord): WhyExplanation {
  return {
    reference: str(raw.reference ?? raw.receiptId ?? raw.receipt_id),
    receipt_id: str(raw.receiptId ?? raw.receipt_id),
    attempt_id: str(raw.attemptId ?? raw.attempt_id),
    heading: str(raw.heading, "Why this happened"),
    verdict: normVerdict(raw.verdict),
    status_code: str(raw.statusCode ?? raw.status_code),
    component: str(raw.component, "Guardrails ADR"),
    action_class: str(raw.actionClass ?? raw.action_class, "action"),
    rule_id: str(raw.ruleId ?? raw.rule_id),
    rule_title: str(raw.ruleTitle ?? raw.rule_title),
    pack_id: str(raw.packId ?? raw.pack_id),
    agent_name: str(raw.agentName ?? raw.agent_name),
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    session_id: str(raw.sessionId ?? raw.session_id),
    target_quoted: str(raw.targetQuoted ?? raw.target_quoted),
    reason: str(raw.reason),
    agent_told: str(raw.agentTold ?? raw.agent_told),
    timestamp: str(raw.timestamp),
    key_id: optStr(raw.keyId ?? raw.key_id),
    signature_status: str(raw.signatureStatus ?? raw.signature_status, "unsigned"),
    primary_action_label: str(raw.primaryActionLabel ?? raw.primary_action_label, "Inspect"),
    primary_action_route: str(raw.primaryActionRoute ?? raw.primary_action_route, "/sessions"),
    approval_id: optStr(raw.approvalId ?? raw.approval_id),
    approver_label: optStr(raw.approverLabel ?? raw.approver_label),
  };
}

export function normReviewCluster(raw: RawRecord): ReviewCluster {
  const bucketRaw = str(raw.bucket, "routine");
  const bucket: ReviewBucket =
    bucketRaw === "worth_a_look" || bucketRaw === "routine" || bucketRaw === "noise"
      ? bucketRaw
      : "routine";
  const stRaw = stripEnum(raw.status, "REVIEW_CLUSTER_STATUS_", "open");
  const status: ReviewStatus =
    stRaw === "open" ||
    stRaw === "promoted" ||
    stRaw === "suppressed" ||
    stRaw === "dismissed" ||
    stRaw === "escalated"
      ? stRaw
      : "open";
  return {
    id: str(raw.id),
    bucket,
    score: num(raw.score),
    rule_id: str(raw.ruleId ?? raw.rule_id),
    rule_title: str(raw.ruleTitle ?? raw.rule_title),
    observable_digest: str(raw.observableDigest ?? raw.observable_digest),
    agent_name: str(raw.agentName ?? raw.agent_name),
    device_id: str(raw.deviceId ?? raw.device_id),
    device_name: str(raw.deviceName ?? raw.device_name),
    session_id: str(raw.sessionId ?? raw.session_id),
    receipt_ref: str(raw.receiptRef ?? raw.receipt_ref),
    occurrence_count: num(raw.occurrenceCount ?? raw.occurrence_count, 1),
    latest_timestamp: str(raw.latestTimestamp ?? raw.latest_timestamp),
    target_preview: str(raw.targetPreview ?? raw.target_preview),
    current_mode: normMode(raw.currentMode ?? raw.current_mode),
    suggested_mode: normMode(raw.suggestedMode ?? raw.suggested_mode),
    risk_label: str(raw.riskLabel ?? raw.risk_label, "Neutral"),
    status,
    reason: str(raw.reason),
    note: str(raw.note),
  };
}

export function normReviewQueue(raw: RawRecord): ReviewQueueResponse {
  return {
    clusters: recArr(raw.clusters).map(normReviewCluster),
    worth_a_look_count: num(raw.worthALookCount ?? raw.worth_a_look_count),
    routine_count: num(raw.routineCount ?? raw.routine_count),
    noise_count: num(raw.noiseCount ?? raw.noise_count),
  };
}

export function normRetention(raw: RawRecord): RetentionStateSummary {
  const prof = str(raw.privacyProfile ?? raw.privacy_profile, "standard");
  const presets = strArr(raw.presets);
  return {
    organisation: str(raw.organisation, "org-default"),
    privacy_profile: prof === "works-council" ? "works-council" : "standard",
    presets: presets.length > 0 ? presets : ["default"],
    content_days: num(raw.contentDays ?? raw.content_days, 30),
    activity_days: num(raw.activityDays ?? raw.activity_days, 90),
    decision_days: num(raw.decisionDays ?? raw.decision_days, 396),
    audit_days: num(raw.auditDays ?? raw.audit_days, 396),
    hot_days: num(raw.hotDays ?? raw.hot_days, 30),
    backup_days_max: num(raw.backupDaysMax ?? raw.backup_days_max, 35),
    legal_basis: strArr(raw.legalBasis ?? raw.legal_basis),
    conflict_note: str(raw.conflictNote ?? raw.conflict_note),
  };
}

export function normLegalHold(raw: RawRecord): LegalHoldEntry {
  return {
    hold_id: str(raw.holdId ?? raw.hold_id),
    matter_ref: str(raw.matterRef ?? raw.matter_ref),
    reason: str(raw.reason),
    lifecycle: str(raw.lifecycle, "active"),
    created_by: str(raw.createdBy ?? raw.created_by),
    approvers: strArr(raw.approvers),
    created_at: str(raw.createdAt ?? raw.created_at),
    review_by: str(raw.reviewBy ?? raw.review_by),
    notice_mode: str(raw.noticeMode ?? raw.notice_mode, "immediate"),
    scope_summary: str(raw.scopeSummary ?? raw.scope_summary),
  };
}

export function normReidRequest(raw: RawRecord): ReidentificationRequestEntry {
  const st = stripEnum(raw.status, "REID_REQUEST_STATUS_", "pending_quorum");
  return {
    request_id: str(raw.requestId ?? raw.request_id),
    pseudonym_id: str(raw.pseudonymId ?? raw.pseudonym_id),
    requester: str(raw.requester),
    reason: str(raw.reason),
    legal_basis: str(raw.legalBasis ?? raw.legal_basis),
    status: st === "approved" || st === "denied" ? st : "pending_quorum",
    approvers: strArr(raw.approvers),
    required_approvals: num(raw.requiredApprovals ?? raw.required_approvals, 2),
    resolved_identity: optStr(raw.resolvedIdentity ?? raw.resolved_identity),
    created_at: str(raw.createdAt ?? raw.created_at),
    resolved_at: optStr(raw.resolvedAt ?? raw.resolved_at),
  };
}

export function normFirstRunState(raw: RawRecord): FirstRunState {
  const prof = str(raw.selectedProfile ?? raw.selected_profile, "protected");
  return {
    selected_profile: prof === "user" ? "user" : "protected",
    confirmed: Boolean(raw.confirmed),
    step_up_enabled: Boolean(raw.stepUpEnabled ?? raw.step_up_enabled),
    steps: recArr(raw.steps).map((s) => ({
      id: str(s.id),
      label: str(s.label),
      done: Boolean(s.done),
      detail: str(s.detail),
    })),
  };
}

export function normComplianceWorkspace(raw: RawRecord): ComplianceWorkspaceResponse {
  const frameworks: FrameworkCoverageSummary[] = recArr(raw.frameworks).map((f) => ({
    framework_id: str(f.frameworkId ?? f.framework_id),
    display_title: str(f.displayTitle ?? f.display_title),
    total_controls: num(f.totalControls ?? f.total_controls),
    addressed_controls: num(f.addressedControls ?? f.addressed_controls),
    coverage_percent: num(f.coveragePercent ?? f.coverage_percent),
  }));
  const evidence_items: ComplianceEvidenceEntry[] = recArr(raw.evidenceItems ?? raw.evidence_items).map((e) => ({
    id: str(e.id),
    capability: str(e.capability),
    statement: str(e.statement),
    result: str(e.result),
    responsibility: str(e.responsibility),
    control_refs: strArr(e.controlRefs ?? e.control_refs),
    sample_ids: strArr(e.sampleIds ?? e.sample_ids),
    period_end: str(e.periodEnd ?? e.period_end),
    signature_status: str(e.signatureStatus ?? e.signature_status),
  }));
  const subject_requests: SubjectRequestEntry[] = recArr(raw.subjectRequests ?? raw.subject_requests).map((s) => {
    const st = stripEnum(s.status, "SUBJECT_REQUEST_STATUS_", "executed");
    return {
      request_id: str(s.requestId ?? s.request_id),
      kind: str(s.kind),
      subject_ref: str(s.subjectRef ?? s.subject_ref),
      status: st === "pending_held" ? "pending_held" : "executed",
      hold_ids: strArr(s.holdIds ?? s.hold_ids),
      requested_at: str(s.requestedAt ?? s.requested_at),
      detail: str(s.detail),
    };
  });
  const connectors: ComplianceConnectorEntry[] = recArr(raw.connectors).map((c) => ({
    id: str(c.id),
    name: str(c.name),
    kind: str(c.kind),
    stability: str(c.stability),
    circuit_state: str(c.circuitState ?? c.circuit_state, "closed"),
    queued_items: num(c.queuedItems ?? c.queued_items),
    delivered_items: num(c.deliveredItems ?? c.delivered_items),
    capture_ceiling: str(c.captureCeiling ?? c.capture_ceiling),
    assurance_label: str(c.assuranceLabel ?? c.assurance_label),
    last_delivery_at: optStr(c.lastDeliveryAt ?? c.last_delivery_at),
    summary: str(c.summary),
  }));
  const disclosures: DisclosureLedgerEntry[] = recArr(raw.disclosures).map((d) => ({
    id: str(d.id),
    kind: str(d.kind),
    actor: str(d.actor),
    target_ref: str(d.targetRef ?? d.target_ref),
    legal_basis: str(d.legalBasis ?? d.legal_basis),
    timestamp: str(d.timestamp),
    quarter: str(d.quarter),
    summary: str(d.summary),
  }));
  const dmRaw = rec(raw.disclosureMetrics ?? raw.disclosure_metrics);
  const disclosure_metrics: DisclosureMetrics = {
    quarter: str(dmRaw.quarter, "2026-Q4"),
    total_reidentifications: num(dmRaw.totalReidentifications ?? dmRaw.total_reidentifications),
    total_holds: num(dmRaw.totalHolds ?? dmRaw.total_holds),
    total_erasures: num(dmRaw.totalErasures ?? dmRaw.total_erasures),
    total_exports: num(dmRaw.totalExports ?? dmRaw.total_exports),
  };

  return {
    frameworks,
    evidence_items,
    retention: normRetention(rec(raw.retention)),
    legal_holds: recArr(raw.legalHolds ?? raw.legal_holds).map(normLegalHold),
    subject_requests,
    connectors,
    reid_requests: recArr(raw.reidRequests ?? raw.reid_requests).map(normReidRequest),
    disclosures,
    disclosure_metrics,
    first_run: normFirstRunState(rec(raw.firstRun ?? raw.first_run)),
  };
}

export function normComplianceExport(raw: RawRecord): ComplianceExportArtifact {
  return {
    format: str(raw.format),
    filename: str(raw.filename),
    content_type: str(raw.contentType ?? raw.content_type),
    payload: str(raw.payload),
    oscal_version: str(raw.oscalVersion ?? raw.oscal_version, "1.2.3"),
    digest: str(raw.digest),
  };
}

export function normGrcPush(raw: RawRecord): GrcPushResult {
  return {
    target: str(raw.target),
    envelope_id: str(raw.envelopeId ?? raw.envelope_id),
    outbox_state: str(raw.outboxState ?? raw.outbox_state),
    circuit_state: str(raw.circuitState ?? raw.circuit_state),
    summary: str(raw.summary),
    payload_preview: str(raw.payloadPreview ?? raw.payload_preview),
  };
}

export function normProviderRing(raw: RawRecord): ProviderRingSummary {
  return {
    ring: str(raw.ring),
    org_count: num(raw.orgCount ?? raw.org_count),
    target_version: str(raw.targetVersion ?? raw.target_version),
    health_state: str(raw.healthState ?? raw.health_state),
    soak_hours: num(raw.soakHours ?? raw.soak_hours),
  };
}

export function normProviderWorkspace(raw: RawRecord): ProviderWorkspaceResponse {
  const orgs: ProviderOrgEntry[] = recArr(raw.orgs).map((o) => {
    const st = stripEnum(o.status, "PROVIDER_ORG_STATUS_", "healthy");
    return {
      org_id: str(o.orgId ?? o.org_id),
      name: str(o.name),
      org_set: str(o.orgSet ?? o.org_set),
      ring: str(o.ring),
      devices_count: num(o.devicesCount ?? o.devices_count),
      open_findings: num(o.openFindings ?? o.open_findings),
      pending_approvals: num(o.pendingApprovals ?? o.pending_approvals),
      coverage_pct: num(o.coveragePct ?? o.coverage_pct),
      floor_version: str(o.floorVersion ?? o.floor_version),
      delegated_overrides: num(o.delegatedOverrides ?? o.delegated_overrides),
      status: st === "attention" || st === "offline" ? st : "healthy",
    };
  });
  return {
    acting_as_org_id: optStr(raw.actingAsOrgId ?? raw.acting_as_org_id),
    acting_as_org_name: optStr(raw.actingAsOrgName ?? raw.acting_as_org_name),
    acting_as_reason: optStr(raw.actingAsReason ?? raw.acting_as_reason),
    orgs,
    rings: recArr(raw.rings).map(normProviderRing),
  };
}

export function normOperatorConfig(raw: RawRecord): OperatorRuntimeConfig {
  return {
    revision_id: str(raw.revisionId ?? raw.revision_id),
    version: num(raw.version, 1),
    capture_level: str(raw.captureLevel ?? raw.capture_level, "metadata-only"),
    privacy_profile: str(raw.privacyProfile ?? raw.privacy_profile, "standard"),
    retention_preset: str(raw.retentionPreset ?? raw.retention_preset, "default"),
    hot_days: num(raw.hotDays ?? raw.hot_days, 30),
    activity_days: num(raw.activityDays ?? raw.activity_days, 184),
    decision_days: num(raw.decisionDays ?? raw.decision_days, 396),
    audit_days: num(raw.auditDays ?? raw.audit_days, 396),
    otlp_enabled: Boolean(raw.otlpEnabled ?? raw.otlp_enabled),
    release_channel: str(raw.releaseChannel ?? raw.release_channel, "stable"),
    summary: str(raw.summary),
  };
}

export function normConfigRevision(raw: RawRecord): ConfigRevisionEntry {
  const st = stripEnum(raw.state, "CONFIG_REVISION_LIFECYCLE_", "applied") as ConfigRevisionState;
  const diffs: ConfigDiffEntry[] = recArr(raw.diffLines ?? raw.diff_lines).map((d) => ({
    field: str(d.field),
    previous: str(d.previous),
    next: str(d.next),
  }));
  return {
    revision_id: str(raw.revisionId ?? raw.revision_id),
    version: num(raw.version, 1),
    state: st,
    author: str(raw.author),
    summary: str(raw.summary),
    created_at: str(raw.createdAt ?? raw.created_at),
    applied_at: optStr(raw.appliedAt ?? raw.applied_at),
    diff_lines: diffs,
    config: normOperatorConfig(rec(raw.config)),
  };
}

export function normCompatCheck(raw: RawRecord): CompatCheckEntry {
  const st = stripEnum(raw.status, "COMPAT_OUTCOME_KIND_", "compatible");
  return {
    component: str(raw.component),
    current_version: str(raw.currentVersion ?? raw.current_version),
    target_version: str(raw.targetVersion ?? raw.target_version),
    supported_range: str(raw.supportedRange ?? raw.supported_range),
    status: st === "compatible_with_warnings" || st === "incompatible" ? st : "compatible",
    agreed_capabilities: strArr(raw.agreedCapabilities ?? raw.agreed_capabilities),
    warnings: strArr(raw.warnings),
    remediation: str(raw.remediation),
  };
}

export function normTargetHealth(raw: RawRecord): TargetHealthEntry {
  const st = stripEnum(raw.status, "TARGET_HEALTH_STATUS_", "healthy");
  return {
    id: str(raw.id),
    name: str(raw.name),
    tier: num(raw.tier),
    kind: str(raw.kind),
    status: st === "degraded" || st === "open_circuit" ? st : "healthy",
    circuit_state: str(raw.circuitState ?? raw.circuit_state, "closed"),
    failure_count: num(raw.failureCount ?? raw.failure_count),
    latency_ms: num(raw.latencyMs ?? raw.latency_ms),
    detail: str(raw.detail),
    last_checked_at: str(raw.lastCheckedAt ?? raw.last_checked_at),
  };
}

export function normBackupDrill(raw: RawRecord): BackupDrillRecord {
  const st = stripEnum(raw.status, "BACKUP_DRILL_STATUS_", "passed");
  return {
    drill_id: str(raw.drillId ?? raw.drill_id),
    kind: str(raw.kind, "backup"),
    status: st === "running" || st === "failed" ? st : "passed",
    snapshot_digest: str(raw.snapshotDigest ?? raw.snapshot_digest),
    record_count: num(raw.recordCount ?? raw.record_count),
    verified_tables: num(raw.verifiedTables ?? raw.verified_tables),
    duration_ms: num(raw.durationMs ?? raw.duration_ms),
    executed_at: str(raw.executedAt ?? raw.executed_at),
    actor: str(raw.actor),
    note: str(raw.note),
  };
}

export function normOperatorState(raw: RawRecord): OperatorStateResponse {
  return {
    runtime_config: normOperatorConfig(rec(raw.runtimeConfig ?? raw.runtime_config)),
    revisions: recArr(raw.revisions).map(normConfigRevision),
    preflight_matrix: recArr(raw.preflightMatrix ?? raw.preflight_matrix).map(normCompatCheck),
    target_version: str(raw.targetVersion ?? raw.target_version, "0.2.0"),
    overall_compatible: Boolean(raw.overallCompatible ?? raw.overall_compatible ?? true),
    targets: recArr(raw.targets).map(normTargetHealth),
    drills: recArr(raw.drills).map(normBackupDrill),
  };
}
