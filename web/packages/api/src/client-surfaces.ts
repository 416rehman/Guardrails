import { CONNECT_PATHS, connectConfirmedPost, connectGet, connectPost } from "./connect";
import { optStr, rec, recArr, str, type RawRecord } from "./normalize";
import {
  normBackupDrill,
  normCompatCheck,
  normComplianceExport,
  normComplianceWorkspace,
  normConfigRevision,
  normFirstRunState,
  normGrcPush,
  normLegalHold,
  normOperatorConfig,
  normOperatorState,
  normProviderRing,
  normProviderWorkspace,
  normReidRequest,
  normRetention,
  normReviewCluster,
  normReviewQueue,
  normTargetHealth,
  normWhyExplanation,
} from "./normalize-surfaces";
import type {
  BackupDrillRecord,
  ComplianceExportArtifact,
  ComplianceWorkspaceResponse,
  ConfigRevisionEntry,
  FirstRunState,
  GrcPushResult,
  LegalHoldEntry,
  OperatorRuntimeConfig,
  OperatorStateResponse,
  ProviderRingSummary,
  ProviderWorkspaceResponse,
  ReidentificationRequestEntry,
  RetentionStateSummary,
  ReviewCluster,
  ReviewQueueResponse,
  TargetHealthEntry,
  WhyExplanation,
} from "./types-surfaces";

type Raw = RawRecord;

export const surfaceApi = {
  explainReceipt: async (reference: string): Promise<WhyExplanation> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.explainReceipt, { reference });
    return normWhyExplanation(rec(res.explanation ?? res));
  },

  listReviewQueue: async (
    bucket = "all",
    search = "",
  ): Promise<ReviewQueueResponse> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listReviewQueue, {
      bucket,
      search,
    });
    return normReviewQueue(res);
  },

  decideReviewCluster: async (body: {
    id: string;
    decision: "promote" | "suppress" | "dismiss" | "escalate";
    target_mode?: "off" | "watch" | "ask" | "block";
    note?: string;
    step_up?: boolean;
    step_up_token?: string;
  }): Promise<ReviewCluster> => {
    const res = await connectConfirmedPost<Raw>(
      CONNECT_PATHS.decideReviewCluster,
      {
        id: body.id,
        decision: body.decision,
        targetMode: body.target_mode,
        note: body.note,
      },
      body.step_up ? "step-up" : "confirmed",
      body.step_up_token,
    );
    return normReviewCluster(rec(res.cluster ?? res));
  },

  getComplianceWorkspace: async (): Promise<ComplianceWorkspaceResponse> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.getComplianceWorkspace);
    return normComplianceWorkspace(res);
  },

  updateCompliancePolicy: async (body: {
    privacy_profile: "standard" | "works-council";
    presets: string[];
    override_legal_basis?: string;
    capture_level?: string;
    step_up?: boolean;
    step_up_token?: string;
  }): Promise<RetentionStateSummary> => {
    const res = await connectConfirmedPost<Raw>(
      CONNECT_PATHS.updateCompliancePolicy,
      {
        privacyProfile: body.privacy_profile,
        presets: body.presets,
        overrideLegalBasis: body.override_legal_basis,
        captureLevel: body.capture_level,
      },
      body.step_up ? "step-up" : "confirmed",
      body.step_up_token,
    );
    return normRetention(rec(res.retention ?? res));
  },

  createLegalHold: async (body: {
    matter_ref: string;
    reason: string;
    pseudonym_or_session: string;
  }): Promise<LegalHoldEntry> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.createLegalHold, {
      matterRef: body.matter_ref,
      reason: body.reason,
      pseudonymOrSession: body.pseudonym_or_session,
    });
    return normLegalHold(rec(res.hold ?? res));
  },

  approveLegalHold: async (body: {
    hold_id: string;
    note?: string;
  }): Promise<LegalHoldEntry> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.approveLegalHold, {
      holdId: body.hold_id,
      note: body.note,
    });
    return normLegalHold(rec(res.hold ?? res));
  },

  exportComplianceArtifact: async (body: {
    format: "oscal-component" | "oscal-assessment" | "csv" | "markdown";
    framework_id?: string;
  }): Promise<ComplianceExportArtifact> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.exportComplianceArtifact, {
      format: body.format,
      frameworkId: body.framework_id,
    });
    return normComplianceExport(res);
  },

  pushGrcEvidence: async (body: {
    target: "ciso-assistant" | "probo";
  }): Promise<GrcPushResult> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.pushGrcEvidence, body);
    return normGrcPush(res);
  },

  requestReidentification: async (body: {
    pseudonym_id: string;
    reason: string;
    legal_basis: string;
  }): Promise<ReidentificationRequestEntry> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.requestReidentification, {
      pseudonymId: body.pseudonym_id,
      reason: body.reason,
      legalBasis: body.legal_basis,
    });
    return normReidRequest(rec(res.request ?? res));
  },

  approveReidentification: async (body: {
    request_id: string;
    note?: string;
  }): Promise<ReidentificationRequestEntry> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.approveReidentification, {
      requestId: body.request_id,
      note: body.note,
    });
    return normReidRequest(rec(res.request ?? res));
  },

  completeFirstRun: async (body: {
    profile: "protected" | "user";
    confirm_protection: boolean;
    step_up_enabled: boolean;
  }): Promise<FirstRunState> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.completeFirstRun, {
      profile: body.profile,
      confirmProtection: body.confirm_protection,
      stepUpEnabled: body.step_up_enabled,
    });
    return normFirstRunState(rec(res.firstRun ?? res.first_run ?? res));
  },

  getProviderWorkspace: async (
    orgSet?: string,
  ): Promise<ProviderWorkspaceResponse> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.getProviderWorkspace, {
      orgSet,
    });
    return normProviderWorkspace(res);
  },

  switchProviderOrg: async (body: {
    org_id?: string | null;
    reason?: string;
  }): Promise<{
    acting_as_org_id: string | null;
    acting_as_org_name: string | null;
    acting_as_reason: string | null;
  }> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.switchProviderOrg, {
      orgId: body.org_id ?? undefined,
      reason: body.reason,
    });
    return {
      acting_as_org_id: optStr(res.actingAsOrgId ?? res.acting_as_org_id),
      acting_as_org_name: optStr(res.actingAsOrgName ?? res.acting_as_org_name),
      acting_as_reason: optStr(res.actingAsReason ?? res.acting_as_reason),
    };
  },

  advanceProviderRing: async (body: {
    ring: string;
    target_version: string;
  }): Promise<ProviderRingSummary> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.advanceProviderRing, {
      ring: body.ring,
      targetVersion: body.target_version,
    });
    return normProviderRing(rec(res.ring ?? res));
  },

  getOperatorState: async (): Promise<OperatorStateResponse> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.getOperatorState);
    return normOperatorState(res);
  },

  stageConfigRevision: async (body: {
    capture_level: string;
    privacy_profile: string;
    retention_preset: string;
    otlp_enabled: boolean;
    release_channel: string;
    summary: string;
  }): Promise<ConfigRevisionEntry> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.stageConfigRevision, {
      captureLevel: body.capture_level,
      privacyProfile: body.privacy_profile,
      retentionPreset: body.retention_preset,
      otlpEnabled: body.otlp_enabled,
      releaseChannel: body.release_channel,
      summary: body.summary,
    });
    return normConfigRevision(rec(res.revision ?? res));
  },

  applyConfigRevision: async (body: {
    revision_id: string;
    step_up?: boolean;
    step_up_token?: string;
  }): Promise<{
    runtime_config: OperatorRuntimeConfig;
    applied_revision: ConfigRevisionEntry;
  }> => {
    const res = await connectConfirmedPost<Raw>(
      CONNECT_PATHS.applyConfigRevision,
      { revisionId: body.revision_id },
      body.step_up ? "step-up" : "confirmed",
      body.step_up_token,
    );
    return {
      runtime_config: normOperatorConfig(rec(res.runtimeConfig ?? res.runtime_config)),
      applied_revision: normConfigRevision(rec(res.appliedRevision ?? res.applied_revision)),
    };
  },

  rollbackConfigRevision: async (body: {
    target_revision_id?: string;
    reason: string;
    step_up?: boolean;
    step_up_token?: string;
  }): Promise<{
    runtime_config: OperatorRuntimeConfig;
    rolled_back_revision: ConfigRevisionEntry;
  }> => {
    const res = await connectConfirmedPost<Raw>(
      CONNECT_PATHS.rollbackConfigRevision,
      {
        targetRevisionId: body.target_revision_id,
        reason: body.reason,
      },
      body.step_up ? "step-up" : "confirmed",
      body.step_up_token,
    );
    return {
      runtime_config: normOperatorConfig(rec(res.runtimeConfig ?? res.runtime_config)),
      rolled_back_revision: normConfigRevision(
        rec(res.rolledBackRevision ?? res.rolled_back_revision),
      ),
    };
  },

  runUpgradePreflight: async (body: {
    target_version: string;
  }): Promise<{
    target_version: string;
    overall_compatible: boolean;
    preflight_matrix: ReturnType<typeof normCompatCheck>[];
  }> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.runUpgradePreflight, {
      targetVersion: body.target_version,
    });
    return {
      target_version: str(res.targetVersion ?? res.target_version, body.target_version),
      overall_compatible: Boolean(res.overallCompatible ?? res.overall_compatible ?? true),
      preflight_matrix: recArr(res.preflightMatrix ?? res.preflight_matrix).map(normCompatCheck),
    };
  },

  resetTargetBreaker: async (body: {
    target_id: string;
  }): Promise<TargetHealthEntry> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.resetTargetBreaker, {
      targetId: body.target_id,
    });
    return normTargetHealth(rec(res.target ?? res));
  },

  runBackupDrill: async (body: {
    kind: "backup" | "restore";
    note?: string;
  }): Promise<BackupDrillRecord> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.runBackupDrill, body);
    return normBackupDrill(rec(res.drill ?? res));
  },
};
