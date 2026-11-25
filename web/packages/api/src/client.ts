import { CONNECT_PATHS, connectConfirmedPost, connectGet, connectPost } from "./connect";
import { surfaceApi } from "./client-surfaces";
import {
  normAgent,
  normApproval,
  normArtifact,
  normAudit,
  normBrowserEvaluate,
  normBrowserPolicy,
  normConnectConfig,
  normCreateDeploymentKey,
  normDeploymentKey,
  normDevice,
  normFinding,
  normHealth,
  normIncident,
  normIntegration,
  normKillSwitch,
  normMcpServer,
  normMdmRender,
  normOverview,
  normPack,
  normPageInfo,
  normPrivacyConfig,
  normReceipt,
  normReplay,
  normRule,
  normSession,
  normSessionDetail,
  normTrustedKey,
  normUser,
  normUserDetail,
  optStr,
  rec,
  recArr,
  str,
  type RawRecord,
} from "./normalize";
import type {
  ActionClass,
  AgentInventoryItem,
  ApprovalRequest,
  ArtifactEntry,
  AuditEntry,
  DecisionReceipt,
  Device,
  DiscoveredAgent,
  Finding,
  FindingLifecycle,
  GrantScope,
  HealthResponse,
  IdentityMode,
  Incident,
  KillAction,
  KillScope,
  KillSwitchState,
  McpInventoryItem,
  McpServerEntry,
  Mode,
  OrgPrivacyConfig,
  OverviewResponse,
  PageQuery,
  PagedResult,
  PolicyPack,
  PolicyRule,
  ReplaySummary,
  SessionDetailResponse,
  SessionSummary,
  TrustedKeyInfo,
  UserDetailResponse,
  UserProfile,
} from "./types";
import type {
  BrowserAppPolicy,
  BrowserDlpClass,
  BrowserEvaluateResponse,
  ConnectConfigResponse,
  CreateDeploymentKeyResponse,
  DeploymentKey,
  IntegrationEntry,
  MdmFormat,
  MdmRenderResponse,
} from "./types-connect";

type Raw = RawRecord;

function pageReqBody(query?: PageQuery): Record<string, unknown> {
  return {
    pageSize: query?.page_size ?? 50,
    pageToken: query?.page_token ?? "",
    filter: query?.filter ?? "",
    orderBy: query?.order_by ?? "",
  };
}

function triggerDownload(filename: string, contentType: string, payload: string): void {
  const blob = new Blob([payload], { type: contentType || "application/octet-stream" });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

export const api = {
  getHealth: async (): Promise<HealthResponse> =>
    normHealth(await connectGet<Raw>(CONNECT_PATHS.getHealth)),

  getOverview: async (): Promise<OverviewResponse> =>
    normOverview(await connectGet<Raw>(CONNECT_PATHS.getOverview)),

  getPrivacyConfig: async (): Promise<OrgPrivacyConfig> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.getPrivacyConfig);
    return normPrivacyConfig(rec(res.config ?? res));
  },

  updatePrivacyConfig: async (body: {
    identity_mode?: IdentityMode;
    user_risk_scoring?: boolean;
    step_up?: boolean;
    step_up_token?: string;
  }): Promise<OrgPrivacyConfig> => {
    const res = await connectConfirmedPost<Raw>(
      CONNECT_PATHS.updatePrivacyConfig,
      {
        identityMode: body.identity_mode,
        userRiskScoring: body.user_risk_scoring,
      },
      body.step_up ? "step-up" : "confirmed",
      body.step_up_token,
    );
    return normPrivacyConfig(rec(res.config ?? res));
  },

  listUsersPage: async (query?: PageQuery): Promise<PagedResult<UserProfile>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listUsers, pageReqBody(query));
    return {
      items: recArr(res.users).map(normUser),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getUsers: async (): Promise<UserProfile[]> =>
    (await api.listUsersPage({ page_size: 200 })).items,

  getUserDetail: async (id: string): Promise<UserDetailResponse> =>
    normUserDetail(await connectPost<Raw>(CONNECT_PATHS.getUser, { id })),

  listDevicesPage: async (query?: PageQuery): Promise<PagedResult<Device>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listDevices, pageReqBody(query));
    return {
      items: recArr(res.devices).map(normDevice),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getDevices: async (): Promise<Device[]> =>
    (await api.listDevicesPage({ page_size: 200 })).items,

  listAgentsPage: async (query?: PageQuery): Promise<PagedResult<AgentInventoryItem>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listAgents, pageReqBody(query));
    return {
      items: recArr(res.items).map((it) => ({
        device_id: str(it.deviceId ?? it.device_id),
        device_name: str(it.deviceName ?? it.device_name),
        agent: normAgent(rec(it.agent)),
      })),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getAgents: async (): Promise<DiscoveredAgent[]> =>
    (await api.listAgentsPage({ page_size: 200 })).items.map((it) => it.agent),

  listMcpServersPage: async (query?: PageQuery): Promise<PagedResult<McpInventoryItem>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listMcpServers, pageReqBody(query));
    return {
      items: recArr(res.items).map((it) => ({
        device_id: str(it.deviceId ?? it.device_id),
        device_name: str(it.deviceName ?? it.device_name),
        server: normMcpServer(rec(it.server)),
      })),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getMcpServers: async (): Promise<McpServerEntry[]> =>
    (await api.listMcpServersPage({ page_size: 200 })).items.map((it) => it.server),

  listArtifactsPage: async (query?: PageQuery): Promise<PagedResult<ArtifactEntry>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listArtifacts, pageReqBody(query));
    return {
      items: recArr(res.artifacts).map(normArtifact),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getArtifacts: async (): Promise<ArtifactEntry[]> =>
    (await api.listArtifactsPage({ page_size: 200 })).items,

  listSessionsPage: async (query?: PageQuery): Promise<PagedResult<SessionSummary>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listSessions, pageReqBody(query));
    return {
      items: recArr(res.sessions).map(normSession),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getSessions: async (): Promise<SessionSummary[]> =>
    (await api.listSessionsPage({ page_size: 200 })).items,

  getSessionDetail: async (id: string): Promise<SessionDetailResponse> =>
    normSessionDetail(await connectPost<Raw>(CONNECT_PATHS.getSession, { id })),

  getPacks: async (): Promise<PolicyPack[]> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.listPacks);
    return recArr(res.packs).map(normPack);
  },

  createRule: async (body: {
    title: string;
    description: string;
    mode: Mode;
    matcher: {
      action_classes: ActionClass[];
      target_prefixes: string[];
      target_contains: string[];
      agents: string[];
    };
    reason_template: string;
  }): Promise<PolicyRule> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.createRule, {
      title: body.title,
      description: body.description,
      mode: body.mode,
      matcher: {
        actionClasses: body.matcher.action_classes,
        targetPrefixes: body.matcher.target_prefixes,
        targetContains: body.matcher.target_contains,
        agents: body.matcher.agents,
      },
      reasonTemplate: body.reason_template,
    });
    return normRule(rec(res.rule ?? res));
  },

  updateRule: async (
    id: string,
    body: {
      title?: string;
      description?: string;
      mode?: Mode;
      matcher?: {
        action_classes: ActionClass[];
        target_prefixes: string[];
        target_contains: string[];
        agents: string[];
      };
      reason_template?: string;
    },
  ): Promise<PolicyRule> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.updateRule, {
      id,
      title: body.title,
      description: body.description,
      mode: body.mode,
      matcher: body.matcher
        ? {
            actionClasses: body.matcher.action_classes,
            targetPrefixes: body.matcher.target_prefixes,
            targetContains: body.matcher.target_contains,
            agents: body.matcher.agents,
          }
        : undefined,
      reasonTemplate: body.reason_template,
    });
    return normRule(rec(res.rule ?? res));
  },

  deleteRule: async (id: string): Promise<void> => {
    await connectConfirmedPost<Raw>(CONNECT_PATHS.deleteRule, { id });
  },

  updateRuleMode: async (id: string, mode: Mode, replayConfirmed = false): Promise<PolicyRule> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.updateRuleMode, {
      id,
      mode,
      replayConfirmed,
    });
    return normRule(rec(res.rule ?? res));
  },

  replayRule: async (id: string, candidateMode: Mode): Promise<ReplaySummary> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.replayRule, {
      id,
      candidateMode,
    });
    return normReplay(rec(res.summary ?? res));
  },

  listApprovalsPage: async (query?: PageQuery): Promise<PagedResult<ApprovalRequest>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listApprovals, pageReqBody(query));
    return {
      items: recArr(res.approvals).map(normApproval),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getApprovals: async (): Promise<ApprovalRequest[]> =>
    (await api.listApprovalsPage({ page_size: 200 })).items,

  decideApproval: async (
    id: string,
    approve: boolean,
    scope: GrantScope,
    note: string,
  ): Promise<ApprovalRequest> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.decideApproval, {
      id,
      approve,
      scope,
      note,
    });
    return normApproval(rec(res.approval ?? res));
  },

  listFindingsPage: async (query?: PageQuery): Promise<PagedResult<Finding>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listFindings, pageReqBody(query));
    return {
      items: recArr(res.findings).map(normFinding),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getFindings: async (): Promise<Finding[]> =>
    (await api.listFindingsPage({ page_size: 200 })).items,

  listIncidentsPage: async (query?: PageQuery): Promise<PagedResult<Incident>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listIncidents, pageReqBody(query));
    return {
      items: recArr(res.incidents).map(normIncident),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getIncidents: async (): Promise<Incident[]> =>
    (await api.listIncidentsPage({ page_size: 200 })).items,

  updateFinding: async (id: string, lifecycle: FindingLifecycle): Promise<Finding> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.updateFinding, { id, lifecycle });
    return normFinding(rec(res.finding ?? res));
  },

  getKillSwitch: async (): Promise<KillSwitchState> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.getKillSwitch);
    return normKillSwitch(rec(res.killSwitch ?? res.kill_switch ?? res));
  },

  setKillSwitch: async (body: {
    action: KillAction;
    scope: KillScope;
    target_id: string;
    reason: string;
    duration_minutes?: number;
  }): Promise<KillSwitchState> => {
    const res = await connectConfirmedPost<Raw>(
      CONNECT_PATHS.setKillSwitch,
      {
        action: body.action,
        scope: body.scope,
        targetId: body.target_id,
        reason: body.reason,
        durationMinutes: body.duration_minutes,
      },
      "confirmed",
    );
    return normKillSwitch(rec(res.killSwitch ?? res.kill_switch ?? res));
  },

  listAuditEventsPage: async (query?: PageQuery): Promise<PagedResult<AuditEntry>> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.listAuditEvents, pageReqBody(query));
    return {
      items: recArr(res.entries).map(normAudit),
      page_info: normPageInfo(res.pageInfo ?? res.page_info),
      etag: optStr(rec(res.revision).etag) ?? undefined,
    };
  },

  getAudit: async (): Promise<AuditEntry[]> =>
    (await api.listAuditEventsPage({ page_size: 200 })).items,

  getKeys: async (): Promise<TrustedKeyInfo[]> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.listKeys);
    return recArr(res.keys).map(normTrustedKey);
  },

  decideAction: async (body: {
    session_id: string;
    device_id: string;
    device_name: string;
    agent_name: string;
    action_class: ActionClass;
    target: string;
    summary: string;
  }): Promise<DecisionReceipt> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.evaluate, {
      sessionId: body.session_id,
      deviceId: body.device_id,
      deviceName: body.device_name,
      agentName: body.agent_name,
      actionClass: body.action_class,
      target: body.target,
      summary: body.summary,
    });
    return normReceipt(rec(res.receipt ?? res));
  },

  exportOcsf: async (): Promise<void> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.exportOcsf);
    triggerDownload(
      str(res.filename, "guardrails-ocsf-1.9.json"),
      str(res.contentType, "application/json"),
      str(res.payload, "[]"),
    );
  },

  exportAuditJsonl: async (): Promise<void> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.exportAuditJsonl);
    triggerDownload(
      str(res.filename, "guardrails-audit.jsonl"),
      str(res.contentType, "application/x-ndjson"),
      str(res.payload),
    );
  },

  getConnectConfig: async (): Promise<ConnectConfigResponse> =>
    normConnectConfig(await connectGet<Raw>(CONNECT_PATHS.getConnectConfig)),

  createDeploymentKey: async (body: {
    label: string;
    wave: string;
    install_profile: string;
    max_uses: number;
    ttl_days: number;
  }): Promise<CreateDeploymentKeyResponse> =>
    normCreateDeploymentKey(
      await connectConfirmedPost<Raw>(CONNECT_PATHS.createDeploymentKey, {
        label: body.label,
        wave: body.wave,
        installProfile: body.install_profile,
        maxUses: body.max_uses,
        ttlDays: body.ttl_days,
      }),
    ),

  revokeDeploymentKey: async (id: string): Promise<DeploymentKey> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.revokeDeploymentKey, { id });
    return normDeploymentKey(rec(res.key ?? res));
  },

  renderMdmConfig: async (body: {
    format: MdmFormat;
    deployment_key_id?: string | null;
    include_browser_extension: boolean;
    update_authority: string;
  }): Promise<MdmRenderResponse> =>
    normMdmRender(
      await connectPost<Raw>(CONNECT_PATHS.renderMdmConfig, {
        format: body.format,
        deploymentKeyId: body.deployment_key_id ?? undefined,
        includeBrowserExtension: body.include_browser_extension,
        updateAuthority: body.update_authority,
      }),
    ),

  checkIntegrationReadiness: async (id: string): Promise<IntegrationEntry> => {
    const res = await connectPost<Raw>(CONNECT_PATHS.checkIntegrationReadiness, { id });
    return normIntegration(rec(res.integration ?? res));
  },

  getBrowserPolicies: async (): Promise<BrowserAppPolicy[]> => {
    const res = await connectGet<Raw>(CONNECT_PATHS.listBrowserPolicies);
    return recArr(res.policies).map(normBrowserPolicy);
  },

  updateBrowserPolicy: async (
    id: string,
    body: {
      mode?: Mode;
      block_file_uploads?: boolean;
      block_secret_paste?: boolean;
      managed_extension_only?: boolean;
    },
  ): Promise<BrowserAppPolicy> => {
    const res = await connectConfirmedPost<Raw>(CONNECT_PATHS.updateBrowserPolicy, {
      id,
      mode: body.mode,
      blockFileUploads: body.block_file_uploads,
      blockSecretPaste: body.block_secret_paste,
      managedExtensionOnly: body.managed_extension_only,
    });
    return normBrowserPolicy(rec(res.policy ?? res));
  },

  evaluateBrowserAction: async (body: {
    app_id: string;
    domain: string;
    dlp_class: BrowserDlpClass;
    file_extension?: string | null;
    has_secret_match: boolean;
  }): Promise<BrowserEvaluateResponse> =>
    normBrowserEvaluate(
      await connectPost<Raw>(CONNECT_PATHS.evaluateBrowser, {
        appId: body.app_id,
        domain: body.domain,
        dlpClass: body.dlp_class,
        fileExtension: body.file_extension ?? undefined,
        hasSecretMatch: body.has_secret_match,
      }),
    ),
  ...surfaceApi,
};
