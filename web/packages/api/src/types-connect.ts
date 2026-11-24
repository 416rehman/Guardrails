import type { Mode, Verdict } from "./types";

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

// grdr:allow-s4 orthogonal browser policy configuration toggles
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
