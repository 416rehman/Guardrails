// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_model::{
    CodedError, DeploymentKey, DeploymentKeyStatus, InstallerSpec, IntegrationCategory,
    IntegrationEntry, IntegrationHealthState, MdmFormat, MdmRenderRequest, MdmRenderResponse,
    OTLP_DEFAULT_BIND_ADDRESS, OTLP_DEFAULT_GRPC_PORT, OTLP_DEFAULT_HTTP_PORT, OtlpFanoutConfig,
    ReadinessCheck,
};

pub(crate) const CODE_CONNECT_INVALID: &str = "GRDR-CONNECT-0001";
pub(crate) const DEMO_ORIGIN: &str = "https://guardrails.internal:8443";
const SECONDS_PER_DAY: i64 = 86_400;

pub(crate) struct DemoConnectState {
    pub deployment_keys: Vec<DeploymentKey>,
    pub integrations: Vec<IntegrationEntry>,
    pub otlp_config: OtlpFanoutConfig,
}

pub(crate) fn demo_connect_state(now: Timestamp) -> DemoConnectState {
    let created = Timestamp::from_second(now.as_second().saturating_sub(14 * SECONDS_PER_DAY))
        .unwrap_or(now)
        .to_string();
    let expires_pilot =
        Timestamp::from_second(now.as_second().saturating_add(16 * SECONDS_PER_DAY))
            .unwrap_or(now)
            .to_string();
    let expires_fleet =
        Timestamp::from_second(now.as_second().saturating_add(45 * SECONDS_PER_DAY))
            .unwrap_or(now)
            .to_string();
    let expires_legacy =
        Timestamp::from_second(now.as_second().saturating_add(5 * SECONDS_PER_DAY))
            .unwrap_or(now)
            .to_string();
    let recent_sync = Timestamp::from_second(now.as_second().saturating_sub(420))
        .unwrap_or(now)
        .to_string();

    let deployment_keys = vec![
        DeploymentKey {
            id: "key-pilot-wave-1".into(),
            label: "Pilot Wave 1".into(),
            token_preview: "grdr_wk_pilot_9f1a".into(),
            install_profile: "standard".into(),
            wave: "wave-1-pilot".into(),
            max_uses: 50,
            used_count: 14,
            status: DeploymentKeyStatus::Active,
            created_at: created.clone(),
            expires_at: expires_pilot,
            created_by: "maya.chen@acme.dev".into(),
        },
        DeploymentKey {
            id: "key-eng-mac-fleet".into(),
            label: "Engineering Mac Fleet".into(),
            token_preview: "grdr_wk_mac_48c2".into(),
            install_profile: "enforced".into(),
            wave: "wave-2-eng".into(),
            max_uses: 50,
            used_count: 48,
            status: DeploymentKeyStatus::Active,
            created_at: created.clone(),
            expires_at: expires_fleet,
            created_by: "priya.nair@acme.dev".into(),
        },
        DeploymentKey {
            id: "key-legacy-contractor".into(),
            label: "Legacy Contractor Key".into(),
            token_preview: "grdr_wk_old_03b7".into(),
            install_profile: "watch".into(),
            wave: "wave-0-trial".into(),
            max_uses: 25,
            used_count: 21,
            status: DeploymentKeyStatus::Revoked,
            created_at: created,
            expires_at: expires_legacy,
            created_by: "secops@acme.dev".into(),
        },
    ];

    let integrations = vec![
        IntegrationEntry {
            id: "idp-okta".into(),
            name: "Okta Directory Sync".into(),
            provider: "Okta".into(),
            category: IntegrationCategory::DirectorySync,
            state: IntegrationHealthState::Connected,
            synced_users: 12,
            last_sync_at: Some(recent_sync.clone()),
            credential_expires_in_days: Some(90),
            detail: "Read-only SCIM pull resolves users, managers, and org units.".into(),
            readiness_checks: vec![
                ReadinessCheck {
                    name: "Credential validity".into(),
                    passed: true,
                    detail: "API token rotates in 90 days".into(),
                },
                ReadinessCheck {
                    name: "Scope permissions".into(),
                    passed: true,
                    detail: "okta.users.read, okta.groups.read verified".into(),
                },
                ReadinessCheck {
                    name: "Endpoint reachability".into(),
                    passed: true,
                    detail: "TLS 1.3 handshake verified".into(),
                },
            ],
        },
        IntegrationEntry {
            id: "idp-entra".into(),
            name: "Microsoft Entra ID".into(),
            provider: "Entra".into(),
            category: IntegrationCategory::DirectorySync,
            state: IntegrationHealthState::AtRisk,
            synced_users: 28,
            last_sync_at: Some(recent_sync.clone()),
            credential_expires_in_days: Some(9),
            detail: "App registration secret expires within 14 days.".into(),
            readiness_checks: vec![
                ReadinessCheck {
                    name: "Credential validity".into(),
                    passed: true,
                    detail: "Secret expires in 9 days (rotates below 14d threshold)".into(),
                },
                ReadinessCheck {
                    name: "Scope permissions".into(),
                    passed: true,
                    detail: "User.Read.All granted".into(),
                },
                ReadinessCheck {
                    name: "Endpoint reachability".into(),
                    passed: true,
                    detail: "Graph API responsive".into(),
                },
            ],
        },
        IntegrationEntry {
            id: "saas-anthropic".into(),
            name: "Anthropic Compliance API".into(),
            provider: "Anthropic".into(),
            category: IntegrationCategory::SaasConnector,
            state: IntegrationHealthState::Connected,
            synced_users: 18,
            last_sync_at: Some(recent_sync),
            credential_expires_in_days: Some(64),
            detail: "Read-only activity polling over /v1/compliance/activities.".into(),
            readiness_checks: vec![
                ReadinessCheck {
                    name: "Credential validity".into(),
                    passed: true,
                    detail: "Compliance Access Key valid for 64 days".into(),
                },
                ReadinessCheck {
                    name: "Scope permissions".into(),
                    passed: true,
                    detail: "Read-only compliance activity cursor verified".into(),
                },
                ReadinessCheck {
                    name: "Endpoint reachability".into(),
                    passed: true,
                    detail: "Egress allowlist permitted".into(),
                },
            ],
        },
        IntegrationEntry {
            id: "saas-m365-copilot".into(),
            name: "Microsoft 365 Copilot Export".into(),
            provider: "Microsoft 365".into(),
            category: IntegrationCategory::SaasConnector,
            state: IntegrationHealthState::NotConfigured,
            synced_users: 0,
            last_sync_at: None,
            credential_expires_in_days: None,
            detail: "Requires Entra tenant admin consent for Interaction Export API.".into(),
            readiness_checks: vec![
                ReadinessCheck {
                    name: "Credential validity".into(),
                    passed: false,
                    detail: "No Entra client credential configured".into(),
                },
                ReadinessCheck {
                    name: "Scope permissions".into(),
                    passed: false,
                    detail: "AiEnterpriseInteraction.Read.All pending admin consent".into(),
                },
                ReadinessCheck {
                    name: "Endpoint reachability".into(),
                    passed: true,
                    detail: "Graph export endpoint reachable".into(),
                },
            ],
        },
    ];

    let otlp_config = OtlpFanoutConfig {
        enabled: true,
        grpc_port: OTLP_DEFAULT_GRPC_PORT,
        http_port: OTLP_DEFAULT_HTTP_PORT,
        bind_address: OTLP_DEFAULT_BIND_ADDRESS.into(),
        downstream_targets: vec![
            "https://collector.soc.internal:4317".into(),
            "https://splunk-hec.soc.internal:8088".into(),
        ],
        loopback_only: true,
        accepted_spans_24h: 18_420,
    };

    DemoConnectState {
        deployment_keys,
        integrations,
        otlp_config,
    }
}

pub(crate) fn default_installers(origin: &str) -> Vec<InstallerSpec> {
    vec![
        InstallerSpec {
            platform: "macos".into(),
            label: "macOS pkg installer".into(),
            version: "0.4.2".into(),
            command: format!(
                "curl -fsSL {origin}/dl/guardrails-0.4.2.pkg -o /tmp/grdr.pkg && sudo installer -pkg /tmp/grdr.pkg -target /"
            ),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            doctor_command: "grdr doctor net".into(),
            notes: "Universal arm64 + x86_64 signed package with system extension preflight."
                .into(),
        },
        InstallerSpec {
            platform: "windows".into(),
            label: "Windows MSI (/MT static)".into(),
            version: "0.4.2".into(),
            command: format!(
                "msiexec /i {origin}/dl/guardrails-0.4.2-x64.msi /qn INSTALL_PROFILE=standard"
            ),
            sha256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4".into(),
            doctor_command: "grdr.exe doctor net".into(),
            notes: "Statically links MSVC CRT (/MT) with zero VC++ redistributable dependencies."
                .into(),
        },
        InstallerSpec {
            platform: "linux".into(),
            label: "Linux apt / dnf package".into(),
            version: "0.4.2".into(),
            command: format!(
                "curl -fsSL {origin}/dl/linux-install.sh | sudo sh -s -- --profile standard"
            ),
            sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae".into(),
            doctor_command: "grdr doctor net".into(),
            notes:
                "Configures systemd unit and drops signed repository key under /etc/apt/keyrings."
                    .into(),
        },
    ]
}

pub(crate) fn render_mdm_artifact(
    req: &MdmRenderRequest,
    origin: &str,
    key: Option<&DeploymentKey>,
) -> Result<MdmRenderResponse, CodedError> {
    if req.update_authority != "managed" && req.update_authority != "self" {
        return Err(CodedError::new(
            CODE_CONNECT_INVALID,
            "Update authority must be `managed` or `self`.",
            "Pass `managed` for MDM-controlled upgrades or `self` for automatic agent updates.",
        ));
    }

    let key_preview = key.map_or("grdr_wk_REPLACE_WITH_WAVE_TOKEN", |k| {
        k.token_preview.as_str()
    });
    let profile = key.map_or("standard", |k| k.install_profile.as_str());
    let authority = req.update_authority.as_str();
    let ext_flag = if req.include_browser_extension {
        "enabled"
    } else {
        "disabled"
    };

    let response = match req.format {
        MdmFormat::IntuneWin32 => MdmRenderResponse {
            format: MdmFormat::IntuneWin32,
            filename: "guardrails-intune-install.ps1".into(),
            content_type: "text/plain".into(),
            payload: format!(
                "$ProgressPreference = 'SilentlyContinue'\nNew-Item -ItemType Directory -Force -Path 'C:\\ProgramData\\Guardrails' | Out-Null\n$cfg = @\"\norigin = \"{origin}\"\ninstall_profile = \"{profile}\"\nupdate_authority = \"{authority}\"\nbrowser_extension = \"{ext_flag}\"\nenrollment_token = \"{key_preview}\"\n\"@\nSet-Content -Path 'C:\\ProgramData\\Guardrails\\install.toml' -Value $cfg -Encoding UTF8\nStart-Process msiexec.exe -Wait -ArgumentList '/i guardrails-0.4.2-x64.msi /qn'\n"
            ),
            deployment_notes: vec![
                "Package as .intunewin with MSI product-code detection rule.".into(),
                "Stages enrollment config idempotently to avoid 0x87D3014A retry loops.".into(),
            ],
        },
        MdmFormat::JamfMobileconfig => MdmRenderResponse {
            format: MdmFormat::JamfMobileconfig,
            filename: "com.guardrails.adr.mobileconfig".into(),
            content_type: "application/x-apple-aspen-config".into(),
            payload: format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n  <key>PayloadType</key><string>com.guardrails.adr</string>\n  <key>ServerOrigin</key><string>{origin}</string>\n  <key>InstallProfile</key><string>{profile}</string>\n  <key>UpdateAuthority</key><string>{authority}</string>\n  <key>BrowserExtension</key><string>{ext_flag}</string>\n  <key>EnrollmentToken</key><string>{key_preview}</string>\n</dict></plist>\n"
            ),
            deployment_notes: vec![
                "Upload raw .mobileconfig payload without MDM XML re-encoding.".into(),
                "Pair with macOS PPPC profile if deploying Managed Chrome/Edge policies.".into(),
            ],
        },
        MdmFormat::Hexnode => MdmRenderResponse {
            format: MdmFormat::Hexnode,
            filename: "guardrails-hexnode-policy.json".into(),
            content_type: "application/json".into(),
            payload: format!(
                "{{\n  \"bundle_id\": \"com.guardrails.adr\",\n  \"origin\": \"{origin}\",\n  \"install_profile\": \"{profile}\",\n  \"update_authority\": \"{authority}\",\n  \"browser_extension\": \"{ext_flag}\",\n  \"enrollment_token\": \"{key_preview}\"\n}}\n"
            ),
            deployment_notes: vec![
                "Deploy via Hexnode Custom Script or App Configuration payload.".into(),
            ],
        },
        MdmFormat::Tanium => MdmRenderResponse {
            format: MdmFormat::Tanium,
            filename: "guardrails-tanium-deploy.sh".into(),
            content_type: "text/x-shellscript".into(),
            payload: format!(
                "#!/usr/bin/env bash\nset -euo pipefail\ngrdr enroll --origin \"{origin}\" --profile \"{profile}\" --update-authority \"{authority}\" --token \"{key_preview}\"\n"
            ),
            deployment_notes: vec![
                "Attach to a Tanium Deploy software package with `grdr --version` applicability check."
                    .into(),
            ],
        },
        MdmFormat::ChromeEnterprise => MdmRenderResponse {
            format: MdmFormat::ChromeEnterprise,
            filename: "guardrails-chrome-forcelist.json".into(),
            content_type: "application/json".into(),
            payload: format!(
                "{{\n  \"ExtensionInstallForcelist\": [\n    \"grdrkjhmpfghijklmno;{origin}/extensions/chrome-update.xml\"\n  ],\n  \"ExtensionSettings\": {{\n    \"grdrkjhmpfghijklmno\": {{\n      \"installation_mode\": \"force_installed\",\n      \"toolbar_pin\": \"force_pinned\"\n    }}\n  }}\n}}\n"
            ),
            deployment_notes: vec![
                "Append entry to existing ExtensionInstallForcelist rather than overwriting existing org extensions.".into(),
            ],
        },
        MdmFormat::FirefoxGpo => MdmRenderResponse {
            format: MdmFormat::FirefoxGpo,
            filename: "guardrails-firefox-policies.json".into(),
            content_type: "application/json".into(),
            payload: format!(
                "{{\n  \"policies\": {{\n    \"ExtensionSettings\": {{\n      \"adr@guardrails.dev\": {{\n        \"installation_mode\": \"force_installed\",\n        \"install_url\": \"{origin}/extensions/guardrails-firefox.xpi\"\n      }}\n    }}\n  }}\n}}\n"
            ),
            deployment_notes: vec![
                "On Windows AD GPO, ensure mozilla.admx is imported prior to applying policy.".into(),
            ],
        },
        MdmFormat::LinuxRepo => MdmRenderResponse {
            format: MdmFormat::LinuxRepo,
            filename: "10-guardrails-enroll.toml".into(),
            content_type: "application/toml".into(),
            payload: format!(
                "origin = \"{origin}\"\ninstall_profile = \"{profile}\"\nupdate_authority = \"{authority}\"\nbrowser_extension = \"{ext_flag}\"\nenrollment_token = \"{key_preview}\"\n"
            ),
            deployment_notes: vec![
                "Place under /etc/grdr/config.d/10-enroll.toml (mode 0640 root:grdr).".into(),
            ],
        },
    };

    Ok(response)
}
