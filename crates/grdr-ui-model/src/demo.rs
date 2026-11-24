use grdr_strings::{Locale, MessageKey, lookup, sanitize_untrusted_text};

use crate::{
    ActivityVm, AgentStatusVm, AppVm, ControlMode, FirstRunVm, HomeVm, InsightTileVm,
    InstallProfile, ModeLevel, PagingStore, PendingApprovalVm, Preferences, PrivacyVm, RulePreset,
    RuleRowVm, RulesVm, Screen, SessionRowVm, SettingsVm, SetupStepVm, ViewState,
};

impl AppVm {
    /// Builds a deterministic populated demo state starting 3 of 6 setup steps ticked.
    #[must_use]
    pub fn demo() -> Self {
        let locale = Locale::EnUs;
        let notice = grdr_messages::AgentNoticeInput {
            brand: lookup(locale, MessageKey::BrandName),
            verb: grdr_messages::AgentVerb::Blocked,
            action_class: "file.write".to_owned(),
            status_code: "GRDR-DEC-DENY".to_owned(),
            rule_id: "essentials.agent-control-files".to_owned(),
            reference: "8F2KQ-M41TZW".to_owned(),
            reason: "Agent settings cannot be modified inside an active agent session.".to_owned(),
            next_step: grdr_messages::NextStepKind::Blocked,
        };
        let card = grdr_messages::build_block_card(
            locale,
            grdr_messages::AgentVerb::Blocked,
            "essentials.agent-control-files",
            "grdr.essentials",
            ".claude/settings.json",
            &notice,
        );

        Self {
            screen: Screen::Home,
            agent_caller: false,
            preferences: Preferences::default(),
            first_run: FirstRunVm {
                selected_profile: InstallProfile::Protected,
                steps: vec![
                    SetupStepVm {
                        id: "scan-agents".to_owned(),
                        label: "Read-only agent scan completed".to_owned(),
                        detail: "Discovered Claude Code and Cursor".to_owned(),
                        done: true,
                    },
                    SetupStepVm {
                        id: "baseline-pack".to_owned(),
                        label: "Essentials policy pack staged".to_owned(),
                        detail: "Control files and bypass switches locked".to_owned(),
                        done: true,
                    },
                    SetupStepVm {
                        id: "local-receipts".to_owned(),
                        label: "Local Ed25519 receipt signing ready".to_owned(),
                        detail: "Keys stored locally".to_owned(),
                        done: true,
                    },
                    SetupStepVm {
                        id: "turn-on-protection".to_owned(),
                        label: "Confirm protection profile".to_owned(),
                        detail: "Protected is pre-selected with one OS confirmation".to_owned(),
                        done: false,
                    },
                    SetupStepVm {
                        id: "canary-session".to_owned(),
                        label: "Prove hook enforcement in next session".to_owned(),
                        detail: "Upgrades agents to sandboxed protection".to_owned(),
                        done: false,
                    },
                    SetupStepVm {
                        id: "stepup-grade".to_owned(),
                        label: "Enable biometric approval".to_owned(),
                        detail: "Windows Hello / Touch ID / polkit".to_owned(),
                        done: false,
                    },
                ],
            },
            home: HomeVm {
                view_state: ViewState::Ready,
                install_profile: InstallProfile::Protected,
                summary_line: "Protected, except Cursor: hook not yet proven.".to_owned(),
                boundary_pct: 50,
                pending_approvals: vec![PendingApprovalVm {
                    id: "apr-demo-01".to_owned(),
                    rule_id: "essentials.cred-store.read".to_owned(),
                    rule_title: "Guard credential stores and private keys".to_owned(),
                    agent_name: "Claude Code".to_owned(),
                    device_name: "dev-workstation".to_owned(),
                    target_quoted: sanitize_untrusted_text("~/.ssh/id_ed25519"),
                    approver_label: lookup(locale, MessageKey::ApproverSelf),
                    required_grade: "G1".to_owned(),
                }],
                agents: vec![
                    AgentStatusVm {
                        id: "claude-code".to_owned(),
                        name: "Claude Code".to_owned(),
                        assurance_level: "AL3".to_owned(),
                        hook_health: "Hooks active (Boundary)".to_owned(),
                        control_mode: ControlMode::Boundary,
                    },
                    AgentStatusVm {
                        id: "cursor".to_owned(),
                        name: "Cursor".to_owned(),
                        assurance_level: "AL1".to_owned(),
                        hook_health: "Set up, hook not yet proven".to_owned(),
                        control_mode: ControlMode::Request,
                    },
                ],
                tiles: vec![
                    InsightTileVm {
                        id: "blind-spots".to_owned(),
                        headline: "Blind spots".to_owned(),
                        metric: "1 agent".to_owned(),
                        comparison: "Cursor hooks missing confirmation".to_owned(),
                        action_label: "Inspect coverage".to_owned(),
                        target_screen: Screen::Settings,
                    },
                    InsightTileVm {
                        id: "prompt-health".to_owned(),
                        headline: "Approval prompts".to_owned(),
                        metric: "2 today".to_owned(),
                        comparison: "Normal approval volume".to_owned(),
                        action_label: "Review rules".to_owned(),
                        target_screen: Screen::Rules,
                    },
                ],
            },
            activity: ActivityVm {
                filter: None,
                selected_session_id: Some("sess-demo-refactor".to_owned()),
                sessions: PagingStore::new(vec![
                    SessionRowVm {
                        id: "sess-demo-refactor".to_owned(),
                        agent_name: "Claude Code".to_owned(),
                        device_name: "dev-workstation".to_owned(),
                        verdict_summary: "4 calls, 1 blocked, 0 asked".to_owned(),
                        blocked_count: 1,
                        ask_count: 0,
                        block_card: Some(card),
                    },
                    SessionRowVm {
                        id: "sess-demo-mcp".to_owned(),
                        agent_name: "Cursor".to_owned(),
                        device_name: "dev-workstation".to_owned(),
                        verdict_summary: "2 calls, 0 blocked, 1 waiting".to_owned(),
                        blocked_count: 0,
                        ask_count: 1,
                        block_card: None,
                    },
                ]),
            },
            rules: RulesVm {
                preset: RulePreset::Recommended,
                pending_widening_rule_id: None,
                rules: vec![
                    RuleRowVm {
                        id: "essentials.agent-control-files".to_owned(),
                        pack_id: "grdr.essentials".to_owned(),
                        title: "Protect agent and Guardrails control files".to_owned(),
                        description:
                            "Prevent agent writes to hooks, MCP configs, and local policy."
                                .to_owned(),
                        target_pattern: ".claude/, .cursor/, .claude.json".to_owned(),
                        mode: ModeLevel::Block,
                        locked: true,
                        effective_note: "Boundary on protected endpoints".to_owned(),
                    },
                    RuleRowVm {
                        id: "essentials.cred-store.read".to_owned(),
                        pack_id: "grdr.essentials".to_owned(),
                        title: "Guard credential stores and private keys".to_owned(),
                        description:
                            "Require approval before reading ~/.ssh, ~/.aws, or token caches."
                                .to_owned(),
                        target_pattern: "~/.ssh/, ~/.aws/, ~/.gnupg/".to_owned(),
                        mode: ModeLevel::Ask,
                        locked: false,
                        effective_note: "Prompts for approval before opening".to_owned(),
                    },
                    RuleRowVm {
                        id: "essentials.secret-exfil-egress".to_owned(),
                        pack_id: "grdr.essentials".to_owned(),
                        title: "Observe outbound paste and webhook transfers".to_owned(),
                        description: "Record curl and webhook invocations before promoting to Ask."
                            .to_owned(),
                        target_pattern: "curl, Invoke-WebRequest, pastebin".to_owned(),
                        mode: ModeLevel::Watch,
                        locked: false,
                        effective_note: "Watch mode logs local telemetry".to_owned(),
                    },
                ],
            },
            privacy: PrivacyVm {
                disclosure_header: lookup(locale, MessageKey::PrivacyNoticeHeader),
                capture_scope:
                    "Tool arguments stay on this device, and targets are normalized locally."
                        .to_owned(),
                local_retention_days: 30,
                telemetry_destination: "Standalone (zero external telemetry)".to_owned(),
                managed_org: None,
            },
            settings: SettingsVm {
                install_profile: InstallProfile::Protected,
                organization_name: None,
                diagnostic_code: None,
            },
        }
    }
}
