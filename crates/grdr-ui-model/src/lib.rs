use grdr_messages::BlockCard;
use grdr_strings::{Locale, MessageKey, lookup, sanitize_untrusted_text};
use serde::{Deserialize, Serialize};

pub const PAGING_MOUNT_CAP: usize = 500;
pub const PAGING_SLICE_SIZE: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Screen {
    FirstRun,
    Home,
    MyActivity,
    Rules,
    Privacy,
    Settings,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewState {
    #[default]
    Ready,
    Loading,
    Empty,
    Unreachable,
    Degraded,
    ReadOnlyAgent,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderTier {
    #[default]
    Full,
    Lite,
    Web,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallProfile {
    #[default]
    Protected,
    User,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    #[default]
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeLevel {
    Off = 0,
    #[default]
    Watch = 1,
    Ask = 2,
    Block = 3,
}

impl ModeLevel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Watch => "Watch",
            Self::Ask => "Ask",
            Self::Block => "Block",
        }
    }

    #[must_use]
    pub fn is_widening(self, target: Self) -> bool {
        (target as u8) < (self as u8)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePreset {
    #[default]
    Recommended,
    Stricter,
    WatchOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preferences {
    pub theme: ThemeChoice,
    pub render_tier: RenderTier,
    pub locale: Locale,
    pub time_zone: String,
    pub show_technical_detail: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::Light,
            render_tier: RenderTier::Full,
            locale: Locale::EnUs,
            time_zone: "UTC".to_owned(),
            show_technical_detail: false,
        }
    }
}

/// Paged store capped at 500 mounted rows with 200-row slice reads (`design/28` section 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagingStore<T> {
    items: Vec<T>,
    cursor: usize,
}

impl<T: Clone> PagingStore<T> {
    #[must_use]
    pub fn new(mut items: Vec<T>) -> Self {
        if items.len() > PAGING_MOUNT_CAP {
            items.truncate(PAGING_MOUNT_CAP);
        }
        Self { items, cursor: 0 }
    }

    #[must_use]
    pub fn total(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn current_page(&self) -> Vec<T> {
        let end = self
            .cursor
            .saturating_add(PAGING_SLICE_SIZE)
            .min(self.items.len());
        self.items
            .get(self.cursor..end)
            .map_or_else(Vec::new, |slice| slice.to_vec())
    }

    pub fn next_page(&mut self) {
        let next = self.cursor.saturating_add(PAGING_SLICE_SIZE);
        if next < self.items.len() {
            self.cursor = next;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupStepVm {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub done: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstRunVm {
    pub steps: Vec<SetupStepVm>,
    pub selected_profile: InstallProfile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApprovalVm {
    pub id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub agent_name: String,
    pub device_name: String,
    pub target_quoted: String,
    pub approver_label: String,
    pub required_grade: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusVm {
    pub id: String,
    pub name: String,
    pub assurance_level: String,
    pub hook_health: String,
    pub control_mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsightTileVm {
    pub id: String,
    pub headline: String,
    pub metric: String,
    pub comparison: String,
    pub action_label: String,
    pub target_screen: Screen,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeVm {
    pub view_state: ViewState,
    pub install_profile: InstallProfile,
    pub summary_line: String,
    pub boundary_pct: u8,
    pub pending_approvals: Vec<PendingApprovalVm>,
    pub agents: Vec<AgentStatusVm>,
    pub tiles: Vec<InsightTileVm>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRowVm {
    pub id: String,
    pub agent_name: String,
    pub device_name: String,
    pub verdict_summary: String,
    pub blocked_count: u32,
    pub ask_count: u32,
    pub block_card: Option<BlockCard>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityVm {
    pub filter: Option<String>,
    pub sessions: PagingStore<SessionRowVm>,
    pub selected_session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRowVm {
    pub id: String,
    pub pack_id: String,
    pub title: String,
    pub description: String,
    pub target_pattern: String,
    pub mode: ModeLevel,
    pub locked: bool,
    pub effective_note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesVm {
    pub preset: RulePreset,
    pub rules: Vec<RuleRowVm>,
    pub pending_widening_rule_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyVm {
    pub disclosure_header: String,
    pub capture_scope: String,
    pub local_retention_days: u16,
    pub telemetry_destination: String,
    pub managed_org: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsVm {
    pub install_profile: InstallProfile,
    pub organization_name: Option<String>,
    pub diagnostic_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayVm {
    pub status_label: String,
    pub pending_count: usize,
    pub install_profile: InstallProfile,
    pub render_tier: RenderTier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationVm {
    pub title: String,
    pub reference: String,
    pub deep_link: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppVm {
    pub screen: Screen,
    pub agent_caller: bool,
    pub preferences: Preferences,
    pub first_run: FirstRunVm,
    pub home: HomeVm,
    pub activity: ActivityVm,
    pub rules: RulesVm,
    pub privacy: PrivacyVm,
    pub settings: SettingsVm,
}

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
                        control_mode: "Boundary".to_owned(),
                    },
                    AgentStatusVm {
                        id: "cursor".to_owned(),
                        name: "Cursor".to_owned(),
                        assurance_level: "AL1".to_owned(),
                        hook_health: "Set up, hook not yet proven".to_owned(),
                        control_mode: "Request".to_owned(),
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

    #[must_use]
    pub fn tray_vm(&self) -> TrayVm {
        let key = match self.home.install_profile {
            InstallProfile::Protected => MessageKey::ProfileProtectedStatus,
            InstallProfile::User => MessageKey::ProfileUserRequestsOnly,
        };
        TrayVm {
            status_label: lookup(self.preferences.locale, key),
            pending_count: self.home.pending_approvals.len(),
            install_profile: self.home.install_profile,
            render_tier: self.preferences.render_tier,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "snake_case")]
pub enum Intent {
    Navigate(Screen),
    ToggleTheme,
    SelectInstallProfile(InstallProfile),
    ConfirmProtection,
    SelectSession(String),
    FilterActivity(Option<String>),
    SelectRulePreset(RulePreset),
    SetRuleMode {
        rule_id: String,
        next_mode: ModeLevel,
    },
    OpenApproval {
        request_id: String,
    },
    OpenWebConsole {
        route: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum Effect {
    ApplyLocalRuleMode {
        rule_id: String,
        mode: ModeLevel,
    },
    ProposeWidening {
        rule_id: String,
        target_mode: ModeLevel,
    },
    LaunchApprove {
        request_id: String,
    },
    OpenWebConsole {
        route: String,
    },
    NotifyReadOnly {
        reason: String,
    },
}

/// Pure view-model state transition enforcing narrowing-immediate, widening-proposal, and
/// agent-caller refusal (`design/28` requirements R4 and R5).
pub fn reduce(app: &mut AppVm, intent: Intent) -> Vec<Effect> {
    match intent {
        Intent::Navigate(screen) => {
            app.screen = screen;
            Vec::new()
        }
        Intent::ToggleTheme => {
            app.preferences.theme = match app.preferences.theme {
                ThemeChoice::Light => ThemeChoice::Dark,
                ThemeChoice::Dark => ThemeChoice::Light,
            };
            Vec::new()
        }
        Intent::SelectSession(session_id) => {
            app.activity.selected_session_id = Some(session_id);
            Vec::new()
        }
        Intent::FilterActivity(filter) => {
            app.activity.filter = filter;
            Vec::new()
        }
        Intent::OpenWebConsole { route } => vec![Effect::OpenWebConsole { route }],
        Intent::SelectInstallProfile(profile) => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot modify install profile.".to_owned(),
                }];
            }
            app.first_run.selected_profile = profile;
            app.home.install_profile = profile;
            app.settings.install_profile = profile;
            Vec::new()
        }
        Intent::ConfirmProtection => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot confirm protection settings.".to_owned(),
                }];
            }
            let profile = app.first_run.selected_profile;
            app.home.install_profile = profile;
            app.settings.install_profile = profile;
            if let Some(step) = app
                .first_run
                .steps
                .iter_mut()
                .find(|s| s.id == "turn-on-protection")
            {
                step.done = true;
            }
            Vec::new()
        }
        Intent::OpenApproval { request_id } => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot approve requests.".to_owned(),
                }];
            }
            vec![Effect::LaunchApprove { request_id }]
        }
        Intent::SelectRulePreset(preset) => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot alter policy presets.".to_owned(),
                }];
            }
            if matches!(preset, RulePreset::WatchOnly) {
                return vec![Effect::ProposeWidening {
                    rule_id: "preset.watch_only".to_owned(),
                    target_mode: ModeLevel::Watch,
                }];
            }
            app.rules.preset = preset;
            Vec::new()
        }
        Intent::SetRuleMode { rule_id, next_mode } => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot modify rule enforcement modes.".to_owned(),
                }];
            }
            let Some(rule) = app.rules.rules.iter_mut().find(|r| r.id == rule_id) else {
                return Vec::new();
            };
            if rule.locked && rule.mode.is_widening(next_mode) {
                app.rules.pending_widening_rule_id = Some(rule_id.clone());
                return vec![Effect::ProposeWidening {
                    rule_id,
                    target_mode: next_mode,
                }];
            }
            if rule.mode.is_widening(next_mode) {
                app.rules.pending_widening_rule_id = Some(rule_id.clone());
                vec![Effect::ProposeWidening {
                    rule_id,
                    target_mode: next_mode,
                }]
            } else {
                rule.mode = next_mode;
                app.rules.pending_widening_rule_id = None;
                vec![Effect::ApplyLocalRuleMode {
                    rule_id,
                    mode: next_mode,
                }]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_opens_with_three_of_six_steps_ticked() {
        let vm = AppVm::demo();
        assert_eq!(vm.first_run.steps.len(), 6);
        assert_eq!(vm.first_run.steps.iter().filter(|s| s.done).count(), 3);
    }

    #[test]
    fn narrowing_applies_immediately_while_widening_emits_proposal() {
        let mut vm = AppVm::demo();
        let narrow = reduce(
            &mut vm,
            Intent::SetRuleMode {
                rule_id: "essentials.secret-exfil-egress".to_owned(),
                next_mode: ModeLevel::Ask,
            },
        );
        assert_eq!(
            narrow,
            vec![Effect::ApplyLocalRuleMode {
                rule_id: "essentials.secret-exfil-egress".to_owned(),
                mode: ModeLevel::Ask,
            }]
        );

        let widen = reduce(
            &mut vm,
            Intent::SetRuleMode {
                rule_id: "essentials.cred-store.read".to_owned(),
                next_mode: ModeLevel::Watch,
            },
        );
        assert_eq!(
            widen,
            vec![Effect::ProposeWidening {
                rule_id: "essentials.cred-store.read".to_owned(),
                target_mode: ModeLevel::Watch,
            }]
        );
    }

    #[test]
    fn agent_caller_refuses_all_mutations() {
        let mut vm = AppVm::demo();
        vm.agent_caller = true;
        let out = reduce(
            &mut vm,
            Intent::OpenApproval {
                request_id: "apr-1".to_owned(),
            },
        );
        assert!(matches!(out.as_slice(), [Effect::NotifyReadOnly { .. }]));
    }
}
