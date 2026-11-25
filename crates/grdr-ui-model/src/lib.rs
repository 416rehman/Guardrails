mod demo;
mod reduce;

pub use reduce::reduce;

use grdr_messages::BlockCard;
use grdr_strings::{Locale, MessageKey, lookup};
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

/// Paged store capped at 500 mounted rows with 200-row slice reads (`design/28` section 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagingStore<T> {
    items: Vec<T>,
    cursor: usize,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    Boundary,
    Request,
    Observe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceSurfaceState {
    Protected,
    RequestsOnly,
    ScanOnly,
    Degraded,
    SafeMode,
    Stale,
    Snoozed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusVm {
    pub id: String,
    pub name: String,
    pub assurance_level: String,
    pub hook_health: String,
    pub control_mode: ControlMode,
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
pub struct ReviewClusterVm {
    pub id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub bucket_label: String,
    pub occurrence_count: u32,
    pub target_preview: String,
    pub receipt_ref: String,
    pub decided: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityVm {
    pub filter: Option<String>,
    pub sessions: PagingStore<SessionRowVm>,
    pub selected_session_id: Option<String>,
    pub inspected_receipt_ref: Option<String>,
    pub review_clusters: Vec<ReviewClusterVm>,
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
    pub privacy_profile_label: String,
    pub legal_hold_count: usize,
    pub quarterly_disclosures: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsVm {
    pub install_profile: InstallProfile,
    pub organization_name: Option<String>,
    pub diagnostic_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayVm {
    pub surface_state: DeviceSurfaceState,
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
    InspectReceipt {
        reference: String,
    },
    DismissWhyCard,
    TriageReviewCluster {
        cluster_id: String,
        action: String,
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
    InspectWhyCard {
        reference: String,
    },
    ApplyReviewDecision {
        cluster_id: String,
        action: String,
    },
    NotifyReadOnly {
        reason: String,
    },
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

impl DeviceSurfaceState {
    #[must_use]
    pub fn label(self, locale: Locale) -> String {
        let key = match self {
            Self::Protected => MessageKey::ProfileProtectedStatus,
            Self::RequestsOnly | Self::Degraded | Self::SafeMode | Self::Stale | Self::Snoozed => {
                MessageKey::ProfileUserRequestsOnly
            }
            Self::ScanOnly => MessageKey::ScanOnlyStatus,
        };
        lookup(locale, key)
    }
}

impl AppVm {
    #[must_use]
    pub fn tray_vm(&self) -> TrayVm {
        let surface_state = match self.home.install_profile {
            InstallProfile::Protected => DeviceSurfaceState::Protected,
            InstallProfile::User => DeviceSurfaceState::RequestsOnly,
        };
        TrayVm {
            surface_state,
            pending_count: self.home.pending_approvals.len(),
            install_profile: self.home.install_profile,
            render_tier: self.preferences.render_tier,
        }
    }
}
