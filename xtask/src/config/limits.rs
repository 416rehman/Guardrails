//! The typed loader of `.agents/kit/limits.toml`, every bound of the kit (owner instructions 15
//! and 26), in the format the file's header documents. Every key is required, so no bound falls
//! back to a number in code.

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::Deserialize;

use super::parse_toml;
use crate::git::{self, Base};
use crate::repo::Repo;

pub const LIMITS_PATH: &str = ".agents/kit/limits.toml";
/// The copy this binary was built with: the kit binary is built from the comparison base, so it
/// is the base's copy when neither the base commit nor the working tree has the file.
const BUILT_WITH: &str = include_str!("../../../.agents/kit/limits.toml");

static BUILT_IN: LazyLock<Result<Limits, String>> =
    LazyLock::new(|| Limits::parse(BUILT_WITH).map_err(|error| format!("{error:#}")));

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub hook: HookLimits,
    pub gates: GateLimits,
    pub orchestrate: OrchestrateLimits,
    pub dispatch: DispatchLimits,
    pub kit: KitLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookLimits {
    pub runner: RunnerLimits,
    pub outcome: OutcomeLimits,
    pub session_start: SessionStartLimits,
    pub post_edit: PostEditLimits,
    pub post_bash: PostBashLimits,
    pub stop_gate: StopGateLimits,
    pub transcript: TranscriptLimits,
    pub pre_compact: PreCompactLimits,
    pub subagent: SubagentLimits,
    pub shell: ShellLimits,
    pub selftest: SelftestLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerLimits {
    pub deadline_margin_s: u64,
    pub input_bytes: u64,
    pub logged_input_chars: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeLimits {
    pub diagnostic_lines: usize,
    pub context_lines: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStartLimits {
    pub rebuild_margin_s: u64,
    pub startup_command_line_s: u64,
    pub write_set_lines: usize,
    pub summary_lines: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostEditLimits {
    pub format_timeout_s: u64,
    pub format_margin_s: u64,
    pub printed_findings: usize,
    pub min_reason_chars: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostBashLimits {
    pub protected_listed: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopGateLimits {
    pub blocks: u32,
    pub printed_findings: usize,
    pub evidence_files: usize,
    pub transcript_bytes: u64,
    pub verify_margin_s: u64,
    pub handoff_problems: usize,
    pub verify_tail_lines: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptLimits {
    pub model_tail_bytes: u64,
    pub widened_tail_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreCompactLimits {
    pub transcript_bytes: u64,
    pub listed: usize,
    pub evidence_files: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentLimits {
    pub transcript_bytes: u64,
    pub path_extension_chars: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellLimits {
    pub nested_shells: usize,
    pub substitutions: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelftestLimits {
    pub case_s: u64,
    pub process_s: u64,
    pub short_timeout_s: i64,
    pub deadline_wait_s: u64,
    pub poll_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateLimits {
    pub structure: StructureLimits,
    pub run: RunLimits,
    pub evidence: EvidenceLimits,
    pub skills: SkillsLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureLimits {
    pub max_code_lines: usize,
    pub max_nesting_depth: usize,
    pub bool_field_threshold: usize,
    pub printed_findings: usize,
    pub excerpt_chars: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    pub summary_chars: usize,
    pub metadata_timeout_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLimits {
    pub printed_errors: usize,
    pub recorded_problems: usize,
    pub line_chars: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillsLimits {
    pub max_lines: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrateLimits {
    pub claude: ClaudeLimits,
    pub launch: LaunchLimits,
    pub prove: ProveLimits,
    pub audit: AuditLimits,
    pub ready: ReadyLimits,
    pub risk: RiskLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeLimits {
    pub poll_ms: u64,
    pub drain_grace_s: u64,
    pub turn_margin: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchLimits {
    pub fable_heartbeat_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveLimits {
    pub run_timeout_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLimits {
    pub scope_files_named: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyLimits {
    pub printed_problems: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskLimits {
    pub printed_reasons: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchLimits {
    pub worker: WorkerLimits,
    pub lease: LeaseLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseLimits {
    pub lease_factor: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLimits {
    pub install_timeout_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KitLimits {
    pub check: KitCheckLimits,
    pub install: InstallLimits,
    pub git: GitLimits,
    pub process: ProcessLimits,
    pub lock: LockLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KitCheckLimits {
    pub printed_problems: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallLimits {
    pub build_timeout_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitLimits {
    pub timeout_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLimits {
    pub poll_ms: u64,
    pub drain_grace_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockLimits {
    pub stale_beats: u32,
}

impl Limits {
    /// The base commit's copy, else the working tree's, else the copy the binary was built with.
    pub fn load(repo: &Repo, base: &Base) -> Result<Limits> {
        let text = match base.commit() {
            Some(commit) => git::show(repo, commit, LIMITS_PATH)?,
            None => repo.read_optional(LIMITS_PATH)?,
        };
        match text {
            Some(text) => Limits::parse(&text),
            None => Limits::built_with().cloned(),
        }
    }

    /// The working tree's copy, else the copy the binary was built with. The hook handlers read
    /// this one: they run on every tool call, and the file is protected, so no session edits it.
    pub fn working_tree(repo: &Repo) -> Result<Limits> {
        Limits::load(repo, &Base::Unborn)
    }

    /// The copy the binary was built with, parsed once.
    pub fn built_with() -> Result<&'static Limits> {
        BUILT_IN.as_ref().map_err(|error| anyhow!("{error}"))
    }

    pub fn parse(text: &str) -> Result<Limits> {
        parse_toml(text, LIMITS_PATH)
    }
}

impl RunnerLimits {
    pub fn deadline_margin(&self) -> Duration {
        Duration::from_secs(self.deadline_margin_s)
    }
}

impl SessionStartLimits {
    pub fn rebuild_margin(&self) -> Duration {
        Duration::from_secs(self.rebuild_margin_s)
    }

    pub fn startup_command_line(&self) -> Duration {
        Duration::from_secs(self.startup_command_line_s)
    }
}

impl StopGateLimits {
    pub fn verify_margin(&self) -> Duration {
        Duration::from_secs(self.verify_margin_s)
    }
}

impl SelftestLimits {
    pub fn case(&self) -> Duration {
        Duration::from_secs(self.case_s)
    }

    pub fn process(&self) -> Duration {
        Duration::from_secs(self.process_s)
    }

    pub fn deadline_wait(&self) -> Duration {
        Duration::from_secs(self.deadline_wait_s)
    }

    pub fn poll(&self) -> Duration {
        Duration::from_millis(self.poll_ms)
    }
}

impl PostEditLimits {
    pub fn format_timeout(&self) -> Duration {
        Duration::from_secs(self.format_timeout_s)
    }

    pub fn format_margin(&self) -> Duration {
        Duration::from_secs(self.format_margin_s)
    }
}

impl RunLimits {
    pub fn metadata_timeout(&self) -> Duration {
        Duration::from_secs(self.metadata_timeout_s)
    }
}

impl ClaudeLimits {
    pub fn poll(&self) -> Duration {
        Duration::from_millis(self.poll_ms)
    }

    pub fn drain_grace(&self) -> Duration {
        Duration::from_secs(self.drain_grace_s)
    }
}

impl LaunchLimits {
    pub fn lock_heartbeat(&self) -> Duration {
        Duration::from_secs(self.fable_heartbeat_s)
    }
}

impl ProveLimits {
    pub fn run_timeout(&self) -> Duration {
        Duration::from_secs(self.run_timeout_s)
    }
}

impl WorkerLimits {
    pub fn install_timeout(&self) -> Duration {
        Duration::from_secs(self.install_timeout_s)
    }
}

impl InstallLimits {
    pub fn build_timeout(&self) -> Duration {
        Duration::from_secs(self.build_timeout_s)
    }
}

impl GitLimits {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_s)
    }
}

impl ProcessLimits {
    pub fn poll(&self) -> Duration {
        Duration::from_millis(self.poll_ms)
    }

    pub fn drain_grace(&self) -> Duration {
        Duration::from_secs(self.drain_grace_s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_file_parses_and_every_key_is_required() {
        let limits = Limits::built_with().unwrap();
        assert!(limits.gates.structure.max_code_lines > 0);
        let missing = BUILT_WITH.replace("max_code_lines", "# max_code_lines");
        assert!(Limits::parse(&missing).is_err());
        let unknown = BUILT_WITH.replace("[kit.check]", "[kit.check]\nstray = 1");
        assert!(Limits::parse(&unknown).is_err());
    }
}
