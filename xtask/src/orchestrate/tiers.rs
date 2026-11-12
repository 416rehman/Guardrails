//! `.agents/risk-tiers.toml` and `security/trust-core.paths` (team/01 section 5), read from the
//! base commit so a change cannot lower its own tier, and from the working tree only while the
//! base has no copy (before the seed commit). The highest matching tier wins; a path no tier names
//! is medium. Every key is required: the code holds no evaluator set, lane limit or path of its
//! own (owner instruction 26), so a missing one fails the load. [`RiskPolicy::lane_evaluators`]
//! is the one answer to which evaluators a review needs, for `cargo xtask risk` and the
//! dispatcher alike.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::issue::{raise, tier_rank};
use super::overlap::overlaps;
use super::risk::Lane;
use crate::config::session::RiskTier;
use crate::git::{self, Base, read_at};
use crate::globs::{Case, GlobList};
use crate::repo::Repo;

pub const TIERS_FILE: &str = ".agents/risk-tiers.toml";
/// The plan's name for the review by the model that did not write the change.
pub const CROSS_MODEL: &str = "cross-model review";
/// The trigger `cargo xtask risk` reports for a trust-core path under `[trust_core]
/// runtime_paths`, whose `[trigger_evaluators]` row names the evaluators that need the lab.
pub const RUNTIME_TRUST_CORE: &str = "runtime_trust_core";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TiersFile {
    trust_core: TrustCoreSource,
    high: TierRule,
    medium: TierRule,
    low: TierRule,
    kinds: BTreeMap<String, Vec<String>>,
    trigger_evaluators: BTreeMap<String, Vec<String>>,
    lanes: LaneLimits,
    protected_change: ProtectedChange,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustCoreSource {
    paths_file: String,
    evaluators: Vec<String>,
    distinct_models: usize,
    /// The product's code roots: a trust-core path under one is the runtime trust core. A base
    /// whose file predates the key has no runtime class, and every trust-core evaluator applies.
    #[serde(default)]
    runtime_paths: Vec<String>,
}

/// Owner instruction 7: what a protected-change item needs before it lands.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedChange {
    pub evaluators: Vec<String>,
    pub distinct_models: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRule {
    pub paths: Vec<String>,
    pub triggers: Vec<String>,
    pub evaluators: Vec<String>,
}

/// Owner instruction 8: the lanes' limits and what each lane's review needs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneLimits {
    pub light_max_lines: usize,
    pub light_max_files: usize,
    /// Lockfile names whose change is static when no package gains a new name or major.
    pub lockfiles: Vec<String>,
    /// Paths `kit check` re-derives; a change to them outside the protected paths is static.
    pub generated: Vec<String>,
    pub light: LightLane,
    pub full: FullLane,
}

/// The `light` lane's one review pass.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightLane {
    pub evaluators: Vec<String>,
    pub model: String,
    pub effort: String,
}

/// The evaluators the `full` lane adds to the high tier's set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullLane {
    pub evaluators: Vec<String>,
}

/// What a review is asked about the change.
#[derive(Debug, Clone, Copy)]
pub struct Change<'a> {
    pub tier: RiskTier,
    pub trust_core: bool,
    pub protected: bool,
    /// The issue's `kind:` value.
    pub kind: Option<&'a str>,
    /// The triggers `cargo xtask risk` found in the diff, by name.
    pub triggers: &'a [String],
}

/// One evaluator a review needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneEvaluator {
    pub agent: String,
    /// The model name the lane asks of it; otherwise its roster binding, or for `eval-diff` the
    /// model that did not write the change.
    pub model: Option<String>,
    pub effort: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RiskPolicy {
    tiers: Vec<(RiskTier, GlobList)>,
    rules: BTreeMap<u8, TierRule>,
    trust_core_patterns: Vec<String>,
    trust_core: GlobList,
    trust_core_evaluators: Vec<String>,
    runtime_patterns: Vec<String>,
    runtime: GlobList,
    kinds: BTreeMap<String, Vec<String>>,
    trigger_evaluators: BTreeMap<String, Vec<String>>,
    /// Passing evaluators on this many models for a trust-core change.
    pub trust_core_models: usize,
    pub lanes: LaneLimits,
    pub protected_change: ProtectedChange,
    /// Where the policy was read from, for the evidence record.
    pub source: String,
}

impl RiskPolicy {
    /// The policy at the base commit, or in the working tree while the base has none.
    pub fn load(repo: &Repo) -> Result<RiskPolicy> {
        let base = git::resolve_base(repo)?;
        RiskPolicy::load_at(repo, &base)
    }

    pub fn load_at(repo: &Repo, base: &Base) -> Result<RiskPolicy> {
        let (text, source) = read_at(repo, base, TIERS_FILE)?;
        let text = text.with_context(|| {
            format!("{TIERS_FILE} is missing at the base and in the working tree")
        })?;
        let file: TiersFile = crate::config::parse_toml(&text, TIERS_FILE)?;
        let trust_file = file.trust_core.paths_file.clone();
        let (trust_text, _) = read_at(repo, base, &trust_file)?;
        let trust_core_patterns = trust_text
            .as_deref()
            .map(path_lines)
            .with_context(|| format!("{trust_file}, which {TIERS_FILE} names, is missing"))?;
        RiskPolicy::build(file, trust_core_patterns, source)
    }

    fn build(
        file: TiersFile,
        trust_core_patterns: Vec<String>,
        source: String,
    ) -> Result<RiskPolicy> {
        if file.trust_core.distinct_models == 0 || file.protected_change.distinct_models == 0 {
            bail!("{TIERS_FILE}: every distinct_models is at least 1");
        }
        let glob = |paths: &[String]| GlobList::new(paths, Case::Insensitive);
        let tiers = vec![
            (RiskTier::High, glob(&file.high.paths)?),
            (RiskTier::Medium, glob(&file.medium.paths)?),
            (RiskTier::Low, glob(&file.low.paths)?),
        ];
        let rules = BTreeMap::from([
            (tier_rank(RiskTier::High), file.high),
            (tier_rank(RiskTier::Medium), file.medium),
            (tier_rank(RiskTier::Low), file.low),
        ]);
        Ok(RiskPolicy {
            tiers,
            rules,
            trust_core: glob(&trust_core_patterns)?,
            trust_core_patterns,
            trust_core_evaluators: file.trust_core.evaluators,
            runtime: glob(&file.trust_core.runtime_paths)?,
            runtime_patterns: file.trust_core.runtime_paths,
            kinds: file.kinds,
            trigger_evaluators: file.trigger_evaluators,
            trust_core_models: file.trust_core.distinct_models,
            lanes: file.lanes,
            protected_change: file.protected_change,
            source,
        })
    }

    /// The tier of one path: the highest tier whose paths match, or medium.
    pub fn tier_of(&self, path: &str) -> RiskTier {
        let matched = self
            .tiers
            .iter()
            .filter(|(_, globs)| globs.is_match(path))
            .map(|(tier, _)| *tier)
            .reduce(raise);
        match matched {
            Some(RiskTier::Low) if !self.only_low(path) => RiskTier::Medium,
            Some(tier) => tier,
            None => RiskTier::Medium,
        }
    }

    pub fn is_trust_core(&self, path: &str) -> bool {
        self.trust_core.is_match(path)
    }

    /// Whether any path a write set allows is on the trust-core list.
    pub fn touches_trust_core(&self, write_set: &[String]) -> Result<bool> {
        overlaps(write_set, &self.trust_core_patterns)
    }

    /// A trust-core path that ships in the product: under `[trust_core] runtime_paths`.
    pub fn is_runtime_trust_core(&self, path: &str) -> bool {
        self.is_trust_core(path) && self.runtime.is_match(path)
    }

    /// Whether a write set can reach both the trust-core list and a runtime root, for a review
    /// that has no diff to classify.
    pub fn may_touch_runtime_trust_core(&self, write_set: &[String]) -> Result<bool> {
        Ok(self.touches_trust_core(write_set)? && overlaps(write_set, &self.runtime_patterns)?)
    }

    /// The tier a write set implies: the highest tier any of its globs can reach.
    pub fn tier_of_write_set(&self, write_set: &[String]) -> Result<Option<RiskTier>> {
        let mut found: Option<RiskTier> = None;
        for (tier, rule) in [RiskTier::High, RiskTier::Medium, RiskTier::Low]
            .iter()
            .filter_map(|tier| self.rules.get(&tier_rank(*tier)).map(|rule| (*tier, rule)))
        {
            if overlaps(write_set, &rule.paths)? {
                found = Some(found.map_or(tier, |current| raise(current, tier)));
            }
        }
        Ok(match found {
            None if !write_set.is_empty() => Some(RiskTier::Medium),
            other => other,
        })
    }

    pub fn triggers(&self, tier: RiskTier) -> &[String] {
        self.rules
            .get(&tier_rank(tier))
            .map(|rule| rule.triggers.as_slice())
            .unwrap_or_default()
    }

    /// The evaluators a tier requires, with the trust-core additions when it applies.
    pub fn evaluators(&self, tier: RiskTier, trust_core: bool) -> Vec<String> {
        let mut list = self
            .rules
            .get(&tier_rank(tier))
            .map(|rule| rule.evaluators.clone())
            .unwrap_or_default();
        if trust_core {
            list.extend(self.trust_core_evaluators.iter().cloned());
        }
        list
    }

    /// The lane a review takes: a protected-change item never one with fewer evaluators than
    /// standard (owner instruction 7), and a trust-core change the full lane unless the
    /// classifier proved it static, which on a trust-core path only a lockfile inside the
    /// supply-chain policy can be (D-63).
    pub fn review_lane(&self, lane: Lane, trust_core: bool, protected: bool) -> Lane {
        let lane = if protected {
            lane.max(Lane::Standard)
        } else {
            lane
        };
        if trust_core && lane != Lane::Static {
            Lane::Full
        } else {
            lane
        }
    }

    /// The evaluators the review of `change` in `lane` needs, each once (owner instructions 7 and
    /// 8, team/02 section 10): none in the static lane; the light lane's one pass; in standard the
    /// tier's set and in full the high tier's set plus the full lane's, each with the evaluators
    /// of the change's kind and of the diff's triggers; and a protected-change item's evaluators.
    /// A light lane that names no evaluator reviews as standard.
    pub fn lane_evaluators(&self, lane: Lane, change: &Change) -> Vec<LaneEvaluator> {
        let named = |agent: &String| LaneEvaluator {
            agent: agent.clone(),
            model: None,
            effort: None,
        };
        let light = &self.lanes.light;
        let mut list: Vec<LaneEvaluator> = match lane {
            Lane::Static => Vec::new(),
            Lane::Light if !light.evaluators.is_empty() => light
                .evaluators
                .iter()
                .map(|agent| LaneEvaluator {
                    agent: agent.clone(),
                    model: Some(light.model.clone()),
                    effort: Some(light.effort.clone()),
                })
                .collect(),
            Lane::Light | Lane::Standard => {
                let mut list = self.evaluators(change.tier, change.trust_core);
                list.extend(self.by_kind_and_trigger(change));
                list.iter().map(named).collect()
            }
            Lane::Full => {
                let mut list = self.evaluators(RiskTier::High, change.trust_core);
                list.extend(self.lanes.full.evaluators.iter().cloned());
                list.extend(self.by_kind_and_trigger(change));
                list.iter().map(named).collect()
            }
        };
        if change.protected {
            list.extend(self.protected_change.evaluators.iter().map(named));
        }
        let mut seen = BTreeSet::new();
        list.retain(|evaluator| seen.insert(evaluator.agent.clone()));
        list
    }

    fn by_kind_and_trigger(&self, change: &Change) -> Vec<String> {
        let kind = change.kind.and_then(|kind| self.kinds.get(kind));
        let triggered = change
            .triggers
            .iter()
            .filter_map(|trigger| self.trigger_evaluators.get(trigger));
        kind.into_iter()
            .chain(triggered)
            .flatten()
            .cloned()
            .collect()
    }

    /// How many models a change's passing evaluators must come from.
    pub fn required_models(&self, trust_core: bool, protected: bool) -> usize {
        let trust = if trust_core {
            self.trust_core_models
        } else {
            1
        };
        let gate = if protected {
            self.protected_change.distinct_models
        } else {
            1
        };
        trust.max(gate)
    }

    /// Every evaluator the policy names, for `kit check` against the roster.
    pub fn evaluator_names(&self) -> BTreeSet<&str> {
        self.rules
            .values()
            .flat_map(|rule| &rule.evaluators)
            .chain(&self.trust_core_evaluators)
            .chain(self.kinds.values().flatten())
            .chain(self.trigger_evaluators.values().flatten())
            .chain(&self.lanes.light.evaluators)
            .chain(&self.lanes.full.evaluators)
            .chain(&self.protected_change.evaluators)
            .map(String::as_str)
            .filter(|name| *name != CROSS_MODEL)
            .collect()
    }

    /// Low tier holds only for paths no higher tier names (team/01 section 5: low is limited to
    /// docs and additive changes behind a flag).
    fn only_low(&self, path: &str) -> bool {
        self.tiers
            .iter()
            .filter(|(tier, _)| *tier != RiskTier::Low)
            .all(|(_, globs)| !globs.is_match(path))
    }
}

/// Globs, one per line, with `#` comments and blank lines dropped.
pub fn path_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"[trust_core]
paths_file = "security/trust-core.paths"
evaluators = ["eval-adversarial"]
distinct_models = 2
[high]
paths = ["proto/**", "**/AGENTS.md", "Cargo.lock"]
triggers = ["unsafe_added", "new_dependency"]
evaluators = ["eval-tier", "eval-diff", "eval-security"]
[medium]
paths = ["crates/**", "web/**"]
triggers = []
evaluators = ["eval-tier", "eval-diff"]
[low]
paths = ["docs/**", "**/*.md"]
triggers = []
evaluators = ["eval-tier", "eval-diff"]
[kinds]
ui = ["eval-ux", "eval-a11y"]
[trigger_evaluators]
new_dependency = ["eval-licence"]
[protected_change]
evaluators = ["eval-security"]
distinct_models = 2
[lanes]
light_max_lines = 50
light_max_files = 3
lockfiles = ["Cargo.lock"]
generated = []
[lanes.light]
evaluators = ["eval-diff"]
model = "sonnet"
effort = "low"
[lanes.full]
evaluators = ["eval-adversarial"]
"#;

    fn build(text: &str) -> Result<RiskPolicy> {
        let file: TiersFile = crate::config::parse_toml(text, "risk-tiers.toml")?;
        let trust = path_lines("# comment\ncrates/grdr-crypto/**\n\nxtask/**\n");
        RiskPolicy::build(file, trust, "test".into())
    }

    pub fn policy() -> RiskPolicy {
        build(FILE).unwrap()
    }

    fn names(list: &[LaneEvaluator]) -> Vec<&str> {
        list.iter()
            .map(|evaluator| evaluator.agent.as_str())
            .collect()
    }

    #[test]
    fn highest_tier_wins_and_unnamed_paths_are_medium() {
        let policy = policy();
        assert_eq!(policy.tier_of("proto/grdr/v1/a.proto"), RiskTier::High);
        assert_eq!(policy.tier_of("crates/grdr-core/AGENTS.md"), RiskTier::High);
        assert_eq!(
            policy.tier_of("crates/grdr-core/src/lib.rs"),
            RiskTier::Medium
        );
        assert_eq!(policy.tier_of("docs/guide.md"), RiskTier::Low);
        assert_eq!(
            policy.tier_of("crates/grdr-core/README.md"),
            RiskTier::Medium
        );
        assert_eq!(policy.tier_of("tools/x.sh"), RiskTier::Medium);
        assert!(policy.is_trust_core("crates/grdr-crypto/src/lib.rs"));
        assert!(!policy.is_trust_core("crates/grdr-core/src/lib.rs"));
    }

    #[test]
    fn write_sets_take_the_highest_reachable_tier() {
        let policy = policy();
        let set = |globs: &[&str]| globs.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        assert_eq!(
            policy.tier_of_write_set(&set(&["docs/guide/**"])).unwrap(),
            Some(RiskTier::Low)
        );
        assert_eq!(
            policy
                .tier_of_write_set(&set(&["crates/grdr-core/src/**"]))
                .unwrap(),
            Some(RiskTier::Medium)
        );
        assert_eq!(
            policy.tier_of_write_set(&set(&["proto/**"])).unwrap(),
            Some(RiskTier::High)
        );
        assert_eq!(policy.tier_of_write_set(&[]).unwrap(), None);
        assert!(policy.touches_trust_core(&set(&["crates/**"])).unwrap());
        assert!(!policy.touches_trust_core(&set(&["web/**"])).unwrap());
    }

    #[test]
    fn evaluators_follow_tier_and_trust_core() {
        let policy = policy();
        assert_eq!(
            policy.evaluators(RiskTier::Low, false),
            vec!["eval-tier", "eval-diff"]
        );
        let trust = policy.evaluators(RiskTier::High, true);
        assert!(trust.contains(&"eval-adversarial".to_owned()));
        assert_eq!(
            policy.triggers(RiskTier::High),
            ["unsafe_added".to_owned(), "new_dependency".to_owned()]
        );
    }

    #[test]
    fn runtime_trust_core_is_a_trust_core_path_under_a_runtime_root() {
        let policy = build(&FILE.replace(
            "distinct_models = 2
[high]",
            "distinct_models = 2
runtime_paths = [\"crates/**\"]
[high]",
        ))
        .unwrap();
        let set = |globs: &[&str]| globs.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        assert!(policy.is_runtime_trust_core("crates/grdr-crypto/src/lib.rs"));
        assert!(!policy.is_runtime_trust_core("xtask/src/main.rs"));
        assert!(!policy.is_runtime_trust_core("crates/grdr-core/src/lib.rs"));
        assert!(
            policy
                .may_touch_runtime_trust_core(&set(&["crates/**"]))
                .unwrap()
        );
        assert!(
            !policy
                .may_touch_runtime_trust_core(&set(&["xtask/**"]))
                .unwrap()
        );
        let without = build(FILE).unwrap();
        assert!(!without.is_runtime_trust_core("crates/grdr-crypto/src/lib.rs"));
    }

    #[test]
    fn every_key_is_required_and_distinct_models_is_at_least_one() {
        assert!(build(FILE).is_ok());
        let missing = FILE.replace("distinct_models = 2\n[high]", "[high]");
        assert!(build(&missing).is_err());
        let none = FILE.replace(
            "evaluators = [\"eval-security\"]\ndistinct_models = 2",
            "evaluators = [\"eval-security\"]\ndistinct_models = 0",
        );
        assert!(build(&none).is_err());
        assert!(build(&FILE.replace("[kinds]\nui = [\"eval-ux\", \"eval-a11y\"]\n", "")).is_err());
    }

    #[test]
    fn each_lane_names_its_evaluators_once() {
        let policy = policy();
        let plain = Change {
            tier: RiskTier::Medium,
            trust_core: false,
            protected: false,
            kind: None,
            triggers: &[],
        };
        assert!(policy.lane_evaluators(Lane::Static, &plain).is_empty());
        let light = policy.lane_evaluators(Lane::Light, &plain);
        assert_eq!(
            light,
            [LaneEvaluator {
                agent: "eval-diff".into(),
                model: Some("sonnet".into()),
                effort: Some("low".into()),
            }]
        );
        let ui = Change {
            kind: Some("ui"),
            ..plain
        };
        assert_eq!(
            names(&policy.lane_evaluators(Lane::Standard, &ui)),
            ["eval-tier", "eval-diff", "eval-ux", "eval-a11y"]
        );
        let triggers = ["new_dependency".to_owned()];
        let dependency = Change {
            tier: RiskTier::High,
            triggers: &triggers,
            ..plain
        };
        assert_eq!(
            names(&policy.lane_evaluators(Lane::Full, &dependency)),
            [
                "eval-tier",
                "eval-diff",
                "eval-security",
                "eval-adversarial",
                "eval-licence"
            ]
        );
        let protected = Change {
            protected: true,
            ..plain
        };
        let lane = policy.review_lane(Lane::Static, false, true);
        assert_eq!(lane, Lane::Standard);
        assert_eq!(
            names(&policy.lane_evaluators(lane, &protected)),
            ["eval-tier", "eval-diff", "eval-security"]
        );
        assert_eq!(policy.review_lane(Lane::Light, true, false), Lane::Full);
        assert_eq!(policy.review_lane(Lane::Static, true, false), Lane::Static);
        assert_eq!(policy.review_lane(Lane::Static, true, true), Lane::Full);
        assert_eq!(policy.review_lane(Lane::Light, false, false), Lane::Light);
        assert_eq!(policy.required_models(false, false), 1);
        assert_eq!(policy.required_models(true, false), 2);
        assert_eq!(policy.required_models(false, true), 2);
    }

    fn repository_policy() -> RiskPolicy {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.agents/risk-tiers.toml"),
        )
        .unwrap();
        let file: TiersFile = crate::config::parse_toml(&text, TIERS_FILE).unwrap();
        RiskPolicy::build(file, Vec::new(), "repo".into()).unwrap()
    }

    #[test]
    fn the_repository_tiers_file_names_every_lane() {
        let policy = repository_policy();
        assert_eq!(policy.lanes.light_max_lines, 50);
        assert_eq!(policy.lanes.light_max_files, 3);
        assert_eq!(policy.lanes.light.evaluators, ["eval-diff"]);
        assert_eq!(policy.lanes.light.effort, "low");
        assert_eq!(policy.lanes.light.model, "sonnet");
        assert_eq!(
            policy.lanes.full.evaluators,
            ["eval-security", "eval-adversarial"]
        );
        assert_eq!(policy.protected_change.evaluators, ["eval-security"]);
        assert_eq!(policy.protected_change.distinct_models, 2);
        assert_eq!(policy.trust_core_models, 2);
        assert!(policy.lanes.lockfiles.contains(&"Cargo.lock".to_owned()));
        assert!(policy.evaluator_names().contains("eval-ux"));
    }

    #[test]
    fn the_first_crates_take_no_evaluator_whose_lab_command_is_not_built() {
        let policy = repository_policy();
        let triggers = [RUNTIME_TRUST_CORE.to_owned()];
        let change = Change {
            tier: RiskTier::High,
            trust_core: true,
            protected: true,
            kind: Some("gate"),
            triggers: &triggers,
        };
        let agents: Vec<String> = policy
            .lane_evaluators(Lane::Full, &change)
            .into_iter()
            .map(|evaluator| evaluator.agent)
            .collect();
        assert!(
            agents.iter().any(|agent| agent == "eval-security")
                && agents.iter().any(|agent| agent == "eval-adversarial"),
            "{agents:?}"
        );
        assert!(
            !agents
                .iter()
                .any(|agent| agent == "eval-platform" || agent == "eval-performance"),
            "{agents:?}"
        );
    }
}
