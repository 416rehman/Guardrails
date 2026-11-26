// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dynamic `session-rules.yaml` restrict-only loader, rolling window counters,
//! and highest-severity escalation evaluator (`D-54`, `D-28`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::OnceLock;

use grdr_model::{ActionAttempt, ActionClass, ApprovalGrade, SessionLabel, Verdict};

use crate::analyze::TargetAnalysis;
use crate::detect::types::DetectError;
use crate::detect::yaml::{YamlValue, parse_yaml};

const EMBEDDED_ESSENTIALS_SESSION_YAML: &str =
    include_str!("../../../../packs/essentials/session-rules.yaml");
const EMBEDDED_EXTENDED_SESSION_YAML: &str =
    include_str!("../../../../packs/detections/session-rules.yaml");
const FALLBACK_FAIL_CLOSED_RULE_ID: &str = "session.fail-closed-parse-error";
const MAX_SESSION_RULE_WINDOW_SECS: u64 = 86_400;
const MAX_SESSION_RULE_THRESHOLD: u32 = 10_000;

static DEFAULT_RULES_CACHE: OnceLock<Result<SessionRuleSet, DetectError>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicLabelKey {
    Core(SessionLabel),
    Named(String),
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRuleSpec {
    pub id: String,
    pub when_label: DynamicLabelKey,
    pub action_classes: Vec<ActionClass>,
    pub min_risk_score: Option<u32>,
    pub count_threshold: Option<u32>,
    pub window_secs: Option<u64>,
    pub verdict: Verdict,
    pub min_grade: ApprovalGrade,
    pub reason: String,
    pub next_step: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicSessionEscalation {
    pub rule_id: String,
    pub verdict: Verdict,
    pub min_grade: ApprovalGrade,
    pub reason: String,
    pub next_step: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRuleSet {
    pub pack_id: String,
    pub rules: Vec<SessionRuleSpec>,
}

impl SessionRuleSet {
    /// Parses both embedded session packs with restrict-only channel non-shadowing and caches the result.
    pub fn try_load_default_dynamic() -> Result<Self, DetectError> {
        DEFAULT_RULES_CACHE
            .get_or_init(|| {
                let ess = Self::from_yaml(EMBEDDED_ESSENTIALS_SESSION_YAML)?;
                let ext = Self::from_yaml(EMBEDDED_EXTENDED_SESSION_YAML)?;
                Self::merge_restrict_only(&ess, &ext)
            })
            .clone()
    }

    /// Returns cached default session rules, failing closed if embedded YAML were ever invalid.
    #[must_use]
    pub fn load_default_dynamic() -> Self {
        match Self::try_load_default_dynamic() {
            Ok(set) => set,
            Err(_) => fail_closed_fallback_ruleset(),
        }
    }

    /// Merges `base` (`essentials`) and `restricted_ext` without letting `restricted_ext` override or drop any `base` rule ID.
    pub fn merge_restrict_only(base: &Self, restricted_ext: &Self) -> Result<Self, DetectError> {
        let mut combined = base.rules.clone();
        let existing_ids: BTreeSet<&str> = base.rules.iter().map(|r| r.id.as_str()).collect();
        for ext_rule in &restricted_ext.rules {
            if existing_ids.contains(ext_rule.id.as_str()) {
                return Err(DetectError::DuplicateRule(format!(
                    "detection pack session rule `{}` cannot override essentials rule",
                    ext_rule.id
                )));
            }
            combined.push(ext_rule.clone());
        }
        Ok(Self {
            pack_id: format!("{}+{}", base.pack_id, restricted_ext.pack_id),
            rules: combined,
        })
    }

    /// Strictly parses a `grdr.session-rules.v1` YAML document, rejecting unknown fields/enums or duplicates.
    pub fn from_yaml(raw_yaml: &str) -> Result<Self, DetectError> {
        let doc = parse_yaml(raw_yaml)?;
        let pack_id = doc
            .get("pack_id")
            .and_then(YamlValue::as_str)
            .ok_or_else(|| DetectError::InvalidRule("session rules missing `pack_id`".into()))?
            .to_owned();
        let raw_rules = doc
            .get("rules")
            .and_then(YamlValue::as_seq)
            .ok_or_else(|| {
                DetectError::InvalidRule("session rules missing `rules` sequence".into())
            })?;

        let mut seen_ids = BTreeSet::new();
        let mut rules = Vec::with_capacity(raw_rules.len());
        for entry in raw_rules {
            let rule = parse_single_rule(entry)?;
            if !seen_ids.insert(rule.id.clone()) {
                return Err(DetectError::DuplicateRule(rule.id));
            }
            rules.push(rule);
        }
        Ok(Self { pack_id, rules })
    }

    #[must_use]
    pub fn evaluate(
        &self,
        labels: &BTreeSet<SessionLabel>,
        extra_labels: &BTreeSet<String>,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
    ) -> Option<DynamicSessionEscalation> {
        let empty = BTreeMap::new();
        self.evaluate_with_history(labels, extra_labels, attempt, analysis, &empty)
    }

    /// Evaluates ALL matching session rules (using rolling `(count_threshold, window_secs)` windows)
    /// and selects the highest-restrictiveness `(Verdict, ApprovalGrade)` escalation.
    #[must_use]
    pub fn evaluate_with_history(
        &self,
        labels: &BTreeSet<SessionLabel>,
        extra_labels: &BTreeSet<String>,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
        action_history: &BTreeMap<String, VecDeque<i64>>,
    ) -> Option<DynamicSessionEscalation> {
        let is_outbound_tagged = analysis.risk_tags.iter().any(|t| t == "external-network");
        let hist_max_sec = action_history
            .values()
            .flatten()
            .copied()
            .max()
            .unwrap_or(i64::MIN);
        let att_sec = attempt.timestamp.as_second();
        let now_sec = if hist_max_sec == i64::MIN {
            att_sec
        } else if att_sec.saturating_sub(hist_max_sec) > 3_600 {
            hist_max_sec
        } else {
            att_sec.max(hist_max_sec)
        };
        let mut best: Option<DynamicSessionEscalation> = None;

        for rule in &self.rules {
            if !label_is_active(&rule.when_label, labels, extra_labels) {
                continue;
            }
            let action_matches = rule.action_classes.contains(&attempt.action_class)
                || (is_outbound_tagged && rule.action_classes.contains(&ActionClass::NetRequest));
            if !action_matches {
                continue;
            }
            if let Some(min_risk) = rule.min_risk_score
                && analysis.risk_score < min_risk
            {
                continue;
            }
            if let Some(threshold) = rule.count_threshold
                && threshold > 1
            {
                let win = i64::try_from(rule.window_secs.unwrap_or(600)).unwrap_or(600);
                let cutoff = now_sec.saturating_sub(win);
                let mut prior_count: usize = 0;
                for ac in &rule.action_classes {
                    if let Some(ts_list) = action_history.get(ac.as_str()) {
                        let c = ts_list
                            .iter()
                            .filter(|&&ts| ts >= cutoff && ts <= now_sec)
                            .count();
                        prior_count = prior_count.saturating_add(c);
                    }
                }
                let total = prior_count.saturating_add(1);
                if total < usize::try_from(threshold).unwrap_or(usize::MAX) {
                    continue;
                }
            }
            let cand = DynamicSessionEscalation {
                rule_id: rule.id.clone(),
                verdict: rule.verdict,
                min_grade: rule.min_grade,
                reason: rule.reason.clone(),
                next_step: rule.next_step.clone(),
            };
            let replace = best
                .as_ref()
                .is_none_or(|cur| escalation_rank(&cand) > escalation_rank(cur));
            if replace {
                best = Some(cand);
            }
        }
        best
    }
}

fn parse_single_rule(entry: &YamlValue) -> Result<SessionRuleSpec, DetectError> {
    let id = entry
        .get("id")
        .and_then(YamlValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DetectError::InvalidRule("session rule missing `id`".into()))?
        .to_owned();
    let lbl_str = entry
        .get("when_label")
        .and_then(YamlValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DetectError::InvalidRule("session rule missing `when_label`".into()))?;
    let when_label = parse_dynamic_label(lbl_str);

    let mut action_classes = Vec::new();
    if let Some(single) = entry.get("action_class") {
        let raw = single
            .as_str()
            .ok_or_else(|| DetectError::InvalidRule("`action_class` must be a string".into()))?;
        let parsed = parse_action_class(raw).ok_or_else(|| {
            DetectError::InvalidRule(format!("unknown session rule action_class `{raw}`"))
        })?;
        action_classes.push(parsed);
    }
    if let Some(many) = entry.get("action_classes") {
        let seq = many.as_seq().ok_or_else(|| {
            DetectError::InvalidRule("`action_classes` must be a sequence".into())
        })?;
        for item in seq {
            let raw = item.as_str().ok_or_else(|| {
                DetectError::InvalidRule("`action_classes` entry must be string".into())
            })?;
            let parsed = parse_action_class(raw).ok_or_else(|| {
                DetectError::InvalidRule(format!("unknown session rule action_class `{raw}`"))
            })?;
            if !action_classes.contains(&parsed) {
                action_classes.push(parsed);
            }
        }
    }
    if action_classes.is_empty() {
        return Err(DetectError::InvalidRule(format!(
            "session rule `{id}` requires non-empty `action_class`/`action_classes`"
        )));
    }

    let min_risk_score = match entry.get("min_risk_score") {
        None => None,
        Some(v) => {
            let n = v.as_i64().ok_or_else(|| {
                DetectError::InvalidRule("`min_risk_score` must be integer".into())
            })?;
            let score = u32::try_from(n)
                .map_err(|_| DetectError::InvalidRule(format!("invalid `min_risk_score` `{n}`")))?;
            Some(score)
        }
    };

    let count_threshold = match entry.get("count_threshold") {
        None => None,
        Some(v) => {
            let n = v.as_i64().ok_or_else(|| {
                DetectError::InvalidRule("`count_threshold` must be integer".into())
            })?;
            let t = u32::try_from(n).map_err(|_| {
                DetectError::InvalidRule(format!("invalid `count_threshold` `{n}`"))
            })?;
            if t == 0 || t > MAX_SESSION_RULE_THRESHOLD {
                return Err(DetectError::InvalidRule(format!(
                    "`count_threshold` must be within 1..={MAX_SESSION_RULE_THRESHOLD}"
                )));
            }
            Some(t)
        }
    };

    let window_secs = match entry.get("window_secs") {
        None => None,
        Some(v) => {
            let n = v
                .as_i64()
                .ok_or_else(|| DetectError::InvalidRule("`window_secs` must be integer".into()))?;
            let w = u64::try_from(n)
                .map_err(|_| DetectError::InvalidRule(format!("invalid `window_secs` `{n}`")))?;
            if w == 0 || w > MAX_SESSION_RULE_WINDOW_SECS {
                return Err(DetectError::InvalidRule(format!(
                    "`window_secs` must be within 1..={MAX_SESSION_RULE_WINDOW_SECS}"
                )));
            }
            Some(w)
        }
    };
    if count_threshold.is_some_and(|c| c > 1) && window_secs.is_none() {
        return Err(DetectError::InvalidRule(format!(
            "session rule `{id}` with `count_threshold` > 1 requires `window_secs`"
        )));
    }

    let verdict = match entry.get("verdict") {
        None => Verdict::StepUp,
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| DetectError::InvalidRule("`verdict` must be a string".into()))?;
            parse_escalation_verdict(s)?
        }
    };

    let min_grade = match entry.get("min_grade") {
        None => ApprovalGrade::G1,
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| DetectError::InvalidRule("`min_grade` must be a string".into()))?;
            parse_grade(s)?
        }
    };

    let reason = entry
        .get("reason")
        .and_then(YamlValue::as_str)
        .unwrap_or("Dynamic session policy escalation triggered.")
        .to_owned();
    let next_step = entry
        .get("next_step")
        .and_then(YamlValue::as_str)
        .unwrap_or("Review in Respond and approve if intentional.")
        .to_owned();

    Ok(SessionRuleSpec {
        id,
        when_label,
        action_classes,
        min_risk_score,
        count_threshold,
        window_secs,
        verdict,
        min_grade,
        reason,
        next_step,
    })
}

fn label_is_active(
    key: &DynamicLabelKey,
    labels: &BTreeSet<SessionLabel>,
    extra_labels: &BTreeSet<String>,
) -> bool {
    match key {
        DynamicLabelKey::Always => true,
        DynamicLabelKey::Core(lbl) => labels.contains(lbl),
        DynamicLabelKey::Named(name) => match name.as_str() {
            "secret-read" => {
                labels.contains(&SessionLabel::CredentialAccessed) || extra_labels.contains(name)
            }
            "untrusted-input" => {
                labels.contains(&SessionLabel::UntrustedWebFetched)
                    || extra_labels.contains("untrusted-input")
                    || extra_labels.contains("untrusted-mcp")
                    || extra_labels.contains("untrusted-repo")
                    || extra_labels.contains("untrusted-paste")
            }
            _ => extra_labels.contains(name),
        },
    }
}

fn escalation_rank(esc: &DynamicSessionEscalation) -> (u8, u8) {
    let v_rank = match esc.verdict {
        Verdict::Deny => 4,
        Verdict::StepUp => 3,
        Verdict::Defer | Verdict::Modify => 2,
        Verdict::Allow => 1,
    };
    let g_rank = match esc.min_grade {
        ApprovalGrade::G3 => 4,
        ApprovalGrade::G2 => 3,
        ApprovalGrade::G1 => 2,
        ApprovalGrade::G0 => 1,
    };
    (v_rank, g_rank)
}

fn parse_escalation_verdict(raw: &str) -> Result<Verdict, DetectError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "deny" | "block" => Ok(Verdict::Deny),
        "step-up" | "step_up" => Ok(Verdict::StepUp),
        "defer" => Ok(Verdict::Defer),
        other => Err(DetectError::InvalidRule(format!(
            "invalid session rule verdict `{other}`"
        ))),
    }
}

fn parse_grade(raw: &str) -> Result<ApprovalGrade, DetectError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "g0" => Ok(ApprovalGrade::G0),
        "g1" => Ok(ApprovalGrade::G1),
        "g2" => Ok(ApprovalGrade::G2),
        "g3" => Ok(ApprovalGrade::G3),
        other => Err(DetectError::InvalidRule(format!(
            "invalid session rule min_grade `{other}`"
        ))),
    }
}

fn parse_dynamic_label(raw: &str) -> DynamicLabelKey {
    match raw.trim().to_ascii_lowercase().as_str() {
        "credential-accessed" | "credential_accessed" => {
            DynamicLabelKey::Core(SessionLabel::CredentialAccessed)
        }
        "untrusted-web-fetched" | "untrusted_web_fetched" => {
            DynamicLabelKey::Core(SessionLabel::UntrustedWebFetched)
        }
        "repeated-denials" | "repeated_denials" => {
            DynamicLabelKey::Core(SessionLabel::RepeatedDenials)
        }
        "tainted-exfil-risk" | "tainted_exfil_risk" => {
            DynamicLabelKey::Core(SessionLabel::TaintedExfilRisk)
        }
        other => DynamicLabelKey::Named(other.to_owned()),
    }
}

fn parse_action_class(raw: &str) -> Option<ActionClass> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "exec" => Some(ActionClass::Exec),
        "file.read" => Some(ActionClass::FileRead),
        "file.write" => Some(ActionClass::FileWrite),
        "file.delete" => Some(ActionClass::FileDelete),
        "net.connect" => Some(ActionClass::NetConnect),
        "net.request" => Some(ActionClass::NetRequest),
        "llm.request" => Some(ActionClass::LlmRequest),
        "mcp.connect" => Some(ActionClass::McpConnect),
        "mcp.call" => Some(ActionClass::McpCall),
        "cred.use" => Some(ActionClass::CredUse),
        "agent.spawn" => Some(ActionClass::AgentSpawn),
        "config.change" => Some(ActionClass::ConfigChange),
        "elevate" => Some(ActionClass::Elevate),
        "ui.act" => Some(ActionClass::UiAct),
        "data.flow" => Some(ActionClass::DataFlow),
        _ => None,
    }
}

fn fail_closed_fallback_ruleset() -> SessionRuleSet {
    SessionRuleSet {
        pack_id: "grdr.fail-closed".into(),
        rules: vec![SessionRuleSpec {
            id: FALLBACK_FAIL_CLOSED_RULE_ID.into(),
            when_label: DynamicLabelKey::Always,
            action_classes: vec![
                ActionClass::Exec,
                ActionClass::FileWrite,
                ActionClass::FileDelete,
                ActionClass::NetRequest,
                ActionClass::NetConnect,
                ActionClass::DataFlow,
                ActionClass::LlmRequest,
                ActionClass::McpCall,
                ActionClass::CredUse,
                ActionClass::ConfigChange,
                ActionClass::Elevate,
            ],
            min_risk_score: None,
            count_threshold: None,
            window_secs: None,
            verdict: Verdict::Deny,
            min_grade: ApprovalGrade::G3,
            reason: "Session rules failed validation; failing closed on sensitive actions.".into(),
            next_step: "Inspect embedded session-rules pack integrity.".into(),
        }],
    }
}
