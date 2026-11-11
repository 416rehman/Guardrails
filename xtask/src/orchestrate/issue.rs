//! A work item as `gh` returns it: an issue of the configured repository with its labels, its
//! form sections and its comments (owner instruction 5). [`WorkItem`] is the view the kit
//! commands and the dispatcher share; the acceptance digest follows
//! `.agents/skills/grdr-write-spec/references/issue-work-item.md`.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::session::{ItemStatus, RiskTier};

pub const ACCEPTANCE_HEADING: &str = "### Acceptance criteria";
const SECTION_PREFIX: &str = "### ";
const NO_RESPONSE: &str = "_No response_";
const STATUS_PREFIX: &str = "status:";
const TIER_PREFIX: &str = "tier:";
const KIND_PREFIX: &str = "kind:";
const SIZE_PREFIX: &str = "size:";
const SQUAD_PREFIX: &str = "squad:";
const AGENT_PREFIX: &str = "agent:";
const PRIORITY_PREFIX: &str = "priority:p";
pub const TRUST_CORE_LABEL: &str = "trust-core";
const STATUSES: &[(&str, ItemStatus)] = &[
    ("proposed", ItemStatus::Proposed),
    ("ready", ItemStatus::Ready),
    ("leased", ItemStatus::Leased),
    ("in-review", ItemStatus::InReview),
    ("blocked", ItemStatus::Blocked),
    ("escalated", ItemStatus::Escalated),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum IssueState {
    #[default]
    #[serde(rename = "OPEN", alias = "open")]
    Open,
    #[serde(rename = "CLOSED", alias = "closed")]
    Closed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Named {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Login {
    #[serde(default)]
    pub login: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Comment {
    #[serde(default)]
    pub author: Login,
    /// GitHub's relation of the author to the repository: `OWNER`, `MEMBER`, `NONE` and so on.
    #[serde(default, rename = "authorAssociation")]
    pub author_association: String,
    #[serde(default)]
    pub body: String,
    #[serde(default, rename = "createdAt")]
    pub created_at: String,
}

/// `gh issue view --json number,title,body,labels,state,createdAt,updatedAt,assignees,comments`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Issue {
    pub number: u64,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub labels: Vec<Named>,
    #[serde(default)]
    pub state: IssueState,
    #[serde(default, rename = "createdAt")]
    pub created_at: String,
    /// Moves with every edit, label change and comment; the planning pass compares it.
    #[serde(default, rename = "updatedAt")]
    pub updated_at: String,
    #[serde(default)]
    pub assignees: Vec<Login>,
    #[serde(default)]
    pub comments: Vec<Comment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acceptance {
    pub text: String,
    pub sha256: String,
}

/// The fields a work item carries in its labels and its form sections. Labels win over sections,
/// because the readying agent sets the labels last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    pub number: u64,
    pub title: String,
    pub status: Option<ItemStatus>,
    pub agent: Option<String>,
    pub kind: Option<String>,
    pub squad: Option<String>,
    pub size: Option<String>,
    pub tier: Option<RiskTier>,
    pub trust_core: bool,
    /// 0 to 3 from `priority:p0` to `priority:p3`; `None` sorts after p3.
    pub priority: Option<u8>,
    pub write_set: Vec<String>,
    pub acceptance: Option<Acceptance>,
}

impl Issue {
    pub fn label_names(&self) -> impl Iterator<Item = &str> {
        self.labels.iter().map(|label| label.name.as_str())
    }

    pub fn has_label(&self, name: &str) -> bool {
        self.label_names().any(|label| label == name)
    }

    pub fn is_open(&self) -> bool {
        self.state == IssueState::Open
    }

    pub fn work_item(&self) -> WorkItem {
        let label = |prefix: &str| {
            self.label_names()
                .find_map(|name| name.strip_prefix(prefix))
                .map(str::to_owned)
        };
        let field = |heading: &str| section(&self.body, heading).and_then(first_word);
        let labelled_tier = self
            .label_names()
            .filter_map(|name| name.strip_prefix(TIER_PREFIX))
            .filter_map(parse_tier)
            .reduce(raise);
        let trust_section =
            field("Trust core").is_some_and(|value| value.eq_ignore_ascii_case("yes"));
        WorkItem {
            number: self.number,
            title: self.title.clone(),
            status: self.status(),
            agent: label(AGENT_PREFIX).or_else(|| field("Agent")),
            kind: label(KIND_PREFIX).or_else(|| field("Kind")),
            squad: label(SQUAD_PREFIX).or_else(|| field("Squad")),
            size: label(SIZE_PREFIX).or_else(|| field("Size")),
            tier: labelled_tier.or_else(|| field("Risk tier").as_deref().and_then(parse_tier)),
            trust_core: self.has_label(TRUST_CORE_LABEL) || trust_section,
            priority: label(PRIORITY_PREFIX).and_then(|digit| digit.parse().ok()),
            write_set: section(&self.body, "Write set")
                .map(|text| globs_in(&text))
                .unwrap_or_default(),
            acceptance: acceptance(&self.body),
        }
    }

    /// The one `status:` label, or `Closed` for a closed issue.
    pub fn status(&self) -> Option<ItemStatus> {
        if self.state == IssueState::Closed {
            return Some(ItemStatus::Closed);
        }
        self.label_names()
            .find_map(|name| name.strip_prefix(STATUS_PREFIX))
            .and_then(status_from_label)
    }
}

impl WorkItem {
    /// The SHA-256, in lowercase hex, of the write set's globs one per line, which `ready.v1`
    /// holds; a fence or bullet around the same globs leaves it unchanged.
    pub fn write_set_sha256(&self) -> String {
        sha256_hex(self.write_set.join("\n").as_bytes())
    }
}

/// `low`, `medium` or `high`, as labels and the form write them.
pub fn parse_tier(text: &str) -> Option<RiskTier> {
    match text.trim().to_ascii_lowercase().as_str() {
        "low" => Some(RiskTier::Low),
        "medium" => Some(RiskTier::Medium),
        "high" => Some(RiskTier::High),
        _ => None,
    }
}

pub fn tier_name(tier: RiskTier) -> &'static str {
    match tier {
        RiskTier::Low => "low",
        RiskTier::Medium => "medium",
        RiskTier::High => "high",
    }
}

pub fn tier_rank(tier: RiskTier) -> u8 {
    match tier {
        RiskTier::Low => 0,
        RiskTier::Medium => 1,
        RiskTier::High => 2,
    }
}

/// The higher of two tiers: a tier may be raised, never lowered.
pub fn raise(current: RiskTier, other: RiskTier) -> RiskTier {
    if tier_rank(other) > tier_rank(current) {
        other
    } else {
        current
    }
}

pub fn status_from_label(name: &str) -> Option<ItemStatus> {
    STATUSES
        .iter()
        .find(|(label, _)| *label == name)
        .map(|(_, status)| *status)
}

/// `status:in-review` for [`ItemStatus::InReview`]; a closed issue has no status label.
pub fn status_label(status: ItemStatus) -> Option<String> {
    STATUSES
        .iter()
        .find(|(_, known)| *known == status)
        .map(|(name, _)| format!("{STATUS_PREFIX}{name}"))
}

/// The text of the `### <heading>` section, without the heading line, CRLF turned into LF.
pub fn section(body: &str, heading: &str) -> Option<String> {
    let body = body.replace("\r\n", "\n");
    let wanted = format!("{SECTION_PREFIX}{heading}");
    let mut lines = body.split('\n');
    lines.by_ref().find(|line| line.trim_end() == wanted)?;
    let text: Vec<&str> = lines
        .take_while(|line| !line.starts_with(SECTION_PREFIX))
        .collect();
    Some(text.join("\n"))
}

/// The acceptance section and its digest: the text after the `### Acceptance criteria` line and
/// before the next line that starts with `### ` (or the end), CRLF turned into LF, leading and
/// trailing newlines removed, SHA-256 in lowercase hex.
pub fn acceptance(body: &str) -> Option<Acceptance> {
    let body = body.replace("\r\n", "\n");
    let start = acceptance_start(&body)?;
    let rest = body.get(start..)?;
    let end = next_section(rest).unwrap_or(rest.len());
    let text = rest.get(..end)?.trim_matches('\n').to_owned();
    let sha256 = sha256_hex(text.as_bytes());
    Some(Acceptance { text, sha256 })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Globs from a write-set section: one per line, code fences, bullets and the form's empty marker
/// dropped.
pub fn globs_in(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("```") && *line != NO_RESPONSE)
        .map(|line| line.trim_start_matches(['-', '*']).trim().trim_matches('`'))
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn first_word(text: String) -> Option<String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("```"))?;
    if line == NO_RESPONSE {
        return None;
    }
    line.split_whitespace()
        .next()
        .map(|word| word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-'))
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
}

/// The byte offset just after the acceptance heading line, which must stand alone on its line.
fn acceptance_start(body: &str) -> Option<usize> {
    let mut offset = 0;
    for line in body.split_inclusive('\n') {
        let next = offset + line.len();
        if line.strip_suffix('\n') == Some(ACCEPTANCE_HEADING) {
            return Some(next);
        }
        offset = next;
    }
    None
}

fn next_section(text: &str) -> Option<usize> {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.starts_with(SECTION_PREFIX) {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "### Kind\n\nbug\n\n### Squad\n\ncore\n\n### Agent\n\nimpl-rust\n\n### Size\n\nS\n\n### Write set\n\n```text\ncrates/grdr-core/src/analyze/shell/**\ncrates/grdr-core/tests/shell_*.rs\n```\n\n### Spec\n\n#### Problem\nHere-docs.\n\n### Acceptance criteria\n\n```json\n{\"criteria\": [{\"id\": \"AC-1\", \"check\": \"cargo test\", \"expect\": \"exit 0\", \"oracle\": \"bash\"}]}\n```\n\n### Risk tier\n\nhigh (fail_mode_change)\n\n### Trust core\n\nno\n";

    fn issue(labels: &[&str]) -> Issue {
        Issue {
            number: 142,
            title: "Shell canonicaliser".into(),
            body: BODY.into(),
            labels: labels
                .iter()
                .map(|name| Named {
                    name: (*name).into(),
                })
                .collect(),
            ..Issue::default()
        }
    }

    #[test]
    fn the_highest_tier_label_wins() {
        let item = issue(&["tier:low", "tier:medium"]).work_item();
        assert_eq!(item.tier, Some(RiskTier::Medium));
        let item = issue(&["tier:high", "tier:low"]).work_item();
        assert_eq!(item.tier, Some(RiskTier::High));
    }

    #[test]
    fn fields_come_from_labels_then_sections() {
        let item = issue(&[
            "status:ready",
            "tier:medium",
            "priority:p1",
            "agent:impl-web",
        ])
        .work_item();
        assert_eq!(item.status, Some(ItemStatus::Ready));
        assert_eq!(item.tier, Some(RiskTier::Medium));
        assert_eq!(item.agent.as_deref(), Some("impl-web"));
        assert_eq!(item.kind.as_deref(), Some("bug"));
        assert_eq!(item.size.as_deref(), Some("S"));
        assert_eq!(item.priority, Some(1));
        assert!(!item.trust_core);
        assert_eq!(
            item.write_set,
            vec![
                "crates/grdr-core/src/analyze/shell/**",
                "crates/grdr-core/tests/shell_*.rs"
            ]
        );
        let sections_only = issue(&[]).work_item();
        assert_eq!(sections_only.tier, Some(RiskTier::High));
        assert_eq!(sections_only.agent.as_deref(), Some("impl-rust"));
        assert_eq!(sections_only.status, None);
        assert!(issue(&["trust-core"]).work_item().trust_core);
    }

    #[test]
    fn acceptance_digest_matches_the_reference_rule() {
        let found = acceptance(BODY).unwrap();
        assert!(found.text.starts_with("```json\n{\"criteria\""));
        assert!(found.text.ends_with("```"));
        let expected = sha256_hex(found.text.as_bytes());
        assert_eq!(found.sha256, expected);
        let crlf = BODY.replace('\n', "\r\n");
        assert_eq!(acceptance(&crlf).unwrap().sha256, found.sha256);
        let edited = BODY.replace("exit 0", "exit 1");
        assert_ne!(acceptance(&edited).unwrap().sha256, found.sha256);
        assert!(acceptance("### Spec\nx\n").is_none());
        let last = "### Acceptance criteria\n\nAC-1 | cmd\n\n";
        assert_eq!(acceptance(last).unwrap().text, "AC-1 | cmd");
    }

    #[test]
    fn the_write_set_digest_covers_the_globs_and_not_their_formatting() {
        let item = issue(&[]).work_item();
        assert_eq!(
            item.write_set_sha256(),
            sha256_hex(b"crates/grdr-core/src/analyze/shell/**\ncrates/grdr-core/tests/shell_*.rs")
        );
        let bulleted = Issue {
            body: BODY
                .replace("```text\n", "")
                .replace("\ncrates/", "\n- crates/"),
            ..issue(&[])
        };
        assert_eq!(
            bulleted.work_item().write_set_sha256(),
            item.write_set_sha256()
        );
        let widened = Issue {
            body: BODY.replace("shell_*.rs\n", "shell_*.rs\n.github/**\n"),
            ..issue(&[])
        };
        assert_ne!(
            widened.work_item().write_set_sha256(),
            item.write_set_sha256()
        );
    }

    #[test]
    fn known_python_digest() {
        let body =
            "### Acceptance criteria\n\nAC-1 | true | exit 0 | oracle: sh\n\n### Risk tier\nlow\n";
        assert_eq!(
            acceptance(body).unwrap().sha256,
            sha256_hex(b"AC-1 | true | exit 0 | oracle: sh")
        );
    }

    #[test]
    fn status_labels_round_trip_and_closed_wins() {
        assert_eq!(
            status_label(ItemStatus::InReview).as_deref(),
            Some("status:in-review")
        );
        assert_eq!(status_label(ItemStatus::Closed), None);
        let mut closed = issue(&["status:in-review"]);
        closed.state = IssueState::Closed;
        assert_eq!(closed.status(), Some(ItemStatus::Closed));
        assert_eq!(raise(RiskTier::High, RiskTier::Low), RiskTier::High);
        assert_eq!(raise(RiskTier::Low, RiskTier::Medium), RiskTier::Medium);
    }

    #[test]
    fn parses_gh_json() {
        let json = r#"{"number": 7, "title": "t", "body": "b", "state": "OPEN", "labels": [{"name": "status:ready", "color": "x"}], "assignees": [], "createdAt": "2026-11-11T10:00:00Z", "comments": [{"author": {"login": "416rehman"}, "body": "hi", "createdAt": "2026-11-11T10:01:00Z"}]}"#;
        let issue: Issue = serde_json::from_str(json).unwrap();
        assert_eq!(issue.status(), Some(ItemStatus::Ready));
        assert_eq!(issue.comments[0].author.login, "416rehman");
    }
}
