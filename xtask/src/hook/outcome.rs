//! A handler's answer and how each event takes it (team/03 section 1): exit 2 with the reason on
//! stderr blocks; PostToolUse takes `decision: block` as JSON; context goes into
//! `hookSpecificOutput.additionalContext`, and PreCompact's stdout becomes the compaction
//! instructions. Silence approves nothing, so a PreToolUse handler that has checked a call answers
//! `permissionDecision: allow` for it to run without a prompt; deny and ask rules still apply.

use serde_json::{Map, Value, json};

use super::Event;
use crate::config::limits::HookLimits;

/// The exit code with which Claude Code takes a hook's stderr as the reason it blocks.
pub const BLOCK_EXIT: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No decision: Claude Code's permission rules and mode decide.
    Allow,
    /// Text for the model that does not stop it.
    Context(String),
    /// The call is checked and runs without a prompt, with context for the model if any.
    Approve {
        reason: String,
        context: Option<String>,
    },
    Block(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rendered {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
}

impl Outcome {
    pub fn kind(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Context(_) => "context",
            Outcome::Approve { .. } => "approve",
            Outcome::Block(_) => "block",
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Outcome::Allow => "",
            Outcome::Context(text) | Outcome::Block(text) => text,
            Outcome::Approve { reason, context } => context.as_deref().unwrap_or(reason),
        }
    }

    /// Whether a log of this outcome would hold nothing but its kind.
    pub fn is_quiet(&self) -> bool {
        matches!(
            self,
            Outcome::Allow | Outcome::Approve { context: None, .. }
        )
    }

    /// Blocks with every reason, one per line, or allows when there is none.
    pub fn block_if(reasons: Vec<String>) -> Outcome {
        if reasons.is_empty() {
            Outcome::Allow
        } else {
            Outcome::Block(reasons.join("\n"))
        }
    }

    /// The answer in `event`'s form; `limits` caps its lines, and a handler that could not read
    /// them answers uncut.
    pub fn render(&self, event: Event, log: Option<&str>, limits: Option<&HookLimits>) -> Rendered {
        match self {
            Outcome::Allow => Rendered::default(),
            Outcome::Block(text) => {
                let reason = with_log(
                    text,
                    log,
                    limits.map(|limits| limits.outcome.diagnostic_lines),
                );
                if event == Event::PostToolUse {
                    return Rendered {
                        stdout: json!({ "decision": "block", "reason": reason }).to_string(),
                        ..Rendered::default()
                    };
                }
                Rendered {
                    stderr: format!("{reason}\n"),
                    code: BLOCK_EXIT,
                    ..Rendered::default()
                }
            }
            Outcome::Context(text) => {
                let context =
                    with_log(text, log, limits.map(|limits| limits.outcome.context_lines));
                let stdout = match event {
                    Event::PreCompact => context,
                    Event::SessionStart
                    | Event::SubagentStart
                    | Event::UserPromptSubmit
                    | Event::PreToolUse
                    | Event::PostToolUse => json!({
                        "hookSpecificOutput": { "hookEventName": event.name(), "additionalContext": context }
                    })
                    .to_string(),
                    _ => String::new(),
                };
                Rendered {
                    stdout,
                    ..Rendered::default()
                }
            }
            Outcome::Approve { reason, context } if event == Event::PreToolUse => {
                let mut output = Map::new();
                output.insert("hookEventName".into(), json!(event.name()));
                output.insert("permissionDecision".into(), json!("allow"));
                output.insert("permissionDecisionReason".into(), json!(reason));
                if let Some(text) = context {
                    let lines = limits.map(|limits| limits.outcome.context_lines);
                    output.insert(
                        "additionalContext".into(),
                        json!(with_log(text, log, lines)),
                    );
                }
                Rendered {
                    stdout: json!({ "hookSpecificOutput": Value::Object(output) }).to_string(),
                    ..Rendered::default()
                }
            }
            Outcome::Approve { context, .. } => match context {
                Some(text) => Outcome::Context(text.clone()).render(event, log, limits),
                None => Rendered::default(),
            },
        }
    }
}

/// The first `max` lines, then a line that counts the rest, which the handler's log keeps.
pub fn capped(lines: &[String], max: usize) -> Vec<String> {
    let mut kept: Vec<String> = lines.iter().take(max).cloned().collect();
    if let Some(more) = lines.len().checked_sub(max).filter(|more| *more > 0) {
        kept.push(format!("... and {more} more; the log has them all"));
    }
    kept
}

/// `text` cut to `max` lines with the log path as the last one.
pub fn with_log(text: &str, log: Option<&str>, max: Option<usize>) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let max = max.unwrap_or(lines.len().saturating_add(1));
    let budget = if log.is_some() {
        max.saturating_sub(1)
    } else {
        max
    };
    let mut kept: Vec<String> = lines
        .iter()
        .take(budget)
        .map(|line| (*line).to_owned())
        .collect();
    if lines.len() > budget
        && let Some(last) = kept.last_mut()
    {
        *last = format!("... and {} more lines", lines.len() - budget + 1);
    }
    if let Some(log) = log {
        kept.push(format!("log: {log}"));
    }
    kept.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::limits::kit_limits;

    #[test]
    fn blocks_exit_two_except_after_a_tool_ran() {
        let block = Outcome::Block("protected path".into());
        let rendered = block.render(
            Event::PreToolUse,
            Some(".agent/logs/x.log"),
            Some(&kit_limits()),
        );
        assert_eq!(rendered.code, BLOCK_EXIT);
        assert_eq!(rendered.stderr, "protected path\nlog: .agent/logs/x.log\n");
        let post = block.render(Event::PostToolUse, None, None);
        assert_eq!(post.code, 0);
        assert!(post.stdout.contains("\"decision\":\"block\""));
    }

    #[test]
    fn capped_lines_count_the_rest() {
        let lines: Vec<String> = ["a", "b", "c"].map(str::to_owned).to_vec();
        assert_eq!(capped(&lines, 3), lines);
        assert_eq!(
            capped(&lines, 2),
            ["a", "b", "... and 1 more; the log has them all"]
        );
    }

    #[test]
    fn context_shapes_and_line_cap() {
        let start = Outcome::Context("hello".into()).render(Event::SessionStart, None, None);
        let value: serde_json::Value = serde_json::from_str(&start.stdout).unwrap();
        assert_eq!(value["hookSpecificOutput"]["hookEventName"], "SessionStart");
        assert_eq!(value["hookSpecificOutput"]["additionalContext"], "hello");
        assert_eq!(
            Outcome::Context("keep".into())
                .render(Event::PreCompact, None, None)
                .stdout,
            "keep"
        );
        let long: String = (0..20).map(|i| format!("line {i}\n")).collect();
        let cut = with_log(&long, Some("l"), Some(10));
        assert_eq!(cut.lines().count(), 10);
        assert!(cut.lines().nth(8).unwrap().contains("more lines"));
        assert_eq!(with_log(&long, Some("l"), None).lines().count(), 21);
        let tool =
            Outcome::Context("load ui-architect".into()).render(Event::PreToolUse, None, None);
        let value: serde_json::Value = serde_json::from_str(&tool.stdout).unwrap();
        assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn an_approval_is_a_permission_decision_only_before_a_tool_runs() {
        let approve = |context: Option<&str>| Outcome::Approve {
            reason: "in the write set".into(),
            context: context.map(str::to_owned),
        };
        let rendered = approve(Some("load grdr-structure")).render(Event::PreToolUse, None, None);
        assert_eq!(rendered.code, 0);
        let value: serde_json::Value = serde_json::from_str(&rendered.stdout).unwrap();
        let output = &value["hookSpecificOutput"];
        assert_eq!(output["permissionDecision"], "allow");
        assert_eq!(output["permissionDecisionReason"], "in the write set");
        assert_eq!(output["additionalContext"], "load grdr-structure");
        let bare: serde_json::Value =
            serde_json::from_str(&approve(None).render(Event::PreToolUse, None, None).stdout)
                .unwrap();
        assert!(
            bare["hookSpecificOutput"]
                .get("additionalContext")
                .is_none()
        );
        assert!(approve(None).is_quiet());
        assert!(!approve(Some("x")).is_quiet());
        let after = approve(Some("load it")).render(Event::PostToolUse, None, None);
        assert!(
            !after.stdout.contains("permissionDecision"),
            "{}",
            after.stdout
        );
        assert!(after.stdout.contains("load it"));
        assert_eq!(
            approve(None).render(Event::PostToolUse, None, None),
            Rendered::default()
        );
    }
}
