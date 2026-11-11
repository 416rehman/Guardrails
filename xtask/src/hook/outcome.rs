//! A handler's answer and how each event takes it (team/03 section 1): exit 2 with the reason on
//! stderr blocks; PostToolUse takes `decision: block` as JSON; context goes into
//! `hookSpecificOutput.additionalContext`, and PreCompact's stdout becomes the compaction
//! instructions.

use serde_json::json;

use super::Event;
use crate::config::limits::HookLimits;

/// The exit code with which Claude Code takes a hook's stderr as the reason it blocks.
pub const BLOCK_EXIT: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    /// Text for the model that does not stop it.
    Context(String),
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
            Outcome::Block(_) => "block",
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Outcome::Allow => "",
            Outcome::Context(text) | Outcome::Block(text) => text,
        }
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
}
