//! `.agents/kit/hooks.toml`: one `[[hook]]` entry per handler, rendered into the `hooks` block of
//! `.claude/settings.json` (team/03 section 4).

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::repo::Repo;

/// Events on which Claude Code ignores `onFailure`.
pub const EVENTS_WITHOUT_ON_FAILURE: &[&str] = &[
    "Stop",
    "StopFailure",
    "SubagentStop",
    "TaskCompleted",
    "TeammateIdle",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnFailure {
    Block,
    Continue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `xtask hook <handler>` from the installed kit binary.
    Command {
        handler: String,
        on_failure: Option<OnFailure>,
    },
    /// A prompt hook; `model` is a name from models.toml.
    Prompt { model: String, prompt_file: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub event: String,
    pub matcher: Option<String>,
    pub timeout: Option<u32>,
    pub status_message: Option<String>,
    pub action: Action,
}

#[derive(Debug, Clone, Default)]
pub struct Hooks {
    pub hooks: Vec<Hook>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HooksFile {
    #[serde(default)]
    hook: Vec<toml::Table>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandEntry {
    event: String,
    matcher: Option<String>,
    handler: String,
    timeout: Option<u32>,
    on_failure: Option<OnFailure>,
    status_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptEntry {
    event: String,
    matcher: Option<String>,
    model: String,
    prompt_file: String,
    timeout: Option<u32>,
    status_message: Option<String>,
}

impl Hook {
    pub fn handler(&self) -> Option<&str> {
        match &self.action {
            Action::Command { handler, .. } => Some(handler),
            Action::Prompt { .. } => None,
        }
    }
}

impl Hooks {
    pub fn load(repo: &Repo) -> Result<Hooks> {
        let (label, path) = super::agents_file(repo, "kit/hooks.toml");
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {label}"))?;
        Hooks::parse(&text, &label)
    }

    pub fn parse(text: &str, label: &str) -> Result<Hooks> {
        let file: HooksFile = super::parse_toml(text, label)?;
        let hooks = file
            .hook
            .into_iter()
            .enumerate()
            .map(|(index, entry)| {
                parse_entry(entry).with_context(|| format!("{label}: [[hook]] entry {}", index + 1))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Hooks { hooks })
    }

    pub fn handlers(&self) -> impl Iterator<Item = &str> {
        self.hooks.iter().filter_map(Hook::handler)
    }
}

fn parse_entry(mut table: toml::Table) -> Result<Hook> {
    let kind = match table.remove("type") {
        Some(toml::Value::String(kind)) => kind,
        Some(other) => bail!("`type` must be a string, found {other}"),
        None => "command".to_owned(),
    };
    let value = toml::Value::Table(table);
    match kind.as_str() {
        "command" => {
            let entry: CommandEntry = value.try_into()?;
            validate_handler(&entry.handler)?;
            let on_failure_ignored = EVENTS_WITHOUT_ON_FAILURE.contains(&entry.event.as_str());
            if on_failure_ignored && entry.on_failure.is_some() {
                bail!(
                    "`on_failure` has no effect on {} hooks; remove it",
                    entry.event
                );
            }
            Ok(Hook {
                event: entry.event,
                matcher: entry.matcher,
                timeout: entry.timeout,
                status_message: entry.status_message,
                action: Action::Command {
                    handler: entry.handler,
                    on_failure: entry.on_failure,
                },
            })
        }
        "prompt" => {
            let entry: PromptEntry = value.try_into()?;
            Ok(Hook {
                event: entry.event,
                matcher: entry.matcher,
                timeout: entry.timeout,
                status_message: entry.status_message,
                action: Action::Prompt {
                    model: entry.model,
                    prompt_file: entry.prompt_file,
                },
            })
        }
        other => bail!("unknown hook type `{other}` (command or prompt)"),
    }
}

/// Handler names are spliced into a shell command, so they are kebab-case and nothing else.
fn validate_handler(handler: &str) -> Result<()> {
    let valid = handler.starts_with(|c: char| c.is_ascii_lowercase())
        && handler
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        bail!("handler `{handler}` must be lowercase letters, digits and dashes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_and_prompt_entries() {
        let hooks = Hooks::parse(
            r#"
[[hook]]
event = "PreToolUse"
matcher = "Edit|Write"
handler = "guard-path"
timeout = 10
on_failure = "block"

[[hook]]
event = "Stop"
type = "prompt"
model = "sonnet"
prompt_file = "kit/prompts/stop.md"
"#,
            "hooks.toml",
        )
        .unwrap();
        assert_eq!(hooks.handlers().collect::<Vec<_>>(), vec!["guard-path"]);
        assert!(matches!(hooks.hooks[1].action, Action::Prompt { .. }));
    }

    #[test]
    fn rejects_bad_entries() {
        let unsafe_name = "[[hook]]\nevent = \"Stop\"\nhandler = \"stop; rm -rf /\"\n";
        assert!(Hooks::parse(unsafe_name, "h").is_err());
        let ignored =
            "[[hook]]\nevent = \"Stop\"\nhandler = \"stop-gate\"\non_failure = \"block\"\n";
        assert!(Hooks::parse(ignored, "h").is_err());
        let prompt_with_handler = "[[hook]]\nevent = \"Stop\"\ntype = \"prompt\"\nhandler = \"x\"\nmodel = \"sonnet\"\nprompt_file = \"p\"\n";
        assert!(Hooks::parse(prompt_with_handler, "h").is_err());
        let agent_hook = "[[hook]]\nevent = \"Stop\"\ntype = \"agent\"\n";
        assert!(Hooks::parse(agent_hook, "h").is_err());
        let other_table = "[timeouts]\nx = 1\n";
        assert!(Hooks::parse(other_table, "h").is_err());
        let limits_table = "[limits]\ncontext_lines = 60\n";
        assert!(Hooks::parse(limits_table, "h").is_err());
    }
}
