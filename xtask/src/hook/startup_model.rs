//! The model a session starts on when its `SessionStart` input names none, which is the usual
//! case: the `--model` argument of the `claude` process (`CLAUDE_PID`), else `ANTHROPIC_MODEL`,
//! else the `model` key of the settings files in Claude Code's precedence order. The model gate
//! reads it on the first prompt, before the transcript holds an assistant message.

use std::path::Path;
#[cfg(not(target_os = "linux"))]
use std::process::Command;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use super::context::Context;
use crate::kit::claude_config;
use crate::kit::install::LOCAL_SETTINGS;
use crate::kit::settings::SETTINGS_PATH;

const PID_VARIABLE: &str = "CLAUDE_PID";
const MODEL_VARIABLE: &str = "ANTHROPIC_MODEL";
const MODEL_ARGUMENT: &str = r#"(?:^|\s)--model(?:=|\s+)"?([^\s"]+)"#;

pub fn find(context: &Context) -> Option<String> {
    let from_process = context
        .env
        .get(PID_VARIABLE)
        .and_then(|pid| pid.parse::<u32>().ok())
        .and_then(|pid| command_line(pid, context.limits.session_start.startup_command_line()))
        .and_then(|line| model_argument(&line));
    from_process
        .or_else(|| context.env.get(MODEL_VARIABLE).map(str::to_owned))
        .or_else(|| settings_model(context))
}

/// The value of `--model` or `--model=` in a command line.
pub fn model_argument(line: &str) -> Option<String> {
    let pattern = Regex::new(MODEL_ARGUMENT).ok()?;
    pattern
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_owned())
}

/// Local project settings, then project settings, then the user's, which live in
/// `CLAUDE_CONFIG_DIR` when it is set.
fn settings_model(context: &Context) -> Option<String> {
    let mut files = vec![
        context.repo.path(LOCAL_SETTINGS),
        context.repo.path(SETTINGS_PATH),
    ];
    files.extend(claude_config::user_settings(context.env.lookup()));
    files.iter().find_map(|path| model_key(path))
}

fn model_key(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.get("model")?.as_str().map(str::to_owned)
}

#[cfg(target_os = "linux")]
fn command_line(pid: u32, _timeout: Duration) -> Option<String> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(String::from_utf8_lossy(&bytes).replace('\0', " "))
}

#[cfg(windows)]
fn command_line(pid: u32, timeout: Duration) -> Option<String> {
    let query = format!("(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine");
    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-NonInteractive", "-Command", &query]);
    run(command, timeout)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn command_line(pid: u32, timeout: Duration) -> Option<String> {
    let mut command = Command::new("ps");
    command.args(["-o", "command=", "-p", &pid.to_string()]);
    run(command, timeout)
}

#[cfg(not(target_os = "linux"))]
fn run(mut command: Command, timeout: Duration) -> Option<String> {
    let ran = crate::process::run(&mut command, None, timeout).ok()?;
    ran.success().then(|| ran.stdout().trim().to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;
    use crate::hook::context::{Env, Input};
    use crate::hook::limits::kit_limits;
    use crate::repo::Repo;

    #[test]
    fn reads_both_argument_forms() {
        let windows = r#""C:\Users\dev\.local\bin\claude.exe" -p "Reply." --model claude-fable-5-2 --max-turns 1"#;
        assert_eq!(model_argument(windows).as_deref(), Some("claude-fable-5-2"));
        assert_eq!(
            model_argument("claude --model=sonnet -p hi").as_deref(),
            Some("sonnet")
        );
        assert_eq!(model_argument("claude -p \"use --models\""), None);
    }

    #[test]
    fn user_settings_come_from_the_config_dir_variable() {
        let root = std::env::temp_dir().join(format!("xtask-startup-model-{}", std::process::id()));
        let config = root.join("config");
        let home = root.join("home");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(
            config.join("settings.json"),
            r#"{"model":"from-config-dir"}"#,
        )
        .unwrap();
        std::fs::write(
            home.join(".claude").join("settings.json"),
            r#"{"model":"from-home"}"#,
        )
        .unwrap();
        let home_text = home.to_string_lossy().into_owned();
        let env = Env::from_pairs([
            ("CLAUDE_CONFIG_DIR", config.to_string_lossy().into_owned()),
            ("HOME", home_text.clone()),
            ("USERPROFILE", home_text),
        ]);
        let context = Context::new(
            Repo::at(root.join("repo")),
            Input::parse("{}").unwrap(),
            env,
            Instant::now(),
            Arc::default(),
            kit_limits(),
        );
        assert_eq!(settings_model(&context).as_deref(), Some("from-config-dir"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
