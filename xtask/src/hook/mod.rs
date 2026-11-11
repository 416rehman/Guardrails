//! `xtask hook <handler>` and `xtask hooks selftest` (team/03 sections 1 and 4). Each handler
//! reads its event's JSON on stdin, answers within its registered timeout less
//! `[hook.runner] deadline_margin_s` of `.agents/kit/limits.toml`, prints at most the lines
//! `[hook.outcome]` allows and logs the rest under `.agent/logs/`. Pre-action handlers block when
//! they panic, err or miss the deadline; `stop-gate` blocks under its round counter; the others
//! allow and log.

mod command;
mod context;
#[cfg(test)]
mod escape_tests;
mod github;
mod guard_path;
pub mod handoff;
mod identity;
mod lifecycle;
mod limits;
mod model;
mod outcome;
mod path_skills;
mod post_bash;
mod post_edit;
mod runner;
mod selftest;
mod session_start;
mod shell;
mod signoff;
mod startup_model;
mod state;
mod stop_failure;
mod stop_gate;
mod subagent;
mod transcript;

use std::process::ExitCode;

use anyhow::Result;

use context::Context;
use outcome::Outcome;

/// Handlers this binary implements; `kit check` fails for any `.agents/kit/hooks.toml` handler not listed.
pub const HANDLERS: &[&str] = &[
    "session-start",
    "session-restore",
    "model-gate",
    "model-switch",
    "guard-path",
    "guard-command",
    "post-edit",
    "post-bash",
    "subagent-start",
    "subagent-stop",
    "stop-gate",
    "stop-failure",
    "pre-compact",
    "config-change",
    "session-end",
];
const USAGE: &str = "usage: xtask hook <handler> (JSON on stdin) | xtask hooks selftest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    SessionStart,
    SessionRestore,
    ModelGate,
    ModelSwitch,
    GuardPath,
    GuardCommand,
    PostEdit,
    PostBash,
    SubagentStart,
    SubagentStop,
    StopGate,
    StopFailure,
    PreCompact,
    ConfigChange,
    SessionEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    SessionStart,
    UserPromptSubmit,
    PreModelSwitch,
    PreToolUse,
    PostToolUse,
    SubagentStart,
    SubagentStop,
    Stop,
    StopFailure,
    PreCompact,
    ConfigChange,
    SessionEnd,
}

/// What a handler does when it panics, errs or misses its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Block,
    /// Block, but let the round counter allow the stop after `[hook.stop_gate] blocks` blocks on
    /// one diff.
    CountedBlock,
    Allow,
}

impl Handler {
    pub const ALL: [Handler; 15] = [
        Handler::SessionStart,
        Handler::SessionRestore,
        Handler::ModelGate,
        Handler::ModelSwitch,
        Handler::GuardPath,
        Handler::GuardCommand,
        Handler::PostEdit,
        Handler::PostBash,
        Handler::SubagentStart,
        Handler::SubagentStop,
        Handler::StopGate,
        Handler::StopFailure,
        Handler::PreCompact,
        Handler::ConfigChange,
        Handler::SessionEnd,
    ];

    pub fn name(self) -> &'static str {
        Handler::ALL
            .iter()
            .position(|h| *h == self)
            .and_then(|index| HANDLERS.get(index).copied())
            .unwrap_or_default()
    }

    pub fn from_name(name: &str) -> Option<Handler> {
        HANDLERS
            .iter()
            .position(|h| *h == name)
            .and_then(|index| Handler::ALL.get(index).copied())
    }

    pub fn event(self) -> Event {
        match self {
            Handler::SessionStart | Handler::SessionRestore => Event::SessionStart,
            Handler::ModelGate => Event::UserPromptSubmit,
            Handler::ModelSwitch => Event::PreModelSwitch,
            Handler::GuardPath | Handler::GuardCommand => Event::PreToolUse,
            Handler::PostEdit | Handler::PostBash => Event::PostToolUse,
            Handler::SubagentStart => Event::SubagentStart,
            Handler::SubagentStop => Event::SubagentStop,
            Handler::StopGate => Event::Stop,
            Handler::StopFailure => Event::StopFailure,
            Handler::PreCompact => Event::PreCompact,
            Handler::ConfigChange => Event::ConfigChange,
            Handler::SessionEnd => Event::SessionEnd,
        }
    }

    pub fn failure(self) -> Failure {
        match self {
            Handler::ModelGate
            | Handler::ModelSwitch
            | Handler::GuardPath
            | Handler::GuardCommand
            | Handler::ConfigChange => Failure::Block,
            Handler::StopGate => Failure::CountedBlock,
            _ => Failure::Allow,
        }
    }

    fn handle(self, context: &Context) -> Result<Outcome> {
        match self {
            Handler::SessionStart => session_start::start(context),
            Handler::SessionRestore => session_start::restore(context),
            Handler::ModelGate => model::gate(context),
            Handler::ModelSwitch => model::switch(context),
            Handler::GuardPath => guard_path::run(context),
            Handler::GuardCommand => command::run(context),
            Handler::PostEdit => post_edit::run(context),
            Handler::PostBash => post_bash::run(context),
            Handler::SubagentStart => subagent::start(context),
            Handler::SubagentStop => subagent::stop(context),
            Handler::StopGate => stop_gate::run(context),
            Handler::StopFailure => stop_failure::run(context),
            Handler::PreCompact => lifecycle::pre_compact(context),
            Handler::ConfigChange => lifecycle::config_change(context),
            Handler::SessionEnd => lifecycle::session_end(context),
        }
    }
}

impl Event {
    pub fn name(self) -> &'static str {
        match self {
            Event::SessionStart => "SessionStart",
            Event::UserPromptSubmit => "UserPromptSubmit",
            Event::PreModelSwitch => "PreModelSwitch",
            Event::PreToolUse => "PreToolUse",
            Event::PostToolUse => "PostToolUse",
            Event::SubagentStart => "SubagentStart",
            Event::SubagentStop => "SubagentStop",
            Event::Stop => "Stop",
            Event::StopFailure => "StopFailure",
            Event::PreCompact => "PreCompact",
            Event::ConfigChange => "ConfigChange",
            Event::SessionEnd => "SessionEnd",
        }
    }
}

/// Gate V18: every failing self-test case, for `verify`.
pub fn selftest_problems() -> anyhow::Result<Vec<String>> {
    selftest::problems()
}

/// For `kit check`: why the handlers cannot read the `[hook.*]` tables of the working tree's
/// `.agents/kit/limits.toml`, if they cannot.
pub fn limits_problem(repo: &crate::repo::Repo) -> Option<String> {
    limits::load(repo).err().map(|error| format!("{error:#}"))
}

/// For `kit check`: every skill `.agents/kit/path-skills.toml` names, each once, so each can be
/// checked against what is installed.
pub fn path_skill_names(repo: &crate::repo::Repo) -> Result<Vec<String>> {
    let mapping = path_skills::PathSkills::load(repo)?;
    Ok(mapping.skill_names())
}

/// `hook <handler>`, `hooks selftest` and `hooks-selftest`. An unknown handler exits 2, so a
/// pre-action hook the binary does not know blocks instead of passing.
pub fn run(command: &str, args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match (command, args.as_slice()) {
        ("hook" | "hooks", ["selftest", rest @ ..]) | ("hooks-selftest", rest) => {
            selftest::run(rest)
        }
        ("hook", [name]) => match Handler::from_name(name) {
            Some(handler) => runner::run(handler),
            None => {
                eprintln!(
                    "xtask hook: unknown handler `{name}`; known: {}",
                    HANDLERS.join(", ")
                );
                ExitCode::from(outcome::BLOCK_EXIT)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_handler_has_one_name() {
        assert_eq!(HANDLERS.len(), Handler::ALL.len());
        for handler in Handler::ALL {
            assert_eq!(Handler::from_name(handler.name()), Some(handler));
        }
        assert_eq!(Handler::from_name("guard-everything"), None);
    }

    #[test]
    fn pre_action_handlers_fail_closed() {
        assert_eq!(Handler::GuardPath.failure(), Failure::Block);
        assert_eq!(Handler::StopGate.failure(), Failure::CountedBlock);
        assert_eq!(Handler::PostEdit.failure(), Failure::Allow);
        assert_eq!(Handler::GuardCommand.event(), Event::PreToolUse);
    }
}
