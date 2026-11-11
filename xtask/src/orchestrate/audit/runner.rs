//! How one audit pass runs: `claude -p` on the pass's model in the audit worktree with read tools
//! and one writable output directory, every `GRDR_*` identity removed so the hooks treat it as no
//! agent, and a usage limit waited out and resumed in the same session.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::runtime::Harness;
use crate::config::session::{
    AGENT_VARIABLE, LAUNCHER_MODEL_VARIABLE, SCOPE_VARIABLE, WORK_ITEM_VARIABLE,
};
use crate::dispatch::worker::Prepare;
use crate::orchestrate::claude::{Ended, Running, SessionRules};
use crate::orchestrate::ids;
use crate::orchestrate::launch::{SessionStart, claude_program};
use crate::repo::Repo;

const FINDER_TOOLS: &str = "Read,Grep,Glob,Edit(./.agent/audit-out/**)";
const DENIED_TOOLS: &str = "Bash,NotebookEdit,WebFetch,WebSearch";
const RESUME_PROMPT: &str = "The usage window has reset. Continue, then write the output file.";

/// How passes run: the Claude program, the worktree preparation and the session limits.
#[derive(Debug, Clone)]
pub struct Runner {
    pub claude: PathBuf,
    pub prepare: Prepare,
    pub session: SessionRules,
    /// `.agents/harness.toml [launch] harness`, the harness name every record carries.
    pub harness: String,
    pub claude_pin: String,
}

/// One finished pass: what it wrote, and its usage.
pub(super) struct Pass {
    pub(super) output: Option<Value>,
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    pub(super) paused: Duration,
}

impl Runner {
    pub fn from_kit(repo: &Repo) -> Result<Runner> {
        Ok(Runner {
            claude: claude_program(repo)?,
            prepare: Prepare::CopyOrInstall,
            session: SessionRules::load(repo)?,
            harness: crate::orchestrate::form::Form::load(repo)?.harness,
            claude_pin: Harness::load(repo)?
                .dispatch
                .claude_pin
                .context(".agents/harness.toml [dispatch] has no claude_pin")?,
        })
    }

    /// One `claude -p` pass in `worktree` that writes `out`; a usage limit waits and resumes the
    /// same session, so a paused pass is never failed or empty.
    pub(super) fn pass(
        &self,
        worktree: &Path,
        model: &str,
        turns: u32,
        prompt: &str,
        out: &str,
        log: &Path,
    ) -> Result<Pass> {
        let mut start = SessionStart::Named(ids::session_id());
        let mut paused = Duration::ZERO;
        loop {
            let input = match start {
                SessionStart::Resume(_) => RESUME_PROMPT,
                SessionStart::Named(_) | SessionStart::New => prompt,
            };
            let command = self.command(worktree, model, turns, &start);
            let watch = self.session.watch(Some(turns), None);
            let ended = Running::spawn(command, Some(input.to_owned()), Some(log), watch)?.wait();
            if let Ended::UsageLimited { .. } = ended {
                std::thread::sleep(self.session.retry_after_limit);
                paused += self.session.retry_after_limit;
                if let SessionStart::Named(id) = start {
                    start = SessionStart::Resume(id);
                }
                continue;
            }
            let (input_tokens, output_tokens) = ended
                .report()
                .result
                .as_ref()
                .map_or((0, 0), |r| (r.input_tokens, r.output_tokens));
            let output = std::fs::read_to_string(worktree.join(out))
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok());
            return Ok(Pass {
                output,
                input_tokens,
                output_tokens,
                paused,
            });
        }
    }

    fn command(&self, worktree: &Path, model: &str, turns: u32, start: &SessionStart) -> Command {
        let mut command = Command::new(&self.claude);
        command.args([
            "-p",
            "--model",
            model,
            "--max-turns",
            &turns.to_string(),
            "--permission-mode",
            "dontAsk",
            "--output-format",
            "stream-json",
            "--verbose",
            "--allowedTools",
            FINDER_TOOLS,
            "--disallowedTools",
            DENIED_TOOLS,
        ]);
        match start {
            SessionStart::Named(id) => command.args(["--session-id", id]),
            SessionStart::Resume(id) => command.args(["--resume", id]),
            SessionStart::New => &mut command,
        };
        command
            .current_dir(worktree)
            .env("CLAUDE_PROJECT_DIR", worktree);
        for name in [
            AGENT_VARIABLE,
            WORK_ITEM_VARIABLE,
            SCOPE_VARIABLE,
            LAUNCHER_MODEL_VARIABLE,
        ] {
            command.env_remove(name);
        }
        command
    }
}
