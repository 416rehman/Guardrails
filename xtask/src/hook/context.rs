//! What a handler reads: the hook event's JSON from stdin, the environment the launcher set, the
//! repository, and its own deadline. Paths in the payload are placed relative to the repository
//! root before any match (team/03 section 1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde_json::Value;

use crate::config::limits::HookLimits;
use crate::paths::{Located, RepoPath};
use crate::repo::Repo;

/// Variables whose value the hook may substitute into a shell word, because the shell that runs
/// the command inherits them unchanged from the same Claude Code process.
const RESOLVABLE: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "CLAUDE_PROJECT_DIR",
];

#[derive(Debug, Clone, Default)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Input {
    value: Value,
}

/// Facts a handler leaves behind for the runner, which still has them when the handler misses
/// its deadline or panics.
#[derive(Debug, Default)]
pub struct Progress {
    pub session: Option<String>,
    pub digest: Option<String>,
    pub detail: Vec<String>,
}

pub struct Context {
    pub repo: Repo,
    pub input: Input,
    pub env: Env,
    pub deadline: Instant,
    pub progress: Arc<Mutex<Progress>>,
    pub limits: HookLimits,
}

impl Env {
    pub fn capture() -> Env {
        Env {
            vars: std::env::vars_os()
                .map(|(name, value)| {
                    (
                        name.to_string_lossy().into_owned(),
                        value.to_string_lossy().into_owned(),
                    )
                })
                .collect(),
        }
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Env
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Env {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// A set, non-empty value.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars
            .get(name)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }

    /// The names of every variable with a value.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.vars
            .iter()
            .filter(|(_, value)| !value.trim().is_empty())
            .map(|(name, _)| name.as_str())
    }

    pub fn lookup(&self) -> impl Fn(&str) -> Option<String> + '_ {
        |name| self.get(name).map(str::to_owned)
    }

    /// A variable the shell scanner may substitute; `HOME` falls back to `USERPROFILE`.
    pub fn resolvable(&self, name: &str) -> Option<String> {
        if !RESOLVABLE.contains(&name) {
            return None;
        }
        let value = self
            .get(name)
            .or_else(|| (name == "HOME").then(|| self.get("USERPROFILE")).flatten())?;
        Some(value.replace('\\', "/"))
    }

    pub fn home(&self) -> Option<PathBuf> {
        self.get("HOME")
            .or_else(|| self.get("USERPROFILE"))
            .map(PathBuf::from)
    }
}

impl Input {
    pub fn parse(text: &str) -> Result<Input> {
        let value: Value = serde_json::from_str(text).context("the hook input is not JSON")?;
        if !value.is_object() {
            bail!("the hook input is not a JSON object");
        }
        Ok(Input { value })
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        self.value
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    }

    /// A JSON pointer such as `/tool_input/file_path`.
    pub fn at(&self, pointer: &str) -> Option<&Value> {
        self.value.pointer(pointer)
    }

    pub fn text_at(&self, pointer: &str) -> Option<&str> {
        self.at(pointer).and_then(Value::as_str)
    }

    pub fn session_id(&self) -> Option<&str> {
        self.str("session_id")
    }

    pub fn tool_name(&self) -> Option<&str> {
        self.str("tool_name")
    }

    pub fn agent_type(&self) -> Option<&str> {
        self.str("agent_type")
    }

    /// Set when the event comes from a subagent rather than the main thread.
    pub fn agent_id(&self) -> Option<&str> {
        self.str("agent_id")
    }

    pub fn cwd(&self) -> Option<PathBuf> {
        self.str("cwd").map(PathBuf::from)
    }

    pub fn path(&self, key: &str, env: &Env) -> Option<PathBuf> {
        self.str(key).map(|raw| expand_home(raw, env))
    }
}

impl Context {
    pub fn new(
        repo: Repo,
        input: Input,
        env: Env,
        deadline: Instant,
        progress: Arc<Mutex<Progress>>,
        limits: HookLimits,
    ) -> Context {
        Context {
            repo,
            input,
            env,
            deadline,
            progress,
            limits,
        }
    }

    /// Where a payload path lands: relative paths are taken against the payload's `cwd`.
    pub fn locate(&self, raw: &str) -> Located {
        let cwd = self.input.cwd();
        self.repo.locate(raw, cwd.as_deref())
    }

    pub fn locate_inside(&self, raw: &str) -> Option<RepoPath> {
        match self.locate(raw) {
            Located::Inside(path) => Some(path),
            Located::Outside(_) => None,
        }
    }

    /// The payload's working directory, or the root when it has none.
    pub fn cwd(&self) -> PathBuf {
        self.input
            .cwd()
            .unwrap_or_else(|| self.repo.root().to_path_buf())
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn note(&self, line: impl Into<String>) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.detail.push(line.into());
        }
    }

    pub fn record_digest(&self, digest: &str) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.digest = Some(digest.to_owned());
        }
    }
}

/// `~/x` against the home directory; other paths unchanged.
pub fn expand_home(raw: &str, env: &Env) -> PathBuf {
    match (
        raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")),
        env.home(),
    ) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(raw),
    }
}

/// The file a tool call names: `file_path`, `notebook_path` for NotebookEdit, or `path`.
pub fn tool_path(input: &Input) -> Option<&str> {
    input
        .text_at("/tool_input/file_path")
        .or_else(|| input.text_at("/tool_input/notebook_path"))
        .or_else(|| input.text_at("/tool_input/path"))
        .filter(|path| !path.is_empty())
}

pub fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_values_and_resolvable_variables() {
        let env = Env::from_pairs([
            ("GRDR_AGENT", " impl-rust "),
            ("EMPTY", ""),
            ("USERPROFILE", r"C:\Users\dev"),
        ]);
        assert_eq!(env.get("GRDR_AGENT"), Some("impl-rust"));
        assert_eq!(env.get("EMPTY"), None);
        assert_eq!(env.resolvable("HOME").as_deref(), Some("C:/Users/dev"));
        assert_eq!(env.resolvable("GRDR_AGENT"), None);
    }

    #[test]
    fn input_accessors() {
        let input = Input::parse(
            r#"{"session_id":"s1","tool_input":{"notebook_path":"a.ipynb"},"agent_type":""}"#,
        )
        .unwrap();
        assert_eq!(input.session_id(), Some("s1"));
        assert_eq!(input.agent_type(), None);
        assert_eq!(tool_path(&input), Some("a.ipynb"));
        assert!(Input::parse("[1]").is_err());
        assert!(Input::parse("{").is_err());
    }
}
