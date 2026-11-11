//! What a handler needs before it starts: its registered `timeout` from `.agents/kit/hooks.toml`
//! and the `[hook.*]` tables of `.agents/kit/limits.toml` (owner instructions 15 and 26). The
//! handlers read hooks.toml on their own, without the renderer's checks, so a handler learns its
//! deadline even when `kit check` would reject another entry.

use std::time::Duration;

use anyhow::{Context as _, Result};
use serde::Deserialize;

use crate::config::limits::{HookLimits, Limits};
use crate::repo::Repo;

pub const HOOKS_FILE: &str = ".agents/kit/hooks.toml";

#[derive(Debug, Clone)]
pub struct Registration {
    pub limits: HookLimits,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct HooksData {
    #[serde(default)]
    hook: Vec<RegisteredHook>,
}

#[derive(Debug, Deserialize)]
struct RegisteredHook {
    handler: Option<String>,
    timeout: Option<u64>,
}

impl Registration {
    /// The hook limits and `handler`'s registered timeout; either missing is an error.
    pub fn load(repo: &Repo, handler: &str) -> Result<Registration> {
        let timeout = HooksData::load(repo)?.timeout(handler)?;
        Ok(Registration {
            limits: load(repo)?,
            timeout,
        })
    }

    /// The registered timeout less the margin, and never less than half the timeout.
    pub fn deadline(&self) -> Duration {
        self.timeout
            .saturating_sub(self.limits.runner.deadline_margin())
            .max(self.timeout / 2)
    }
}

impl HooksData {
    fn load(repo: &Repo) -> Result<HooksData> {
        let text = repo.read(HOOKS_FILE)?;
        HooksData::parse(&text)
    }

    fn parse(text: &str) -> Result<HooksData> {
        crate::config::parse_toml(text, HOOKS_FILE)
    }

    fn timeout(&self, handler: &str) -> Result<Duration> {
        self.hook
            .iter()
            .find(|hook| hook.handler.as_deref() == Some(handler))
            .and_then(|hook| hook.timeout)
            .map(Duration::from_secs)
            .with_context(|| format!("{HOOKS_FILE} registers no timeout for `{handler}`"))
    }
}

/// The `[hook.*]` tables the handlers read.
pub fn load(repo: &Repo) -> Result<HookLimits> {
    Ok(Limits::working_tree(repo)?.hook)
}

#[cfg(test)]
pub fn kit_limits() -> HookLimits {
    Limits::built_with().unwrap().hook.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kit_file_registers_a_timeout_for_every_handler() {
        let data = HooksData::parse(include_str!("../../../.agents/kit/hooks.toml")).unwrap();
        for handler in crate::hook::HANDLERS {
            assert!(
                data.timeout(handler).is_ok(),
                "{handler} has no registered timeout"
            );
        }
    }

    #[test]
    fn deadline_is_timeout_minus_the_margin_and_at_least_half() {
        let registration = |seconds| Registration {
            limits: kit_limits(),
            timeout: Duration::from_secs(seconds),
        };
        let margin = kit_limits().runner.deadline_margin();
        assert_eq!(
            registration(600).deadline(),
            Duration::from_secs(600).saturating_sub(margin)
        );
        assert_eq!(registration(2).deadline(), Duration::from_secs(1));
    }

    #[test]
    fn a_handler_without_a_timeout_fails() {
        let data =
            HooksData::parse("[[hook]]\nevent = \"Stop\"\nhandler = \"stop-gate\"\n").unwrap();
        assert!(data.timeout("stop-gate").is_err());
        assert!(data.timeout("post-edit").is_err());
    }
}
