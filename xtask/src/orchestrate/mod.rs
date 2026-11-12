//! The session launcher and the work-item tooling around GitHub issues (team/03 K6, owner
//! instructions 5 to 8): `kit launch`, `kit ready`, `kit handoff`, `kit digest`, `kit claim`,
//! `kit ci-env`, `labels`, `risk`, `prove` and `audit`. Work items are issues of the repository
//! `.agents/harness.toml` names and nothing else; every GitHub call goes through
//! [`crate::github::Gh`].

pub mod audit;
pub mod claude;
pub mod digest;
pub mod form;
pub mod handoff;
pub mod ids;
pub mod issue;
pub mod labels;
pub mod launch;
pub mod overlap;
pub mod prove;
pub mod ready;
pub mod records;
pub mod risk;
pub mod tiers;
pub mod tracker;

#[cfg(test)]
pub(crate) mod testkit;

use std::process::ExitCode;

use anyhow::{Result, bail};

/// Routes `labels`, `risk`, `prove`, `audit` and every `kit <sub>` that is not render, check or
/// install. `risk`, `prove` and `audit` also answer as `kit risk`, `kit prove` and `kit audit`.
pub fn run(command: &str, args: &[String]) -> Result<ExitCode> {
    let name = command.strip_prefix("kit ").unwrap_or(command);
    match name {
        "labels" => labels::command(args),
        "launch" => launch::command(args),
        "ready" => ready::command(args),
        "handoff" => handoff::command(args),
        "digest" => digest::command(args),
        "claim" => crate::dispatch::claim_command(args),
        "ci-env" => crate::dispatch::ci_env::command(args),
        "risk" => risk::command(args),
        "prove" => prove::command(args),
        "audit" => audit::command(args),
        other => bail!(
            "xtask {other}: unknown; the orchestration commands are kit launch, kit ready, kit handoff, kit digest, kit claim, kit ci-env, labels, risk, prove and audit"
        ),
    }
}
