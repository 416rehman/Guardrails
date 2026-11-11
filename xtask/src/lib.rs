//! Repository tooling for Guardrails ADR: the agent kit, the gates and the hook binary
//! (team/03, team/05). `main.rs` routes each subcommand to one of these modules.

pub mod cli;
pub mod clock;
pub mod config;
pub mod dispatch;
pub mod frontmatter;
pub mod gates;
pub mod git;
pub mod github;
pub mod globs;
pub mod hook;
pub mod kit;
pub mod lock;
pub mod orchestrate;
pub mod paths;
pub mod process;
pub mod repo;

#[cfg(test)]
mod testkit;
