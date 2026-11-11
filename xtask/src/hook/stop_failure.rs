//! `StopFailure` (D-47): a turn that ends on an API error is recorded in
//! `.agent/state/stop-failure-<session>.json`, so the dispatcher pauses on a usage limit instead
//! of counting a failed attempt. The cause is a usage limit when the error text or its details
//! contain one of `.agents/harness.toml [limits] usage_limit_strings`, and an API error otherwise.
//! Claude Code ignores this hook's output and exit code.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::context::Context;
use super::outcome::Outcome;
use super::state::{STATE_DIR, safe_id, write_json};
use crate::clock::Utc;
use crate::config::runtime::Harness;
use crate::config::session::Session;

pub const STOP_FAILURE_SCHEMA: &str = "stop-failure.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cause {
    /// The subscription's usage window is spent: pause, never fail.
    UsageLimit,
    ApiError,
}

/// The last API error a session's turn ended on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopFailure {
    pub schema: String,
    pub session_id: String,
    pub agent: Option<String>,
    pub work_item: Option<u64>,
    /// Claude Code's error type, such as `rate_limit` or `server_error`.
    pub error: String,
    pub details: Option<String>,
    pub message: Option<String>,
    pub cause: Cause,
    pub at: String,
}

impl StopFailure {
    pub fn path(session_id: &str) -> String {
        format!("{STATE_DIR}/stop-failure-{}.json", safe_id(session_id))
    }
}

pub fn run(context: &Context) -> Result<Outcome> {
    let Some(session_id) = context.input.session_id() else {
        context.note("a StopFailure event without a session id; nothing recorded");
        return Ok(Outcome::Allow);
    };
    let details = context.input.str("error_details").map(str::to_owned);
    let message = context
        .input
        .str("last_assistant_message")
        .map(str::to_owned);
    let limit_strings = Harness::load(&context.repo)?.limits.usage_limit_strings;
    let limited = [details.as_deref(), message.as_deref()]
        .into_iter()
        .flatten()
        .any(|text| {
            limit_strings
                .iter()
                .any(|limit| text.contains(limit.as_str()))
        });
    let session = Session::from_lookup(context.env.lookup()).ok();
    let record = StopFailure {
        schema: STOP_FAILURE_SCHEMA.to_owned(),
        session_id: session_id.to_owned(),
        agent: session.as_ref().and_then(|session| session.agent.clone()),
        work_item: session.as_ref().and_then(|session| session.work_item),
        error: context.input.str("error").unwrap_or("unknown").to_owned(),
        details,
        message,
        cause: if limited {
            Cause::UsageLimit
        } else {
            Cause::ApiError
        },
        at: Utc::now().iso(),
    };
    let path = StopFailure::path(session_id);
    write_json(&context.repo, &path, &record)?;
    context.note(format!(
        "recorded {} ({:?}) in {path}",
        record.error, record.cause
    ));
    Ok(Outcome::Allow)
}
