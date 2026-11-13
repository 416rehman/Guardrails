//! The locks a launch holds while its session runs: one fable session on the machine, and one
//! printed session of an agent on an item in its checkout. A launch a lock refuses exits with the
//! plan's busy code, so the dispatcher starts that session again later.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;

use super::Plan;
use crate::config::limits::Limits;
use crate::lock::{Busy, Lock};
use crate::repo::Repo;

/// One fable session at a time on this machine (design/_review/03: on demand, never in a loop).
const FABLE_LOCK: &str = "grdr-fable-session.lock";
pub(super) const FABLE_BUSY: &str =
    "a fable session already runs on this machine; the chief architect runs one session at a time";
const SESSION_BUSY: &str = "this agent's session on this item already runs in this checkout";

/// The machine-wide lock path for fable sessions.
pub fn fable_lock_path() -> PathBuf {
    std::env::temp_dir().join(FABLE_LOCK)
}

/// Whether a fable session already runs on this machine.
pub fn fable_session_running() -> Result<bool> {
    let heartbeat = Limits::built_with()?.orchestrate.launch.lock_heartbeat();
    Ok(Lock::is_held(&fable_lock_path(), heartbeat))
}

/// The lock a printed session of `agent` on `item` holds in `checkout` while it runs.
pub fn session_lock_path(checkout: &Repo, item: u64, agent: &str) -> PathBuf {
    checkout.path(&format!(".agent/state/session-{item}-{agent}.lock"))
}

/// Whether a printed session of `agent` on `item` runs in `checkout`.
pub fn session_running(checkout: &Repo, item: u64, agent: &str) -> Result<bool> {
    let heartbeat = Limits::built_with()?.orchestrate.launch.lock_heartbeat();
    let path = session_lock_path(checkout, item, agent);
    Ok(Lock::is_held(&path, heartbeat))
}

/// The locks `plan`'s session holds while it runs; one a fresh holder has refuses it with
/// [`Busy`].
pub(super) fn take(plan: &Plan) -> Result<Vec<Lock>> {
    let heartbeat = Limits::built_with()?.orchestrate.launch.lock_heartbeat();
    let fable = (plan.model.name == "fable").then(|| (fable_lock_path(), FABLE_BUSY));
    let session = plan.session_lock.clone().map(|path| (path, SESSION_BUSY));
    [session, fable]
        .into_iter()
        .flatten()
        .map(|(path, busy)| Lock::take(path, heartbeat, busy))
        .collect()
}

/// A launch a lock refused exits with `code`, the plan's busy code, so the dispatcher starts its
/// session again later instead of ending the attempt; any other error stays one.
pub(super) fn busy_exit(error: anyhow::Error, code: Option<u8>) -> Result<ExitCode> {
    match code {
        Some(code) if error.is::<Busy>() => {
            eprintln!("kit launch: {error:#}");
            Ok(ExitCode::from(code))
        }
        _ => Err(error),
    }
}
