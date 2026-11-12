//! The kit binary contract (team/03 section 1) around one handler: stdin is read and parsed inside
//! the deadline, a panic is caught, and the answer is printed in the event's form with a log path.
//! The deadline is the registered timeout less `[hook.runner] deadline_margin_s` of
//! `.agents/kit/limits.toml`, so the binary answers before Claude Code gives up on it. A handler
//! whose registration cannot be read fails at once, as its failure policy says.

use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;

use anyhow::{Context as _, Result};

use super::context::{Context, Env, Input, Progress};
use super::limits::Registration;
use super::outcome::Outcome;
use super::{Failure, Handler, stop_gate};
use crate::clock::Utc;
use crate::config::limits::HookLimits;
use crate::gates::LOG_DIR;
use crate::repo::{Repo, write_if_changed};

static PANIC_MESSAGE: Mutex<Option<String>> = Mutex::new(None);

type Finished = std::thread::Result<Result<Outcome>>;

pub fn run(handler: Handler) -> ExitCode {
    let started = Instant::now();
    let env = Env::capture();
    let repo = Repo::discover().ok();
    let progress = Arc::new(Mutex::new(Progress::default()));
    let registration = repo
        .as_ref()
        .context("cannot find the repository: CLAUDE_PROJECT_DIR is unset and the working directory is outside it")
        .and_then(|repo| Registration::load(repo, handler.name()));
    let (outcome, failure, limits) = match registration {
        Ok(registration) => {
            let (outcome, failure) =
                supervise(handler, repo.clone(), env, &registration, &progress);
            (outcome, failure, Some(registration.limits))
        }
        Err(error) => {
            let reason = format!("cannot read its registration: {error:#}");
            let outcome = on_failure(handler, repo.as_ref(), &progress, &reason, None);
            (outcome, Some(reason), None)
        }
    };
    let log = write_log(
        handler,
        repo.as_ref(),
        &outcome,
        failure.as_deref(),
        &progress,
        started,
    );
    let rendered = outcome.render(handler.event(), log.as_deref(), limits.as_ref());
    if !rendered.stdout.is_empty() {
        println!("{}", rendered.stdout);
    }
    if !rendered.stderr.is_empty() {
        eprint!("{}", rendered.stderr);
    }
    ExitCode::from(rendered.code)
}

/// Runs the handler on its own thread and waits until its deadline; a panic, an error or a
/// missed deadline becomes the handler's failure outcome and the reason for the log.
fn supervise(
    handler: Handler,
    repo: Option<Repo>,
    env: Env,
    registration: &Registration,
    progress: &Arc<Mutex<Progress>>,
) -> (Outcome, Option<String>) {
    let Some(deadline) = Instant::now().checked_add(registration.deadline()) else {
        let reason = format!(
            "has a registered timeout of {} s, past what this machine's clock can count to",
            registration.timeout.as_secs()
        );
        let outcome = on_failure(
            handler,
            repo.as_ref(),
            progress,
            &reason,
            Some(&registration.limits),
        );
        return (outcome, Some(reason));
    };
    panic::set_hook(Box::new(|info| {
        if let Ok(mut message) = PANIC_MESSAGE.lock() {
            *message = Some(info.to_string());
        }
    }));
    let (sender, receiver) = mpsc::channel::<Finished>();
    let worker_progress = Arc::clone(progress);
    let worker_repo = repo.clone();
    let worker_limits = registration.limits.clone();
    thread::spawn(move || {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            execute(
                handler,
                worker_repo,
                env,
                deadline,
                worker_progress,
                worker_limits,
            )
        }));
        let _ = sender.send(result);
    });
    let waited = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let reason = match waited {
        Ok(Ok(Ok(outcome))) => return (outcome, None),
        Ok(Ok(Err(error))) => format!("failed: {error:#}"),
        Ok(Err(_)) => {
            let message = PANIC_MESSAGE
                .lock()
                .ok()
                .and_then(|m| m.clone())
                .unwrap_or_default();
            format!("panicked: {message}")
        }
        Err(_) => format!(
            "missed its deadline of {} s",
            registration.deadline().as_secs_f32()
        ),
    };
    let outcome = on_failure(
        handler,
        repo.as_ref(),
        progress,
        &reason,
        Some(&registration.limits),
    );
    (outcome, Some(reason))
}

fn execute(
    handler: Handler,
    repo: Option<Repo>,
    env: Env,
    deadline: Instant,
    progress: Arc<Mutex<Progress>>,
    limits: HookLimits,
) -> Result<Outcome> {
    let repo = repo.context("cannot find the repository")?;
    let mut text = String::new();
    std::io::stdin()
        .take(limits.runner.input_bytes)
        .read_to_string(&mut text)
        .context("reading the hook input from stdin")?;
    let input = Input::parse(&text)?;
    if let Ok(mut shared) = progress.lock() {
        shared.session = input.session_id().map(str::to_owned);
        shared.detail.push(format!(
            "input: {}",
            excerpt(&text, limits.runner.logged_input_chars)
        ));
    }
    let context = Context::new(repo, input, env, deadline, progress, limits);
    handler.handle(&context)
}

fn on_failure(
    handler: Handler,
    repo: Option<&Repo>,
    progress: &Mutex<Progress>,
    reason: &str,
    limits: Option<&HookLimits>,
) -> Outcome {
    match handler.failure() {
        Failure::Allow => Outcome::Allow,
        Failure::Block => Outcome::Block(format!(
            "{}: the hook {reason}, so the action is blocked; retry, and if it keeps failing run `cargo xtask kit install`",
            handler.name()
        )),
        Failure::CountedBlock => {
            let (session, digest) = progress
                .lock()
                .map(|shared| (shared.session.clone(), shared.digest.clone()))
                .unwrap_or_default();
            match repo {
                Some(repo) => stop_gate::after_failure(
                    repo,
                    session.as_deref(),
                    digest.as_deref(),
                    reason,
                    limits,
                    progress,
                ),
                None => Outcome::Allow,
            }
        }
    }
}

fn write_log(
    handler: Handler,
    repo: Option<&Repo>,
    outcome: &Outcome,
    failure: Option<&str>,
    progress: &Mutex<Progress>,
    started: Instant,
) -> Option<String> {
    let repo = repo?;
    let detail = progress
        .lock()
        .map(|shared| shared.detail.clone())
        .unwrap_or_default();
    if outcome.is_quiet() && failure.is_none() && detail.len() <= 1 {
        return None;
    }
    let stamp = Utc::now();
    let path = format!(
        "{LOG_DIR}/{}-{}-{}.log",
        handler.name(),
        stamp.compact(),
        std::process::id()
    );
    let mut text = format!(
        "handler: {}\nevent: {}\nat: {}\nelapsed_ms: {}\noutcome: {}\n",
        handler.name(),
        handler.event().name(),
        stamp.iso(),
        started.elapsed().as_millis(),
        outcome.kind()
    );
    if let Some(failure) = failure {
        text.push_str(&format!("failure: {failure}\n"));
    }
    for line in detail {
        text.push_str(&line);
        text.push('\n');
    }
    if !outcome.text().is_empty() {
        text.push_str("---\n");
        text.push_str(outcome.text());
        text.push('\n');
    }
    write_if_changed(&repo.path(&path), text.as_bytes()).ok()?;
    Some(path)
}

fn excerpt(text: &str, max_chars: usize) -> String {
    let mut out: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        out.push_str(&format!("... ({} bytes)", text.len()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_past_the_clock_fails_closed() {
        let registration = Registration {
            limits: crate::config::limits::Limits::built_with()
                .unwrap()
                .hook
                .clone(),
            timeout: std::time::Duration::from_secs(u64::MAX),
        };
        let progress = Arc::new(Mutex::new(Progress::default()));
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let (outcome, reason) = supervise(Handler::GuardPath, None, env, &registration, &progress);
        assert!(matches!(outcome, Outcome::Block(_)), "{outcome:?}");
        assert!(reason.unwrap().contains("past what"));
    }

    #[test]
    fn excerpts_are_cut_and_say_so() {
        assert_eq!(excerpt("abc", 5), "abc");
        assert_eq!(excerpt("abcdef", 3), "abc... (6 bytes)");
    }
}
