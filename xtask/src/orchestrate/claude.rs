//! Watching a headless Claude Code session (`claude -p --output-format stream-json --verbose`)
//! for the dispatcher and the audit runner: every output line goes to a log, assistant turns are
//! counted, a stall, a turn cap or a deadline ends the session, and a subscription usage limit
//! (the strings in `.agents/harness.toml [limits]`) ends it as a pause, never as a failure.
//! Ending a session kills its whole process tree, because the session runs under `kit launch`.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::config;
use crate::config::limits::Limits;
use crate::repo::Repo;

const SYNTHETIC_MODEL: &str = "<synthetic>";

/// What every session the dispatcher or the audit runner starts is watched for, from
/// `.agents/harness.toml` and `.agents/kit/limits.toml [orchestrate.claude]`. Every key is
/// required.
#[derive(Debug, Clone)]
pub struct SessionRules {
    /// A session with no output for this long has stalled (`[dispatch] stall_seconds`).
    pub stall: Duration,
    /// How long after a usage limit the window is tried again (`[limits] retry_seconds`).
    pub retry_after_limit: Duration,
    pub limit_strings: Vec<String>,
    pub poll: Duration,
    /// After the process exits, how long to wait for a grandchild that still holds the pipes.
    pub drain_grace: Duration,
    /// Claude Code stops itself at `--max-turns`; the watch stops a session this many turns
    /// past it, so the two counts never race.
    pub turn_margin: u32,
}

#[derive(Deserialize)]
struct RulesFile {
    dispatch: StallKey,
    limits: LimitKeys,
}

#[derive(Deserialize)]
struct StallKey {
    stall_seconds: u64,
}

#[derive(Deserialize)]
struct LimitKeys {
    usage_limit_strings: Vec<String>,
    retry_seconds: u64,
}

/// The limits one session runs under.
#[derive(Debug, Clone)]
pub struct Watch {
    pub stall: Duration,
    pub turn_cap: Option<u32>,
    pub deadline: Option<Duration>,
    pub limit_strings: Vec<String>,
    pub poll: Duration,
    pub drain_grace: Duration,
    pub turn_margin: u32,
}

/// The `result` event of a finished session.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunResult {
    pub subtype: String,
    pub is_error: bool,
    pub num_turns: Option<u32>,
    pub session_id: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub text: String,
}

/// What a session did, whatever ended it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub turns: u32,
    pub result: Option<RunResult>,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Ended {
    Exited {
        code: Option<i32>,
        report: Report,
    },
    /// A usage limit: the session is resumable and the attempt does not count.
    UsageLimited {
        matched: String,
        report: Report,
    },
    Stalled {
        quiet: Duration,
        report: Report,
    },
    OverTurns {
        report: Report,
    },
    OverTime {
        report: Report,
    },
}

enum Line {
    Out(String),
    Err(String),
}

enum Process {
    Alive(Child),
    Exited { code: Option<i32>, at: Instant },
}

pub struct Running {
    process: Process,
    lines: Receiver<Line>,
    log: Option<File>,
    started: Instant,
    last_output: Instant,
    message_ids: BTreeSet<String>,
    unnamed_turns: u32,
    result: Option<RunResult>,
    watch: Watch,
}

impl SessionRules {
    pub fn load(repo: &Repo) -> Result<SessionRules> {
        let (label, path) = config::agents_file(repo, "harness.toml");
        let file: RulesFile = config::read_toml(&path, &label)?;
        let limits = &Limits::built_with()?.orchestrate.claude;
        Ok(SessionRules {
            stall: Duration::from_secs(file.dispatch.stall_seconds),
            retry_after_limit: Duration::from_secs(file.limits.retry_seconds),
            limit_strings: file.limits.usage_limit_strings,
            poll: limits.poll(),
            drain_grace: limits.drain_grace(),
            turn_margin: limits.turn_margin,
        })
    }

    /// The watch for one session under these rules.
    pub fn watch(&self, turn_cap: Option<u32>, deadline: Option<Duration>) -> Watch {
        Watch {
            stall: self.stall,
            turn_cap,
            deadline,
            limit_strings: self.limit_strings.clone(),
            poll: self.poll,
            drain_grace: self.drain_grace,
            turn_margin: self.turn_margin,
        }
    }
}

impl Ended {
    pub fn report(&self) -> &Report {
        match self {
            Ended::Exited { report, .. }
            | Ended::UsageLimited { report, .. }
            | Ended::Stalled { report, .. }
            | Ended::OverTurns { report }
            | Ended::OverTime { report } => report,
        }
    }

    pub fn describe(&self) -> String {
        let turns = self.report().turns;
        match self {
            Ended::Exited { code, .. } => format!(
                "exited {} after {turns} turns",
                code.map_or_else(|| "by signal".to_owned(), |code| code.to_string())
            ),
            Ended::UsageLimited { matched, .. } => format!("paused at a usage limit (`{matched}`)"),
            Ended::Stalled { quiet, .. } => format!("stalled: no output for {} s", quiet.as_secs()),
            Ended::OverTurns { .. } => format!("stopped at the turn cap after {turns} turns"),
            Ended::OverTime { .. } => format!("stopped at its deadline after {turns} turns"),
        }
    }
}

impl Running {
    /// Starts `command` with `stdin` as its input and its output logged to `log`.
    pub fn spawn(
        mut command: Command,
        stdin: Option<String>,
        log: Option<&Path>,
        watch: Watch,
    ) -> Result<Running> {
        command
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        own_group(&mut command);
        let mut child = command.spawn().context("starting the session")?;
        if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
            thread::spawn(move || {
                let _ = pipe.write_all(text.as_bytes());
            });
        }
        let (sender, lines) = mpsc::channel();
        if let Some(out) = child.stdout.take() {
            read_lines(out, sender.clone(), Line::Out);
        }
        if let Some(err) = child.stderr.take() {
            read_lines(err, sender, Line::Err);
        }
        let log = match log {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                Some(File::create(path).with_context(|| format!("creating {}", path.display()))?)
            }
            None => None,
        };
        let now = Instant::now();
        Ok(Running {
            process: Process::Alive(child),
            lines,
            log,
            started: now,
            last_output: now,
            message_ids: BTreeSet::new(),
            unnamed_turns: 0,
            result: None,
            watch,
        })
    }

    /// Reads what arrived and returns how the session ended, once it has.
    pub fn poll(&mut self) -> Option<Ended> {
        let now = Instant::now();
        let disconnected = loop {
            match self.lines.try_recv() {
                Ok(line) => {
                    if let Some(matched) = self.observe(line, now) {
                        self.kill();
                        return Some(Ended::UsageLimited {
                            matched,
                            report: self.report(),
                        });
                    }
                }
                Err(TryRecvError::Empty) => break false,
                Err(TryRecvError::Disconnected) => break true,
            }
        };
        let exit = match &mut self.process {
            Process::Alive(child) => match child.try_wait() {
                Ok(Some(status)) => Some(status.code()),
                Ok(None) => return self.limit_reached(now),
                Err(_) => Some(None),
            },
            Process::Exited { code, at } => {
                let (code, at) = (*code, *at);
                let drained = disconnected || now.duration_since(at) >= self.watch.drain_grace;
                return drained.then(|| Ended::Exited {
                    code,
                    report: self.report(),
                });
            }
        };
        if let Some(code) = exit {
            self.process = Process::Exited { code, at: now };
        }
        None
    }

    /// Polls until the session ends.
    pub fn wait(&mut self) -> Ended {
        loop {
            if let Some(ended) = self.poll() {
                return ended;
            }
            thread::sleep(self.watch.poll);
        }
    }

    /// Ends the session now, as a pause; its transcript stays resumable.
    pub fn stop(&mut self) -> Ended {
        self.kill();
        Ended::UsageLimited {
            matched: "paused with the other sessions".to_owned(),
            report: self.report(),
        }
    }

    fn limit_reached(&mut self, now: Instant) -> Option<Ended> {
        let quiet = now.duration_since(self.last_output);
        let ended = if quiet >= self.watch.stall {
            Some(Ended::Stalled {
                quiet,
                report: self.report(),
            })
        } else if self
            .watch
            .turn_cap
            .is_some_and(|cap| self.turns() > cap.saturating_add(self.watch.turn_margin))
        {
            Some(Ended::OverTurns {
                report: self.report(),
            })
        } else if self
            .watch
            .deadline
            .is_some_and(|deadline| now.duration_since(self.started) >= deadline)
        {
            Some(Ended::OverTime {
                report: self.report(),
            })
        } else {
            None
        };
        if ended.is_some() {
            self.kill();
        }
        ended
    }

    fn turns(&self) -> u32 {
        u32::try_from(self.message_ids.len())
            .unwrap_or(u32::MAX)
            .saturating_add(self.unnamed_turns)
    }

    fn report(&self) -> Report {
        Report {
            turns: self.turns(),
            result: self.result.clone(),
            elapsed: self.started.elapsed(),
        }
    }

    /// Logs a line and reads what it says; returns the usage-limit string it carries, if any.
    fn observe(&mut self, line: Line, now: Instant) -> Option<String> {
        self.last_output = now;
        let (text, from_stderr) = match line {
            Line::Out(text) => (text, false),
            Line::Err(text) => (text, true),
        };
        if let Some(log) = &mut self.log {
            let prefix = if from_stderr { "stderr: " } else { "" };
            let _ = writeln!(log, "{prefix}{text}");
        }
        let event: Option<Value> = text
            .trim_start()
            .starts_with('{')
            .then(|| serde_json::from_str(&text).ok())
            .flatten();
        let Some(event) = event else {
            return self.limit_in(&text);
        };
        match event.get("type").and_then(Value::as_str) {
            Some("assistant") => self.assistant(&event),
            Some("result") => self.finish(&event),
            _ => None,
        }
    }

    fn assistant(&mut self, event: &Value) -> Option<String> {
        let message = event.get("message");
        match message.and_then(|m| m.get("id")).and_then(Value::as_str) {
            Some(id) => {
                self.message_ids.insert(id.to_owned());
            }
            None => self.unnamed_turns = self.unnamed_turns.saturating_add(1),
        }
        let synthetic = message.and_then(|m| m.get("model")).and_then(Value::as_str)
            == Some(SYNTHETIC_MODEL)
            || event.get("error").is_some();
        if !synthetic {
            return None;
        }
        self.limit_in(&message_text(message))
    }

    fn finish(&mut self, event: &Value) -> Option<String> {
        let usage = event.get("usage");
        let tokens = |key: &str| {
            usage
                .and_then(|u| u.get(key))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        };
        let result = RunResult {
            subtype: event
                .get("subtype")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            is_error: event
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            num_turns: event
                .get("num_turns")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            session_id: event
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            input_tokens: tokens("input_tokens"),
            output_tokens: tokens("output_tokens"),
            text: event
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        };
        let limited = if result.is_error {
            self.limit_in(&result.text)
        } else {
            None
        };
        self.result = Some(result);
        limited
    }

    fn limit_in(&self, text: &str) -> Option<String> {
        self.watch
            .limit_strings
            .iter()
            .find(|limit| !limit.is_empty() && text.contains(limit.as_str()))
            .cloned()
    }

    fn kill(&mut self) {
        if let Process::Alive(child) = &mut self.process {
            kill_tree(child);
            let code = child.wait().ok().and_then(|status| status.code());
            self.process = Process::Exited {
                code,
                at: Instant::now(),
            };
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The log path for one session of the dispatcher or the audit runner.
pub fn log_path(root: &Path, name: &str) -> PathBuf {
    root.join(".agent")
        .join("logs")
        .join(format!("{name}.jsonl"))
}

fn message_text(message: Option<&Value>) -> String {
    let Some(content) = message.and_then(|m| m.get("content")) else {
        return String::new();
    };
    match content {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn read_lines<R: Read + Send + 'static>(pipe: R, sender: Sender<Line>, wrap: fn(String) -> Line) {
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { break };
            if sender.send(wrap(line)).is_err() {
                break;
            }
        }
    });
}

#[cfg(unix)]
fn own_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn own_group(_command: &mut Command) {}

/// Kills the child and everything it started: `kit launch` runs `claude`, which runs tools.
fn kill_tree(child: &mut Child) {
    let id = child.id().to_string();
    let mut killer = if cfg!(windows) {
        let mut command = Command::new("taskkill");
        command.args(["/PID", id.as_str(), "/T", "/F"]);
        command
    } else {
        let mut command = Command::new("kill");
        command.args(["-KILL", "--", &format!("-{id}")]);
        command
    };
    let _ = killer.stdout(Stdio::null()).stderr(Stdio::null()).status();
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrate::testkit::FakeProgram;

    fn watch() -> Watch {
        Watch {
            stall: Duration::from_secs(30),
            turn_cap: Some(5),
            deadline: None,
            limit_strings: vec![
                "You've hit your session limit".into(),
                "Request rejected".into(),
            ],
            poll: Duration::from_millis(50),
            drain_grace: Duration::from_secs(2),
            turn_margin: 2,
        }
    }

    fn run(fake: &FakeProgram, watch: Watch) -> Ended {
        let command = Command::new(fake.program());
        Running::spawn(command, Some("the prompt".into()), None, watch)
            .unwrap()
            .wait()
    }

    const STREAM: &str = "{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"s-1\"}\n{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"model\":\"claude-sonnet-5-5\",\"content\":[{\"type\":\"text\",\"text\":\"The harness lists Request rejected as a limit.\"}]}}\n{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"content\":[]}}\n{\"type\":\"assistant\",\"message\":{\"id\":\"m2\",\"content\":[]}}\n{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"num_turns\":2,\"session_id\":\"s-1\",\"result\":\"done\",\"usage\":{\"input_tokens\":10,\"output_tokens\":4}}\n";

    #[test]
    fn counts_turns_and_reads_the_result() {
        let fake = FakeProgram::new("claude-ok");
        fake.respond(1, STREAM, 0);
        let ended = run(&fake, watch());
        let Ended::Exited { code, report } = &ended else {
            panic!("{ended:?}");
        };
        assert_eq!(*code, Some(0));
        assert_eq!(report.turns, 2);
        let result = report.result.clone().unwrap();
        assert_eq!(result.session_id.as_deref(), Some("s-1"));
        assert_eq!(result.output_tokens, 4);
        assert!(fake.stdin(1).contains("the prompt"));
    }

    #[test]
    fn usage_limits_pause_and_quoted_strings_do_not() {
        let fake = FakeProgram::new("claude-limit");
        fake.respond(1, "{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"result\":\"You've hit your session limit - resets 3pm\"}\n", 1);
        let ended = run(&fake, watch());
        assert!(
            matches!(ended, Ended::UsageLimited { ref matched, .. } if matched == "You've hit your session limit"),
            "{ended:?}"
        );
        let stderr = FakeProgram::new("claude-stderr");
        stderr.respond_err(1, "API Error: 429 Request rejected\n", 1);
        assert!(matches!(run(&stderr, watch()), Ended::UsageLimited { .. }));
    }

    #[test]
    fn stalls_and_turn_caps_end_the_session() {
        let fake = FakeProgram::new("claude-stall");
        fake.sleep(1, 4);
        let mut quick = watch();
        quick.stall = Duration::from_millis(400);
        let started = Instant::now();
        assert!(matches!(run(&fake, quick), Ended::Stalled { .. }));
        assert!(started.elapsed() < Duration::from_secs(4));
        let over = FakeProgram::new("claude-turns");
        over.respond(1, STREAM, 0);
        let mut capped = watch();
        capped.turn_cap = Some(1);
        let ended = run(&over, capped);
        assert!(
            matches!(ended, Ended::OverTurns { .. } | Ended::Exited { .. }),
            "{ended:?}"
        );
    }
}
