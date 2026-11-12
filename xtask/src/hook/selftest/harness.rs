//! Builds a throwaway git repository for each preset, loads the fixture files under
//! `xtask/fixtures/hooks/`, runs every case against its handler in process, and reports any
//! blocking handler that let a case through or allowed handler that blocked one. It also proves
//! the failure contract (a pre-action handler blocks on an error or a missed deadline) and the
//! real path Claude Code takes: the rendered hook command run by Git Bash from a directory
//! outside the repository, with `CLAUDE_PROJECT_DIR` in native and forward-slash form, a missing
//! kit binary that fails with its path named, and a handler whose input never ends, so it misses
//! its deadline and still blocks.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use super::cases;
use crate::config::limits::{HookLimits, LIMITS_PATH};
use crate::hook::context::{Context, Env, Input};
use crate::hook::limits::{self, HOOKS_FILE};
use crate::hook::outcome::{BLOCK_EXIT, Outcome};
use crate::hook::signoff;
use crate::hook::{Failure, Handler};
use crate::process;
use crate::repo::Repo;

const FIXTURE_DIR: &str = "xtask/fixtures/hooks";
const GIT_BASH_VARIABLE: &str = "CLAUDE_CODE_GIT_BASH_PATH";
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// How the subprocess cases spell `CLAUDE_PROJECT_DIR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectDir {
    Native,
    ForwardSlash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expect {
    Block,
    Allow,
    Context,
    /// `permissionDecision: allow`, with or without context.
    Approve,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    pub name: String,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub input: Value,
    pub expect: Expect,
    #[serde(default)]
    pub contains: Option<String>,
    /// Extra files written into the repository before the case runs.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// Whether the cleanup sign-off is written for the scratch repository before the case runs.
    #[serde(default)]
    pub sign_off: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Fixture {
    pub handler: String,
    #[serde(default)]
    pub preset: Option<String>,
    pub cases: Vec<Case>,
}

#[derive(Default)]
pub struct Report {
    passed: usize,
    failures: Vec<String>,
    lines: Vec<String>,
}

struct Scratch {
    root: PathBuf,
    outside: PathBuf,
}

impl Report {
    pub fn failed(&self) -> bool {
        !self.failures.is_empty()
    }

    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    pub fn summary(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            let _ = writeln!(out, "{line}");
        }
        for failure in &self.failures {
            let _ = writeln!(out, "FAIL {failure}");
        }
        let _ = writeln!(
            out,
            "hooks-selftest: {} passed, {} failed",
            self.passed,
            self.failures.len()
        );
        out
    }

    fn record(&mut self, label: &str, result: Result<()>, verbose: bool) {
        match result {
            Ok(()) => {
                self.passed += 1;
                if verbose {
                    self.lines.push(format!("ok   {label}"));
                }
            }
            Err(error) => self.failures.push(format!("{label}: {error:#}")),
        }
    }
}

impl Scratch {
    fn create(preset: &str, limits: &HookLimits) -> Result<Scratch> {
        let wait = limits.selftest.process();
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("xtask-selftest-{}-{id}", std::process::id()));
        let root = base.join("repo");
        let outside = base.join("outside");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&outside)?;
        cases::write_preset(&root, preset)?;
        let kit = Repo::discover()?;
        for path in [HOOKS_FILE, LIMITS_PATH] {
            fs::write(Repo::at(&root).path(path), kit.read(path)?)?;
        }
        git(&root, &["init", "-q", "-b", "agent/7/a1"], wait)?;
        git(
            &root,
            &["config", "user.email", "kit@example.invalid"],
            wait,
        )?;
        git(&root, &["config", "user.name", "kit"], wait)?;
        git(&root, &["add", "-A"], wait)?;
        git(
            &root,
            &["commit", "-q", "-m", "docs: seed the throwaway repository"],
            wait,
        )?;
        Ok(Scratch { root, outside })
    }

    fn repo(&self) -> Repo {
        Repo::at(&self.root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(base) = self.root.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

pub fn run(only: Option<&str>, verbose: bool) -> Result<Report> {
    let repo = Repo::discover()?;
    let limits = limits::load(&repo)?;
    let mut report = Report::default();
    let fixtures = load(&repo.path(FIXTURE_DIR))?;
    for fixture in &fixtures {
        if only.is_some_and(|only| only != fixture.handler) {
            continue;
        }
        let handler = Handler::from_name(&fixture.handler)
            .with_context(|| format!("fixture names unknown handler `{}`", fixture.handler))?;
        for case in &fixture.cases {
            let label = format!("{}/{}", fixture.handler, case.name);
            let preset = case
                .preset
                .as_deref()
                .or(fixture.preset.as_deref())
                .unwrap_or("worker");
            report.record(&label, run_case(handler, preset, case, &limits), verbose);
        }
    }
    for (handler, preset, case) in cases::programmatic() {
        if only.is_some_and(|only| only != handler.name()) {
            continue;
        }
        let label = format!("{}/{}", handler.name(), case.name);
        report.record(&label, run_case(handler, &preset, &case, &limits), verbose);
    }
    for handler in Handler::ALL {
        if only.is_some_and(|only| only != handler.name()) {
            continue;
        }
        report.record(
            &format!("{}/failure-contract", handler.name()),
            failure_contract(handler),
            verbose,
        );
    }
    if only.is_none_or(|only| only == "guard-command") {
        for (form, label) in [
            (ProjectDir::Native, "native"),
            (ProjectDir::ForwardSlash, "forward-slash"),
        ] {
            report.record(
                &format!("guard-command/subprocess-deny-{label}"),
                subprocess_contract(true, form, &limits),
                verbose,
            );
            report.record(
                &format!("guard-command/subprocess-allow-{label}"),
                subprocess_contract(false, form, &limits),
                verbose,
            );
        }
        report.record(
            "guard-command/subprocess-missing-binary",
            missing_binary_contract(&limits),
            verbose,
        );
        report.record(
            "guard-command/subprocess-missed-deadline",
            deadline_contract(&limits),
            verbose,
        );
    }
    Ok(report)
}

fn run_case(handler: Handler, preset: &str, case: &Case, limits: &HookLimits) -> Result<()> {
    let scratch = Scratch::create(preset, limits)?;
    let repo = scratch.repo();
    for (path, text) in &case.files {
        let target = repo.path(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, text)?;
    }
    if case.sign_off {
        signoff::sign(&repo)?;
    }
    let mut pairs: BTreeMap<String, String> = BTreeMap::new();
    pairs.insert(
        "CLAUDE_PROJECT_DIR".into(),
        scratch.root.to_string_lossy().into_owned(),
    );
    pairs.insert(
        "HOME".into(),
        scratch.outside.to_string_lossy().into_owned(),
    );
    pairs.extend(case.env.clone());
    let input = with_defaults(&case.input, &scratch)?;
    let outcome = invoke(handler, repo, &input, pairs, &scratch.outside)?;
    judge(case, &outcome)
}

fn invoke(
    handler: Handler,
    repo: Repo,
    input: &Value,
    env: BTreeMap<String, String>,
    cwd: &Path,
) -> Result<Outcome> {
    let input = Input::parse(&input.to_string())?;
    let env = Env::from_pairs(env);
    let limits = limits::load(&repo)?;
    let deadline = Instant::now() + limits.selftest.case();
    let progress = std::sync::Arc::default();
    let previous = std::env::current_dir().ok();
    std::env::set_current_dir(cwd).ok();
    let context = Context::new(repo, input, env, deadline, progress, limits);
    let result = handler.handle(&context);
    if let Some(previous) = previous {
        let _ = std::env::set_current_dir(previous);
    }
    result
}

fn judge(case: &Case, outcome: &Outcome) -> Result<()> {
    let matched = match case.expect {
        Expect::Block => matches!(outcome, Outcome::Block(_)),
        Expect::Allow => matches!(outcome, Outcome::Allow),
        Expect::Context => matches!(outcome, Outcome::Context(_)),
        Expect::Approve => matches!(outcome, Outcome::Approve { .. }),
    };
    if !matched {
        bail!(
            "expected {:?}, got {} ({})",
            case.expect,
            outcome.kind(),
            first_line(outcome.text())
        );
    }
    if let Some(needle) = &case.contains
        && !outcome
            .text()
            .to_lowercase()
            .contains(&needle.to_lowercase())
    {
        bail!(
            "the {} does not mention `{needle}`: {}",
            outcome.kind(),
            first_line(outcome.text())
        );
    }
    Ok(())
}

/// A pre-action handler blocks when its work fails; the others allow.
fn failure_contract(handler: Handler) -> Result<()> {
    let rendered =
        Outcome::Block("the hook missed its deadline".into()).render(handler.event(), None, None);
    match handler.failure() {
        Failure::Block if rendered.code != BLOCK_EXIT && rendered.stdout.is_empty() => {
            bail!("a {} failure does not block", handler.name())
        }
        Failure::Allow => {
            let allow = Outcome::Allow.render(handler.event(), None, None);
            if allow.code != 0 {
                bail!("a {} that allows should exit 0", handler.name());
            }
        }
        _ => {}
    }
    Ok(())
}

/// The rendered hook command, run by Git Bash with the no-extension path, denies and allows from a
/// directory outside the repository (team/03 section 4.2).
fn subprocess_contract(deny: bool, form: ProjectDir, limits: &HookLimits) -> Result<()> {
    let scratch = Scratch::create("worker", limits)?;
    install_binary(&scratch)?;
    let command = if deny {
        "git push --force"
    } else {
        "git status"
    };
    let payload = json!({
        "session_id": "s1",
        "cwd": scratch.root.to_string_lossy(),
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    let mut spawn = rendered_hook(&scratch, form, limits)?;
    spawn
        .env("GRDR_AGENT", "impl-rust")
        .env("GRDR_WORK_ITEM", "7");
    let ran = process::run(
        &mut spawn,
        Some(payload.to_string().as_bytes()),
        limits.selftest.process(),
    )?;
    let blocked = matches!(
        ran.finished,
        process::Finished::Exited { code: Some(code), .. } if code == i32::from(BLOCK_EXIT)
    );
    if deny && !blocked {
        bail!(
            "the installed binary did not block `{command}` ({}): {}",
            ran.describe(),
            ran.stderr()
        );
    }
    if !deny && blocked {
        bail!("the installed binary blocked `{command}`: {}", ran.stderr());
    }
    if !deny && !ran.success() {
        bail!(
            "the rendered hook command did not run ({}): {}",
            ran.describe(),
            ran.stderr()
        );
    }
    Ok(())
}

/// Without the kit binary the rendered command fails, not 0, and names the path it looked for.
fn missing_binary_contract(limits: &HookLimits) -> Result<()> {
    let scratch = Scratch::create("worker", limits)?;
    let mut spawn = rendered_hook(&scratch, ProjectDir::ForwardSlash, limits)?;
    let ran = process::run(&mut spawn, Some(b"{}"), limits.selftest.process())?;
    if ran.success() {
        bail!("a missing kit binary let the hook exit 0");
    }
    if !ran.stderr().contains(".agent/kit/bin/xtask") {
        bail!(
            "a missing kit binary fails without naming its path ({}): {}",
            ran.describe(),
            ran.stderr()
        );
    }
    Ok(())
}

/// guard-command whose stdin never ends misses its shortened deadline and still blocks.
fn deadline_contract(limits: &HookLimits) -> Result<()> {
    let scratch = Scratch::create("worker", limits)?;
    install_binary(&scratch)?;
    shorten_guard_command(&scratch.repo(), limits.selftest.short_timeout_s)?;
    let mut spawn = rendered_hook(&scratch, ProjectDir::Native, limits)?;
    let mut child = spawn
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting the hook")?;
    let _held_open = child.stdin.take();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > limits.selftest.deadline_wait() {
            let _ = child.kill();
            bail!("the hook kept running past its deadline");
        }
        std::thread::sleep(limits.selftest.poll());
    };
    if status.code() != Some(i32::from(BLOCK_EXIT)) {
        bail!("a missed deadline exited {status} instead of blocking with {BLOCK_EXIT}");
    }
    Ok(())
}

/// Registers guard-command with `seconds` as its timeout in the scratch copy of the hooks file.
fn shorten_guard_command(repo: &Repo, seconds: i64) -> Result<()> {
    let mut table: toml::Table = repo.read(HOOKS_FILE)?.parse()?;
    let hooks = table
        .get_mut("hook")
        .and_then(toml::Value::as_array_mut)
        .context("the hooks file has no [[hook]] entries")?;
    let guard = hooks
        .iter_mut()
        .filter_map(toml::Value::as_table_mut)
        .find(|hook| hook.get("handler").and_then(toml::Value::as_str) == Some("guard-command"))
        .context("the hooks file registers no guard-command")?;
    guard.insert("timeout".to_owned(), toml::Value::Integer(seconds));
    fs::write(repo.path(HOOKS_FILE), toml::to_string(&table)?)?;
    Ok(())
}

fn install_binary(scratch: &Scratch) -> Result<()> {
    let bin = scratch.root.join(".agent/kit/bin");
    fs::create_dir_all(&bin)?;
    let installed = bin.join(format!("xtask{}", std::env::consts::EXE_SUFFIX));
    fs::copy(std::env::current_exe()?, &installed)?;
    Ok(())
}

/// `bash -c '<the command settings.json renders for guard-command>'` from outside the repository.
fn rendered_hook(scratch: &Scratch, form: ProjectDir, limits: &HookLimits) -> Result<Command> {
    let rendered = crate::kit::settings::hook_command("guard-command");
    let root = scratch.root.to_string_lossy().into_owned();
    let project = match form {
        ProjectDir::Native => root,
        ProjectDir::ForwardSlash => root.replace('\\', "/"),
    };
    let mut spawn = Command::new(git_bash(limits)?);
    spawn
        .args(["-c", &rendered])
        .current_dir(&scratch.outside)
        .env("CLAUDE_PROJECT_DIR", project);
    Ok(spawn)
}

/// The bash Claude Code runs hooks with: `CLAUDE_CODE_GIT_BASH_PATH`, else Git for Windows'
/// own bash beside `git --exec-path`, else `bash` from `PATH` off Windows.
fn git_bash(limits: &HookLimits) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(GIT_BASH_VARIABLE).filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    if !cfg!(windows) {
        return Ok(PathBuf::from("bash"));
    }
    let mut command = Command::new("git");
    command.arg("--exec-path");
    let ran = process::run(&mut command, None, limits.selftest.process())?;
    let exec = PathBuf::from(ran.stdout().trim());
    exec.ancestors()
        .map(|dir| dir.join("bin").join("bash.exe"))
        .find(|candidate| candidate.is_file())
        .with_context(|| {
            format!(
                "no Git Bash beside {}; set {GIT_BASH_VARIABLE}",
                exec.display()
            )
        })
}

/// Common fields every handler reads, filled in when a case leaves them out.
fn with_defaults(input: &Value, scratch: &Scratch) -> Result<Value> {
    let mut value = input.clone();
    let Some(object) = value.as_object_mut() else {
        bail!("a case input is not a JSON object");
    };
    object
        .entry("session_id")
        .or_insert_with(|| json!(format!("s-{}", std::process::id())));
    object
        .entry("cwd")
        .or_insert_with(|| json!(scratch.root.to_string_lossy()));
    object
        .entry("hook_event_name")
        .or_insert_with(|| json!("event"));
    Ok(value)
}

fn load(dir: &Path) -> Result<Vec<Fixture>> {
    let mut fixtures = Vec::new();
    for path in crate::repo::walk_files(dir)? {
        if path.extension().is_some_and(|ext| ext == "json") {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let fixture: Fixture = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", path.display()))?;
            fixtures.push(fixture);
        }
    }
    if fixtures.is_empty() {
        bail!("no fixtures under {}", dir.display());
    }
    Ok(fixtures)
}

fn git(root: &Path, args: &[&str], wait: Duration) -> Result<()> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0");
    let ran = process::run(&mut command, None, wait)?;
    if !ran.success() {
        bail!("git {} failed: {}", args.join(" "), ran.stderr());
    }
    Ok(())
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("")
}
