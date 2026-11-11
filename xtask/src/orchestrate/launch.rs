//! `cargo xtask kit launch <agent> [--item <n>] [--seed] [--print <prompt>] [--model <m>]
//! [--effort <e>]` (team/03 section 1, K6): fetch the issue once, write its snapshot for the hooks,
//! pick the model by the rule of team/01 section 9 and design/_review/03 and the effort by the
//! item's size, set the session identity, and start Claude Code with every variable of the
//! owner's user settings `env` blanked, so no credential kept there reaches an agent or its
//! subprocesses; `[launch] setting_sources` in harness.toml can narrow the settings further. The
//! dispatcher starts every session through this command in print mode. It refuses to run inside
//! an agent session or while Claude Code does not trust the repository folder (`trust`), and a
//! fable session holds a machine-wide lock: one at a time. `--seed` first checks out the seed
//! scope's branch, new from the fetched base tip when it does not exist yet.

mod harness;
mod item;
mod kit;
pub mod trust;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};

use super::form::Form;
use super::issue::tier_name;
use super::tracker::{GhTracker, Tracker, missing_step};
use crate::cli::{self, Spec};
use crate::config::limits::Limits;
use crate::config::protected::SeedScope;
use crate::config::session::{
    AGENT_VARIABLE, ItemSnapshot, ItemStatus, LAUNCHER_MODEL_VARIABLE, SCOPE_VARIABLE,
    WORK_ITEM_VARIABLE, parse_item_number,
};
use crate::git;
use crate::github::{EXIT_OWNER_STEP, Gh, Mode};
use crate::kit::claude_config;
use crate::kit::{CHIEF_ARCHITECT, OWNERSHIP_SENTENCE};
use crate::lock::Lock;
use crate::repo::Repo;

use self::harness::harness_text;
pub use self::harness::{HARNESS_FILE, claude_from, claude_program};
use self::item::fetch_item;
pub use self::item::{acceptance_path, snapshot_of};
use self::kit::model_name;
pub use self::kit::{LaunchKit, ModelChoice, protected_change_agents};
use self::trust::{Trust, Untrusted};

pub const CLAUDE_VARIABLE: &str = "GRDR_CLAUDE";
const SPEC: Spec = Spec {
    flags: &["--seed", "--dry-run"],
    options: &[
        "--item",
        "--print",
        "--session-id",
        "--resume",
        "--model",
        "--effort",
    ],
};
const EFFORTS: &[&str] = &["low", "medium", "high", "xhigh", "max"];
const PROJECT_SETTINGS: &str = ".claude/settings.json";
/// One fable session at a time on this machine (design/_review/03: on demand, never in a loop).
const FABLE_LOCK: &str = "grdr-fable-session.lock";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompting {
    Interactive,
    /// `claude -p`, with the prompt on stdin.
    Print(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStart {
    New,
    Named(String),
    Resume(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchScope {
    Ordinary,
    /// The chief architect's first session (team/06 section 14).
    Seed,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub agent: String,
    pub item: Option<u64>,
    pub scope: LaunchScope,
    pub prompting: Prompting,
    pub session: SessionStart,
    /// A model the caller asks for: `opus` for a cross-model review, for one; the rule decides.
    pub model: Option<String>,
    /// An effort the caller asks for; otherwise the item's size row in usage.toml, else the roster.
    pub effort: Option<String>,
}

/// Everything about one launch, decided before anything starts.
#[derive(Debug, Clone)]
pub struct Plan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub stdin: Option<String>,
    pub env: Vec<(&'static str, String)>,
    pub unset: Vec<&'static str>,
    pub model: ModelChoice,
    pub turns: u32,
    pub effort: Option<String>,
    pub snapshot: Option<ItemSnapshot>,
}

/// `kit launch`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    if let Some(agent) = std::env::var_os(AGENT_VARIABLE).filter(|value| !value.is_empty()) {
        bail!(
            "kit launch runs outside agent sessions; this one is {} (only the dispatcher and a person start sessions)",
            agent.to_string_lossy()
        );
    }
    let parsed = cli::parse(args, &SPEC)?;
    let Some(agent) = parsed.positional.first().cloned() else {
        bail!(
            "usage: cargo xtask kit launch <agent> [--item <n>] [--seed] [--print <prompt>] [--session-id <id> | --resume <id>] [--dry-run]"
        );
    };
    let session = match (parsed.value("--session-id"), parsed.value("--resume")) {
        (Some(_), Some(_)) => bail!("--session-id and --resume exclude each other"),
        (Some(id), None) => SessionStart::Named(id.to_owned()),
        (None, Some(id)) => SessionStart::Resume(id.to_owned()),
        (None, None) => SessionStart::New,
    };
    let request = Request {
        agent,
        item: parsed.value("--item").map(parse_item_number).transpose()?,
        scope: if parsed.has("--seed") {
            LaunchScope::Seed
        } else {
            LaunchScope::Ordinary
        },
        prompting: parsed
            .value("--print")
            .map_or(Prompting::Interactive, |prompt| {
                Prompting::Print(prompt.to_owned())
            }),
        session,
        model: parsed.value("--model").map(str::to_owned),
        effort: parsed.value("--effort").map(str::to_owned),
    };
    let repo = Repo::discover()?;
    let trust = trust::check(&repo)?;
    if let Trust::Refused(step) = trust {
        return owner_step_or(Untrusted(step).into());
    }
    let kit = LaunchKit::load(&repo)?;
    let tracker = GhTracker::new(Gh::for_repo(&repo, Mode::Live)?);
    let plan = match plan(&repo, &kit, &tracker, claude_program(&repo)?, &request) {
        Ok(plan) => plan,
        Err(error) => return owner_step_or(error),
    };
    eprintln!("{}", describe(&plan, &request));
    if parsed.has("--dry-run") {
        eprintln!("kit launch: {}", trust.describe());
        println!("{}", command_line(&plan));
        return Ok(ExitCode::SUCCESS);
    }
    if request.scope == LaunchScope::Seed {
        let scope = seed_scope(&kit, &request.agent)?;
        check_out_seed_branch(&repo, &Form::load(&repo)?, &scope.branch)?;
    }
    start(&plan)
}

/// The seed session works on `branch`: as it is when it exists, else new from the fetched base
/// tip, or from `HEAD` while the checkout has no remote yet.
pub fn check_out_seed_branch(repo: &Repo, form: &Form, branch: &str) -> Result<()> {
    if git::current_branch(repo)?.as_deref() == Some(branch) {
        return Ok(());
    }
    let changes = git::output(repo, &["status", "--porcelain", "--untracked-files=no"])?;
    if !changes.trim().is_empty() {
        bail!(
            "kit launch --seed checks out {branch}, and the working tree has uncommitted changes; commit them on {branch} first"
        );
    }
    let local = format!("refs/heads/{branch}");
    if git::try_output(repo, &["rev-parse", "--verify", "--quiet", &local])?.is_some() {
        git::output(repo, &["switch", "--quiet", branch])?;
        return Ok(());
    }
    let remote = form.remote.as_str();
    let start = if git::try_output(repo, &["remote", "get-url", remote])?.is_some() {
        git::output(repo, &["fetch", "--quiet", remote, &form.base])?;
        format!("refs/remotes/{remote}/{}", form.base)
    } else {
        "HEAD".to_owned()
    };
    git::output(repo, &["switch", "--quiet", "-c", branch, &start])?;
    println!("kit launch: the seed session works on {branch}, from {start}");
    Ok(())
}

/// Decides the launch: snapshot, model, caps, identity and the exact command.
pub fn plan(
    repo: &Repo,
    kit: &LaunchKit,
    tracker: &dyn Tracker,
    program: PathBuf,
    request: &Request,
) -> Result<Plan> {
    let name = request.agent.as_str();
    kit.agent(name)?;
    let seed = match request.scope {
        LaunchScope::Seed => Some(seed_scope(kit, name)?),
        LaunchScope::Ordinary => None,
    };
    let (snapshot, own_lease) = match request.item {
        Some(number) => {
            let (snapshot, lease) = fetch_item(repo, kit, tracker, number, name)?;
            (Some(snapshot), lease)
        }
        None => (None, None),
    };
    let mut model = kit.choose_model(name, snapshot.as_ref())?;
    let lease_model = own_lease.as_ref().map(|lease| lease.model.clone());
    if let Some(id) = lease_model
        .filter(|id| *id != model.id && kit.may_run_on(name, id) && kit.ranks_above(id, &model.id))
    {
        model = raised_model(
            kit,
            id,
            "the lease comment names it, and an attempt never changes model",
        );
    }
    if let Some(asked) = &request.model {
        let id = kit.models.resolve(asked).unwrap_or(asked).to_owned();
        if !kit.may_run_on(name, &id) {
            bail!("model rule: {name} may not run on {asked}");
        }
        if kit.ranks_above(&id, &model.id) || model.raised_for.is_none() {
            model = raised_model(kit, id, "the dispatcher asked for it (cross-model review)");
        }
    }
    let size = snapshot.as_ref().and_then(|s| s.size.as_deref());
    let turns = kit.session_turns(name, size, request.scope)?;
    let effort = match &request.effort {
        Some(asked) if EFFORTS.contains(&asked.as_str()) => Some(asked.clone()),
        Some(asked) => bail!("--effort {asked} is not one of {}", EFFORTS.join(", ")),
        None => kit.effort(name, size),
    };
    let leased_to_it = snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.status == ItemStatus::Leased)
        && own_lease.is_some();
    let protected = match &snapshot {
        Some(snapshot) if leased_to_it => kit.is_protected_change(name, &snapshot.write_set)?,
        _ => false,
    };
    let scope_value = match (&seed, protected) {
        (Some(_), _) => Some("seed"),
        (None, true) => Some("protected"),
        (None, false) => None,
    };
    let prompting = match (&request.prompting, &seed) {
        (Prompting::Interactive, Some(scope)) => Some(seed_prompt(repo, scope)?),
        (Prompting::Print(prompt), _) => Some(prompt.clone()),
        (Prompting::Interactive, None) => None,
    }
    .map(|prompt| with_ownership(name, prompt));
    let mut env = vec![
        (AGENT_VARIABLE, name.to_owned()),
        (LAUNCHER_MODEL_VARIABLE, model.id.clone()),
    ];
    let mut unset = Vec::new();
    match request.item {
        Some(number) => env.push((WORK_ITEM_VARIABLE, number.to_string())),
        None => unset.push(WORK_ITEM_VARIABLE),
    }
    match scope_value {
        Some(value) => env.push((SCOPE_VARIABLE, value.to_owned())),
        None => unset.push(SCOPE_VARIABLE),
    }
    let (mut args, stdin) = arguments(
        name,
        &model.id,
        turns,
        &request.prompting,
        prompting,
        &request.session,
    );
    let mut leading = Vec::new();
    if let Some(sources) = harness_text(repo, "launch", "setting_sources")? {
        leading.extend(["--setting-sources".to_owned(), sources]);
    }
    let scrub =
        harness_text(repo, "launch", "scrub_user_env")?.is_some_and(|value| value == "true");
    if scrub
        && let Some(user) = claude_config::user_settings(claude_config::process_variable)
        && let Some(settings) = scrubbed_env(&user, &repo.path(PROJECT_SETTINGS))
    {
        leading.extend(["--settings".to_owned(), settings]);
    }
    if let Some(effort) = &effort {
        leading.extend(["--effort".to_owned(), effort.clone()]);
    }
    let insert_at = usize::from(args.first().is_some_and(|first| first == "-p"));
    args.splice(insert_at..insert_at, leading);
    Ok(Plan {
        program,
        args,
        stdin,
        env,
        unset,
        model,
        turns,
        effort,
        snapshot,
    })
}

fn raised_model(kit: &LaunchKit, id: String, reason: &str) -> ModelChoice {
    ModelChoice {
        name: model_name(&kit.models, &id).unwrap_or_default(),
        id,
        raised_for: Some(reason.to_owned()),
    }
}

/// `{"env": {"NAME": ""}}` for every variable the user settings' `env` sets and the project's does
/// not: only the names are read, and the session sees them empty.
pub fn scrubbed_env(user: &std::path::Path, project: &std::path::Path) -> Option<String> {
    let names = |path: &std::path::Path| -> Vec<String> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| {
                value
                    .get("env")
                    .and_then(serde_json::Value::as_object)
                    .cloned()
            })
            .map(|env| env.keys().cloned().collect())
            .unwrap_or_default()
    };
    let kept = names(project);
    let blanked: serde_json::Map<String, serde_json::Value> = names(user)
        .into_iter()
        .filter(|name| !kept.contains(name))
        .map(|name| (name, serde_json::Value::String(String::new())))
        .collect();
    (!blanked.is_empty()).then(|| serde_json::json!({ "env": blanked }).to_string())
}

/// The machine-wide lock path for fable sessions.
pub fn fable_lock_path() -> PathBuf {
    std::env::temp_dir().join(FABLE_LOCK)
}

/// Whether a fable session already runs on this machine.
pub fn fable_session_running() -> Result<bool> {
    let heartbeat = Limits::built_with()?.orchestrate.launch.fable_heartbeat();
    Ok(Lock::is_held(&fable_lock_path(), heartbeat))
}

/// Starts the planned session with this terminal, or the dispatcher's pipes, as its own.
pub fn start(plan: &Plan) -> Result<ExitCode> {
    let _fable = match plan.model.name.as_str() {
        "fable" => Some(Lock::take(
            fable_lock_path(),
            Limits::built_with()?.orchestrate.launch.fable_heartbeat(),
            "a fable session already runs on this machine; the chief architect runs one session at a time",
        )?),
        _ => None,
    };
    let mut command = Command::new(&plan.program);
    command.args(&plan.args);
    for (name, value) in &plan.env {
        command.env(name, value);
    }
    for name in &plan.unset {
        command.env_remove(name);
    }
    command.stdin(if plan.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    let mut child = command
        .spawn()
        .with_context(|| format!("starting {}", plan.program.display()))?;
    if let (Some(prompt), Some(mut stdin)) = (&plan.stdin, child.stdin.take()) {
        stdin
            .write_all(prompt.as_bytes())
            .context("sending the prompt")?;
    }
    let status = child.wait().context("waiting for claude")?;
    let code = status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1);
    Ok(ExitCode::from(code))
}

/// The command as one line, for `--dry-run` and the logs.
pub fn command_line(plan: &Plan) -> String {
    let env: Vec<String> = plan
        .env
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    format!(
        "{} {} {}",
        env.join(" "),
        plan.program.display(),
        plan.args.join(" ")
    )
}

/// A missing owner step, or a repository Claude Code does not trust, exits 3 with the step;
/// anything else stays an error.
pub fn owner_step_or(error: anyhow::Error) -> Result<ExitCode> {
    let step = missing_step(&error)
        .map(str::to_owned)
        .or_else(|| error.downcast_ref::<Untrusted>().map(ToString::to_string));
    match step {
        Some(step) => {
            eprintln!("owner step needed: {step}");
            Ok(ExitCode::from(EXIT_OWNER_STEP))
        }
        None => Err(error),
    }
}

fn describe(plan: &Plan, request: &Request) -> String {
    let item = plan
        .snapshot
        .as_ref()
        .map(|s| {
            format!(
                ", issue #{} ({} tier, attempt {})",
                s.number,
                tier_name(s.risk_tier),
                s.attempt
            )
        })
        .unwrap_or_default();
    let raised = plan
        .model
        .raised_for
        .as_ref()
        .map(|why| format!(" because {why}"))
        .unwrap_or_default();
    let effort = plan
        .effort
        .as_ref()
        .map(|effort| format!(", effort {effort}"))
        .unwrap_or_default();
    format!(
        "kit launch: {} on {}{raised}{item}, at most {} turns{effort}",
        request.agent, plan.model.id, plan.turns
    )
}

fn arguments(
    name: &str,
    model: &str,
    turns: u32,
    prompting: &Prompting,
    prompt: Option<String>,
    session: &SessionStart,
) -> (Vec<String>, Option<String>) {
    let mut args: Vec<String> = Vec::new();
    if let Prompting::Print(_) = prompting {
        args.push("-p".into());
    }
    args.extend([
        "--agent".into(),
        name.to_owned(),
        "--model".into(),
        model.to_owned(),
    ]);
    match session {
        SessionStart::New => {}
        SessionStart::Named(id) => args.extend(["--session-id".into(), id.clone()]),
        SessionStart::Resume(id) => args.extend(["--resume".into(), id.clone()]),
    }
    match prompting {
        Prompting::Print(_) => {
            args.extend(
                [
                    "--max-turns",
                    &turns.to_string(),
                    "--permission-mode",
                    "dontAsk",
                    "--output-format",
                    "stream-json",
                    "--verbose",
                ]
                .map(str::to_owned),
            );
            (args, prompt)
        }
        Prompting::Interactive => {
            args.extend(prompt);
            (args, None)
        }
    }
}

/// The seed scope, refused for any other agent.
fn seed_scope(kit: &LaunchKit, name: &str) -> Result<SeedScope> {
    let Some(scope) = kit.seed.clone() else {
        bail!("--seed needs .agents/kit/seed-scope.toml");
    };
    if scope.agent != name {
        bail!("--seed is only for {} (team/06 section 14)", scope.agent);
    }
    Ok(scope)
}

fn seed_prompt(repo: &Repo, scope: &SeedScope) -> Result<String> {
    let Some(relative) = &scope.prompt else {
        bail!(".agents/kit/seed-scope.toml names no prompt");
    };
    repo.read(&format!(".agents/{relative}"))
}

/// Owner instruction 1: every prompt to the chief architect opens with the ownership sentence.
fn with_ownership(name: &str, prompt: String) -> String {
    if name == CHIEF_ARCHITECT && !prompt.trim_start().starts_with(OWNERSHIP_SENTENCE) {
        format!("{OWNERSHIP_SENTENCE}\n\n{prompt}")
    } else {
        prompt
    }
}

#[cfg(test)]
mod tests;
