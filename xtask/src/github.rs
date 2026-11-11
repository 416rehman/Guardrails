//! The one door to GitHub: every call goes through the `gh` CLI against the repository that
//! `.agents/harness.toml [github] repository` names (owner instruction 5). Work items are issues
//! there and nowhere else. `GRDR_GH` names another `gh` executable, which is how tests inject a
//! fake one. In dry-run mode no call that changes GitHub runs; it is printed instead. When `gh`,
//! its login or the repository is missing, the error carries the one owner step that fixes it,
//! from the same table, and callers exit with [`EXIT_OWNER_STEP`]. `github check` also reads the
//! repository settings `[[github.settings]]` lists and prints the fix of each one that does not
//! hold.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::cli::{self, Spec};
use crate::process;
use crate::repo::Repo;

pub const PROGRAM_VARIABLE: &str = "GRDR_GH";
/// Exit code of a command that stopped because an owner step is missing.
pub const EXIT_OWNER_STEP: u8 = 3;
const HARNESS_FILE: &str = ".agents/harness.toml";
const REPOSITORY_MISSING: &[&str] = &["Could not resolve to a Repository", "HTTP 404"];
const NOT_LOGGED_IN: &[&str] = &[
    "gh auth login",
    "not logged into",
    "authentication required",
    "HTTP 401",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Live,
    /// Calls that change GitHub are printed, not run; reads still run.
    DryRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    Cli,
    Login,
    Repository,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhError {
    /// An owner step is missing; `step` says which and how to take it.
    Missing {
        missing: Missing,
        step: String,
    },
    /// `.agents/harness.toml [github]` could not be read, so no call was made.
    Unconfigured(String),
    Failed {
        args: Vec<String>,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    Ran(String),
    DryRun(String),
}

/// `.agents/harness.toml [github]`: the repository, the call timeouts, what to print when an
/// owner step is missing, and the repository settings `github check` reads. `{repository}`,
/// `{owner}`, `{name}` and `{branch}` are filled in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Identity {
    pub repository: String,
    pub call_timeout_seconds: u64,
    pub push_timeout_seconds: u64,
    missing_cli: String,
    missing_login: String,
    missing_repository: String,
    missing_remote: String,
    #[serde(default)]
    settings: Vec<Setting>,
}

/// One repository setting: the read-only gh call that shows it, the JSON value it must have at
/// each pointer of the reply, and the gh call that sets it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Setting {
    name: String,
    read: Vec<String>,
    expect: BTreeMap<String, Value>,
    fix: String,
}

/// What reading one setting found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Holds,
    Differs(Vec<String>),
    /// The call failed or its reply lacks a pointer, as when the token may not read the setting.
    Unreadable(String),
}

#[derive(Debug, Clone)]
enum Target {
    Repository(Identity),
    Unconfigured(String),
}

#[derive(Debug, Clone)]
pub struct Gh {
    program: PathBuf,
    target: Target,
    mode: Mode,
}

#[derive(Deserialize)]
struct HarnessGithub {
    github: Identity,
}

impl Identity {
    pub fn load(repo: &Repo) -> Result<Identity> {
        let text = repo
            .read_optional(HARNESS_FILE)?
            .with_context(|| format!("{HARNESS_FILE} is missing"))?;
        Identity::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Identity> {
        let parsed: HarnessGithub = crate::config::parse_toml(text, HARNESS_FILE)
            .with_context(|| format!("reading [github] in {HARNESS_FILE}"))?;
        Ok(parsed.github)
    }

    /// The account the repository belongs to.
    pub fn owner(&self) -> &str {
        self.repository
            .split_once('/')
            .map_or(self.repository.as_str(), |(owner, _)| owner)
    }

    /// The repository's name without its owner.
    pub fn name(&self) -> &str {
        self.repository
            .split_once('/')
            .map_or(self.repository.as_str(), |(_, name)| name)
    }

    pub fn owner_step(&self, missing: Missing) -> String {
        let template = match missing {
            Missing::Cli => &self.missing_cli,
            Missing::Login => &self.missing_login,
            Missing::Repository => &self.missing_repository,
        };
        self.fill(template, "")
    }

    /// The step to take when the checkout has no `origin` remote for `branch` to go to.
    pub fn missing_remote(&self, branch: &str) -> String {
        self.fill(&self.missing_remote, branch)
    }

    fn fill(&self, template: &str, branch: &str) -> String {
        template
            .replace("{repository}", &self.repository)
            .replace("{owner}", self.owner())
            .replace("{name}", self.name())
            .replace("{branch}", branch)
    }
}

impl Setting {
    /// Runs the setting's read and compares the reply with what it expects.
    fn read(&self, gh: &Gh, identity: &Identity) -> Finding {
        let args: Vec<String> = self.read.iter().map(|arg| identity.fill(arg, "")).collect();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let reply = match gh.read(&args) {
            Ok(text) => text,
            Err(error) => return Finding::Unreadable(error.to_string()),
        };
        match serde_json::from_str(&reply) {
            Ok(value) => self.judge(&value),
            Err(error) => Finding::Unreadable(format!("the reply is not JSON: {error}")),
        }
    }

    fn judge(&self, reply: &Value) -> Finding {
        let mut differs = Vec::new();
        for (pointer, want) in &self.expect {
            match reply.pointer(pointer) {
                None => {
                    return Finding::Unreadable(format!(
                        "the reply has no {pointer}; the token may not be allowed to read it"
                    ));
                }
                Some(found) if found == want => {}
                Some(found) => differs.push(format!("{pointer} is {found}, not {want}")),
            }
        }
        if differs.is_empty() {
            Finding::Holds
        } else {
            Finding::Differs(differs)
        }
    }
}

impl Finding {
    fn line(&self, setting: &Setting, identity: &Identity) -> String {
        let fix = identity.fill(&setting.fix, "");
        let name = &setting.name;
        match self {
            Finding::Holds => format!("github: {name}: holds"),
            Finding::Differs(details) => format!(
                "github: {name}: does not hold ({}); fix: {fix}",
                details.join("; ")
            ),
            Finding::Unreadable(why) => {
                format!("github: {name}: could not be read ({why}); fix if it does not hold: {fix}")
            }
        }
    }
}

impl fmt::Display for GhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GhError::Missing { step, .. } => write!(f, "owner step needed: {step}"),
            GhError::Unconfigured(why) => write!(f, "gh was not called: {why}"),
            GhError::Failed { args, detail } => write!(f, "gh {} failed: {detail}", args.join(" ")),
        }
    }
}

impl std::error::Error for GhError {}

impl Gh {
    /// `gh`, or the executable `GRDR_GH` names, against the repository `repo` configures.
    pub fn for_repo(repo: &Repo, mode: Mode) -> Result<Gh> {
        Ok(Gh::new(
            program_from(|name| std::env::var_os(name)),
            Identity::load(repo)?,
            mode,
        ))
    }

    /// [`Gh::for_repo`] for the checkout around the current directory; when its configuration
    /// cannot be read, every call fails with [`GhError::Unconfigured`].
    pub fn from_env(mode: Mode) -> Gh {
        let program = program_from(|name| std::env::var_os(name));
        let target = match Repo::discover().and_then(|repo| Identity::load(&repo)) {
            Ok(identity) => Target::Repository(identity),
            Err(error) => Target::Unconfigured(format!("{error:#}")),
        };
        Gh {
            program,
            target,
            mode,
        }
    }

    pub fn new(program: PathBuf, identity: Identity, mode: Mode) -> Gh {
        Gh {
            program,
            target: Target::Repository(identity),
            mode,
        }
    }

    /// The configured repository, `owner/name`; empty when the configuration was unreadable.
    pub fn repository(&self) -> &str {
        match &self.target {
            Target::Repository(identity) => &identity.repository,
            Target::Unconfigured(_) => "",
        }
    }

    pub fn identity(&self) -> Result<&Identity, GhError> {
        match &self.target {
            Target::Repository(identity) => Ok(identity),
            Target::Unconfigured(why) => Err(GhError::Unconfigured(why.clone())),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// A call that only reads; it runs in both modes.
    pub fn read(&self, args: &[&str]) -> Result<String, GhError> {
        self.call(args, None)
    }

    /// A call that changes GitHub. `input` goes to stdin, for `--body-file -` and `--input -`,
    /// so issue text never appears on a command line.
    pub fn write(&self, args: &[&str], input: Option<&str>) -> Result<Written, GhError> {
        let identity = self.identity()?;
        if self.mode == Mode::DryRun {
            let line = format!(
                "dry run: gh {} (repository {})",
                args.join(" "),
                identity.repository
            );
            println!("{line}");
            return Ok(Written::DryRun(line));
        }
        self.call(args, input).map(Written::Ran)
    }

    /// Checks that `gh` runs, is logged in and can see the repository.
    pub fn preflight(&self) -> Result<String, GhError> {
        let repository = self.identity()?.repository.clone();
        self.read(&[
            "repo",
            "view",
            &repository,
            "--json",
            "nameWithOwner,visibility",
        ])
    }

    fn call(&self, args: &[&str], input: Option<&str>) -> Result<String, GhError> {
        let identity = self.identity()?;
        let mut command = Command::new(&self.program);
        command
            .args(args)
            .env("GH_REPO", &identity.repository)
            .env("GH_PROMPT_DISABLED", "1")
            .env("GH_NO_UPDATE_NOTIFIER", "1")
            .env("GH_PAGER", "")
            .env("NO_COLOR", "1");
        let failed = |detail: String| GhError::Failed {
            args: args.iter().map(|a| a.to_string()).collect(),
            detail,
        };
        let missing = |missing: Missing| GhError::Missing {
            missing,
            step: identity.owner_step(missing),
        };
        let timeout = Duration::from_secs(identity.call_timeout_seconds);
        let ran = match process::run(&mut command, input.map(str::as_bytes), timeout) {
            Ok(ran) => ran,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(missing(Missing::Cli));
            }
            Err(error) => return Err(failed(error.to_string())),
        };
        if ran.success() {
            return Ok(ran.stdout());
        }
        let stderr = ran.stderr();
        if NOT_LOGGED_IN.iter().any(|marker| stderr.contains(marker)) {
            return Err(missing(Missing::Login));
        }
        if REPOSITORY_MISSING
            .iter()
            .any(|marker| stderr.contains(marker))
            && stderr.contains(&identity.repository)
        {
            return Err(missing(Missing::Repository));
        }
        Err(failed(format!("{}: {}", ran.describe(), stderr.trim())))
    }
}

/// `cargo xtask github check`: whether `gh`, its login and the repository are in place.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(
        args,
        &Spec {
            flags: &[],
            options: &[],
        },
    )?;
    match parsed.positional.first().map(String::as_str) {
        Some("check") => Ok(check(&Gh::for_repo(&Repo::discover()?, Mode::Live)?)),
        _ => anyhow::bail!("usage: cargo xtask github check"),
    }
}

/// Prints the result of [`Gh::preflight`] and of every repository setting, and returns the exit
/// code a caller should use: 1 when a setting does not hold or could not be read.
pub fn check(gh: &Gh) -> ExitCode {
    let view = match gh.preflight() {
        Ok(view) => view,
        Err(error) => return report(&error),
    };
    println!("github: {} is reachable: {}", gh.repository(), view.trim());
    let identity = match gh.identity() {
        Ok(identity) => identity,
        Err(error) => return report(&error),
    };
    let mut all_hold = true;
    for setting in &identity.settings {
        let finding = setting.read(gh, identity);
        all_hold &= finding == Finding::Holds;
        println!("{}", finding.line(setting, identity));
    }
    if all_hold {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Prints a GitHub error; a missing owner step exits [`EXIT_OWNER_STEP`], anything else 1.
pub fn report(error: &GhError) -> ExitCode {
    eprintln!("{error}");
    match error {
        GhError::Missing { .. } => ExitCode::from(EXIT_OWNER_STEP),
        GhError::Unconfigured(_) | GhError::Failed { .. } => ExitCode::from(1),
    }
}

/// The program `GRDR_GH` names, or `gh` from `PATH`.
pub fn program_from(lookup: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    lookup(PROGRAM_VARIABLE)
        .filter(|value| !value.is_empty())
        .map_or_else(|| PathBuf::from("gh"), PathBuf::from)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static SERIAL: Mutex<()> = Mutex::new(());

    pub(crate) const GITHUB: &str = "[github]\nrepository = \"416rehman/Guardrails\"\ncall_timeout_seconds = 60\npush_timeout_seconds = 300\nmissing_cli = \"Install gh, run `gh auth login` as {owner}.\"\nmissing_login = \"Run `gh auth login` as {owner}.\"\nmissing_repository = \"Create it: `gh repo create {repository} --public`.\"\nmissing_remote = \"Add the remote for {repository}; {branch} stays local.\"\n";
    const SETTINGS: &str = "[[github.settings]]\nname = \"public\"\nread = [\"api\", \"repos/{repository}\"]\nexpect = { \"/visibility\" = \"public\" }\nfix = \"gh api --method PATCH repos/{repository} -f visibility=public\"\n[[github.settings]]\nname = \"reporting\"\nread = [\"api\", \"repos/{repository}/private-vulnerability-reporting\"]\nexpect = { \"/enabled\" = true }\nfix = \"gh api --method PUT repos/{repository}/private-vulnerability-reporting\"\n[[github.settings]]\nname = \"workflow\"\nread = [\"api\", \"repos/{owner}/{name}/actions/permissions/workflow\"]\nexpect = { \"/can_approve_pull_request_reviews\" = true }\nfix = \"gh api --method PUT repos/{repository}/actions/permissions/workflow\"\n[[github.settings]]\nname = \"scanning\"\nread = [\"api\", \"repos/{repository}\"]\nexpect = { \"/security_and_analysis/secret_scanning/status\" = \"enabled\" }\nfix = \"gh api --method PATCH repos/{repository}\"\n";

    const FAKE_CMD: &str = "@echo off\r\nsetlocal EnableExtensions\r\nset \"dir=%~dp0\"\r\nset n=0\r\nif exist \"%dir%count\" set /p n=<\"%dir%count\"\r\nset /a n=n+1\r\n>\"%dir%count\" echo %n%\r\n>>\"%dir%calls.log\" echo %GH_REPO% %*\r\nfindstr \"^\" > \"%dir%stdin%n%.txt\"\r\nif exist \"%dir%out%n%.txt\" type \"%dir%out%n%.txt\"\r\nif exist \"%dir%err%n%.txt\" type \"%dir%err%n%.txt\" 1>&2\r\nset code=0\r\nif exist \"%dir%code%n%.txt\" set /p code=<\"%dir%code%n%.txt\"\r\nexit /b %code%\r\n";
    const FAKE_SH: &str = "#!/bin/sh\ndir=$(dirname \"$0\")\nn=0\n[ -f \"$dir/count\" ] && n=$(cat \"$dir/count\")\nn=$((n+1))\necho \"$n\" > \"$dir/count\"\necho \"$GH_REPO $*\" >> \"$dir/calls.log\"\ncat > \"$dir/stdin$n.txt\"\n[ -f \"$dir/out$n.txt\" ] && cat \"$dir/out$n.txt\"\n[ -f \"$dir/err$n.txt\" ] && cat \"$dir/err$n.txt\" >&2\ncode=0\n[ -f \"$dir/code$n.txt\" ] && code=$(cat \"$dir/code$n.txt\")\nexit \"$code\"\n";

    /// The `[github]` table tests share.
    pub(crate) fn identity() -> Identity {
        Identity::parse(GITHUB).unwrap()
    }

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A fake `gh` in a scratch directory; call `n` prints `out<n>.txt`, `err<n>.txt` and exits `code<n>.txt`.
    struct FakeGh {
        dir: PathBuf,
        program: PathBuf,
    }

    impl FakeGh {
        fn new(name: &str) -> FakeGh {
            let dir =
                std::env::temp_dir().join(format!("xtask-fake-gh-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let program = if cfg!(windows) {
                dir.join("gh.cmd")
            } else {
                dir.join("gh")
            };
            fs::write(&program, if cfg!(windows) { FAKE_CMD } else { FAKE_SH }).unwrap();
            make_executable(&program);
            FakeGh { dir, program }
        }

        fn respond(&self, call: usize, out: &str, err: &str, code: i32) -> &FakeGh {
            fs::write(self.dir.join(format!("out{call}.txt")), out).unwrap();
            fs::write(self.dir.join(format!("err{call}.txt")), err).unwrap();
            fs::write(self.dir.join(format!("code{call}.txt")), code.to_string()).unwrap();
            self
        }

        fn gh(&self, mode: Mode) -> Gh {
            self.gh_for(identity(), mode)
        }

        fn gh_for(&self, identity: Identity, mode: Mode) -> Gh {
            let program = self.program.clone().into_os_string();
            Gh::new(
                program_from(|name| (name == PROGRAM_VARIABLE).then(|| program.clone())),
                identity,
                mode,
            )
        }

        fn calls(&self) -> String {
            fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }

        fn stdin(&self, call: usize) -> String {
            fs::read_to_string(self.dir.join(format!("stdin{call}.txt"))).unwrap_or_default()
        }
    }

    impl Drop for FakeGh {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    #[test]
    fn the_environment_variable_names_the_program() {
        assert_eq!(program_from(|_| None), PathBuf::from("gh"));
        assert_eq!(
            program_from(|_| Some(OsString::from("/opt/fake-gh"))),
            PathBuf::from("/opt/fake-gh")
        );
        assert_eq!(program_from(|_| Some(OsString::new())), PathBuf::from("gh"));
    }

    #[test]
    fn the_identity_and_its_owner_steps_come_from_the_harness() {
        let identity = identity();
        assert_eq!(identity.owner(), "416rehman");
        assert_eq!(
            identity.owner_step(Missing::Repository),
            "Create it: `gh repo create 416rehman/Guardrails --public`."
        );
        assert_eq!(
            identity.missing_remote("agent/7/a1"),
            "Add the remote for 416rehman/Guardrails; agent/7/a1 stays local."
        );
        assert!(Identity::parse("[github]\nrepository = \"a/b\"\n").is_err());
    }

    #[test]
    fn preflight_reads_the_repository_through_gh() {
        let _serial = serial();
        let fake = FakeGh::new("ok");
        fake.respond(
            1,
            "{\"nameWithOwner\":\"416rehman/Guardrails\",\"visibility\":\"PUBLIC\"}\n",
            "",
            0,
        );
        let view = fake.gh(Mode::Live).preflight().unwrap();
        assert!(view.contains("PUBLIC"));
        let calls = fake.calls();
        assert!(
            calls.contains("416rehman/Guardrails repo view 416rehman/Guardrails --json"),
            "{calls}"
        );
    }

    #[test]
    fn every_setting_is_read_and_a_failed_read_does_not_stop_the_rest() {
        let _serial = serial();
        let fake = FakeGh::new("settings");
        fake.respond(1, "{\"visibility\":\"PUBLIC\"}\n", "", 0)
            .respond(2, "{\"visibility\":\"public\"}\n", "", 0)
            .respond(3, "{\"enabled\":false}\n", "", 0)
            .respond(
                4,
                "",
                "gh: Resource not accessible by personal access token (HTTP 403)\n",
                1,
            )
            .respond(5, "{\"visibility\":\"public\"}\n", "", 0);
        let identity = Identity::parse(&format!("{GITHUB}{SETTINGS}")).unwrap();
        assert_eq!(check(&fake.gh_for(identity, Mode::Live)), ExitCode::from(1));
        let calls = fake.calls();
        assert_eq!(calls.lines().count(), 5, "{calls}");
        assert!(
            calls.contains("api repos/416rehman/Guardrails/actions/permissions/workflow"),
            "{calls}"
        );
    }

    #[test]
    fn a_finding_names_what_differs_and_the_fix() {
        let identity = Identity::parse(&format!("{GITHUB}{SETTINGS}")).unwrap();
        let settings = &identity.settings;
        assert_eq!(
            settings[0].judge(&serde_json::json!({"visibility": "public"})),
            Finding::Holds
        );
        let differs = settings[1].judge(&serde_json::json!({"enabled": false}));
        assert_eq!(
            differs,
            Finding::Differs(vec!["/enabled is false, not true".into()])
        );
        assert_eq!(
            differs.line(&settings[1], &identity),
            "github: reporting: does not hold (/enabled is false, not true); fix: gh api --method PUT repos/416rehman/Guardrails/private-vulnerability-reporting"
        );
        let unreadable = settings[3].judge(&serde_json::json!({"visibility": "public"}));
        assert!(
            matches!(&unreadable, Finding::Unreadable(why) if why.contains("/security_and_analysis/secret_scanning/status")),
            "{unreadable:?}"
        );
        assert!(unreadable.line(&settings[3], &identity).ends_with(
            "fix if it does not hold: gh api --method PATCH repos/416rehman/Guardrails"
        ));
    }

    #[test]
    fn a_harness_without_settings_checks_only_the_repository() {
        let _serial = serial();
        let fake = FakeGh::new("no-settings");
        fake.respond(1, "{\"visibility\":\"PUBLIC\"}\n", "", 0);
        assert_eq!(check(&fake.gh(Mode::Live)), ExitCode::SUCCESS);
        assert_eq!(fake.calls().lines().count(), 1);
    }

    #[test]
    fn a_missing_repository_names_the_owner_step() {
        let _serial = serial();
        let fake = FakeGh::new("missing");
        fake.respond(1, "", "GraphQL: Could not resolve to a Repository with the name '416rehman/Guardrails'. (repository)\n", 1);
        let error = fake.gh(Mode::Live).preflight().unwrap_err();
        assert!(matches!(
            &error,
            GhError::Missing {
                missing: Missing::Repository,
                ..
            }
        ));
        assert!(
            error
                .to_string()
                .contains("gh repo create 416rehman/Guardrails --public")
        );
        assert_eq!(report(&error), ExitCode::from(EXIT_OWNER_STEP));
    }

    #[test]
    fn a_missing_login_or_cli_names_the_owner_step() {
        let _serial = serial();
        let fake = FakeGh::new("login");
        fake.respond(
            1,
            "",
            "To get started with GitHub CLI, please run:  gh auth login\n",
            4,
        );
        assert!(matches!(
            fake.gh(Mode::Live).preflight().unwrap_err(),
            GhError::Missing {
                missing: Missing::Login,
                ..
            }
        ));
        let absent = Gh::new(fake.dir.join("no-such-gh-binary"), identity(), Mode::Live);
        assert!(matches!(
            absent.preflight().unwrap_err(),
            GhError::Missing {
                missing: Missing::Cli,
                ..
            }
        ));
    }

    #[test]
    fn writes_send_bodies_on_stdin_and_dry_runs_send_nothing() {
        let _serial = serial();
        let fake = FakeGh::new("write");
        fake.respond(
            1,
            "https://github.com/416rehman/Guardrails/issues/7\n",
            "",
            0,
        );
        let dry = fake.gh(Mode::DryRun).write(
            &["issue", "create", "--title", "x", "--body-file", "-"],
            Some("body"),
        );
        assert!(matches!(dry, Ok(Written::DryRun(_))));
        assert_eq!(fake.calls(), "");
        let live = fake.gh(Mode::Live).write(
            &["issue", "create", "--title", "x", "--body-file", "-"],
            Some("issue body\n"),
        );
        assert_eq!(
            live.unwrap(),
            Written::Ran("https://github.com/416rehman/Guardrails/issues/7\n".into())
        );
        assert!(
            fake.calls()
                .contains("issue create --title x --body-file -")
        );
        assert!(fake.stdin(1).contains("issue body"));
    }

    #[test]
    fn other_failures_keep_the_detail() {
        let _serial = serial();
        let fake = FakeGh::new("fail");
        fake.respond(1, "", "label not found\n", 1);
        let error = fake.gh(Mode::Live).read(&["issue", "list"]).unwrap_err();
        assert!(
            matches!(&error, GhError::Failed { detail, .. } if detail.contains("label not found"))
        );
        assert_eq!(report(&error), ExitCode::from(1));
    }

    #[test]
    fn an_unconfigured_target_calls_nothing() {
        let gh = Gh {
            program: PathBuf::from("gh"),
            target: Target::Unconfigured("no harness".into()),
            mode: Mode::Live,
        };
        assert_eq!(gh.repository(), "");
        assert!(matches!(
            gh.read(&["issue", "list"]),
            Err(GhError::Unconfigured(_))
        ));
        assert_eq!(
            report(&GhError::Unconfigured("x".into())),
            ExitCode::from(1)
        );
    }
}
