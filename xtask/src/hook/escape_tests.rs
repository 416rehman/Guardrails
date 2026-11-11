//! Writes that would leave a session's repository by a route the path text hides: from a
//! dispatcher worktree up into its main checkout, through a link the repository holds or the same
//! command makes, and into gh's configuration where Windows keeps it. Each is refused for the file
//! tools and the shell alike, and a write to an ordinary path outside stays allowed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;

use super::context::{Context, Env, Input};
use super::limits::kit_limits;
use super::outcome::Outcome;
use super::selftest::cases::write_preset;
use super::{command, guard_path};
use crate::orchestrate::testkit::{git, init_git};
use crate::repo::Repo;
use crate::testkit::{TempRepo, link_dir};

const DEADLINE: Duration = Duration::from_secs(30);

/// A main checkout with a dispatcher worktree in it, and a home directory beside them.
struct Checkouts {
    main: TempRepo,
    home: TempRepo,
    worktree: PathBuf,
}

impl Checkouts {
    fn new() -> Checkouts {
        let main = TempRepo::create();
        write_preset(main.root(), "worker").unwrap();
        init_git(main.root());
        let worktree = main.root().join(".agent/worktrees/7-a1");
        git(
            main.root(),
            &[
                "worktree",
                "add",
                "--quiet",
                "--detach",
                &worktree.to_string_lossy(),
            ],
        );
        Checkouts {
            main,
            home: TempRepo::create(),
            worktree,
        }
    }

    fn env(&self, extra: &[(&str, String)]) -> Env {
        let home = self.home.root().to_string_lossy().into_owned();
        let mut pairs = vec![
            ("GRDR_AGENT".to_owned(), "impl-rust".to_owned()),
            ("HOME".to_owned(), home.clone()),
            ("USERPROFILE".to_owned(), home),
        ];
        pairs.extend(
            extra
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone())),
        );
        Env::from_pairs(pairs)
    }

    fn judge(&self, root: &Path, mut input: serde_json::Value, env: Env) -> Outcome {
        input["cwd"] = json!(root.to_string_lossy());
        let context = Context::new(
            Repo::at(root),
            Input::parse(&input.to_string()).unwrap(),
            env,
            Instant::now() + DEADLINE,
            Arc::default(),
            kit_limits(),
        );
        match input["tool_name"].as_str() {
            Some("Write") => guard_path::run(&context).unwrap(),
            _ => command::run(&context).unwrap(),
        }
    }

    fn write(&self, root: &Path, file_path: &str, env: Env) -> Outcome {
        self.judge(
            root,
            json!({"tool_name": "Write", "tool_input": {"file_path": file_path}}),
            env,
        )
    }

    fn shell(&self, root: &Path, tool: &str, command: &str, env: Env) -> Outcome {
        self.judge(
            root,
            json!({"tool_name": tool, "tool_input": {"command": command}}),
            env,
        )
    }
}

/// `path` with forward slashes, which Git Bash and PowerShell both read as written.
fn shell_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn blocked_for(outcome: &Outcome, reason: &str) {
    match outcome {
        Outcome::Block(text) => assert!(text.contains(reason), "{text}"),
        other => panic!("expected a block for {reason}, got {other:?}"),
    }
}

#[test]
fn a_worktree_session_never_writes_its_main_checkout() {
    let checkouts = Checkouts::new();
    let worktree = &checkouts.worktree;
    let reason = "is in the main checkout";
    for climb in [
        "../../kit/bin/xtask.exe",
        "../../../.claude/settings.local.json",
        "../../../.agents/kit/protected-paths.toml",
        "../other/src/lib.rs",
    ] {
        blocked_for(
            &checkouts.write(worktree, climb, checkouts.env(&[])),
            reason,
        );
    }
    let shell = checkouts.shell(
        worktree,
        "Bash",
        "cp evil.exe ../../kit/bin/xtask.exe",
        checkouts.env(&[("GRDR_WORK_ITEM", "7".to_owned())]),
    );
    blocked_for(&shell, reason);
    let config = checkouts.shell(
        worktree,
        "Bash",
        "printf x >> ../../../.git/config",
        checkouts.env(&[]),
    );
    blocked_for(&config, "inside a git directory");
    let elsewhere = checkouts.home.root().join("notes.txt");
    let allowed = checkouts.write(worktree, &elsewhere.to_string_lossy(), checkouts.env(&[]));
    assert!(matches!(allowed, Outcome::Allow), "{allowed:?}");
}

#[test]
fn a_link_in_the_repository_is_judged_where_it_leads() {
    let checkouts = Checkouts::new();
    let main = checkouts.main.root();
    let claude = checkouts.home.root().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    link_dir(&main.join("cfglink"), &claude);
    let reason = "configures every later session";
    blocked_for(
        &checkouts.write(main, "cfglink/settings.json", checkouts.env(&[])),
        reason,
    );
    let shell = checkouts.shell(
        main,
        "Bash",
        "echo {} > cfglink/settings.json",
        checkouts.env(&[]),
    );
    blocked_for(&shell, reason);
    let ordinary = checkouts.write(main, "crates/a/src/lib.rs", checkouts.env(&[]));
    assert!(!matches!(ordinary, Outcome::Block(_)), "{ordinary:?}");
}

#[test]
fn a_link_the_command_makes_is_judged_as_a_write_to_its_target() {
    let checkouts = Checkouts::new();
    let main = checkouts.main.root();
    let claude = shell_path(&checkouts.home.root().join(".claude"));
    let made = [
        (
            "Bash",
            format!("ln -s {claude} cfglink && echo {{}} > cfglink/settings.json"),
        ),
        (
            "PowerShell",
            format!(
                "New-Item -ItemType Junction -Path cfglink -Target {claude}; Set-Content -Path cfglink/settings.json -Value x"
            ),
        ),
    ];
    for (tool, command) in made {
        blocked_for(
            &checkouts.shell(main, tool, &command, checkouts.env(&[])),
            "configures every later session",
        );
    }
    let outside = shell_path(&checkouts.home.root().join("cache"));
    blocked_for(
        &checkouts.shell(
            main,
            "Bash",
            &format!("ln -s {outside} cache"),
            checkouts.env(&[]),
        ),
        "an agent links only to paths inside the repository",
    );
    blocked_for(
        &checkouts.shell(
            main,
            "Bash",
            "ln -s Cargo.toml manifest",
            checkouts.env(&[]),
        ),
        "protected",
    );
    let inside = checkouts.shell(main, "Bash", "ln -s crates/a docs-a", checkouts.env(&[]));
    assert!(matches!(inside, Outcome::Allow), "{inside:?}");
}

#[test]
fn the_gh_configuration_is_refused_where_gh_keeps_it() {
    let checkouts = Checkouts::new();
    let main = checkouts.main.root();
    let app_data = checkouts.home.root().join("AppData").join("Roaming");
    let env = || checkouts.env(&[("APPDATA", app_data.to_string_lossy().into_owned())]);
    let hosts = app_data.join("GitHub CLI").join("hosts.yml");
    let reason = "configures every later session";
    blocked_for(
        &checkouts.write(main, &hosts.to_string_lossy(), env()),
        reason,
    );
    let shell = checkouts.shell(
        main,
        "Bash",
        &format!("cp hosts.yml '{}'", hosts.to_string_lossy()),
        env(),
    );
    blocked_for(&shell, reason);
    let fallback = checkouts.home.root().join(".config/gh/hosts.yml");
    blocked_for(
        &checkouts.write(main, &fallback.to_string_lossy(), env()),
        reason,
    );
}

#[test]
fn powershell_null_discards_and_wrapped_commands_are_scanned() {
    let checkouts = Checkouts::new();
    let main = checkouts.main.root();
    let env = || checkouts.env(&[("GRDR_WORK_ITEM", "7".to_owned())]);
    for discarded in [
        "cargo build 2>$null",
        "git fetch origin > $null",
        "cargo build *>$NULL",
    ] {
        let outcome = checkouts.shell(main, "PowerShell", discarded, env());
        assert!(
            matches!(outcome, Outcome::Allow),
            "{discarded}: {outcome:?}"
        );
    }
    let variable = checkouts.shell(main, "Bash", "echo x > $null", env());
    assert!(matches!(variable, Outcome::Block(_)), "{variable:?}");
    for (tool, wrapped) in [
        ("PowerShell", "powershell /c \"git push origin HEAD:main\""),
        (
            "PowerShell",
            "powershell /Command \"git push origin HEAD:main\"",
        ),
        (
            "PowerShell",
            "powershell -NoProfile \"git push origin HEAD:main\"",
        ),
        ("Bash", "cmd //c \"git push origin HEAD:main\""),
        ("PowerShell", "cmd /q/c git push origin HEAD:main"),
    ] {
        blocked_for(&checkouts.shell(main, tool, wrapped, env()), "merge queue");
    }
    blocked_for(
        &checkouts.shell(main, "PowerShell", "powershell /enc ZwBpAHQA", env()),
        "hides the command",
    );
    let settings = checkouts.home.root().join(".claude").join("settings.json");
    let copied = format!("cmd /c copy evil {}", settings.to_string_lossy());
    blocked_for(
        &checkouts.shell(main, "PowerShell", &copied, env()),
        "configures every later session",
    );
}
