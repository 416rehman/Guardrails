//! Whether Claude Code trusts the repository folder, read from its global config before any
//! session starts (`.agents/harness.toml [workspace_trust]`). In print mode Claude Code never shows
//! the trust dialog and ignores the project's `permissions.allow` rules in a folder it does not
//! trust, so every agent session would stall on tool denials. A config that is missing,
//! unreadable or in a shape this does not know stops the launch too.

use std::fmt;
use std::path::Path;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;

use super::HARNESS_FILE;
use crate::git;
use crate::kit::claude_config::{self, CONFIG_DIR_VARIABLE, HOME_VARIABLE};
use crate::repo::Repo;

#[derive(Debug, Deserialize)]
struct HarnessTrust {
    workspace_trust: TrustPolicy,
}

/// `[workspace_trust]`: where Claude Code keeps the trust, or that something else sets it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "check", rename_all = "kebab-case")]
enum TrustPolicy {
    ClaudeConfig(ConfigKeys),
    Managed,
}

/// The names of the config file and its keys, and the two messages that stop a launch; `{root}`
/// and `{why}` are filled in. The file's directory is [`claude_config::global_config_dir`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ConfigKeys {
    config_file: String,
    projects_key: String,
    accepted_key: String,
    untrusted: String,
    undecided: String,
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    Trusted {
        root: String,
    },
    /// `check = "managed"`: something other than the kit sets the trust.
    Managed,
    /// No session may start; the message is the owner step.
    Refused(String),
}

/// The owner step that lets sessions start, as an error the launcher and the dispatcher stop on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untrusted(pub String);

impl TrustPolicy {
    fn load(repo: &Repo) -> Result<TrustPolicy> {
        let text = repo.read(HARNESS_FILE)?;
        let parsed: HarnessTrust = crate::config::parse_toml(&text, HARNESS_FILE)?;
        Ok(parsed.workspace_trust)
    }
}

impl ConfigKeys {
    /// The trust of the folder Claude Code keys it on, `repo`'s main checkout, with the config
    /// file located through `lookup`.
    fn trust(&self, repo: &Repo, lookup: impl Fn(&str) -> Option<String>) -> Trust {
        let root = match git::main_checkout(repo) {
            Ok(root) => root,
            Err(error) => return self.undecided(repo.root(), &format!("{error:#}")),
        };
        match claude_config::global_config_dir(lookup) {
            Some(dir) => self.read(&dir.join(&self.config_file), &root),
            None => self.undecided(
                &root,
                &format!("neither {CONFIG_DIR_VARIABLE} nor {HOME_VARIABLE} is set"),
            ),
        }
    }

    /// The trust `config` records for `root`. A matching entry whose flag is true trusts it, as
    /// Claude Code may keep one entry per spelling of the path.
    fn read(&self, config: &Path, root: &Path) -> Trust {
        let text = match std::fs::read_to_string(config) {
            Ok(text) => text,
            Err(error) => {
                return self.undecided(
                    root,
                    &format!("{} cannot be read: {error}", config.display()),
                );
            }
        };
        let parsed: Value = match serde_json::from_str(&text) {
            Ok(parsed) => parsed,
            Err(error) => {
                return self.undecided(root, &format!("{} is not JSON: {error}", config.display()));
            }
        };
        let Some(projects) = parsed.get(&self.projects_key).and_then(Value::as_object) else {
            let why = format!("{} has no `{}` object", config.display(), self.projects_key);
            return self.undecided(root, &why);
        };
        let wanted = folder_key(&root.to_string_lossy());
        let flags: Vec<Option<&Value>> = projects
            .iter()
            .filter(|(key, _)| folder_key(key) == wanted)
            .map(|(_, entry)| entry.get(&self.accepted_key))
            .collect();
        if flags.contains(&Some(&Value::Bool(true))) {
            return Trust::Trusted { root: shown(root) };
        }
        let unknown = flags
            .iter()
            .flatten()
            .any(|flag| !matches!(flag, Value::Bool(_)));
        if unknown {
            let why = format!(
                "`{}` in {} is not true or false",
                self.accepted_key,
                config.display()
            );
            return self.undecided(root, &why);
        }
        Trust::Refused(self.untrusted.replace("{root}", &shown(root)))
    }

    fn undecided(&self, root: &Path, why: &str) -> Trust {
        Trust::Refused(
            self.undecided
                .replace("{root}", &shown(root))
                .replace("{why}", why),
        )
    }
}

impl Trust {
    pub fn describe(&self) -> String {
        match self {
            Trust::Trusted { root } => format!("Claude Code trusts {root}"),
            Trust::Managed => {
                format!("{HARNESS_FILE} says the workspace trust is set outside the kit")
            }
            Trust::Refused(step) => step.clone(),
        }
    }
}

impl fmt::Display for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Untrusted {}

/// The trust of the checkout around `repo`, read as `[workspace_trust]` says.
pub fn check(repo: &Repo) -> Result<Trust> {
    Ok(match TrustPolicy::load(repo)? {
        TrustPolicy::Managed => Trust::Managed,
        TrustPolicy::ClaudeConfig(keys) => keys.trust(repo, claude_config::process_variable),
    })
}

/// [`check`], with a refusal as an [`Untrusted`] error.
pub fn require(repo: &Repo) -> Result<()> {
    match check(repo)? {
        Trust::Trusted { .. } | Trust::Managed => Ok(()),
        Trust::Refused(step) => Err(Untrusted(step).into()),
    }
}

/// A path as Claude Code's `projects` keys spell it: forward slashes, no trailing slash, and on
/// Windows in any case.
fn folder_key(path: &str) -> String {
    let forward = path.replace('\\', "/");
    let trimmed = forward.trim_end_matches('/');
    if cfg!(windows) {
        trimmed.to_lowercase()
    } else {
        trimmed.to_owned()
    }
}

fn shown(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::testkit::TempRepo;

    const TRUST: &str = "[workspace_trust]\ncheck = \"claude-config\"\nconfig_file = \".claude.json\"\nprojects_key = \"projects\"\naccepted_key = \"hasTrustDialogAccepted\"\nuntrusted = \"Run claude once in {root}.\"\nundecided = \"Cannot tell for {root} ({why}).\"\n";

    fn keys() -> ConfigKeys {
        let parsed: HarnessTrust = crate::config::parse_toml(TRUST, "harness.toml").unwrap();
        match parsed.workspace_trust {
            TrustPolicy::ClaudeConfig(keys) => keys,
            TrustPolicy::Managed => panic!("the fixture reads the config"),
        }
    }

    fn config(temp: &TempRepo, text: &str) -> PathBuf {
        temp.write("home/.claude.json", text);
        temp.root().join("home/.claude.json")
    }

    #[test]
    fn the_root_is_trusted_only_by_its_own_entry() {
        let temp = TempRepo::create();
        let root = temp.root().join("repo");
        let key = shown(&root);
        let trusted =
            format!("{{\"projects\": {{\"{key}\": {{\"hasTrustDialogAccepted\": true}}}}}}");
        assert_eq!(
            keys().read(&config(&temp, &trusted), &root),
            Trust::Trusted { root: key.clone() }
        );
        let parent = shown(temp.root());
        let only_parent = format!(
            "{{\"projects\": {{\"{parent}\": {{\"hasTrustDialogAccepted\": true}}, \"{key}\": {{\"hasTrustDialogAccepted\": false}}}}}}"
        );
        assert_eq!(
            keys().read(&config(&temp, &only_parent), &root),
            Trust::Refused(format!("Run claude once in {key}."))
        );
        let backslashed = key.replace('/', "\\\\");
        let slashes = format!(
            "{{\"projects\": {{\"{backslashed}/\": {{\"hasTrustDialogAccepted\": true}}}}}}"
        );
        assert!(matches!(
            keys().read(&config(&temp, &slashes), &root),
            Trust::Trusted { .. }
        ));
    }

    #[test]
    fn a_config_it_cannot_read_stops_the_launch() {
        let temp = TempRepo::create();
        let root = temp.root().join("repo");
        let missing = keys().read(&temp.root().join("absent.json"), &root);
        assert!(
            matches!(&missing, Trust::Refused(step) if step.starts_with("Cannot tell for") && step.contains("cannot be read")),
            "{missing:?}"
        );
        let garbled = keys().read(&config(&temp, "{not json"), &root);
        assert!(matches!(&garbled, Trust::Refused(step) if step.contains("is not JSON")));
        let shapeless = keys().read(&config(&temp, "{\"projects\": []}"), &root);
        assert!(
            matches!(&shapeless, Trust::Refused(step) if step.contains("has no `projects` object"))
        );
        let key = shown(&root);
        let odd =
            format!("{{\"projects\": {{\"{key}\": {{\"hasTrustDialogAccepted\": \"yes\"}}}}}}");
        let flagged = keys().read(&config(&temp, &odd), &root);
        assert!(matches!(&flagged, Trust::Refused(step) if step.contains("is not true or false")));
    }

    #[test]
    fn the_config_is_found_through_the_config_dir_variable() {
        let temp = TempRepo::create();
        crate::orchestrate::testkit::init_git(temp.root());
        let root = shown(&git::main_checkout(&temp.repo()).unwrap());
        temp.write(
            "cfg/.claude.json",
            &format!("{{\"projects\": {{\"{root}\": {{\"hasTrustDialogAccepted\": true}}}}}}"),
        );
        let dir = temp.root().join("cfg").to_string_lossy().into_owned();
        let config_dir = move |name: &str| (name == CONFIG_DIR_VARIABLE).then(|| dir.clone());
        assert!(matches!(
            keys().trust(&temp.repo(), config_dir),
            Trust::Trusted { .. }
        ));
        let unlocated = keys().trust(&temp.repo(), |_: &str| None);
        let unset = format!("neither {CONFIG_DIR_VARIABLE} nor {HOME_VARIABLE} is set");
        assert!(
            matches!(&unlocated, Trust::Refused(step) if step.contains(&unset)),
            "{unlocated:?}"
        );
    }

    #[test]
    fn a_worktree_is_trusted_through_its_main_checkout() {
        let temp = TempRepo::create();
        crate::orchestrate::testkit::init_git(temp.root());
        let worktree = temp.root().join(".agent/worktrees/7-a1");
        crate::orchestrate::testkit::git(
            temp.root(),
            &[
                "worktree",
                "add",
                "--quiet",
                "--detach",
                &worktree.to_string_lossy(),
            ],
        );
        let main = git::main_checkout(&temp.repo()).unwrap();
        assert_eq!(git::main_checkout(&Repo::at(&worktree)).unwrap(), main);
        assert_eq!(
            std::fs::canonicalize(&main).unwrap(),
            std::fs::canonicalize(temp.root()).unwrap()
        );
    }

    #[test]
    fn managed_trust_reads_no_config() {
        let temp = TempRepo::create();
        temp.write(HARNESS_FILE, "[workspace_trust]\ncheck = \"managed\"\n");
        assert_eq!(check(&temp.repo()).unwrap(), Trust::Managed);
        assert!(require(&temp.repo()).is_ok());
        temp.write(HARNESS_FILE, "[launch]\nharness = \"claude-code\"\n");
        assert!(
            check(&temp.repo()).is_err(),
            "no [workspace_trust] stops the launch"
        );
    }
}
