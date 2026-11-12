//! `cargo xtask kit install` (team/03 section 1): builds `xtask` with the `kit` profile from the
//! merge base with `origin/main`, else `main`, else `HEAD`, else the working tree while nothing is
//! committed; copies it to `.agent/kit/bin/` with the source commit and the `xtask/` tree digest
//! beside it; writes what this machine needs of the plugin marketplace into
//! `.claude/settings.local.json` and reports each pinned plugin whose installed commit differs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::clock::Utc;
use crate::config::limits::Limits;
use crate::config::marketplace::{Catalogue, InstalledPlugins, Marketplace, PinState};
use crate::git::{self, Base, BaseOrigin};
use crate::kit::claude_config::{self, process_variable};
use crate::kit::settings::SETTINGS_PATH;
use crate::process;
use crate::repo::{Repo, walk_files, write_if_changed};

pub const BIN_DIR: &str = ".agent/kit/bin";
pub const RECORD_FILE: &str = ".agent/kit/bin/xtask.json";
pub const RECORD_SCHEMA: &str = "kit-install.v1";
pub const LOCAL_SETTINGS: &str = ".claude/settings.local.json";
const SCRATCH_WORKTREE: &str = "target/kit-src";
const PROFILE: &str = "kit";
const SHORT_COMMIT: usize = 12;
const KNOWN_MARKETPLACES: &str = "extraKnownMarketplaces";
const ENABLED_PLUGINS: &str = "enabledPlugins";
const PLUGIN_ROOT_VARIABLE: &str = "CLAUDE_CODE_PLUGIN_CACHE_DIR";
const PLUGINS_DIR_NAME: &str = "plugins";
const INSTALLED_PLUGINS_FILE: &str = "installed_plugins.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum KitSource {
    MergeBase { reference: String, commit: String },
    Head { commit: String },
    WorkingTree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRecord {
    pub schema: String,
    #[serde(flatten)]
    pub source: KitSource,
    /// The git tree id of `xtask/` at the source commit; absent for a working-tree build.
    pub xtask_tree: Option<String>,
    /// SHA-256 over the paths and contents of the `xtask/` files that were built.
    pub tree_digest: String,
    pub built_at: String,
}

/// Where this machine's sessions learn the marketplace from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Declaration {
    /// `.claude/settings.json` names the catalogue's directory, so the local entry goes.
    Tracked,
    /// Only `.claude/settings.local.json` names it, by the main checkout's absolute path.
    Local { path: String },
}

/// The marketplace's part of `.claude/settings.local.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalPlugins {
    declaration: Declaration,
    /// Entries with a git source: Claude Code fetches one only when an untracked, user or managed
    /// settings file enables it.
    fetched: Vec<String>,
    /// User-scope plugins that load under the name an entry here uses.
    shadowed: Vec<String>,
}

impl KitSource {
    pub fn commit(&self) -> Option<&str> {
        match self {
            KitSource::MergeBase { commit, .. } | KitSource::Head { commit } => Some(commit),
            KitSource::WorkingTree => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            KitSource::MergeBase { reference, commit } => {
                format!("the merge base with {reference} ({})", short(commit))
            }
            KitSource::Head { commit } => format!("HEAD ({})", short(commit)),
            KitSource::WorkingTree => "the working tree (nothing is committed yet)".to_owned(),
        }
    }
}

impl LocalPlugins {
    fn describe(&self, marketplace: &str) -> String {
        let named = match &self.declaration {
            Declaration::Tracked => format!("{SETTINGS_PATH} names marketplace {marketplace}"),
            Declaration::Local { path } => {
                format!("{LOCAL_SETTINGS} names marketplace {marketplace} at {path}")
            }
        };
        let mut text = format!(
            "{named}; {LOCAL_SETTINGS} enables the {} plugins with a git source",
            self.fetched.len()
        );
        if !self.shadowed.is_empty() {
            text.push_str(&format!(
                " and turns off the user-scope {}, which load under the same names",
                self.shadowed.join(", ")
            ));
        }
        text
    }
}

/// Where the next install builds from.
pub fn source(repo: &Repo) -> Result<KitSource> {
    Ok(match git::resolve_base(repo)? {
        Base::Commit {
            commit,
            origin: BaseOrigin::MergeBase(reference),
        } => KitSource::MergeBase { reference, commit },
        Base::Commit { commit, .. } => KitSource::Head { commit },
        Base::Unborn => KitSource::WorkingTree,
    })
}

pub fn binary_path(repo: &Repo) -> PathBuf {
    repo.path(&format!("{BIN_DIR}/xtask{}", std::env::consts::EXE_SUFFIX))
}

pub fn installed(repo: &Repo) -> Result<Option<InstallRecord>> {
    let Some(text) = repo.read_optional(RECORD_FILE)? else {
        return Ok(None);
    };
    serde_json::from_str(&text)
        .with_context(|| format!("parsing {RECORD_FILE}"))
        .map(Some)
}

/// Whether the installed binary was built from what the next install would build from: the
/// same commit, or a commit whose `xtask/` tree is the same. `SessionStart` rebuilds otherwise.
pub fn is_current(repo: &Repo) -> Result<bool> {
    let Some(record) = installed(repo)? else {
        return Ok(false);
    };
    if !binary_path(repo).is_file() {
        return Ok(false);
    }
    let next = source(repo)?;
    let Some(commit) = next.commit() else {
        return Ok(record.source == KitSource::WorkingTree
            && digest_dir(&repo.path("xtask"))? == record.tree_digest);
    };
    if record.source.commit() == Some(commit) {
        return Ok(true);
    }
    let tree = git::tree_id(repo, commit, "xtask")?;
    Ok(tree.is_some() && tree == record.xtask_tree)
}

pub fn run(repo: &Repo) -> Result<ExitCode> {
    let source = source(repo)?;
    let stamp = Utc::now();
    let log = format!(".agent/logs/kit-install-{}.log", stamp.compact());
    let (built, digest) = match source.commit() {
        Some(commit) => build_commit(repo, commit, &log)?,
        None => {
            let built = build(repo, repo.root(), &log)?;
            (built, digest_dir(&repo.path("xtask"))?)
        }
    };
    let target = binary_path(repo);
    place(&built, &target)?;
    let xtask_tree = match source.commit() {
        Some(commit) => git::tree_id(repo, commit, "xtask")?,
        None => None,
    };
    let record = InstallRecord {
        schema: RECORD_SCHEMA.to_owned(),
        source: source.clone(),
        xtask_tree,
        tree_digest: digest,
        built_at: stamp.iso(),
    };
    let mut json = serde_json::to_string_pretty(&record)?;
    json.push('\n');
    write_if_changed(&repo.path(RECORD_FILE), json.as_bytes())?;
    println!(
        "kit install: built from {} into {BIN_DIR}/; build log {log}",
        source.describe()
    );
    let marketplace = Marketplace::load(repo)?;
    let catalogue = Catalogue::load(repo, &marketplace)?;
    let local = write_local_settings(repo, &marketplace, &catalogue)?;
    println!(
        "kit install: {}",
        local.describe(&marketplace.marketplace.name)
    );
    for line in pin_report(&catalogue, &marketplace, &read_installed()?) {
        println!("kit install: {line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// SHA-256 over every file below `dir` (build output excluded), path and length framed.
pub fn digest_dir(dir: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    for file in walk_files(dir)? {
        let relative = file.strip_prefix(dir).unwrap_or(&file);
        let name = relative.to_string_lossy().replace('\\', "/");
        if name.starts_with("target/") {
            continue;
        }
        let bytes = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(hex(&hasher.finalize()))
}

/// Builds from a scratch worktree at `commit`, so an edit in this worktree cannot change the hooks.
fn build_commit(repo: &Repo, commit: &str, log: &str) -> Result<(PathBuf, String)> {
    let scratch = repo.path(SCRATCH_WORKTREE);
    remove_worktree(repo, &scratch);
    let scratch_text = scratch.to_string_lossy().into_owned();
    git::output(
        repo,
        &[
            "worktree",
            "add",
            "--detach",
            "--force",
            &scratch_text,
            commit,
        ],
    )
    .context("creating the scratch worktree for the kit build")?;
    let result = build(repo, &scratch, log)
        .and_then(|built| Ok((built, digest_dir(&scratch.join("xtask"))?)));
    remove_worktree(repo, &scratch);
    result
}

fn remove_worktree(repo: &Repo, scratch: &Path) {
    let scratch_text = scratch.to_string_lossy().into_owned();
    let _ = git::try_output(repo, &["worktree", "remove", "--force", &scratch_text]);
    if scratch.exists() {
        let _ = fs::remove_dir_all(scratch);
    }
    let _ = git::try_output(repo, &["worktree", "prune"]);
}

fn build(repo: &Repo, source: &Path, log: &str) -> Result<PathBuf> {
    let target_dir = repo.path("target");
    let mut command = Command::new(process::cargo());
    command
        .args([
            "build",
            "--locked",
            "--profile",
            PROFILE,
            "--package",
            "xtask",
            "--bin",
            "xtask",
            "--target-dir",
        ])
        .arg(&target_dir)
        .current_dir(source)
        .env("CARGO_TERM_COLOR", "never");
    let timeout = Limits::built_with()?.kit.install.build_timeout();
    let ran = process::run(&mut command, None, timeout).context("starting cargo build")?;
    write_if_changed(
        &repo.path(log),
        format!("{}{}", ran.stdout(), ran.stderr()).as_bytes(),
    )?;
    if !ran.success() {
        bail!(
            "cargo build --profile {PROFILE} failed ({}); see {log}",
            ran.describe()
        );
    }
    Ok(target_dir
        .join(PROFILE)
        .join(format!("xtask{}", std::env::consts::EXE_SUFFIX)))
}

/// Windows cannot overwrite a running executable but can rename it, so the old binary moves aside.
pub fn place(built: &Path, target: &Path) -> Result<()> {
    let dir = target
        .parent()
        .context("the kit binary path has no directory")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let incoming = target.with_extension("new");
    let outgoing = target.with_extension("old");
    fs::copy(built, &incoming)
        .with_context(|| format!("copying {} to {}", built.display(), incoming.display()))?;
    if target.exists() {
        let _ = fs::remove_file(&outgoing);
        fs::rename(target, &outgoing)
            .with_context(|| format!("moving {} aside", target.display()))?;
    }
    fs::rename(&incoming, target).with_context(|| format!("installing {}", target.display()))?;
    let _ = fs::remove_file(&outgoing);
    Ok(())
}

/// Merges the marketplace's part into `.claude/settings.local.json`, keeping every other key.
fn write_local_settings(
    repo: &Repo,
    marketplace: &Marketplace,
    catalogue: &Catalogue,
) -> Result<LocalPlugins> {
    let user = read_json(claude_config::user_settings(process_variable).as_deref())?;
    let plugins = LocalPlugins {
        declaration: declaration(repo, marketplace, &catalogue.root)?,
        fetched: catalogue
            .git_entries(marketplace)
            .map(|(id, _)| id)
            .collect(),
        shadowed: user.map_or_else(Vec::new, |user| marketplace.shadowed_by(&user)),
    };
    let mut settings = match repo.read_optional(LOCAL_SETTINGS)? {
        Some(text) => serde_json::from_str::<Value>(&text)
            .with_context(|| format!("parsing {LOCAL_SETTINGS}"))?,
        None => Value::Object(Map::new()),
    };
    let Some(root) = settings.as_object_mut() else {
        bail!("{LOCAL_SETTINGS} is not a JSON object");
    };
    apply(root, &marketplace.marketplace.name, &plugins)?;
    let mut text = serde_json::to_string_pretty(&settings)?;
    text.push('\n');
    write_if_changed(&repo.path(LOCAL_SETTINGS), text.as_bytes())?;
    Ok(plugins)
}

fn declaration(repo: &Repo, marketplace: &Marketplace, catalogue: &str) -> Result<Declaration> {
    let tracked = match repo.read_optional(SETTINGS_PATH)? {
        Some(text) => serde_json::from_str::<Value>(&text)
            .with_context(|| format!("parsing {SETTINGS_PATH}"))?,
        None => Value::Null,
    };
    let named = tracked
        .get(KNOWN_MARKETPLACES)
        .and_then(|known| known.get(&marketplace.marketplace.name))
        .and_then(|entry| entry.get("source"));
    if named.is_some() && named == marketplace.directory_source().as_ref() {
        return Ok(Declaration::Tracked);
    }
    let directory = main_checkout(repo)?.join(catalogue);
    let directory = fs::canonicalize(&directory).with_context(|| {
        format!(
            "the marketplace directory {} does not exist",
            directory.display()
        )
    })?;
    Ok(Declaration::Local {
        path: display_path(&directory),
    })
}

/// The main checkout, where Claude Code resolves the tracked relative path for every worktree.
fn main_checkout(repo: &Repo) -> Result<PathBuf> {
    let common = git::try_output(
        repo,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    Ok(common
        .as_deref()
        .map(str::trim)
        .map(Path::new)
        .and_then(Path::parent)
        .map_or_else(|| repo.root().to_path_buf(), Path::to_path_buf))
}

fn apply(root: &mut Map<String, Value>, marketplace: &str, plugins: &LocalPlugins) -> Result<()> {
    match &plugins.declaration {
        Declaration::Tracked => {
            let emptied = match root
                .get_mut(KNOWN_MARKETPLACES)
                .and_then(Value::as_object_mut)
            {
                Some(known) => {
                    known.remove(marketplace);
                    known.is_empty()
                }
                None => false,
            };
            if emptied {
                root.remove(KNOWN_MARKETPLACES);
            }
        }
        Declaration::Local { path } => {
            object_entry(root, KNOWN_MARKETPLACES)?.insert(
                marketplace.to_owned(),
                json!({ "source": { "source": "directory", "path": path } }),
            );
        }
    }
    let enabled = object_entry(root, ENABLED_PLUGINS)?;
    let ours = format!("@{marketplace}");
    enabled.retain(|id, _| !id.ends_with(&ours) || plugins.fetched.contains(id));
    for id in &plugins.fetched {
        enabled.insert(id.clone(), json!(true));
    }
    for id in &plugins.shadowed {
        enabled.insert(id.clone(), json!(false));
    }
    Ok(())
}

fn object_entry<'a>(
    root: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>> {
    root.entry(key)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .with_context(|| format!("{LOCAL_SETTINGS}: {key} is not an object"))
}

/// One line per pinned plugin whose installed commit is not its pin (team/03 section 9 rule 2),
/// and one for those not fetched yet.
fn pin_report(
    catalogue: &Catalogue,
    marketplace: &Marketplace,
    installed: &InstalledPlugins,
) -> Vec<String> {
    let mut lines = Vec::new();
    let mut waiting = Vec::new();
    for (id, source) in catalogue.git_entries(marketplace) {
        let pin = source.sha();
        match installed.pin_state(&id, pin) {
            PinState::AtPin => {}
            PinState::NotFetched => waiting.push(id),
            PinState::Unrecorded => lines.push(format!(
                "{id} is installed without a recorded commit, so its pin {pin} is not checked"
            )),
            PinState::Moved { installed, scope } => lines.push(format!(
                "pin mismatch: {id} is installed at {installed}, pinned at {pin}; run `claude plugin uninstall {id} --scope {scope}`, then `claude plugin install {id} --scope local`"
            )),
        }
    }
    if !waiting.is_empty() {
        lines.push(format!(
            "{} pinned plugins are not fetched yet; Claude Code fetches them when a session starts, or `claude plugin install <id> --scope local` fetches one now: {}",
            waiting.len(),
            waiting.join(", ")
        ));
    }
    lines
}

/// What Claude Code records as installed on this machine; empty where it has recorded nothing.
pub fn read_installed() -> Result<InstalledPlugins> {
    let path = std::env::var_os(PLUGIN_ROOT_VARIABLE)
        .filter(|root| !root.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            claude_config::config_dir(process_variable).map(|dir| dir.join(PLUGINS_DIR_NAME))
        })
        .map(|root| root.join(INSTALLED_PLUGINS_FILE));
    let Some(value) = read_json(path.as_deref())? else {
        return Ok(InstalledPlugins::default());
    };
    serde_json::from_value(value).context("reading Claude Code's installed_plugins.json")
}

/// A JSON file's value; `None` when there is no path or no file.
fn read_json(path: Option<&Path>) -> Result<Option<Value>> {
    let Some(path) = path else {
        return Ok(None);
    };
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// A path with forward slashes and without the `\\?\` prefix `fs::canonicalize` adds on Windows.
fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    text.strip_prefix("//?/").map(str::to_owned).unwrap_or(text)
}

fn short(commit: &str) -> &str {
    commit.get(..SHORT_COMMIT).unwrap_or(commit)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "489dd5a409814c9db337a4d53bce440aba75d21f";

    #[test]
    fn digest_changes_with_content_and_ignores_target() {
        let dir = std::env::temp_dir().join(format!("xtask-digest-{}", std::process::id()));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").unwrap();
        let first = digest_dir(&dir).unwrap();
        fs::create_dir_all(dir.join("target")).unwrap();
        fs::write(dir.join("target").join("junk"), "x").unwrap();
        assert_eq!(digest_dir(&dir).unwrap(), first);
        fs::write(dir.join("src").join("main.rs"), "fn main() { }\n").unwrap();
        assert_ne!(digest_dir(&dir).unwrap(), first);
        assert_eq!(first.len(), 64);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn record_round_trips_with_a_tagged_source() {
        let record = InstallRecord {
            schema: RECORD_SCHEMA.into(),
            source: KitSource::MergeBase {
                reference: "origin/main".into(),
                commit: "abc".into(),
            },
            xtask_tree: Some("def".into()),
            tree_digest: "00".repeat(32),
            built_at: "2026-11-11T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"source\":\"merge-base\""));
        assert_eq!(
            serde_json::from_str::<InstallRecord>(&json).unwrap(),
            record
        );
    }

    #[test]
    fn display_path_strips_the_verbatim_prefix() {
        assert_eq!(
            display_path(Path::new(r"\\?\D:\checkout\.agents\marketplace")),
            "D:/checkout/.agents/marketplace"
        );
    }

    #[test]
    fn a_local_declaration_enables_git_entries_and_drops_stale_ones() {
        let mut root = json!({
            "model": "kept",
            "extraKnownMarketplaces": { "other": { "source": { "source": "github", "repo": "a/b" } } },
            "enabledPlugins": { "gone@grdr-agent-marketplace": true, "mine@other": true }
        });
        let plugins = LocalPlugins {
            declaration: Declaration::Local {
                path: "D:/checkout/.agents/marketplace".into(),
            },
            fetched: vec!["cleanup@grdr-agent-marketplace".into()],
            shadowed: vec!["cleanup@claude-mods".into()],
        };
        let map = root.as_object_mut().unwrap();
        apply(map, "grdr-agent-marketplace", &plugins).unwrap();
        assert_eq!(
            root,
            json!({
                "model": "kept",
                "extraKnownMarketplaces": {
                    "other": { "source": { "source": "github", "repo": "a/b" } },
                    "grdr-agent-marketplace": { "source": { "source": "directory", "path": "D:/checkout/.agents/marketplace" } }
                },
                "enabledPlugins": {
                    "mine@other": true,
                    "cleanup@grdr-agent-marketplace": true,
                    "cleanup@claude-mods": false
                }
            })
        );
    }

    #[test]
    fn a_tracked_declaration_removes_the_local_entry() {
        let mut root = json!({ "extraKnownMarketplaces": {
            "grdr-agent-marketplace": { "source": { "source": "directory", "path": "D:/old" } }
        }});
        let plugins = LocalPlugins {
            declaration: Declaration::Tracked,
            fetched: Vec::new(),
            shadowed: Vec::new(),
        };
        apply(
            root.as_object_mut().unwrap(),
            "grdr-agent-marketplace",
            &plugins,
        )
        .unwrap();
        assert_eq!(root, json!({ "enabledPlugins": {} }));
    }

    #[test]
    fn short_commits_never_split_a_character() {
        assert_eq!(short(PIN), "489dd5a40981");
        assert_eq!(short("abc"), "abc");
    }
}
