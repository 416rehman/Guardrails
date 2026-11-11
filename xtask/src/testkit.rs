//! A minimal, valid kit tree in a scratch directory, for tests of the renderer and the kit rules.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::kit::OWNERSHIP_SENTENCE;
use crate::repo::Repo;

static NEXT: AtomicUsize = AtomicUsize::new(0);

const MODELS: &str = "[models]\nfable = \"claude-fable-5-2\"\nopus = \"claude-opus-5-5\"\nsonnet = \"claude-sonnet-5-5\"\n\n[rules]\nfable_agents = [\"chief-architect\"]\n";
const ROSTER: &str = r#"[defaults]
handoff = "issue comment"

[agent.chief-architect]
group = "direction"
description = "Owns the spine: decisions, RFCs and layer rules."
model = "fable"
effort = "xhigh"
cap_role = "direction"
max_turns = 60
tools = ["Read", "Grep", "Write"]
disallowed_tools = ["Bash"]
write = ["rfcs/**"]
deny_write = "@protected"
net = "B"
skills = ["grdr-verify"]
trigger = "manual"
body = "templates/agents/chief-architect.md"

[agent.impl-rust]
group = "implementer"
description = "Implements one leased issue in the Rust crates."
model = "sonnet"
effort = "high"
cap_role = "worker"
max_turns = 80
tools = ["Read", "Edit", "Write", "Bash"]
write = ["crates/**"]
deny_write = "@protected"
net = "A"
skills = ["grdr-verify", "cleanup:cleanup", "simplify"]
trigger = "dispatch"
body = "templates/agents/impl-rust.md"
"#;
const HOOKS: &str = "[[hook]]\nevent = \"PreToolUse\"\nmatcher = \"Edit|Write\"\nhandler = \"guard-path\"\ntimeout = 10\non_failure = \"block\"\n\n[[hook]]\nevent = \"PreToolUse\"\nmatcher = \"Edit|Write\"\nhandler = \"guard-extra\"\ntimeout = 5\n\n[[hook]]\nevent = \"Stop\"\nhandler = \"stop-gate\"\ntimeout = 600\n";
const PERMISSIONS: &str = r#"[permissions]
default_mode = "default"
disable_bypass = "disable"
deny = ["Edit(./.git/**)", "Bash(git push --force *)"]
ask = ["Bash(git push *)"]
allow = ["Bash(cargo xtask *)"]

[sandbox]
enabled = true
allow_unsandboxed_commands = false
deny_read = ["~/.ssh"]
allowed_domains = ["crates.io"]

[settings]
model = "claude-sonnet-5-5"
available_models = ["opus", "sonnet", "fable"]
auto_memory = false
attribution_commit = ""
attribution_pr = ""
disable_auto_mode = "disable"

[settings.env]
GRDR_KIT = "1"

[managed.implementer]
disableAutoMode = "disable"
allowManagedPermissionRulesOnly = true
strictKnownMarketplaces = [{ source = "pathPattern", pathPattern = '(^|/)\.agents/marketplace/?$' }]

[managed.implementer.permissions]
defaultMode = "dontAsk"
deny = ["WebFetch"]
allow = ["Bash(cargo xtask *)"]

[managed.evaluator.permissions]
defaultMode = "dontAsk"
deny = ["Edit"]
"#;
const PROTECTED: &str = "paths = [\"Cargo.toml\", \"**/AGENTS.md\", \".claude/**\"]\n";
const MARKETPLACE: &str = "[marketplace]\nname = \"grdr-agent-marketplace\"\nlocal_path = \".agents/marketplace\"\n\n[plugins]\nenabled = [\"cleanup@grdr-agent-marketplace\"]\n";
const CATALOGUE: &str = r#"{"name": "grdr-agent-marketplace", "owner": {"name": "kit"}, "plugins": [
  {"name": "cleanup", "source": {"source": "git-subdir", "url": "https://example.com/mods.git", "path": "cleanup", "ref": "main", "sha": "489dd5a409814c9db337a4d53bce440aba75d21f"}}
]}"#;
const PINS: &str =
    "| `cleanup` | `example/mods`, `cleanup/` | `489dd5a409814c9db337a4d53bce440aba75d21f` |\n";
const HARNESS: &str = "[dispatch]\nmax_writers = 3\nprotected_change_agents = [\"lead-agent-kit\", \"chief-architect\"]\n\n[skills]\nbuiltin = [\"simplify\"]\n";
const SKILL: &str = "---\nname: grdr-verify\ndescription: Run the gates before claiming anything works.\nlicense: Apache-2.0\nmetadata:\n  version: \"1\"\n  owner: agent-kit\n  requires: K4\n  closes-by: evidence\n---\n\n# Verify\n";

/// A kit tree that renders and passes every rule; dropped, it removes itself.
pub struct TempRepo {
    root: PathBuf,
}

impl TempRepo {
    pub fn create() -> TempRepo {
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("xtask-kit-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let repo = TempRepo { root };
        let chief = format!("{OWNERSHIP_SENTENCE}\n\nYou are the chief architect.\n");
        let default_tiers = risk_tiers(
            &plain_tiers("[\"proto/**\"]", "[\"crates/**\"]", "[\"docs/**\"]"),
            "[]",
        );
        for (path, text) in [
            (".agents/models.toml", MODELS),
            (".agents/roster.toml", ROSTER),
            (".agents/harness.toml", HARNESS),
            (
                ".agents/templates/common.md",
                "## Rules for every agent\n- Read AGENTS.md.\n",
            ),
            (
                ".agents/templates/agents/chief-architect.md",
                chief.as_str(),
            ),
            (
                ".agents/templates/agents/impl-rust.md",
                "You implement one issue.\n",
            ),
            (".agents/kit/hooks.toml", HOOKS),
            (".agents/kit/permissions.toml", PERMISSIONS),
            (".agents/kit/protected-paths.toml", PROTECTED),
            (".agents/kit/marketplace.toml", MARKETPLACE),
            (
                ".agents/marketplace/.claude-plugin/marketplace.json",
                CATALOGUE,
            ),
            (".agents/marketplace/PINS.md", PINS),
            (".agents/kit/usage.toml", "[role.worker]\nmax_turns = 80\n"),
            (".agents/risk-tiers.toml", default_tiers.as_str()),
            ("security/trust-core.paths", "crates/grdr-crypto/**\n"),
            (
                ".agents/kit/workflows/review.js",
                "export const meta = { name: 'review' };\n",
            ),
            (".agents/skills/grdr-verify/SKILL.md", SKILL),
            (
                ".agents/skills/grdr-verify/references/gates.md",
                "# Gates\n",
            ),
        ] {
            repo.write(path, text);
        }
        repo
    }

    pub fn repo(&self) -> Repo {
        Repo::at(&self.root)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Adds agent tables to the fixture's `.agents/roster.toml`.
    pub fn add_agents(&self, tables: &str) {
        let path = self.repo().path(".agents/roster.toml");
        let mut roster = fs::read_to_string(&path).expect("read the fixture roster");
        roster.push('\n');
        roster.push_str(tables);
        fs::write(path, roster).expect("write the fixture roster");
    }

    pub fn write(&self, path: &str, text: &str) {
        let target = self.repo().path(path);
        fs::create_dir_all(target.parent().expect("a parent directory"))
            .expect("create directories");
        fs::write(target, text).expect("write a fixture file");
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A complete `.agents/risk-tiers.toml`: `tiers` holds the `[high]`, `[medium]` and `[low]`
/// tables (see [`tier`]) and `light` the light lane's evaluators; every other evaluator list is
/// empty.
pub fn risk_tiers(tiers: &str, light: &str) -> String {
    format!(
        "[trust_core]\npaths_file = \"security/trust-core.paths\"\nevaluators = []\ndistinct_models = 2\n{tiers}[kinds]\n[trigger_evaluators]\n[protected_change]\nevaluators = []\ndistinct_models = 2\n[lanes]\nlight_max_lines = 50\nlight_max_files = 3\nlockfiles = [\"Cargo.lock\"]\ngenerated = [\"gen/**\"]\n[lanes.light]\nevaluators = {light}\nmodel = \"sonnet\"\neffort = \"low\"\n[lanes.full]\nevaluators = []\n"
    )
}

/// One tier table of `.agents/risk-tiers.toml`.
pub fn tier(name: &str, paths: &str, triggers: &str, evaluators: &str) -> String {
    format!("[{name}]\npaths = {paths}\ntriggers = {triggers}\nevaluators = {evaluators}\n")
}

/// Tiers by path alone, with no trigger and no evaluator.
pub fn plain_tiers(high: &str, medium: &str, low: &str) -> String {
    [("high", high), ("medium", medium), ("low", low)]
        .map(|(name, paths)| tier(name, paths, "[]", "[]"))
        .concat()
}

/// Makes `link` a directory link to `target`: a symbolic link on Unix and a junction on Windows,
/// which needs no privilege there.
pub fn link_dir(link: &Path, target: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    {
        let made = std::process::Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "mklink /J: {}",
            String::from_utf8_lossy(&made.stderr)
        );
    }
}
