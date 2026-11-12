//! `cargo xtask kit render`: every generated file, from the kit sources alone, so a fresh render is
//! byte-identical to the tree whenever the tree is current (team/03 section 1, K1).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::{agents, egress, settings};
use crate::config::Kit;
use crate::config::hooks::{Action, OnFailure};
use crate::repo::{Repo, walk_files, write_if_changed};

pub const SKILLS_SOURCE: &str = ".agents/skills";
pub const SKILLS_OUTPUT: &str = ".claude/skills";
pub const WORKFLOWS_SOURCE: &str = ".agents/kit/workflows";
pub const WORKFLOWS_OUTPUT: &str = ".claude/workflows";
pub const FIXTURE_INDEX: &str = "xtask/fixtures/hooks/README";
/// Directories the render owns outright: a file in them that the render does not produce is stale.
pub const OWNED_DIRS: &[&str] = &[".claude/agents/", ".claude/skills/", ".claude/workflows/"];
/// Files in the fleet directory the render owns, by name prefix; the rest of it is hand-written.
const OWNED_FLEET_PREFIXES: &[&str] = &["deploy/fleet/managed-settings", "deploy/fleet/egress"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rendered {
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    Missing(String),
    Differs(String),
    Stale(String),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WriteSummary {
    pub written: usize,
    pub unchanged: usize,
    pub removed: usize,
}

impl Rendered {
    /// Writes into the repository and removes stale files from the directories the render owns.
    pub fn write(&self, repo: &Repo) -> Result<WriteSummary> {
        let mut summary = self.write_to(repo.root())?;
        for stale in self.stale(repo)? {
            fs::remove_file(repo.path(&stale)).with_context(|| format!("removing {stale}"))?;
            summary.removed += 1;
        }
        Ok(summary)
    }

    pub fn write_to(&self, dir: &Path) -> Result<WriteSummary> {
        let mut summary = WriteSummary::default();
        for (path, bytes) in &self.files {
            let target = path
                .split('/')
                .fold(dir.to_path_buf(), |target, segment| target.join(segment));
            if write_if_changed(&target, bytes)? {
                summary.written += 1;
            } else {
                summary.unchanged += 1;
            }
        }
        Ok(summary)
    }

    /// How the tree differs from this render.
    pub fn drift(&self, repo: &Repo) -> Result<Vec<Drift>> {
        let mut drift = Vec::new();
        for (path, bytes) in &self.files {
            match fs::read(repo.path(path)) {
                Ok(current) if current == *bytes => {}
                Ok(_) => drift.push(Drift::Differs(path.clone())),
                Err(_) => drift.push(Drift::Missing(path.clone())),
            }
        }
        drift.extend(self.stale(repo)?.into_iter().map(Drift::Stale));
        Ok(drift)
    }

    fn stale(&self, repo: &Repo) -> Result<Vec<String>> {
        let mut stale = Vec::new();
        let mut candidates = Vec::new();
        for dir in OWNED_DIRS {
            candidates.extend(walk_files(&repo.path(dir))?);
        }
        candidates.extend(
            walk_files(&repo.path(settings::MANAGED_DIR))?
                .into_iter()
                .filter(|file| {
                    repo.relative(file).is_some_and(|path| {
                        OWNED_FLEET_PREFIXES
                            .iter()
                            .any(|prefix| path.as_str().starts_with(prefix))
                    })
                }),
        );
        for file in candidates {
            if let Some(path) = repo.relative(&file)
                && !self.files.contains_key(path.as_str())
            {
                stale.push(path.to_string());
            }
        }
        Ok(stale)
    }
}

impl std::fmt::Display for Drift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Drift::Missing(path) => write!(f, "{path} is missing; run cargo xtask kit render"),
            Drift::Differs(path) => write!(
                f,
                "{path} differs from a fresh render; run cargo xtask kit render"
            ),
            Drift::Stale(path) => write!(
                f,
                "{path} is not produced by the render; run cargo xtask kit render"
            ),
        }
    }
}

pub fn render(repo: &Repo, kit: &Kit) -> Result<Rendered> {
    let mut files = BTreeMap::new();
    files.insert(
        settings::SETTINGS_PATH.to_owned(),
        settings::to_bytes(&settings::project(repo, kit)?)?,
    );
    for (name, agent) in &kit.roster.agents {
        files.insert(
            agents::output_path(name),
            agents::render(repo, kit, name, agent)?.into_bytes(),
        );
    }
    copy_tree(repo, SKILLS_SOURCE, SKILLS_OUTPUT, |_| true, &mut files)?;
    copy_tree(
        repo,
        WORKFLOWS_SOURCE,
        WORKFLOWS_OUTPUT,
        |path| path.ends_with(".js") && !path.contains('/'),
        &mut files,
    )?;
    for (group, document) in &kit.permissions.managed {
        let value = settings::managed(repo, kit, group, document)?;
        files.insert(settings::managed_path(group), settings::to_bytes(&value)?);
    }
    if let Some(value) = egress::render(kit)? {
        files.insert(
            egress::EGRESS_OUTPUT.to_owned(),
            settings::to_bytes(&value)?,
        );
    }
    files.insert(FIXTURE_INDEX.to_owned(), fixture_index(kit).into_bytes());
    Ok(Rendered { files })
}

/// Copies files below `from` to `to`, byte for byte; `keep` sees the path relative to `from`.
fn copy_tree(
    repo: &Repo,
    from: &str,
    to: &str,
    keep: impl Fn(&str) -> bool,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let source = repo.path(from);
    for file in walk_files(&source)? {
        let Some(path) = repo.relative(&file) else {
            continue;
        };
        let Some(relative) = path.as_str().strip_prefix(&format!("{from}/")) else {
            continue;
        };
        if !keep(relative) {
            continue;
        }
        let bytes = fs::read(&file).with_context(|| format!("reading {path}"))?;
        files.insert(format!("{to}/{relative}"), bytes);
    }
    Ok(())
}

/// The index of hook fixtures: what a fixture file holds, then every registered command handler.
fn fixture_index(kit: &Kit) -> String {
    let mut out = String::from(
        "Hook fixtures for the V18 self-test (team/03 section 4.2). Each .json file here is one\n\
         fixture: the handler its cases run against, a preset and the cases. A file's name says\n\
         what its cases cover and need not be its handler's.\n\
         Generated by `cargo xtask kit render` from .agents/kit/hooks.toml; do not edit.\n\n\
         The registered handlers:\n",
    );
    for hook in &kit.hooks.hooks {
        let Action::Command {
            handler,
            on_failure,
        } = &hook.action
        else {
            continue;
        };
        let matcher = hook.matcher.as_deref().unwrap_or("(all)");
        let timeout = hook
            .timeout
            .map_or_else(|| "default".to_owned(), |seconds| format!("{seconds} s"));
        let failure = match on_failure {
            Some(OnFailure::Block) => "blocks when it fails",
            Some(OnFailure::Continue) => "continues when it fails",
            None => "Claude Code's default when it fails",
        };
        let _ = writeln!(
            out,
            "{handler}  {} {matcher}, timeout {timeout}, {failure}",
            hook.event
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempRepo;

    fn rendered(temp: &TempRepo) -> Rendered {
        let repo = temp.repo();
        render(&repo, &Kit::load(&repo).unwrap()).unwrap()
    }

    fn json(rendered: &Rendered, path: &str) -> serde_json::Value {
        serde_json::from_slice(&rendered.files[path]).unwrap()
    }

    fn text(rendered: &Rendered, path: &str) -> String {
        String::from_utf8(rendered.files[path].clone()).unwrap()
    }

    #[test]
    fn render_is_deterministic_and_a_written_tree_has_no_drift() {
        let temp = TempRepo::create();
        let first = rendered(&temp);
        assert_eq!(first, rendered(&temp));
        assert!(!first.drift(&temp.repo()).unwrap().is_empty());
        first.write(&temp.repo()).unwrap();
        assert!(first.drift(&temp.repo()).unwrap().is_empty());
        assert_eq!(rendered(&temp), first);
    }

    #[test]
    fn settings_carry_permissions_hooks_and_plugins() {
        let settings = json(&rendered(&TempRepo::create()), settings::SETTINGS_PATH);
        let deny: Vec<&str> = settings["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            &deny[..3],
            &[
                "Edit(/Cargo.toml)",
                "Edit(**/AGENTS.md)",
                "Edit(/.claude/**)"
            ]
        );
        assert!(deny.contains(&"Bash(git push --force *)"));
        assert_eq!(settings["permissions"]["defaultMode"], "default");
        assert_eq!(settings["model"], "claude-sonnet-5-5");
        let ids = serde_json::json!(["claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-2"]);
        assert_eq!(settings["availableModels"], ids);
        assert_eq!(
            settings["enabledPlugins"]["cleanup@grdr-agent-marketplace"],
            true
        );
        let pre = &settings["hooks"]["PreToolUse"][0];
        assert_eq!(pre["matcher"], "Edit|Write");
        assert_eq!(
            pre["hooks"][0]["command"],
            "\"${CLAUDE_PROJECT_DIR}/.agent/kit/bin/xtask\" hook guard-path"
        );
        assert_eq!(pre["hooks"][0]["onFailure"], "block");
        assert_eq!(
            pre["hooks"][1]["command"],
            "\"${CLAUDE_PROJECT_DIR}/.agent/kit/bin/xtask\" hook guard-extra"
        );
        assert!(pre["hooks"][0].get("args").is_none());
        assert!(settings["hooks"]["Stop"][0].get("matcher").is_none());
        for key in settings::MANAGED_ONLY_KEYS {
            assert!(settings.get(key).is_none(), "{key}");
        }
    }

    #[test]
    fn agents_are_front_matter_then_common_block_then_body() {
        let rendered = rendered(&TempRepo::create());
        let chief = text(&rendered, ".claude/agents/chief-architect.md");
        assert!(chief.starts_with("---\nname: chief-architect\ndescription: \"Owns the spine"));
        assert!(chief.contains("\nmodel: claude-fable-5-2\n"));
        let tail = "\npermissionMode: dontAsk\nmaxTurns: 60\nskills:\n  - grdr-verify\n---\n\n## Rules for every agent";
        assert!(chief.contains(tail));
        let common = chief.find("## Rules for every agent").unwrap();
        assert!(chief.find(crate::kit::OWNERSHIP_SENTENCE).unwrap() > common);
        let implementer = text(&rendered, ".claude/agents/impl-rust.md");
        assert!(implementer.contains("model: claude-sonnet-5-5"));
        assert!(!implementer.contains("disallowedTools"));
    }

    #[test]
    fn skills_workflows_managed_settings_and_fixture_index() {
        let rendered = rendered(&TempRepo::create());
        assert!(
            rendered
                .files
                .contains_key(".claude/skills/grdr-verify/SKILL.md")
        );
        assert!(
            rendered
                .files
                .contains_key(".claude/skills/grdr-verify/references/gates.md")
        );
        assert!(rendered.files.contains_key(".claude/workflows/review.js"));
        let managed = json(&rendered, "deploy/fleet/managed-settings.json");
        assert_eq!(managed["permissions"]["deny"][0], "Edit(./Cargo.toml)");
        assert_eq!(managed["permissions"]["deny"][3], "WebFetch");
        assert_eq!(
            managed["strictKnownMarketplaces"][0]["pathPattern"],
            r"(^|/)\.agents/marketplace/?$"
        );
        let evaluator = json(&rendered, "deploy/fleet/managed-settings.evaluator.json");
        assert!(
            evaluator["permissions"]["deny"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("Edit"))
        );
        let index = text(&rendered, FIXTURE_INDEX);
        assert!(
            index.contains(
                "\nguard-path  PreToolUse Edit|Write, timeout 10 s, blocks when it fails"
            )
        );
        assert!(index.contains("\nstop-gate  Stop (all)"));
        assert!(index.contains("Each .json file here is one\nfixture"));
        assert!(!index.contains("directory"), "{index}");
    }

    #[test]
    fn stale_rendered_files_are_reported_and_removed() {
        let temp = TempRepo::create();
        let first = rendered(&temp);
        first.write(&temp.repo()).unwrap();
        temp.write(".claude/agents/retired.md", "---\nname: retired\n---\n");
        temp.write("deploy/fleet/managed-settings.gardener.json", "{}\n");
        temp.write("deploy/fleet/Containerfile", "FROM x\n");
        let drift = first.drift(&temp.repo()).unwrap();
        assert_eq!(drift.len(), 2, "{drift:?}");
        assert!(drift.contains(&Drift::Stale(".claude/agents/retired.md".into())));
        assert_eq!(first.write(&temp.repo()).unwrap().removed, 2);
        assert!(
            temp.root()
                .join("deploy")
                .join("fleet")
                .join("Containerfile")
                .is_file()
        );
    }

    const VENDORS: &str = "[research]
skill = \"simplify\"
egress_lists = [\"intel\"]

[vendor.acme]
name = \"Acme\"
domains = [\"docs.acme.example\"]
brief = \"docs/references/research/01-acme.md\"

[sources.ietf]
domains = [\"datatracker.ietf.org\"]
urls = [\"https://datatracker.ietf.org/wg/oauth/\"]
";
    const EGRESS: &str = "[list.A]
hosts = [\"api.anthropic.com\"]

[list.A.group.evaluator]
hosts = [\"replay.example.org\"]

[list.B]
extends = \"A\"
hosts_from_request = true

[list.intel]
hosts = [\"api.osv.dev\"]
";

    /// The fixture with vendors.toml granting `simplify`, which only impl-rust loads, an egress
    /// file, a repository and a folded alias; the managed implementer document no longer denies
    /// WebFetch outright.
    fn research_fixture() -> TempRepo {
        let temp = TempRepo::create();
        temp.write(".agents/kit/vendors.toml", VENDORS);
        temp.write(".agents/kit/egress.toml", EGRESS);
        temp.write(
            ".agents/harness.toml",
            "[github]
repository = \"owner/name\"

[skills]
builtin = [\"simplify\"]
",
        );
        let permissions =
            std::fs::read_to_string(temp.repo().path(".agents/kit/permissions.toml")).unwrap();
        temp.write(
            ".agents/kit/permissions.toml",
            &permissions.replacen(
                "deny = [\"WebFetch\"]",
                "deny = [\"Bash(gh pr merge *)\"]",
                1,
            ),
        );
        let models = std::fs::read_to_string(temp.repo().path(".agents/models.toml")).unwrap();
        temp.write(
            ".agents/models.toml",
            &format!(
                "{models}folded_aliases = {{ haiku = \"sonnet\" }}
"
            ),
        );
        temp
    }

    fn strings(value: &serde_json::Value) -> Vec<&str> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect()
    }

    #[test]
    fn the_research_grant_reaches_definitions_rules_env_and_egress() {
        let rendered = rendered(&research_fixture());
        let implementer = text(&rendered, ".claude/agents/impl-rust.md");
        assert!(implementer.contains(
            "
tools: Read, Edit, Write, Bash, WebFetch, WebSearch
"
        ));
        let chief = text(&rendered, ".claude/agents/chief-architect.md");
        assert!(!chief.contains("WebSearch"), "{chief}");
        let settings = json(&rendered, settings::SETTINGS_PATH);
        let allow = strings(&settings["permissions"]["allow"]);
        assert_eq!(
            &allow[allow.len() - 3..],
            &[
                "WebFetch(domain:docs.acme.example)",
                "WebFetch(domain:datatracker.ietf.org)",
                "WebSearch"
            ]
        );
        assert_eq!(settings["env"]["GH_REPO"], "owner/name");
        assert_eq!(
            settings["env"]["ANTHROPIC_DEFAULT_HAIKU_MODEL"],
            "claude-sonnet-5-5"
        );
        let managed = json(&rendered, "deploy/fleet/managed-settings.json");
        assert!(strings(&managed["permissions"]["allow"]).contains(&"WebSearch"));
        assert_eq!(managed["env"]["GH_REPO"], "owner/name");
        let evaluator = json(&rendered, "deploy/fleet/managed-settings.evaluator.json");
        assert!(evaluator["permissions"].get("allow").is_none());
        let egress = json(&rendered, egress::EGRESS_OUTPUT);
        assert_eq!(
            strings(&egress["lists"]["intel"]["hosts"]),
            vec!["api.osv.dev", "docs.acme.example", "datatracker.ietf.org"]
        );
        assert_eq!(
            strings(&egress["lists"]["B"]["hosts"]),
            vec!["api.anthropic.com"]
        );
        assert_eq!(
            strings(&egress["lists"]["A"]["groups"]["evaluator"]),
            vec!["replay.example.org"]
        );
        assert_eq!(egress["roles"]["impl-rust"]["research"], true);
        assert_eq!(egress["roles"]["chief-architect"]["list"], "B");
        assert_eq!(egress["roles"]["chief-architect"]["research"], false);
    }

    #[test]
    fn rules_fill_their_placeholders_and_every_kit_workflow_is_allowed() {
        let temp = TempRepo::create();
        let path = ".agents/kit/permissions.toml";
        let original = std::fs::read_to_string(temp.repo().path(path)).unwrap();
        let templated = original.replacen(
            "allow = [\"Bash(cargo xtask *)\"]\n\n[sandbox]",
            "allow = [\"Bash(cargo xtask *)\", \"Bash(gh api --method POST repos/{repository}/check-runs *)\", \"Read(~/.claude/plugins/cache/{marketplace}/**)\"]\n\n[sandbox]",
            1,
        );
        assert_ne!(templated, original);
        temp.write(path, &templated);
        let repo = temp.repo();
        let unset = render(&repo, &Kit::load(&repo).unwrap()).unwrap_err();
        assert!(
            format!("{unset:#}").contains("names {repository}"),
            "{unset:#}"
        );
        let harness = std::fs::read_to_string(repo.path(".agents/harness.toml")).unwrap();
        temp.write(
            ".agents/harness.toml",
            &format!("[github]\nrepository = \"owner/name\"\n\n{harness}"),
        );
        let settings = json(&rendered(&temp), settings::SETTINGS_PATH);
        let allow = &settings["permissions"]["allow"];
        assert_eq!(
            allow,
            &serde_json::json!([
                "Bash(cargo xtask *)",
                "Bash(gh api --method POST repos/owner/name/check-runs *)",
                "Read(~/.claude/plugins/cache/grdr-agent-marketplace/**)",
                "Workflow(review)"
            ])
        );
        assert!(!settings.to_string().contains("{repository}"));
        let evaluator = json(
            &rendered(&temp),
            "deploy/fleet/managed-settings.evaluator.json",
        );
        assert!(
            evaluator["permissions"].get("allow").is_none(),
            "no evaluator of the fixture has the Workflow tool: {evaluator}"
        );
        temp.add_agents("[agent.eval-diff]\ngroup = \"evaluator\"\ndescription = \"Reviews diffs.\"\nmodel = \"sonnet\"\neffort = \"high\"\ncap_role = \"evaluator\"\nmax_turns = 40\ntools = [\"Read\", \"Workflow\"]\nwrite = []\ndeny_write = \"@protected\"\nnet = \"A\"\ntrigger = \"event\"\nbody = \"templates/agents/impl-rust.md\"\n");
        let evaluator = json(
            &rendered(&temp),
            "deploy/fleet/managed-settings.evaluator.json",
        );
        assert_eq!(
            evaluator["permissions"]["allow"],
            serde_json::json!(["Workflow(review)"])
        );
    }

    #[test]
    fn contradictions_with_the_grant_or_derived_env_fail_the_render() {
        let cases: [(&str, &str, &str); 5] = [
            (
                ".agents/roster.toml",
                "tools = [\"Read\", \"Grep\", \"Write\"]",
                "tools = [\"Read\", \"WebSearch\"]",
            ),
            (
                ".agents/roster.toml",
                "tools = [\"Read\", \"Edit\", \"Write\", \"Bash\"]
",
                "tools = [\"Read\"]
disallowed_tools = [\"WebFetch\"]
",
            ),
            (
                ".agents/kit/permissions.toml",
                "ask = [\"Bash(git push *)\"]",
                "ask = [\"WebFetch\"]",
            ),
            (
                ".agents/kit/permissions.toml",
                "[settings.env]
",
                "[settings.env]
GH_REPO = \"x/y\"
",
            ),
            (".agents/kit/egress.toml", "[list.intel]", "[list.feeds]"),
        ];
        for (path, from, to) in cases {
            let temp = research_fixture();
            let original = std::fs::read_to_string(temp.repo().path(path)).unwrap();
            assert!(original.contains(from), "{path} lacks {from}");
            temp.write(path, &original.replacen(from, to, 1));
            let repo = temp.repo();
            assert!(render(&repo, &Kit::load(&repo).unwrap()).is_err(), "{to}");
        }
    }
}
